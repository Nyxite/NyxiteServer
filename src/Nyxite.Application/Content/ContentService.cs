using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Keys;
using Nyxite.BlobStore;
using Nyxite.Contracts.Content;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Domain.Structure;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Content;

/// <summary>Tells the relay rooms about updates that arrived over REST, so live peers get them too (05 §5.2).</summary>
public interface IRelayNotifier
{
    Task UpdatesStoredAsync(Guid fileId, IReadOnlyList<CrdtUpdateDto> updates, CancellationToken ct);
}

/// <summary>The outcome of a blob upload: the stored version, and the winning head when it lost a concurrent write.</summary>
public sealed record BlobWriteResult(VersionDto Version, VersionDto? Winner);

/// <summary>A stored ciphertext to stream back, with what the response headers carry.</summary>
public sealed record BlobRead(Stream Content, VersionDto Version);

/// <summary>
/// File content as the server sees it (server 05, 06, 10): ciphertext blobs with a version history, and for text files
/// an ordered log of encrypted CRDT updates that clients compact into encrypted snapshots. The server orders, stores
/// and hands back. It never decrypts, merges or compares content, so every check here is about structure: frame layout,
/// key generation, sequence numbers, sizes and reach.
/// </summary>
public sealed class ContentService(
    NyxiteDbContext db, IBlobStore blobs, DeviceGuard guard, AuditWriter audit, TimeProvider time, IRelayNotifier relay,
    IOptions<ContentOptions> options)
{
    public const int DefaultPageSize = 50;
    public const int MaxPageSize = 200;
    public const int MaxUpdatesPerSubmit = 100;
    public const int MaxLogPage = 500;

    private readonly ContentOptions _options = options.Value;

    public long MaxInlineBlobBytes => _options.MaxInlineBlobBytes;
    public int MaxAwarenessBytes => _options.MaxAwarenessBytes;

    // ---------------------------------------------------------------- blobs (ink, office, image, binary: last write wins)

    /// <summary>
    /// Stores a new version of a blob-synced file (06 §6.5). When <paramref name="parentSeq"/> is the current head the
    /// version becomes the head. Otherwise someone else wrote first: the bytes are still kept, as a version that is not
    /// the head, and the caller gets the winner back, so nothing is lost and the client can offer both.
    /// </summary>
    public async Task<BlobWriteResult> PutBlobAsync(ClaimsPrincipal principal, Guid fileId, long parentSeq, string? contentHash, Guid keyId,
        StagedBlob ciphertext, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var hash = ContentHash(contentHash);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(userId, fileId, ct);
        if (ContentTypes.IsCrdt(file.ContentType)) throw AuthException.Validation("A text file is written through its update log and snapshots, not as a blob.");
        await CheckUploadAsync(file, userId, keyId, ciphertext, ct);

        var head = await HeadAsync(file, ct);
        var wins = parentSeq == (head?.Seq ?? 0);
        var version = await AddVersionAsync(file, userId, hash, keyId, ciphertext, crdtSeq: null, becomesHead: wins, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return new BlobWriteResult(ToDto(version, file), wins ? null : ToDto(head!, file));
    }

    /// <summary>The head ciphertext, or null when the caller's copy named by <paramref name="ifNoneMatch"/> is current.</summary>
    public async Task<BlobRead?> ReadHeadAsync(ClaimsPrincipal principal, Guid fileId, string? ifNoneMatch, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        var head = await HeadAsync(file, ct) ?? throw AuthException.NotFound();
        if (ifNoneMatch is not null && ifNoneMatch.Trim().Trim('"') == Base64UrlCodec.Encode(head.ContentHash)) return null;
        return await OpenAsync(head, file, ct);
    }

    // ---------------------------------------------------------------- versions

    public async Task<(IReadOnlyList<VersionDto> Items, string? NextCursor)> ListVersionsAsync(ClaimsPrincipal principal, Guid fileId, string? cursor,
        int? limit, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        if (limit is < 1 or > MaxPageSize) throw AuthException.Validation($"limit must be 1 to {MaxPageSize}.");
        var take = limit ?? DefaultPageSize;
        var before = long.MaxValue;
        if (cursor is not null && (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != 8
                                   || (before = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(bytes)) < 1))
            throw AuthException.Validation("cursor is malformed.");

        var rows = await db.FileVersions.AsNoTracking().Where(v => v.FileId == fileId && v.Seq < before)
            .OrderByDescending(v => v.Seq).Take(take + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > take)
        {
            var last = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(last, rows[take - 1].Seq);
            next = Base64UrlCodec.Encode(last);
        }

        return (rows.Take(take).Select(v => ToDto(v, file)).ToList(), next);
    }

    public async Task<VersionDto> GetVersionAsync(ClaimsPrincipal principal, Guid fileId, long seq, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        return ToDto(await VersionAsync(fileId, seq, ct), file);
    }

    public async Task<BlobRead> ReadVersionAsync(ClaimsPrincipal principal, Guid fileId, long seq, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        return await OpenAsync(await VersionAsync(fileId, seq, ct), file, ct);
    }

    /// <summary>
    /// Records that the next head is a restore of version <paramref name="seq"/> (10 §10.5). No content moves here:
    /// the restored bytes arrive through the normal write path, and that version then carries the link.
    /// </summary>
    public async Task RecordRestoreAsync(ClaimsPrincipal principal, Guid fileId, RestoreRequest body, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(userId, fileId, ct);
        await VersionAsync(fileId, body.Seq, ct);
        file.PendingRestoreSeq = body.Seq;
        audit.Add("version.restore", userId, request, targetType: "file", targetId: fileId, detail: new { seq = body.Seq });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    // ---------------------------------------------------------------- encrypted update log (text files)

    /// <summary>
    /// Appends encrypted updates to a text file's log and gives each its sequence number (05 §5.5). An update that was
    /// already stored under the same <c>clientUpdateId</c> gets its old number back, so a client can resend after a lost
    /// answer. Sequence numbers come from a counter on the file row, which is locked, so they have no gaps or ties.
    /// </summary>
    public async Task<UpdateAcksDto> SubmitUpdatesAsync(ClaimsPrincipal principal, Guid fileId, IReadOnlyList<SubmitUpdateItem> updates, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        if (updates.Count is 0 or > MaxUpdatesPerSubmit) throw AuthException.Validation($"updates must hold 1 to {MaxUpdatesPerSubmit} entries.");
        var frames = new List<byte[]>(updates.Count);
        foreach (var update in updates)
        {
            if (!Base64UrlCodec.TryDecode(update.UpdateEnc, out var frame) || frame.Length > _options.MaxCrdtUpdateBytes
                || !NyxcFrame.TryParseHeader(frame, out var header) || header.KeyId != update.KeyId)
                throw AuthException.Validation("updateEnc must be an NYXC frame within the size limit, sealed with keyId.");
            frames.Add(frame);
        }

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(userId, fileId, ct);
        if (file.CrdtDocId is not { } docId) throw AuthException.Validation("Only text files have an update log.");
        if (file.SyncPolicy == SyncPolicies.Excluded) throw ExcludedContent();
        var currentKey = await CurrentKeyIdAsync(file, ct);

        var clientIds = updates.Select(u => u.ClientUpdateId).ToList();
        var known = await db.CrdtUpdates.Where(u => u.CrdtDocId == docId && u.ClientUpdateId != null && clientIds.Contains(u.ClientUpdateId.Value))
            .ToDictionaryAsync(u => u.ClientUpdateId!.Value, u => u.Seq, ct);
        var now = time.GetUtcNow();
        var acks = new List<UpdateAckDto>(updates.Count);
        var stored = new List<CrdtUpdateDto>();
        for (var i = 0; i < updates.Count; i++)
        {
            var update = updates[i];
            if (known.TryGetValue(update.ClientUpdateId, out var seq))
            {
                acks.Add(new UpdateAckDto(update.ClientUpdateId, seq));
                continue;
            }

            // Checked only for new updates: a resend from before a key rotation still gets its old number.
            if (update.KeyId != currentKey) throw KeyGenerationStale();
            seq = ++file.CrdtHeadSeq;
            known[update.ClientUpdateId] = seq;
            db.CrdtUpdates.Add(new CrdtUpdateEntity
            {
                CrdtDocId = docId, Seq = seq, UpdateEnc = frames[i], KeyId = update.KeyId, AuthorId = userId,
                ClientUpdateId = update.ClientUpdateId, CreatedAt = now,
            });
            acks.Add(new UpdateAckDto(update.ClientUpdateId, seq));
            stored.Add(new CrdtUpdateDto(seq, update.KeyId, update.UpdateEnc!, userId, now));
        }

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        // After the commit: peers are only told about updates that are durable.
        if (stored.Count > 0) await relay.UpdatesStoredAsync(fileId, stored, ct);
        return new UpdateAcksDto(acks);
    }

    /// <summary>Updates after <paramref name="since"/> in order. Updates a snapshot covers may be pruned; a client then starts from the snapshot.</summary>
    public async Task<CrdtUpdatesDto> ReadUpdatesAsync(ClaimsPrincipal principal, Guid fileId, long since, int? limit, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        if (file.CrdtDocId is not { } docId) throw AuthException.Validation("Only text files have an update log.");
        if (since < 0 || limit is < 1 or > MaxLogPage) throw AuthException.Validation($"since must not be negative and limit must be 1 to {MaxLogPage}.");
        var take = limit ?? MaxPageSize;
        var rows = await db.CrdtUpdates.AsNoTracking().Where(u => u.CrdtDocId == docId && u.Seq > since)
            .OrderBy(u => u.Seq).Take(take + 1).ToListAsync(ct);
        return new CrdtUpdatesDto(
            rows.Take(take).Select(u => new CrdtUpdateDto(u.Seq, u.KeyId, Base64UrlCodec.Encode(u.UpdateEnc), u.AuthorId, u.CreatedAt)).ToList(),
            rows.Count > take);
    }

    // ---------------------------------------------------------------- snapshots (text files)

    /// <summary>
    /// Takes a client-made encrypted snapshot of a text file as a new version (05 §5.6). <paramref name="crdtSeq"/> is the
    /// last update the snapshot contains. It must exist and must not be older than the snapshot that is already the
    /// head, because the head tells every client where to start reading the log.
    /// </summary>
    public async Task<VersionDto> PutSnapshotAsync(ClaimsPrincipal principal, Guid fileId, long crdtSeq, string? contentHash, Guid keyId,
        StagedBlob ciphertext, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var hash = ContentHash(contentHash);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(userId, fileId, ct);
        if (file.CrdtDocId is null) throw AuthException.Validation("Only text files have snapshots.");
        await CheckUploadAsync(file, userId, keyId, ciphertext, ct);
        if (crdtSeq < 0 || crdtSeq > file.CrdtHeadSeq) throw AuthException.Validation("The snapshot names an update the log does not have.");
        var head = await HeadAsync(file, ct);
        if (head?.CrdtSeq > crdtSeq) throw AuthException.Conflict("A newer snapshot is already stored.");

        var version = await AddVersionAsync(file, userId, hash, keyId, ciphertext, crdtSeq, becomesHead: true, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return ToDto(version, file);
    }

    public async Task<BlobRead> ReadSnapshotAsync(ClaimsPrincipal principal, Guid fileId, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        if (file.CrdtDocId is null) throw AuthException.NotFound();
        return await OpenAsync(await HeadAsync(file, ct) ?? throw AuthException.NotFound(), file, ct);
    }

    /// <summary>The head snapshot of a text file, for the relay's join answer; null when there is none yet.</summary>
    public async Task<VersionDto?> SnapshotPointerAsync(ClaimsPrincipal principal, Guid fileId, CancellationToken ct)
    {
        var file = await FileAsync(principal.UserId(), fileId, ct);
        return file.CrdtDocId is null || await HeadAsync(file, ct) is not { } head ? null : ToDto(head, file);
    }

    // ---------------------------------------------------------------- usage

    /// <summary>The ciphertext bytes that count against a user's quota: every version of every file they own, Trash included.</summary>
    public async Task<long> UsageBytesAsync(Guid userId, CancellationToken ct) =>
        await db.FileVersions.Where(v => db.Files.Any(f => f.Id == v.FileId && f.OwnerId == userId)).SumAsync(v => (long?)v.SizeCipher, ct) ?? 0;

    // ---------------------------------------------------------------- shared steps

    private async Task CheckUploadAsync(FileEntity file, Guid userId, Guid keyId, StagedBlob ciphertext, CancellationToken ct)
    {
        if (file.SyncPolicy == SyncPolicies.Excluded) throw ExcludedContent();
        if (ciphertext.Length > _options.MaxInlineBlobBytes) throw PayloadTooLarge("The upload is larger than the inline limit.");
        if (ciphertext.Length < NyxcFrame.Overhead || !NyxcFrame.TryParseHeader(ciphertext.Head.Span, out var header) || header.KeyId != keyId)
            throw AuthException.Validation("The body must be an NYXC frame sealed with the key named in Nyxite-Key-Id.");
        if (keyId != await CurrentKeyIdAsync(file, ct)) throw KeyGenerationStale();

        var quota = await db.Users.Where(u => u.Id == file.OwnerId).Select(u => u.StorageQuotaBytes).SingleAsync(ct);
        if (quota is { } limit && await UsageBytesAsync(file.OwnerId, ct) + ciphertext.Length > limit)
            throw PayloadTooLarge("The upload would exceed the storage quota.");
    }

    private async Task<FileVersionEntity> AddVersionAsync(FileEntity file, Guid userId, byte[] contentHash, Guid keyId, StagedBlob ciphertext,
        long? crdtSeq, bool becomesHead, CancellationToken ct)
    {
        // The blob is named before the row that points to it. A crash in between leaves an unreferenced blob for the
        // garbage collector, never a version without bytes. The address lock keeps the collector from deleting a blob
        // that this transaction is about to reference again (BlobCollector).
        var address = StorageAddress(file.Id, keyId, contentHash);
        await BlobCollector.LockAddressAsync(db, address, ct);
        var reference = await blobs.CommitAsync(ciphertext, address, ct);
        var now = time.GetUtcNow();
        var version = new FileVersionEntity
        {
            Id = Guid.CreateVersion7(now), FileId = file.Id, Seq = ++file.VersionSeq, ContentHash = contentHash, BlobRef = reference.Address.Hex,
            SizeCipher = reference.Size, KeyId = keyId, Layout = "single", AuthorId = userId, CrdtSeq = crdtSeq, CreatedAt = now,
        };
        db.FileVersions.Add(version);
        if (becomesHead)
        {
            version.RestoredFromSeq = file.PendingRestoreSeq;
            file.PendingRestoreSeq = null;
            file.CurrentVersionId = version.Id;
            file.UpdatedAt = now;
        }

        return version;
    }

    /// <summary>
    /// Where a version's ciphertext lies. The client's content address is the hash of the plaintext, which is the same
    /// for equal content in two files, while their ciphertexts differ because each file has its own key. The address is
    /// therefore scoped to the file and the key: equal content dedups within one file and key, and never resolves to
    /// bytes another key sealed (10 §10.3).
    /// </summary>
    private static BlobAddress StorageAddress(Guid fileId, Guid keyId, byte[] contentHash)
    {
        var input = new byte[16 + 16 + contentHash.Length];
        fileId.TryWriteBytes(input, bigEndian: true, out _);
        keyId.TryWriteBytes(input.AsSpan(16), bigEndian: true, out _);
        contentHash.CopyTo(input, 32);
        return BlobAddress.From(Blake3.Hash(input));
    }

    private async Task<BlobRead> OpenAsync(FileVersionEntity version, FileEntity file, CancellationToken ct)
    {
        var reference = new BlobRef(BlobAddress.From(Convert.FromHexString(version.BlobRef)), version.SizeCipher);
        return new BlobRead(await blobs.OpenReadAsync(reference, ct), ToDto(version, file));
    }

    private static byte[] ContentHash(string? contentHash) =>
        Base64UrlCodec.TryDecode(contentHash, out var hash) && hash.Length == BlobAddress.Size
            ? hash
            : throw AuthException.Validation("Nyxite-Content-Hash must be a base64url BLAKE3-256 hash.");

    private Task<FileVersionEntity?> HeadAsync(FileEntity file, CancellationToken ct) =>
        file.CurrentVersionId is { } id ? db.FileVersions.AsNoTracking().SingleOrDefaultAsync(v => v.Id == id, ct) : Task.FromResult<FileVersionEntity?>(null);

    private async Task<FileVersionEntity> VersionAsync(Guid fileId, long seq, CancellationToken ct) =>
        await db.FileVersions.AsNoTracking().SingleOrDefaultAsync(v => v.FileId == fileId && v.Seq == seq, ct) ?? throw AuthException.NotFound();

    private async Task<Guid> CurrentKeyIdAsync(FileEntity file, CancellationToken ct) =>
        await db.FileKeys.Where(k => k.FileId == file.Id && k.Generation == file.KeyGeneration).Select(k => k.KeyId).FirstAsync(ct);

    // ---------------------------------------------------------------- reach

    /// <summary>A live file the caller can reach. Until shares exist (Phase 2.2) that is a file in a project they own.</summary>
    private async Task<FileEntity> FileAsync(Guid userId, Guid id, CancellationToken ct) =>
        await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == id && f.DeletedAt == null
            && db.Projects.Any(p => p.Id == f.ProjectId && p.OwnerId == userId && p.DeletedAt == null), ct)
        ?? throw AuthException.NotFound();

    /// <summary>The same file, tracked and locked for the transaction: writes to one file are ordered one after the other.</summary>
    private async Task<FileEntity> LockFileAsync(Guid userId, Guid id, CancellationToken ct)
    {
        var file = (await db.Files.FromSql($"SELECT * FROM files WHERE id = {id} AND deleted_at IS NULL FOR UPDATE").ToListAsync(ct)).SingleOrDefault();
        if (file is null || !await db.Projects.AnyAsync(p => p.Id == file.ProjectId && p.OwnerId == userId && p.DeletedAt == null, ct))
            throw AuthException.NotFound();
        return file;
    }

    /// <summary>The caller as someone who may write content: on an active device and not blocked (04 "structure").</summary>
    private async Task<Guid> WriterAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        return status == UserStatus.Blocked ? throw new AuthException(403, "account_blocked", "This account is blocked for changes.") : userId;
    }

    private static AuthException ExcludedContent() => new(409, "excluded_content", "This file is excluded from sync; the server takes no content for it.");

    private static AuthException KeyGenerationStale() => new(412, "key_generation_stale", "The content is sealed with a key that is not the file's current key.");

    public static AuthException PayloadTooLarge(string title) => new(413, "payload_too_large", title);

    private static VersionDto ToDto(FileVersionEntity v, FileEntity file) =>
        new(v.Seq, Base64UrlCodec.Encode(v.ContentHash), v.Layout, v.SizeCipher, v.KeyId, v.Id == file.CurrentVersionId, v.AuthorId,
            v.RestoredFromSeq, v.CrdtSeq, v.CreatedAt);
}

/// <summary>
/// Deletes updates a snapshot has made redundant (05 §5.6). An update goes only when the head snapshot covers it, it is
/// older than the safety tail in days and it is not among the newest updates of its document, so a client that was
/// offline for a few days still finds the updates after its cursor.
/// </summary>
public sealed class CrdtLogPruner(NyxiteDbContext db, TimeProvider time, IOptions<RelayOptions> options)
{
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var cutoff = time.GetUtcNow() - TimeSpan.FromDays(options.Value.SafetyTailDays);
        var tail = (long)options.Value.SafetyTailUpdates;
        return await db.Database.ExecuteSqlAsync($"""
            DELETE FROM crdt_updates u
            USING files f, file_versions v
            WHERE v.id = f.current_version_id AND v.crdt_seq IS NOT NULL
              AND u.crdt_doc_id = f.crdt_doc_id
              AND u.seq <= v.crdt_seq AND u.seq <= f.crdt_head_seq - {tail} AND u.created_at < {cutoff}
            """, ct);
    }
}
