using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Keys;
using Nyxite.Application.Sync;
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

/// <summary>
/// Who acts on content: an account, or a link guest through its share (09 §9.4). A guest principal carries the
/// <c>share_id</c> claim of its guest token and nothing else, so it can never pass for an account.
/// </summary>
public readonly record struct ContentActor(Guid? UserId, Guid? ShareId)
{
    public static ContentActor Of(ClaimsPrincipal principal) =>
        principal.GuestShareId() is { } shareId ? new ContentActor(null, shareId) : new ContentActor(principal.UserId(), null);
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
    NyxiteDbContext db, IBlobStore blobs, DeviceGuard guard, AuditWriter audit, TimeProvider time, IRelayNotifier relay, ChangeFeed feed,
    IFileAccess access, IdempotencyStore idempotency, IOptions<ContentOptions> options)
{
    public const string RestoreEndpoint = "POST /files/{id}/restore";
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
        var actor = await WriterAsync(principal, ct);
        var hash = ContentHash(contentHash);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(actor, fileId, ct);
        if (ContentTypes.IsCrdt(file.ContentType)) throw AuthException.Validation("A text file is written through its update log and snapshots, not as a blob.");
        await CheckUploadAsync(file, keyId, ciphertext, ct);

        var head = await HeadAsync(file, ct);
        var wins = parentSeq == (head?.Seq ?? 0);
        var version = await AddVersionAsync(file, actor.UserId, hash, keyId, ciphertext, crdtSeq: null, parentSeq, becomesHead: wins, ct);
        await feed.VersionAsync(file, version, isHead: wins, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return new BlobWriteResult(ToDto(version, file), wins ? null : ToDto(head!, file));
    }

    /// <summary>The head ciphertext, or null when the caller's copy named by <paramref name="ifNoneMatch"/> is current.</summary>
    public async Task<BlobRead?> ReadHeadAsync(ClaimsPrincipal principal, Guid fileId, string? ifNoneMatch, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        var head = await HeadAsync(file, ct) ?? throw AuthException.NotFound();
        if (ifNoneMatch is not null && ifNoneMatch.Trim().Trim('"') == Base64UrlCodec.Encode(head.ContentHash)) return null;
        return await OpenAsync(head, file, ct);
    }

    // ---------------------------------------------------------------- versions

    public async Task<(IReadOnlyList<VersionDto> Items, string? NextCursor)> ListVersionsAsync(ClaimsPrincipal principal, Guid fileId, string? cursor,
        int? limit, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
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
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        return ToDto(await VersionAsync(fileId, seq, ct), file);
    }

    public async Task<BlobRead> ReadVersionAsync(ClaimsPrincipal principal, Guid fileId, long seq, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        return await OpenAsync(await VersionAsync(fileId, seq, ct), file, ct);
    }

    /// <summary>One version, or null when the caller's copy named by <paramref name="ifNoneMatch"/> is that version.</summary>
    public async Task<BlobRead?> ReadVersionAsync(ClaimsPrincipal principal, Guid fileId, long seq, string? ifNoneMatch, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        var version = await VersionAsync(fileId, seq, ct);
        if (ifNoneMatch is not null && ifNoneMatch.Trim().Trim('"') == Base64UrlCodec.Encode(version.ContentHash)) return null;
        return await OpenAsync(version, file, ct);
    }

    /// <summary>
    /// Records that the caller's next version of the file is a restore of version <c>seq</c> (10 §10.5). No content
    /// moves here: the restored bytes arrive through the normal write path, and the caller's next version, head or kept
    /// LWW loser, then carries the link. A version another account writes in between neither takes nor clears it, so a
    /// collaborator's edit is never labelled a restore. A second restore by anyone replaces the pending one, while the
    /// audit keeps both, and a mark no version of its account takes within <see cref="ContentOptions.RestoreMarkLifetime"/>
    /// lapses. A replay of the same <c>Idempotency-Key</c> on the same file answers again without a second audit event;
    /// the key reused on another file is <c>409 idempotency_conflict</c>, because the stored request names the file.
    /// </summary>
    public async Task RecordRestoreAsync(ClaimsPrincipal principal, Guid fileId, RestoreRequest body, string? idempotencyKey, RequestInfo request,
        CancellationToken ct)
    {
        var key = IdempotencyStore.ValidKey(idempotencyKey) ?? throw AuthException.Validation("A valid Idempotency-Key header is required.");
        var actor = await WriterAsync(principal, ct);
        // History is an account feature: a guest token is never accepted under /api/v1 (04 §4.8).
        var userId = actor.UserId ?? throw AuthException.NotFound();
        // The path id is part of the request, so the stored hash names the file as well as the version.
        var hash = IdempotencyStore.Hash(new { fileId, seq = body.Seq });
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(actor, fileId, ct);
        // Looked up under the file lock, so a retry that raced its own first attempt sees that attempt's answer.
        if (await idempotency.FindAsync(userId, RestoreEndpoint, key, hash, ct) is not null) return;
        await VersionAsync(fileId, body.Seq, ct);
        if (file.SyncPolicy == SyncPolicies.Excluded) throw ExcludedContent();
        file.PendingRestoreSeq = body.Seq;
        file.PendingRestoreBy = userId;
        file.PendingRestoreAt = time.GetUtcNow();
        audit.Add("version.restore", userId, request, targetType: "file", targetId: fileId, detail: new { seq = body.Seq });
        idempotency.Add(userId, RestoreEndpoint, key, hash, 204, new { });
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
        var actor = await WriterAsync(principal, ct);
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
        var file = await LockFileAsync(actor, fileId, ct);
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
                CrdtDocId = docId, Seq = seq, UpdateEnc = frames[i], KeyId = update.KeyId, AuthorId = actor.UserId,
                ClientUpdateId = update.ClientUpdateId, CreatedAt = now,
            });
            acks.Add(new UpdateAckDto(update.ClientUpdateId, seq));
            stored.Add(new CrdtUpdateDto(seq, update.KeyId, update.UpdateEnc!, actor.UserId, now));
        }

        // New numbers of one submit are consecutive, because the file row is locked; resends add none.
        if (stored.Count > 0) await feed.UpdatesAsync(file, stored[0].Seq, stored[^1].Seq, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        // After the commit: peers are only told about updates that are durable.
        if (stored.Count > 0) await relay.UpdatesStoredAsync(fileId, stored, ct);
        return new UpdateAcksDto(acks);
    }

    /// <summary>Updates after <paramref name="since"/> in order. Updates a snapshot covers may be pruned; a client then starts from the snapshot.</summary>
    public async Task<CrdtUpdatesDto> ReadUpdatesAsync(ClaimsPrincipal principal, Guid fileId, long since, int? limit, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
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
        var actor = await WriterAsync(principal, ct);
        var hash = ContentHash(contentHash);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(actor, fileId, ct);
        if (file.CrdtDocId is null) throw AuthException.Validation("Only text files have snapshots.");
        await CheckUploadAsync(file, keyId, ciphertext, ct);
        if (crdtSeq < 0 || crdtSeq > file.CrdtHeadSeq) throw AuthException.Validation("The snapshot names an update the log does not have.");
        var head = await HeadAsync(file, ct);
        if (head?.CrdtSeq > crdtSeq) throw AuthException.Conflict("A newer snapshot is already stored.");

        // A snapshot always builds on the head, so its parent is the head it replaces.
        var version = await AddVersionAsync(file, actor.UserId, hash, keyId, ciphertext, crdtSeq, head?.Seq ?? 0, becomesHead: true, ct);
        await feed.VersionAsync(file, version, isHead: true, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return ToDto(version, file);
    }

    public async Task<BlobRead> ReadSnapshotAsync(ClaimsPrincipal principal, Guid fileId, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        if (file.CrdtDocId is null) throw AuthException.NotFound();
        return await OpenAsync(await HeadAsync(file, ct) ?? throw AuthException.NotFound(), file, ct);
    }

    /// <summary>The head snapshot of a text file, for the relay's join answer; null when there is none yet.</summary>
    public async Task<VersionDto?> SnapshotPointerAsync(ClaimsPrincipal principal, Guid fileId, CancellationToken ct)
    {
        var file = await FileAsync(ContentActor.Of(principal), fileId, ct);
        return file.CrdtDocId is null || await HeadAsync(file, ct) is not { } head ? null : ToDto(head, file);
    }

    // ---------------------------------------------------------------- staged head of a key rotation

    /// <summary>
    /// Stages the head of a file re-encrypted under the key a rotation is about to commit (09 §9.6, 04 "file keys"). It
    /// is stored as ciphertext and recorded in <c>file_rotation_heads</c>, but it is no version yet: the commit
    /// <c>POST /files/{id}/keys/rotate</c> names it in <c>newHeadRef</c> and makes it the head in the transaction that
    /// switches the key. Until then every client keeps reading the old head, so nothing is replaced before its
    /// successor exists. A text file stages a snapshot (<paramref name="crdtSeq"/>), any other file the re-encrypted
    /// head version it is based on (<paramref name="parentSeq"/>, 0 when it has none). Staging again for the same key
    /// replaces the earlier stage. Every account with write reach may rotate, so every such account may stage; a link
    /// guest never does, because it holds no wrap to hand the new key on with.
    /// </summary>
    public async Task StageRotationHeadAsync(ClaimsPrincipal principal, Guid fileId, Guid newKeyId, string? contentHash, long? crdtSeq, long? parentSeq,
        StagedBlob ciphertext, CancellationToken ct)
    {
        var actor = await WriterAsync(principal, ct);
        var hash = ContentHash(contentHash);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var file = await LockFileAsync(actor, fileId, ct);
        if (actor.UserId is not { } userId) throw RotateDenied();
        await CheckUploadAsync(file, newKeyId, ciphertext, ct, currentKey: false);
        if (await db.FileKeys.AnyAsync(k => k.FileId == fileId && k.KeyId == newKeyId, ct))
            throw AuthException.Validation("Nyxite-Key-Id must name the new key of the rotation, not a key the file already has.");

        var head = await HeadAsync(file, ct);
        if (file.CrdtDocId is not null)
        {
            if (crdtSeq is not { } seq || parentSeq is not null)
                throw AuthException.Validation("A text file stages a snapshot: Nyxite-Snapshot-Seq is required and If-Match is not taken.");
            if (seq < 0 || seq > file.CrdtHeadSeq) throw AuthException.Validation("The snapshot names an update the log does not have.");
            if (head?.CrdtSeq > seq) throw AuthException.Conflict("A newer snapshot is already stored.");
        }
        else
        {
            if (parentSeq is not { } parent || crdtSeq is not null)
                throw AuthException.Validation("A blob file stages its re-encrypted head: If-Match is required and Nyxite-Snapshot-Seq is not taken.");
            if (parent != (head?.Seq ?? 0)) throw HeadMoved();
        }

        var address = StorageAddress(file.Id, newKeyId, hash);
        await BlobCollector.LockAddressAsync(db, address, ct);
        var reference = await blobs.CommitAsync(ciphertext, address, ct);
        await db.FileRotationHeads.Where(h => h.FileId == fileId && h.KeyId == newKeyId).ExecuteDeleteAsync(ct);
        db.FileRotationHeads.Add(new FileRotationHeadEntity
        {
            FileId = fileId, KeyId = newKeyId, ContentHash = hash, BlobRef = reference.Address.Hex, SizeCipher = reference.Size,
            CrdtSeq = file.CrdtDocId is null ? null : crdtSeq, ParentSeq = file.CrdtDocId is null ? parentSeq : null, AuthorId = userId,
            CreatedAt = time.GetUtcNow(),
        });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>The head moved since the staged head was based on it; the rotating client stages the new head again.</summary>
    public static AuthException HeadMoved() => new(409, "version_conflict", "The head changed since the rotated head was based on it; stage it again.");

    public static AuthException RotateDenied() => new(403, "acl_denied", "Only an account with write access rotates the key of a file.");

    // ---------------------------------------------------------------- usage

    /// <summary>The ciphertext bytes that count against a user's quota: every version of every file they own, Trash included.</summary>
    /// <remarks>Staged rotation heads count as well, until their commit turns them into versions or they expire, so staging cannot pile up beyond the quota.</remarks>
    public async Task<long> UsageBytesAsync(Guid userId, CancellationToken ct) =>
        (await db.FileVersions.Where(v => db.Files.Any(f => f.Id == v.FileId && f.OwnerId == userId)).SumAsync(v => (long?)v.SizeCipher, ct) ?? 0)
        + (await db.FileRotationHeads.Where(h => db.Files.Any(f => f.Id == h.FileId && f.OwnerId == userId)).SumAsync(h => (long?)h.SizeCipher, ct) ?? 0);

    // ---------------------------------------------------------------- shared steps

    /// <summary>
    /// The checks every upload passes: content is taken for the file, the body is an NYXC frame of the named key within
    /// the inline limit, and the owner's quota has room. <paramref name="currentKey"/> false is the staged head of a key
    /// rotation, which is sealed with the key the rotation is about to commit; every other upload must use the current
    /// key and is <c>412 key_generation_stale</c> otherwise.
    /// </summary>
    private async Task CheckUploadAsync(FileEntity file, Guid keyId, StagedBlob ciphertext, CancellationToken ct, bool currentKey = true)
    {
        if (file.SyncPolicy == SyncPolicies.Excluded) throw ExcludedContent();
        if (ciphertext.Length > _options.MaxInlineBlobBytes) throw PayloadTooLarge("The upload is larger than the inline limit.");
        if (ciphertext.Length < NyxcFrame.Overhead || !NyxcFrame.TryParseHeader(ciphertext.Head.Span, out var header) || header.KeyId != keyId)
            throw AuthException.Validation("The body must be an NYXC frame sealed with the key named in Nyxite-Key-Id.");
        if (currentKey && keyId != await CurrentKeyIdAsync(file, ct)) throw KeyGenerationStale();

        var quota = await db.Users.Where(u => u.Id == file.OwnerId).Select(u => u.StorageQuotaBytes).SingleAsync(ct);
        if (quota is { } limit && await UsageBytesAsync(file.OwnerId, ct) + ciphertext.Length > limit)
            throw PayloadTooLarge("The upload would exceed the storage quota.");
    }

    private async Task<FileVersionEntity> AddVersionAsync(FileEntity file, Guid? authorId, byte[] contentHash, Guid keyId, StagedBlob ciphertext,
        long? crdtSeq, long parentSeq, bool becomesHead, CancellationToken ct)
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
            SizeCipher = reference.Size, KeyId = keyId, Layout = "single", AuthorId = authorId, CrdtSeq = crdtSeq, ParentSeq = parentSeq, CreatedAt = now,
        };
        db.FileVersions.Add(version);
        TakeRestoreMark(file, version, now);

        if (becomesHead)
        {
            file.CurrentVersionId = version.Id;
            file.UpdatedAt = now;
        }

        return version;
    }

    /// <summary>
    /// A recorded restore links the restoring account's next version, also when that one lost LWW and is kept as a
    /// sibling, because it still holds the restored bytes (10 §10.5). A version of another account leaves the mark alone.
    /// A mark older than <see cref="ContentOptions.RestoreMarkLifetime"/> has lapsed: it labels nothing and is cleared.
    /// </summary>
    internal void TakeRestoreMark(FileEntity file, FileVersionEntity version, DateTimeOffset now)
    {
        if (file.PendingRestoreSeq is not { } restoredFrom) return;
        var lapsed = file.PendingRestoreAt is not { } at || now - at > _options.RestoreMarkLifetime;
        if (!lapsed && (version.AuthorId is null || file.PendingRestoreBy != version.AuthorId)) return;
        if (!lapsed) version.RestoredFromSeq = restoredFrom;
        file.PendingRestoreSeq = null;
        file.PendingRestoreBy = null;
        file.PendingRestoreAt = null;
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

    /// <summary>A live file the caller can reach, at least to read (09 §9.5). Without reach it does not exist for them.</summary>
    private async Task<FileEntity> FileAsync(ContentActor actor, Guid id, CancellationToken ct)
    {
        var file = await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == id && f.DeletedAt == null, ct);
        if (file is null || await LevelAsync(actor, file, ct) == FileAccessLevel.None) throw AuthException.NotFound();
        return file;
    }

    private Task<FileAccessLevel> LevelAsync(ContentActor actor, FileEntity file, CancellationToken ct) =>
        actor.ShareId is { } shareId ? access.GuestLevelAsync(shareId, file, ct) : access.LevelAsync(actor.UserId!.Value, file, ct);

    /// <summary>
    /// The same file for a write, tracked and locked for the transaction: writes to one file are ordered one after the
    /// other. Read reach without write reach is <c>403 acl_denied</c>, because the caller already knows the file exists.
    /// </summary>
    private async Task<FileEntity> LockFileAsync(ContentActor actor, Guid id, CancellationToken ct)
    {
        var file = (await db.Files.FromSql($"SELECT * FROM files WHERE id = {id} AND deleted_at IS NULL FOR UPDATE").ToListAsync(ct)).SingleOrDefault();
        return file is null ? throw AuthException.NotFound() : await LevelAsync(actor, file, ct) switch
        {
            FileAccessLevel.Write => file,
            FileAccessLevel.Read => throw AclDenied(),
            _ => throw AuthException.NotFound(),
        };
    }

    /// <summary>The caller's level on a live file, for the relay's periodic re-check; <see cref="FileAccessLevel.None"/> when it is gone.</summary>
    public async Task<FileAccessLevel> AccessLevelAsync(Guid userId, Guid fileId, CancellationToken ct)
    {
        var file = await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct);
        return file is null ? FileAccessLevel.None : await access.LevelAsync(userId, file, ct);
    }

    /// <summary>A guest's level on a live file, for the relay's periodic re-check.</summary>
    public async Task<FileAccessLevel> GuestAccessLevelAsync(Guid shareId, Guid fileId, CancellationToken ct)
    {
        var file = await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct);
        return file is null ? FileAccessLevel.None : await access.GuestLevelAsync(shareId, file, ct);
    }

    /// <summary>
    /// The caller as someone who may write content: an account on an active device and not blocked (04 "structure"), or
    /// a link guest, whose write permission is checked with the file. A guest writes with <c>author_id = null</c>.
    /// </summary>
    private async Task<ContentActor> WriterAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var actor = ContentActor.Of(principal);
        if (actor.ShareId is not null) return actor;
        var userId = actor.UserId!.Value;
        await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        return status == UserStatus.Blocked ? throw new AuthException(403, "account_blocked", "This account is blocked for changes.") : actor;
    }

    private static AuthException ExcludedContent() => new(409, "excluded_content", "This file is excluded from sync; the server takes no content for it.");

    private static AuthException KeyGenerationStale() => new(412, "key_generation_stale", "The content is sealed with a key that is not the file's current key.");

    private static AuthException AclDenied() => new(403, "acl_denied", "This file can be read but not changed.");

    public static AuthException PayloadTooLarge(string title) => new(413, "payload_too_large", title);

    private static VersionDto ToDto(FileVersionEntity v, FileEntity file) =>
        new(v.Seq, Base64UrlCodec.Encode(v.ContentHash), v.Layout, v.SizeCipher, v.KeyId, v.Id == file.CurrentVersionId, v.AuthorId,
            v.RestoredFromSeq, v.CrdtSeq, v.ParentSeq, v.CreatedAt);
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
