using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Application.Structure;
using Nyxite.Application.Sync;
using Nyxite.BlobStore;
using Nyxite.Contracts.Sharing;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Domain.Structure;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sharing;

/// <summary>
/// The second layer of revocation (09 §9.6, 07 §7.9): the commit of a client-driven file-key rotation,
/// <c>POST /files/{id}/keys/rotate</c>. Any account with write reach may rotate, so the rotation does not wait for the
/// owner to come online. The rotating client made a new key, sealed the file's head, name and metadata with it, staged
/// the new head (<see cref="ContentService.StageRotationHeadAsync"/>) and wrapped the key to every member who still
/// reaches the file (<see cref="MembersAsync"/>). The commit switches the file to the new generation in one transaction,
/// guarded by the generation: it succeeds only for the current generation + 1, so of two concurrent rotations, by one
/// account or by two writers, exactly one commits and the other gets <c>409 conflict</c> and reads the file again. From
/// the commit on, every write sealed with an older key is <c>412 key_generation_stale</c> (<see cref="ContentService"/>),
/// while the wraps and versions of older generations stay readable for version history to the members who had them.
/// </summary>
/// <remarks>
/// The server opens nothing here. It checks structure only: the frame headers name the new key, every wrap is a hybrid
/// HPKE ciphertext of a key's size, and the wraps go exactly to the accounts that reach the file, so a removed member
/// gets no wrap of the new key and a remaining one is not left without it. Links of the file follow the rotating
/// account's choice in <see cref="RotateFileKeyRequest.Links"/>: revoked (the default), or kept frozen at the old
/// generation, serving only what their fragment key opens.
/// <para>
/// Lock order: the project row (<c>FOR NO KEY UPDATE</c>), then the file row (<c>FOR UPDATE</c>), then the stage
/// (<c>FOR UPDATE</c>). Every share change that can change the members of a file takes the project row
/// <c>FOR SHARE</c> first (<see cref="ShareService"/>), so it lands wholly before or wholly after the member check.
/// </para>
/// </remarks>
public sealed class KeyRotationService(
    NyxiteDbContext db, DeviceGuard guard, IdempotencyStore idempotency, AuditWriter audit, TimeProvider time, ShareAccess access, ChangeFeed feed,
    IOptions<StructureOptions> options, IRelayAccessEvents relay)
{
    public const string RotateEndpoint = "POST /files/{id}/keys/rotate";
    public const string RevokeLinks = "revoke";
    public const string KeepLinks = "keep";

    private readonly StructureOptions _options = options.Value;

    /// <summary>
    /// The accounts a rotation of the file must wrap the new key to, for an account with write reach only (09 §9.6). It
    /// names account ids and nothing else: not how each reaches the file, not its permission and no link, because the
    /// rotating client needs no more to look up the directory keys and wrap. A reader, who cannot rotate, gets
    /// <c>403 acl_denied</c>.
    /// </summary>
    public async Task<RotationMembersDto> MembersAsync(ClaimsPrincipal principal, Guid fileId, CancellationToken ct)
    {
        if (principal.GuestShareId() is not null) throw AuthException.NotFound();
        var userId = principal.UserId();
        var file = await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct) ?? throw AuthException.NotFound();
        var level = await access.FileLevelAsync(userId, file, ct);
        if (level == FileAccessLevel.None) throw AuthException.NotFound();
        if (level != FileAccessLevel.Write) throw ContentService.RotateDenied();
        var members = await access.MembersAsync(file, ct);
        return new RotationMembersDto(file.KeyGeneration, file.RotationPendingAt is not null, members.Order().ToList());
    }

    public async Task CommitAsync(ClaimsPrincipal principal, Guid fileId, RotateFileKeyRequest body, string? idempotencyKey, RequestInfo request,
        CancellationToken ct)
    {
        if (principal.GuestShareId() is not null) throw ContentService.RotateDenied();
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        if (await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct) == UserStatus.Blocked)
            throw new AuthException(403, "account_blocked", "This account is blocked for changes.");
        var key = IdempotencyStore.ValidKey(idempotencyKey) ?? throw AuthException.Validation("A valid Idempotency-Key header is required.");
        var hash = IdempotencyStore.Hash(new { fileId, body });
        var links = body.Links ?? RevokeLinks;
        if (links is not (RevokeLinks or KeepLinks)) throw AuthException.Validation("links must be revoke or keep.");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // The project row orders the member check against every share change of the file's project, folders and file.
        var projectId = await db.Files.AsNoTracking().Where(f => f.Id == fileId && f.DeletedAt == null).Select(f => (Guid?)f.ProjectId).SingleOrDefaultAsync(ct)
                        ?? throw AuthException.NotFound();
        await db.Database.ExecuteSqlAsync($"SELECT 1 FROM projects WHERE id = {projectId} FOR NO KEY UPDATE", ct);
        // The file row lock orders the commit against every write of the file and against a second rotation.
        var file = (await db.Files.FromSql($"SELECT * FROM files WHERE id = {fileId} AND deleted_at IS NULL FOR UPDATE").ToListAsync(ct)).SingleOrDefault()
                   ?? throw AuthException.NotFound();
        if (file.ProjectId != projectId) throw AuthException.Conflict("The file changed while the rotation started; retry.");
        // Authorization is judged here, under the locks, so a share revoked a moment ago cannot carry a rotation through.
        var level = await access.FileLevelAsync(userId, file, ct);
        if (level == FileAccessLevel.None) throw AuthException.NotFound();
        // Looked up under the lock, so a retry that raced its own first attempt sees that attempt's committed answer.
        if (await idempotency.FindAsync(userId, RotateEndpoint, key, hash, ct) is not null) return;
        if (level != FileAccessLevel.Write) throw ContentService.RotateDenied();
        if (body.Generation != file.KeyGeneration + 1) throw AuthException.Conflict("Another rotation committed first; read the file again.");
        if (body.NewKeyId == Guid.Empty || await db.FileKeys.AnyAsync(k => k.FileId == fileId && k.KeyId == body.NewKeyId, ct))
            throw AuthException.Validation("newKeyId must be a new key the file does not have yet.");

        var name = Frame(body.NameEnc, _options.NameEncMaxBytes, body.NewKeyId, "nameEnc")
                   ?? throw AuthException.Validation("nameEnc is required: the name sealed again with the new key.");
        var metadata = Frame(body.MetadataEnc, _options.MetadataEncMaxBytes, body.NewKeyId, "metadataEnc");
        if ((metadata is null) != (file.MetadataEnc is null))
            throw AuthException.Validation(file.MetadataEnc is null ? "The file has no metadata to seal again." : "metadataEnc is required: the metadata sealed again with the new key.");

        var now = time.GetUtcNow();
        var wraps = await WrapsAsync(file, body, now, ct);
        var current = file.CurrentVersionId is { } currentId ? await db.FileVersions.AsNoTracking().SingleAsync(v => v.Id == currentId, ct) : null;
        var head = await StagedHeadAsync(file, current, body, ct);
        var (revoked, frozen) = await LinksAsync(file, current, links, now, ct);

        db.FileKeys.AddRange(wraps);
        file.KeyGeneration = body.Generation;
        file.NameEnc = name;
        file.MetadataEnc = metadata;
        file.RotationPendingAt = null;
        file.UpdatedAt = now;
        FileVersionEntity? version = null;
        if (head is not null)
        {
            // The staged blob becomes a version; the address lock keeps the collector off it until this commits.
            await BlobCollector.LockAddressAsync(db, BlobAddress.From(Convert.FromHexString(head.BlobRef)), ct);
            version = new FileVersionEntity
            {
                Id = Guid.CreateVersion7(now), FileId = file.Id, Seq = ++file.VersionSeq, ContentHash = head.ContentHash, BlobRef = head.BlobRef,
                SizeCipher = head.SizeCipher, KeyId = body.NewKeyId, Layout = "single", AuthorId = userId, CrdtSeq = head.CrdtSeq,
                ParentSeq = current?.Seq ?? 0, CreatedAt = now,
            };
            db.FileVersions.Add(version);
            file.CurrentVersionId = version.Id;
        }

        // Stages of this or of a losing attempt are of no use any more; their blobs go to the collector.
        await db.FileRotationHeads.Where(h => h.FileId == fileId).ExecuteDeleteAsync(ct);
        await feed.KeyRotateAsync(file, body.NewKeyId, body.Generation, ct);
        await feed.FileAsync(file, ct);
        if (version is not null) await feed.VersionAsync(file, version, isHead: true, ct);
        audit.Add("key.rotate", userId, request, targetType: "file", targetId: fileId,
            detail: new
            {
                generation = body.Generation, keyId = body.NewKeyId, members = wraps.Count, headSeq = version?.Seq, links,
                linksRevoked = revoked.Count, linksFrozen = frozen.Count, byOwner = file.OwnerId == userId,
            });
        foreach (var id in revoked)
            audit.Add("share.revoke", userId, request, targetType: "share", targetId: id, detail: new { kind = ShareEntity.Link, by = "rotation" });
        idempotency.Add(userId, RotateEndpoint, key, hash, 204, new { });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        // After the commit: guests of a revoked or frozen link leave the room, because nothing in it opens with their key.
        if (revoked.Count + frozen.Count > 0) relay.AccessChanged(RelayAccessScope.ForShares([.. revoked, .. frozen]));
    }

    /// <summary>
    /// What the rotation does to the file's links (09 §9.6). <see cref="RevokeLinks"/> revokes every link of the file,
    /// frozen ones included, and the rotating client offers to create new links under the new key. <see cref="KeepLinks"/>
    /// freezes every link that still follows the file at the old generation, with the head, name and metadata as they
    /// are now, so the link keeps opening the last content its fragment key can decrypt and nothing written later; a link
    /// frozen by an earlier rotation stays at its generation. A text file must then have a head snapshot that covers
    /// the whole log, otherwise the frozen link would miss the updates after it, and the commit is
    /// <c>409 version_conflict</c> until the client stores one under the old key. A file excluded from sync takes no
    /// snapshot, so its links freeze at the head it has, which the content purge removes later.
    /// </summary>
    private async Task<(List<Guid> Revoked, List<Guid> Frozen)> LinksAsync(FileEntity file, FileVersionEntity? current, string mode, DateTimeOffset now,
        CancellationToken ct)
    {
        var rows = await db.Shares.Where(s => s.Kind == ShareEntity.Link && s.FileId == file.Id && s.RevokedAt == null).ToListAsync(ct);
        if (mode == RevokeLinks)
        {
            foreach (var row in rows) row.RevokedAt = now;
            return (rows.Select(r => r.Id).ToList(), []);
        }

        var following = rows.Where(r => r.FrozenGeneration is null).ToList();
        if (following.Count > 0 && file.CrdtDocId is not null && file.SyncPolicy != SyncPolicies.Excluded && file.CrdtHeadSeq > (current?.CrdtSeq ?? 0))
            throw new AuthException(409, "version_conflict",
                "Keeping links needs a head snapshot under the old key that covers every update; store one, stage again and retry.");
        foreach (var row in following)
        {
            row.FrozenGeneration = file.KeyGeneration;
            row.FrozenVersionSeq = current?.Seq;
            row.FrozenNameEnc = file.NameEnc;
            row.FrozenMetadataEnc = file.MetadataEnc;
        }

        return ([], following.Select(r => r.Id).ToList());
    }

    /// <summary>
    /// One wrap of the new key per member, exactly: the project's owner and every grantee whose live share reaches the
    /// file. A wrap to anyone else, a removed member above all, is refused, and so is a commit that leaves a member out,
    /// because that member would keep its reach without a key for anything written from now on. A client that meets this
    /// after a share changed reads the shares again and retries.
    /// </summary>
    private async Task<List<FileKeyEntity>> WrapsAsync(FileEntity file, RotateFileKeyRequest body, DateTimeOffset now, CancellationToken ct)
    {
        var members = await access.MembersAsync(file, ct);
        var rows = new List<FileKeyEntity>();
        foreach (var wrap in body.WrappedKeys ?? [])
        {
            var member = wrap.MemberId ?? throw AuthException.Validation("Every wrap needs memberId.");
            if (wrap.KeyId != body.NewKeyId || wrap.Generation != body.Generation)
                throw AuthException.Validation("Every wrap must carry newKeyId at the new generation.");
            if (!members.Contains(member)) throw AuthException.Validation("A wrap names an account that does not reach the file.");
            if (rows.Any(r => r.MemberId == member)) throw AuthException.Validation("wrappedKeys names a member twice.");
            rows.Add(new FileKeyEntity
            {
                Id = Guid.CreateVersion7(now), FileId = file.Id, MemberId = member, KeyId = body.NewKeyId,
                WrappedKey = KeyGrantService.WrapBytes(wrap.Ciphertext, wrap.AlgId) ?? throw AuthException.Validation("wrappedKeys holds a malformed wrap."),
                Generation = body.Generation, AlgId = CryptoSuite.HpkeAlgId, CreatedAt = now,
            });
        }

        if (rows.Count != members.Count) throw AuthException.Validation("wrappedKeys must wrap the new key to every member who reaches the file.");
        return rows;
    }

    /// <summary>
    /// The staged head <see cref="RotateFileKeyRequest.NewHeadRef"/> names, still valid against the file as it is now.
    /// A file with content must bring one, because the head is where every member, and every member added later with the
    /// new key only, starts reading: a blob file with a head, and a text file whose log has ever taken an update. A text
    /// head must cover the whole log, so no update sealed with the old key is left behind it, and a blob head must
    /// re-encrypt the current head. Anything that moved since staging, a newer snapshot, a newer update or a newer blob,
    /// is <c>409 version_conflict</c>, never a silent replacement: the newer state stays, and the client stages again.
    /// A file excluded from sync rotates without a head, because the server takes no content for it; its old content is
    /// left to the content purge (06 §6.2).
    /// </summary>
    private async Task<FileRotationHeadEntity?> StagedHeadAsync(FileEntity file, FileVersionEntity? current, RotateFileKeyRequest body, CancellationToken ct)
    {
        var excluded = file.SyncPolicy == SyncPolicies.Excluded;
        if (body.NewHeadRef is null)
        {
            var hasContent = current is not null || (file.CrdtDocId is not null && file.CrdtHeadSeq > 0);
            if (hasContent && !excluded) throw AuthException.Validation("newHeadRef is required: the file's head staged under the new key.");
            return null;
        }

        if (excluded) throw new AuthException(409, "excluded_content", "This file is excluded from sync; the server takes no content for it.");
        if (!Base64UrlCodec.TryDecode(body.NewHeadRef, out var headHash) || headHash.Length != BlobAddress.Size)
            throw AuthException.Validation("newHeadRef must be the base64url BLAKE3-256 content hash of the staged head.");
        // Locked, so the cleaner of abandoned stages cannot delete it, and the collector its blob, before this commits.
        var staged = (await db.FileRotationHeads
                .FromSql($"SELECT * FROM file_rotation_heads WHERE file_id = {file.Id} AND key_id = {body.NewKeyId} FOR UPDATE").AsNoTracking().ToListAsync(ct))
            .SingleOrDefault();
        if (staged is null || !staged.ContentHash.AsSpan().SequenceEqual(headHash))
            throw AuthException.Validation("newHeadRef names no head staged for newKeyId.");
        var moved = file.CrdtDocId is not null
            ? staged.CrdtSeq < file.CrdtHeadSeq || current?.CrdtSeq > staged.CrdtSeq
            : staged.ParentSeq != (current?.Seq ?? 0);
        return moved ? throw ContentService.HeadMoved() : staged;
    }

    /// <summary>A name or metadata frame: NYXC within the size limit and sealed with the new key. Null when absent.</summary>
    private static byte[]? Frame(string? value, int maxBytes, Guid keyId, string field)
    {
        if (value is null) return null;
        if (!Base64UrlCodec.TryDecode(value, out var bytes) || bytes.Length > maxBytes || !NyxcFrame.TryParseHeader(bytes, out var header))
            throw AuthException.Validation($"{field} must be an NYXC frame within the size limit.");
        return header.KeyId == keyId ? bytes : throw AuthException.Validation($"{field} is not sealed with newKeyId.");
    }
}
