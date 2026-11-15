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
/// <c>POST /files/{id}/keys/rotate</c>. The owner's client made a new key, sealed the file's head, name and metadata with
/// it, staged the new head (<see cref="ContentService.StageRotationHeadAsync"/>) and wrapped the key to every member who
/// still reaches the file. The commit switches the file to the new generation in one transaction, guarded by the
/// generation: it succeeds only for the current generation + 1, so of two concurrent rotations exactly one commits and
/// the other gets <c>409 conflict</c>. From the commit on, every write sealed with an older key is
/// <c>412 key_generation_stale</c> (<see cref="ContentService"/>), while the wraps and versions of older generations stay
/// readable for version history to the members who had them.
/// </summary>
/// <remarks>
/// The server opens nothing here. It checks structure only: the frame headers name the new key, every wrap is a hybrid
/// HPKE ciphertext of a key's size, and the wraps go exactly to the accounts that reach the file, so a removed member
/// gets no wrap of the new key and a remaining one is not left without it.
/// </remarks>
public sealed class KeyRotationService(
    NyxiteDbContext db, DeviceGuard guard, IdempotencyStore idempotency, AuditWriter audit, TimeProvider time, ShareAccess access, ChangeFeed feed,
    IOptions<StructureOptions> options)
{
    public const string RotateEndpoint = "POST /files/{id}/keys/rotate";

    private readonly StructureOptions _options = options.Value;

    public async Task CommitAsync(ClaimsPrincipal principal, Guid fileId, RotateFileKeyRequest body, string? idempotencyKey, RequestInfo request,
        CancellationToken ct)
    {
        if (principal.GuestShareId() is not null) throw ContentService.RotateDenied();
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        if (await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct) == UserStatus.Blocked)
            throw new AuthException(403, "account_blocked", "This account is blocked for changes.");
        var key = IdempotencyStore.ValidKey(idempotencyKey) ?? throw AuthException.Validation("A valid Idempotency-Key header is required.");
        var hash = IdempotencyStore.Hash(body);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // The file row lock orders the commit against every write of the file and against a second rotation.
        var file = (await db.Files.FromSql($"SELECT * FROM files WHERE id = {fileId} AND deleted_at IS NULL FOR UPDATE").ToListAsync(ct)).SingleOrDefault()
                   ?? throw AuthException.NotFound();
        var level = await access.FileLevelAsync(userId, file, ct);
        if (level == FileAccessLevel.None) throw AuthException.NotFound();
        // Looked up under the lock, so a retry that raced its own first attempt sees that attempt's committed answer.
        if (await idempotency.FindAsync(userId, RotateEndpoint, key, hash, ct) is not null) return;
        if (!await db.Projects.AnyAsync(p => p.Id == file.ProjectId && p.OwnerId == userId, ct)) throw ContentService.RotateDenied();
        if (body.Generation != file.KeyGeneration + 1) throw AuthException.Conflict("Another rotation committed first.");
        if (body.NewKeyId == Guid.Empty || await db.FileKeys.AnyAsync(k => k.FileId == fileId && k.KeyId == body.NewKeyId, ct))
            throw AuthException.Validation("newKeyId must be a new key the file does not have yet.");

        var name = Frame(body.NameEnc, _options.NameEncMaxBytes, body.NewKeyId, "nameEnc")
                   ?? throw AuthException.Validation("nameEnc is required: the name sealed again with the new key.");
        var metadata = Frame(body.MetadataEnc, _options.MetadataEncMaxBytes, body.NewKeyId, "metadataEnc");
        if ((metadata is null) != (file.MetadataEnc is null))
            throw AuthException.Validation(file.MetadataEnc is null ? "The file has no metadata to seal again." : "metadataEnc is required: the metadata sealed again with the new key.");

        var now = time.GetUtcNow();
        var wraps = await WrapsAsync(file, body, now, ct);
        var head = await StagedHeadAsync(file, body, ct);

        db.FileKeys.AddRange(wraps);
        file.KeyGeneration = body.Generation;
        file.NameEnc = name;
        file.MetadataEnc = metadata;
        file.UpdatedAt = now;
        FileVersionEntity? version = null;
        if (head is not null)
        {
            // The staged blob becomes a version; the address lock keeps the collector off it until this commits.
            await BlobCollector.LockAddressAsync(db, BlobAddress.From(Convert.FromHexString(head.BlobRef)), ct);
            version = new FileVersionEntity
            {
                Id = Guid.CreateVersion7(now), FileId = file.Id, Seq = ++file.VersionSeq, ContentHash = head.ContentHash, BlobRef = head.BlobRef,
                SizeCipher = head.SizeCipher, KeyId = body.NewKeyId, Layout = "single", AuthorId = userId, CrdtSeq = head.CrdtSeq, CreatedAt = now,
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
            detail: new { generation = body.Generation, keyId = body.NewKeyId, members = wraps.Count, headSeq = version?.Seq });
        idempotency.Add(userId, RotateEndpoint, key, hash, 204, new { });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
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
    /// The staged head <see cref="RotateFileKeyRequest.NewHeadRef"/> names, still valid against the head as it is now.
    /// A file with a head must bring one, because the head is where every member, and every member added later with the
    /// new key only, starts reading. A head that moved since staging is <c>409 version_conflict</c>, never a silent
    /// replacement: the newer head stays, and the client stages again.
    /// </summary>
    private async Task<FileRotationHeadEntity?> StagedHeadAsync(FileEntity file, RotateFileKeyRequest body, CancellationToken ct)
    {
        var current = file.CurrentVersionId is { } id ? await db.FileVersions.AsNoTracking().SingleAsync(v => v.Id == id, ct) : null;
        if (body.NewHeadRef is null)
        {
            if (current is not null) throw AuthException.Validation("newHeadRef is required: the file's head staged under the new key.");
            return null;
        }

        if (file.SyncPolicy == SyncPolicies.Excluded)
            throw new AuthException(409, "excluded_content", "This file is excluded from sync; the server takes no content for it.");
        if (!Base64UrlCodec.TryDecode(body.NewHeadRef, out var headHash) || headHash.Length != BlobAddress.Size)
            throw AuthException.Validation("newHeadRef must be the base64url BLAKE3-256 content hash of the staged head.");
        var staged = await db.FileRotationHeads.AsNoTracking().SingleOrDefaultAsync(h => h.FileId == file.Id && h.KeyId == body.NewKeyId, ct);
        if (staged is null || !staged.ContentHash.AsSpan().SequenceEqual(headHash))
            throw AuthException.Validation("newHeadRef names no head staged for newKeyId.");
        var moved = file.CrdtDocId is not null
            ? current?.CrdtSeq > staged.CrdtSeq
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
