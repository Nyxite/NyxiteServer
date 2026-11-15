using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Contracts.Sharing;
using Nyxite.Contracts.Structure;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sharing;

/// <summary>A share target as the server sees it: its project, the project's owner, its key generation and whether it is live.</summary>
internal sealed record ShareTarget(string Type, Guid Id, Guid ProjectId, Guid OwnerId, int KeyGeneration, bool Live);

/// <summary>
/// Account and link shares (server 09, 04 "shares"). Only the owner of a project shares what is in it (08 §8.5
/// <c>resource:share</c>). An account share stores the target's own key wrapped to the grantee, as opaque bytes the
/// server cannot open; a link share stores only the SHA-256 of a token the client minted, because the file key rides
/// the URL fragment and never reaches the server (09 §9.4). Every change is audited without keys or token hashes.
/// </summary>
public sealed class ShareService(
    NyxiteDbContext db, DeviceGuard guard, IdempotencyStore idempotency, AuditWriter audit, TimeProvider time, ShareAccess access, IRelayAccessEvents relay)
{
    public const string CreateShareEndpoint = "POST /shares";
    public const int LinkTokenHashSize = 32;
    public const int DefaultPageSize = 50;
    public const int MaxPageSize = 200;

    private const string LinkTokenInUse = "This link token is already in use.";
    private const string AlreadyShared = "This target is already shared with the grantee; change the share instead.";

    public async Task<IdempotentResponse> CreateAsync(ClaimsPrincipal principal, CreateShareRequest body, string? idempotencyKey, RequestInfo request,
        CancellationToken ct)
    {
        var userId = await WriterAsync(principal, requireDevice: true, ct);
        var key = IdempotencyStore.ValidKey(idempotencyKey) ?? throw AuthException.Validation("A valid Idempotency-Key header is required.");
        var hash = IdempotencyStore.Hash(body);
        if (await idempotency.FindAsync(userId, CreateShareEndpoint, key, hash, ct) is { } replay) return replay;

        var targetType = TargetType(body.TargetType);
        var permission = Permission(body.Permission);
        var now = time.GetUtcNow();
        if (body.ExpiresAt is { } expires && expires <= now) throw AuthException.Validation("expiresAt must lie in the future.");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var target = await OwnedTargetAsync(userId, targetType, body.TargetId, ct);
        var share = new ShareEntity
        {
            Id = Guid.CreateVersion7(now), Kind = body.Kind ?? "", Permission = permission, CreatedBy = userId, CreatedAt = now, ExpiresAt = body.ExpiresAt,
        };
        SetTarget(share, target);

        switch (body.Kind)
        {
            case ShareEntity.UserGrant:
                await AccountShareAsync(share, target, body, userId, now, request, ct);
                break;
            case ShareEntity.Link:
                await LinkShareAsync(share, target, body, ct);
                break;
            default:
                throw AuthException.Validation("kind must be user_grant or link.");
        }

        db.Shares.Add(share);
        audit.Add("share.create", userId, request, targetType: "share", targetId: share.Id,
            detail: new { kind = share.Kind, permission, targetType, targetId = target.Id, granteeId = share.GranteeId, expiresAt = share.ExpiresAt });
        var stored = idempotency.Add(userId, CreateShareEndpoint, key, hash, 201, ToDto(share));
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException e) when (e.InnerException is Npgsql.PostgresException { SqlState: Npgsql.PostgresErrorCodes.UniqueViolation } unique)
        {
            return await AfterUniqueViolationAsync(tx, unique, userId, key, hash, ct);
        }

        await tx.CommitAsync(ct);
        return stored;
    }

    /// <summary>
    /// A unique violation on save means a concurrent create committed first. When it carried the same
    /// <c>Idempotency-Key</c>, this request is its replay, whichever index collided first, so the replay lookup runs
    /// again on a clean unit of work. Otherwise the constraint names the conflict: the link token or the one live
    /// account share per target and grantee (09 §9.4a).
    /// </summary>
    private async Task<IdempotentResponse> AfterUniqueViolationAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx, Npgsql.PostgresException unique, Guid userId, string key, byte[] hash, CancellationToken ct)
    {
        await tx.RollbackAsync(ct);
        db.ChangeTracker.Clear();
        if (await idempotency.FindAsync(userId, CreateShareEndpoint, key, hash, ct) is { } replay) return replay;
        throw unique.ConstraintName switch
        {
            ShareEntity.LinkIndex => (Exception)AuthException.Conflict(LinkTokenInUse),
            ShareEntity.LiveGrantIndex => AuthException.Conflict(AlreadyShared),
            IdempotencyKeyEntity.PrimaryKey => AuthException.Conflict("A request with this Idempotency-Key was still in progress; retry it."),
            _ => new InvalidOperationException($"Unexpected unique violation of {unique.ConstraintName} on share create.", unique),
        };
    }

    /// <summary>
    /// The grantee must be another account with a live directory key, and the request must carry the target's own key
    /// wrapped to it: the current generation at least, older ones for version history. Keys of what lies below a folder
    /// or project follow through <c>POST /files/keys:batch</c> (09 §9.3).
    /// </summary>
    private async Task AccountShareAsync(ShareEntity share, ShareTarget target, CreateShareRequest body, Guid userId, DateTimeOffset now, RequestInfo request,
        CancellationToken ct)
    {
        if (body.LinkTokenHash is not null) throw AuthException.Validation("An account share has no linkTokenHash.");
        var grantee = body.GranteeId ?? throw AuthException.Validation("granteeId is required for an account share.");
        if (grantee == userId) throw AuthException.Validation("A share cannot name its owner as grantee.");
        if (!await db.UserKeys.AnyAsync(k => k.UserId == grantee && k.RevokedAt == null, ct)) throw AuthException.NotFound();
        if (await LiveShares().AnyAsync(s => s.Kind == ShareEntity.UserGrant && s.GranteeId == grantee && s.FileId == share.FileId
                                              && s.FolderId == share.FolderId && s.ProjectId == share.ProjectId, ct))
            throw AuthException.Conflict(AlreadyShared);
        await RevokeExpiredAsync(share, grantee, userId, now, request, ct);
        share.GranteeId = grantee;

        var wraps = body.WrappedKeys is { Count: > 0 } w ? w : throw AuthException.Validation("wrappedKeys must hold the target's key wrapped to the grantee.");
        // A file's generation is read under a share lock of its row, which a key rotation's commit holds exclusively: the
        // share then either lands before the commit, whose member check sees it, or carries the generation it committed.
        var currentGeneration = target.Type == StructureTypes.File
            ? await db.Database.SqlQuery<int>($"SELECT key_generation AS \"Value\" FROM files WHERE id = {target.Id} FOR SHARE").SingleAsync(ct)
            : target.KeyGeneration;
        var generations = await KeyGrantService.GenerationsAsync(db, target.Type, [target.Id], ct);
        var rows = new List<KeyGrantService.Grant>();
        foreach (var wrap in wraps)
        {
            if (wrap.MemberId is { } member && member != grantee) throw AuthException.Validation("wrappedKeys must be wrapped to the grantee.");
            if (!generations.TryGetValue((target.Id, wrap.KeyId), out var generation) || generation != wrap.Generation)
                throw AuthException.Validation("wrappedKeys names a key the target does not have.");
            rows.Add(new KeyGrantService.Grant(target.Type, target.Id, target.ProjectId, wrap.KeyId, generation, grantee,
                KeyGrantService.WrapBytes(wrap.Ciphertext, wrap.AlgId) ?? throw AuthException.Validation("wrappedKeys holds a malformed wrap."), now));
        }

        if (!rows.Any(r => r.Generation == currentGeneration)) throw AuthException.Validation("wrappedKeys must include the target's current key.");
        foreach (var row in rows) await KeyGrantService.InsertAsync(db, row, ct);
    }

    /// <summary>
    /// An expired account share of the same target and grantee still holds the one unrevoked slot of
    /// <c>uq_shares_live_grant</c>, so the create that replaces it revokes it first, in the same transaction. It grants
    /// nothing already, so the revoke changes no reach; it is audited like any other.
    /// </summary>
    private async Task RevokeExpiredAsync(ShareEntity share, Guid grantee, Guid userId, DateTimeOffset now, RequestInfo request, CancellationToken ct)
    {
        var expired = db.Shares.Where(s => s.Kind == ShareEntity.UserGrant && s.GranteeId == grantee && s.FileId == share.FileId
                                           && s.FolderId == share.FolderId && s.ProjectId == share.ProjectId && s.RevokedAt == null
                                           && s.ExpiresAt != null && s.ExpiresAt <= now);
        var ids = await expired.Select(s => s.Id).ToListAsync(ct);
        if (ids.Count == 0) return;
        await db.Shares.Where(s => ids.Contains(s.Id) && s.RevokedAt == null).ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, now), ct);
        foreach (var id in ids)
            audit.Add("share.revoke", userId, request, targetType: "share", targetId: id, detail: new { kind = ShareEntity.UserGrant, by = "replaced" });
    }

    /// <summary>A link names one file, because its URL fragment carries one file key (09 §9.4).</summary>
    private async Task LinkShareAsync(ShareEntity share, ShareTarget target, CreateShareRequest body, CancellationToken ct)
    {
        if (target.Type != StructureTypes.File) throw AuthException.Validation("A link share targets one file, because its URL carries one file key.");
        if (body.GranteeId is not null || body.WrappedKeys is { Count: > 0 })
            throw AuthException.Validation("A link share has no grantee and no wrapped keys; its key stays in the URL fragment.");
        if (!Base64UrlCodec.TryDecode(body.LinkTokenHash, out var tokenHash) || tokenHash.Length != LinkTokenHashSize)
            throw AuthException.Validation("linkTokenHash must be the 32-byte SHA-256 of the link token.");
        if (await db.Shares.AnyAsync(s => s.LinkTokenHash == tokenHash, ct)) throw AuthException.Conflict(LinkTokenInUse);
        share.LinkTokenHash = tokenHash;
    }

    /// <summary>
    /// Shares on a target the caller owns, or with no target the account shares granted to the caller ("shared with
    /// me"), so a recipient finds what it can open. Revoked shares are left out.
    /// </summary>
    public async Task<PageDto<ShareDto>> ListAsync(ClaimsPrincipal principal, string? targetType, Guid? targetId, string? cursor, int? limit, CancellationToken ct)
    {
        var userId = principal.UserId();
        var (after, take) = Page(cursor, limit);
        IQueryable<ShareEntity> query;
        if (targetType is null && targetId is null)
        {
            query = LiveShares().Where(s => s.Kind == ShareEntity.UserGrant && s.GranteeId == userId);
        }
        else
        {
            var type = TargetType(targetType);
            var id = targetId ?? throw AuthException.Validation("targetId is required with targetType.");
            var target = await TargetAsync(type, id, ct) ?? throw AuthException.NotFound();
            if (target.OwnerId != userId)
                throw await ReachesAsync(userId, target, ct) ? AclDenied("Only the owner sees the shares of an object.") : AuthException.NotFound();
            query = db.Shares.AsNoTracking().Where(s => s.RevokedAt == null);
            query = type switch
            {
                StructureTypes.File => query.Where(s => s.FileId == id),
                StructureTypes.Folder => query.Where(s => s.FolderId == id),
                _ => query.Where(s => s.ProjectId == id),
            };
        }

        var rows = await query.Where(s => s.Id > after).OrderBy(s => s.Id).Take(take + 1).ToListAsync(ct);
        var page = rows.Take(take).ToList();
        var next = rows.Count > take ? Base64UrlCodec.Encode(page[^1].Id.ToByteArray(bigEndian: true)) : null;
        return new PageDto<ShareDto>(page.Select(ToDto).ToList(), next);
    }

    /// <summary>Changes permission or expiry. The owner only; a grantee, who knows the share, gets <c>403 acl_denied</c>.</summary>
    public async Task<ShareDto> UpdateAsync(ClaimsPrincipal principal, Guid id, UpdateShareRequest body, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, requireDevice: false, ct);
        var share = await db.Shares.SingleOrDefaultAsync(s => s.Id == id && s.RevokedAt == null, ct) ?? throw AuthException.NotFound();
        var owner = await OwnerOfAsync(share, ct);
        if (owner != userId) throw share.GranteeId == userId ? AclDenied("Only the owner changes a share.") : AuthException.NotFound();

        if (body.Permission is not null) share.Permission = Permission(body.Permission);
        if (body.ExpiresAt.IsSet)
        {
            if (body.ExpiresAt.Value is { } expires && expires <= time.GetUtcNow()) throw AuthException.Validation("expiresAt must lie in the future.");
            share.ExpiresAt = body.ExpiresAt.Value;
        }

        audit.Add("share.update", userId, request, targetType: "share", targetId: share.Id,
            detail: new { permission = share.Permission, expiresAt = share.ExpiresAt });
        await db.SaveChangesAsync(ct);
        // A downgrade or a new expiry is judged in the open rooms now, not at the next periodic pass.
        relay.AccessChanged(RelayScope(share));
        return ToDto(share);
    }

    /// <summary>
    /// Revokes a share: from now on it is no path at any checkpoint (fetch, join, submit, the relay's re-check), which is
    /// the instant first layer of 09 §9.6. The owner revokes, and a grantee removes its own share, which leaves the
    /// object live for everyone else (DL-3). Revoking a revoked share changes nothing. Key rotation is the client's.
    /// </summary>
    public async Task RevokeAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        var share = await db.Shares.SingleOrDefaultAsync(s => s.Id == id, ct) ?? throw AuthException.NotFound();
        var owner = await OwnerOfAsync(share, ct);
        if (owner != userId && share.GranteeId != userId) throw AuthException.NotFound();
        if (share.RevokedAt is not null) return;

        share.RevokedAt = time.GetUtcNow();
        audit.Add("share.revoke", userId, request, targetType: "share", targetId: share.Id,
            detail: new { kind = share.Kind, by = owner == userId ? "owner" : "grantee" });
        await db.SaveChangesAsync(ct);
        // The instant layer of 09 §9.6 for open rooms: the grantee's or the link's connections are judged right away.
        relay.AccessChanged(RelayScope(share));
    }

    /// <summary>Who a share reaches in the relay: the grantee's connections, or the guests of the link.</summary>
    private static RelayAccessScope RelayScope(ShareEntity share) =>
        share.GranteeId is { } grantee ? RelayAccessScope.ForUser(grantee) : RelayAccessScope.ForShare(share.Id);

    // ---------------------------------------------------------------- targets

    internal static string TargetType(string? type) =>
        type is StructureTypes.File or StructureTypes.Folder or StructureTypes.Project ? type : throw AuthException.Validation("targetType must be file, folder or project.");

    private static string Permission(string? permission) =>
        permission is ShareEntity.Read or ShareEntity.Write ? permission : throw AuthException.Validation("permission must be read or write.");

    internal async Task<ShareTarget?> TargetAsync(string type, Guid id, CancellationToken ct) => type switch
    {
        StructureTypes.File => await db.Files.AsNoTracking().Where(f => f.Id == id)
            .Join(db.Projects, f => f.ProjectId, p => p.Id, (f, p) => new ShareTarget(StructureTypes.File, f.Id, p.Id, p.OwnerId, f.KeyGeneration,
                f.DeletedAt == null && p.DeletedAt == null)).SingleOrDefaultAsync(ct),
        StructureTypes.Folder => await db.Folders.AsNoTracking().Where(f => f.Id == id)
            .Join(db.Projects, f => f.ProjectId, p => p.Id, (f, p) => new ShareTarget(StructureTypes.Folder, f.Id, p.Id, p.OwnerId, f.KeyGeneration,
                f.DeletedAt == null && p.DeletedAt == null)).SingleOrDefaultAsync(ct),
        _ => await db.Projects.AsNoTracking().Where(p => p.Id == id)
            .Select(p => new ShareTarget(StructureTypes.Project, p.Id, p.Id, p.OwnerId, p.KeyGeneration, p.DeletedAt == null)).SingleOrDefaultAsync(ct),
    };

    /// <summary>A live target the caller owns. Read reach without ownership is <c>403</c>, no reach <c>404</c> (09 §9.5).</summary>
    private async Task<ShareTarget> OwnedTargetAsync(Guid userId, string type, Guid id, CancellationToken ct)
    {
        var target = await TargetAsync(type, id, ct);
        if (target is not { Live: true }) throw AuthException.NotFound();
        if (target.OwnerId == userId) return target;
        throw await ReachesAsync(userId, target, ct) ? AclDenied("Only the owner shares an object.") : AuthException.NotFound();
    }

    private async Task<bool> ReachesAsync(Guid userId, ShareTarget target, CancellationToken ct)
    {
        if (!target.Live) return false;
        return target.Type switch
        {
            StructureTypes.File => await access.FileLevelAsync(userId, await db.Files.AsNoTracking().SingleAsync(f => f.Id == target.Id, ct), ct),
            StructureTypes.Folder => await access.FolderLevelAsync(userId, await db.Folders.AsNoTracking().SingleAsync(f => f.Id == target.Id, ct), ct),
            _ => await access.ProjectLevelAsync(userId, target.Id, ct),
        } != FileAccessLevel.None;
    }

    private async Task<Guid> OwnerOfAsync(ShareEntity share, CancellationToken ct)
    {
        var (type, id) = TargetOf(share);
        return (await TargetAsync(type, id, ct))!.OwnerId;
    }

    internal static (string Type, Guid Id) TargetOf(ShareEntity s) =>
        s.FileId is { } f ? (StructureTypes.File, f) : s.FolderId is { } d ? (StructureTypes.Folder, d) : (StructureTypes.Project, s.ProjectId!.Value);

    private static void SetTarget(ShareEntity share, ShareTarget target)
    {
        switch (target.Type)
        {
            case StructureTypes.File: share.FileId = target.Id; break;
            case StructureTypes.Folder: share.FolderId = target.Id; break;
            default: share.ProjectId = target.Id; break;
        }
    }

    private IQueryable<ShareEntity> LiveShares()
    {
        var now = time.GetUtcNow();
        return db.Shares.AsNoTracking().Where(s => s.RevokedAt == null && (s.ExpiresAt == null || s.ExpiresAt > now));
    }

    /// <summary>A share is a write: a session on an active device when it carries wraps, and an account that is not blocked (09 §9.5).</summary>
    private async Task<Guid> WriterAsync(ClaimsPrincipal principal, bool requireDevice, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (requireDevice) await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        return status == UserStatus.Blocked ? throw new AuthException(403, "account_blocked", "This account is blocked for changes.") : userId;
    }

    private static AuthException AclDenied(string title) => new(403, "acl_denied", title);

    private static (Guid After, int Take) Page(string? cursor, int? limit)
    {
        if (limit is < 1 or > MaxPageSize) throw AuthException.Validation($"limit must be 1 to {MaxPageSize}.");
        if (cursor is null) return (Guid.Empty, limit ?? DefaultPageSize);
        if (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != 16) throw AuthException.Validation("cursor is malformed.");
        return (new Guid(bytes, bigEndian: true), limit ?? DefaultPageSize);
    }

    public static ShareDto ToDto(ShareEntity s)
    {
        var (type, id) = TargetOf(s);
        return new ShareDto(s.Id, type, id, s.Kind, s.GranteeId, s.Permission, s.CreatedBy, s.ExpiresAt, s.CreatedAt);
    }
}

/// <summary>The three target and object kinds of the share API (09 §9.2).</summary>
public static class StructureTypes
{
    public const string File = "file";
    public const string Folder = "folder";
    public const string Project = "project";
}
