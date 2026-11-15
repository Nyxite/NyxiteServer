using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Application.Structure;
using Nyxite.Contracts.Sharing;
using Nyxite.Contracts.Structure;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sharing;

/// <summary>
/// Wrapped keys for members (server 04 "file keys", 09 §9.3): <c>POST /files/{id}/keys</c> for one file and
/// <c>POST /files/keys:batch</c> for the fan-out of a subtree share. A wrap is opaque bytes the server stores and
/// cannot open. Only the project's owner hands out keys, only to a member that the ACL lets reach the object, and only
/// for a key the object really has. Storing is idempotent: a wrap for a key and member that is already stored is left
/// as it is and counts as applied, so a client drains its resumable batch queue without caring what got through.
/// </summary>
public sealed class KeyGrantService(NyxiteDbContext db, DeviceGuard guard, ShareAccess access, TimeProvider time)
{
    public const int MaxBatch = 500;

    internal sealed record Grant(string Type, Guid ObjectId, Guid ProjectId, Guid KeyId, int Generation, Guid MemberId, byte[] Wrapped, DateTimeOffset At);

    /// <summary>Uploads wraps of one file's keys for members; atomic, unlike the batch, because it addresses one file.</summary>
    public async Task UploadAsync(ClaimsPrincipal principal, Guid fileId, UploadFileKeysRequest body, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var wraps = body.WrappedKeys is { Count: > 0 and <= MaxBatch } w ? w : throw AuthException.Validation($"wrappedKeys must hold 1 to {MaxBatch} wraps.");
        var file = await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == fileId && f.DeletedAt == null, ct) ?? throw AuthException.NotFound();
        await RequireOwnerAsync(userId, file, ct);

        var generations = await GenerationsAsync(db, StructureTypes.File, [fileId], ct);
        var now = time.GetUtcNow();
        var grants = new List<Grant>();
        foreach (var wrap in wraps)
        {
            var member = wrap.MemberId ?? throw AuthException.Validation("Every wrap needs memberId.");
            if (!generations.TryGetValue((fileId, wrap.KeyId), out var generation) || generation != wrap.Generation)
                throw AuthException.Validation("A wrap names a key the file does not have.");
            if (member != userId && await access.FileLevelAsync(member, file, ct) == FileAccessLevel.None)
                throw AuthException.Validation("A wrap names a member no share lets reach the file.");
            grants.Add(new Grant(StructureTypes.File, fileId, file.ProjectId, wrap.KeyId, generation, member,
                WrapBytes(wrap.Ciphertext, wrap.AlgId) ?? throw AuthException.Validation("A wrap is malformed."), now));
        }

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        foreach (var grant in grants) await InsertAsync(db, grant, ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// The subtree fan-out: up to <see cref="MaxBatch"/> wraps of file and folder keys, each judged on its own, so one
    /// bad entry costs that entry only (09 §9.3 "partial success").
    /// </summary>
    public async Task<BatchGrantResultsDto> BatchAsync(ClaimsPrincipal principal, BatchGrantRequest body, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var items = body.Grants is { Count: > 0 and <= MaxBatch } g ? g : throw AuthException.Validation($"grants must hold 1 to {MaxBatch} entries.");

        var fileIds = items.Where(i => i.FileId is not null).Select(i => i.FileId!.Value).Distinct().ToList();
        var folderIds = items.Where(i => i.FolderId is not null).Select(i => i.FolderId!.Value).Distinct().ToList();
        var files = await db.Files.AsNoTracking().Where(f => fileIds.Contains(f.Id) && f.DeletedAt == null).ToDictionaryAsync(f => f.Id, ct);
        var folders = await db.Folders.AsNoTracking().Where(f => folderIds.Contains(f.Id) && f.DeletedAt == null).ToDictionaryAsync(f => f.Id, ct);
        var projectIds = files.Values.Select(f => f.ProjectId).Concat(folders.Values.Select(f => f.ProjectId)).Distinct().ToList();
        var owned = (await db.Projects.AsNoTracking().Where(p => projectIds.Contains(p.Id) && p.OwnerId == userId && p.DeletedAt == null)
            .Select(p => p.Id).ToListAsync(ct)).ToHashSet();
        var mine = await access.GrantsAsync(userId, ct);
        var generations = await GenerationsAsync(db, StructureTypes.File, fileIds, ct);
        foreach (var (k, v) in await GenerationsAsync(db, StructureTypes.Folder, folderIds, ct)) generations[k] = v;
        var members = new Dictionary<Guid, ShareGrants>();
        var now = time.GetUtcNow();

        var results = new List<BatchGrantResultDto>(items.Count);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        foreach (var item in items)
        {
            string? error;
            if ((item.FileId is null) == (item.FolderId is null))
            {
                error = "validation_failed";
            }
            else
            {
                var isFile = item.FileId is not null;
                var objectId = (item.FileId ?? item.FolderId)!.Value;
                FileEntity? file = isFile ? files.GetValueOrDefault(objectId) : null;
                FolderEntity? folder = isFile ? null : folders.GetValueOrDefault(objectId);
                var projectId = file?.ProjectId ?? folder?.ProjectId;
                var wrapped = WrapBytes(item.WrappedKey, item.AlgId);
                if (projectId is null) error = "not_found";
                else if (!owned.Contains(projectId.Value))
                    error = (isFile ? mine.FileLevel(file!) : mine.FolderLevel(folder!)) == FileAccessLevel.None ? "not_found" : "acl_denied";
                else if (wrapped is null || !generations.TryGetValue((objectId, item.KeyId), out var generation)) error = "validation_failed";
                else if (item.MemberId != userId && !await ReachesAsync(item.MemberId, file, folder, members, ct)) error = "not_shared";
                else
                {
                    await InsertAsync(db, new Grant(isFile ? StructureTypes.File : StructureTypes.Folder, objectId, projectId.Value, item.KeyId, generation,
                        item.MemberId, wrapped, now), ct);
                    error = null;
                }
            }

            results.Add(new BatchGrantResultDto(item.FileId, item.FolderId, error is null ? BatchGrantResultDto.Applied : BatchGrantResultDto.Rejected, error));
        }

        await tx.CommitAsync(ct);
        return new BatchGrantResultsDto(results);
    }

    private async Task<bool> ReachesAsync(Guid member, FileEntity? file, FolderEntity? folder, Dictionary<Guid, ShareGrants> cache, CancellationToken ct)
    {
        if (!cache.TryGetValue(member, out var grants)) cache[member] = grants = await access.GrantsAsync(member, ct);
        return (file is not null ? grants.FileLevel(file) : grants.FolderLevel(folder!)) != FileAccessLevel.None;
    }

    private async Task RequireOwnerAsync(Guid userId, FileEntity file, CancellationToken ct)
    {
        if (await db.Projects.AnyAsync(p => p.Id == file.ProjectId && p.OwnerId == userId && p.DeletedAt == null, ct)) return;
        throw await access.FileLevelAsync(userId, file, ct) == FileAccessLevel.None
            ? AuthException.NotFound()
            : new AuthException(403, "acl_denied", "Only the owner hands out the keys of a file.");
    }

    /// <summary>Handing out keys needs a session on an active device, which holds the identity key the wraps come from.</summary>
    private async Task<Guid> WriterAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        return status == UserStatus.Blocked ? throw new AuthException(403, "account_blocked", "This account is blocked for changes.") : userId;
    }

    /// <summary>A wrapped object key: 32 bytes sealed with hybrid HPKE, under the one supported suite. Null when malformed.</summary>
    internal static byte[]? WrapBytes(string? ciphertext, string? algId) =>
        (algId ?? CryptoSuite.HpkeAlgId) == CryptoSuite.HpkeAlgId && Base64UrlCodec.TryDecode(ciphertext, out var bytes)
                                                                   && bytes.Length == StructureService.WrappedKeySize
            ? bytes
            : null;

    /// <summary>The generation of every key the given objects have, keyed by object and key id (1:1, 03 §3.3).</summary>
    internal static async Task<Dictionary<(Guid, Guid), int>> GenerationsAsync(NyxiteDbContext db, string type, List<Guid> ids, CancellationToken ct)
    {
        if (ids.Count == 0) return [];
        var rows = type switch
        {
            StructureTypes.File => await db.FileKeys.AsNoTracking().Where(k => ids.Contains(k.FileId))
                .Select(k => new { ObjectId = k.FileId, k.KeyId, k.Generation }).Distinct().ToListAsync(ct),
            StructureTypes.Folder => await db.StructureKeys.AsNoTracking().Where(k => k.FolderId != null && ids.Contains(k.FolderId.Value))
                .Select(k => new { ObjectId = k.FolderId!.Value, k.KeyId, k.Generation }).Distinct().ToListAsync(ct),
            _ => await db.StructureKeys.AsNoTracking().Where(k => k.ProjectId != null && ids.Contains(k.ProjectId.Value))
                .Select(k => new { ObjectId = k.ProjectId!.Value, k.KeyId, k.Generation }).Distinct().ToListAsync(ct),
        };
        return rows.GroupBy(r => (r.ObjectId, r.KeyId)).ToDictionary(g => g.Key, g => g.First().Generation);
    }

    /// <summary>Stores one wrap unless the member already has one of that key: one statement, so concurrent drains cannot collide.</summary>
    internal static Task InsertAsync(NyxiteDbContext db, Grant g, CancellationToken ct)
    {
        var id = Guid.CreateVersion7(g.At);
        var alg = CryptoSuite.HpkeAlgId;
        return g.Type switch
        {
            StructureTypes.File => db.Database.ExecuteSqlAsync($"""
                INSERT INTO file_keys (id, file_id, member_id, key_id, wrapped_key, generation, alg_id, created_at)
                VALUES ({id}, {g.ObjectId}, {g.MemberId}, {g.KeyId}, {g.Wrapped}, {g.Generation}, {alg}, {g.At})
                ON CONFLICT (file_id, key_id, member_id) WHERE member_id IS NOT NULL DO NOTHING
                """, ct),
            StructureTypes.Folder => db.Database.ExecuteSqlAsync($"""
                INSERT INTO structure_keys (id, folder_id, member_id, key_id, wrapped_key, generation, alg_id, created_at)
                VALUES ({id}, {g.ObjectId}, {g.MemberId}, {g.KeyId}, {g.Wrapped}, {g.Generation}, {alg}, {g.At})
                ON CONFLICT (folder_id, key_id, member_id) WHERE folder_id IS NOT NULL AND member_id IS NOT NULL DO NOTHING
                """, ct),
            _ => db.Database.ExecuteSqlAsync($"""
                INSERT INTO structure_keys (id, project_id, member_id, key_id, wrapped_key, generation, alg_id, created_at)
                VALUES ({id}, {g.ObjectId}, {g.MemberId}, {g.KeyId}, {g.Wrapped}, {g.Generation}, {alg}, {g.At})
                ON CONFLICT (project_id, key_id, member_id) WHERE project_id IS NOT NULL AND member_id IS NOT NULL DO NOTHING
                """, ct),
        };
    }
}
