using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Content;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sharing;

/// <summary>
/// The paths of an account to a folder or file through its live account shares (09 §9.5): the project, the folder and
/// every folder above it, and the file itself. Built once per request for listings and lookups, where a check per
/// object would cost a query each.
/// </summary>
public sealed class ShareGrants
{
    /// <summary>Projects shared as a whole, with the strongest permission over all their shares.</summary>
    public Dictionary<Guid, FileAccessLevel> Projects { get; } = [];

    /// <summary>Every live folder inside a shared folder, the shared folder itself included.</summary>
    public Dictionary<Guid, FileAccessLevel> Folders { get; } = [];

    public Dictionary<Guid, FileAccessLevel> Files { get; } = [];

    public bool ReachesProject(Guid projectId) => Projects.ContainsKey(projectId);

    public FileAccessLevel FolderLevel(FolderEntity folder) =>
        Max(Projects.GetValueOrDefault(folder.ProjectId), Folders.GetValueOrDefault(folder.Id));

    public FileAccessLevel FileLevel(FileEntity file) =>
        Max(Max(Projects.GetValueOrDefault(file.ProjectId), file.FolderId is { } f ? Folders.GetValueOrDefault(f) : FileAccessLevel.None),
            Files.GetValueOrDefault(file.Id));

    public static FileAccessLevel Max(FileAccessLevel a, FileAccessLevel b) => a >= b ? a : b;

    internal static void Raise(Dictionary<Guid, FileAccessLevel> map, Guid id, FileAccessLevel level) =>
        map[id] = Max(map.GetValueOrDefault(id), level);
}

/// <summary>
/// Resolves the server ACL of 09 §9.5: the effective level of a principal is the maximum over ownership of the project,
/// account shares on the project, on the folder or any folder above it and on the file, and, for a guest, the link
/// share it came through. A share counts while it is neither revoked nor expired, and only on live objects in a live
/// project. Structure and content both ask here, so every checkpoint, the relay's included, sees the same answer.
/// </summary>
public sealed class ShareAccess(NyxiteDbContext db, TimeProvider time)
{
    public async Task<FileAccessLevel> ProjectLevelAsync(Guid userId, Guid projectId, CancellationToken ct)
    {
        var owner = await LiveProjectOwnerAsync(projectId, ct);
        if (owner is null) return FileAccessLevel.None;
        return owner == userId ? FileAccessLevel.Write : await GrantLevelAsync(userId, projectId, [], null, ct);
    }

    public async Task<FileAccessLevel> FolderLevelAsync(Guid userId, FolderEntity folder, CancellationToken ct)
    {
        var owner = await LiveProjectOwnerAsync(folder.ProjectId, ct);
        if (owner is null) return FileAccessLevel.None;
        if (owner == userId) return FileAccessLevel.Write;
        return await GrantLevelAsync(userId, folder.ProjectId, await AncestorsAsync(db, folder.Id, ct), null, ct);
    }

    public async Task<FileAccessLevel> FileLevelAsync(Guid userId, FileEntity file, CancellationToken ct)
    {
        var owner = await LiveProjectOwnerAsync(file.ProjectId, ct);
        if (owner is null) return FileAccessLevel.None;
        if (owner == userId) return FileAccessLevel.Write;
        var folders = file.FolderId is { } folderId ? await AncestorsAsync(db, folderId, ct) : [];
        return await GrantLevelAsync(userId, file.ProjectId, folders, file.Id, ct);
    }

    /// <summary>A guest's level on a file: the permission of its live link share, which names exactly this file.</summary>
    public async Task<FileAccessLevel> GuestLevelAsync(Guid shareId, FileEntity file, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var permission = await db.Shares.AsNoTracking()
            .Where(s => s.Id == shareId && s.Kind == ShareEntity.Link && s.FileId == file.Id && s.RevokedAt == null && (s.ExpiresAt == null || s.ExpiresAt > now))
            .Select(s => s.Permission).SingleOrDefaultAsync(ct);
        if (permission is null || await LiveProjectOwnerAsync(file.ProjectId, ct) is null) return FileAccessLevel.None;
        return permission == ShareEntity.Write ? FileAccessLevel.Write : FileAccessLevel.Read;
    }

    /// <summary>Every path of <paramref name="userId"/> through its live account shares, for listings and batches.</summary>
    public async Task<ShareGrants> GrantsAsync(Guid userId, CancellationToken ct)
    {
        var grants = new ShareGrants();
        var rows = await LiveGrants(userId).Select(s => new { s.ProjectId, s.FolderId, s.FileId, s.Permission }).ToListAsync(ct);
        foreach (var row in rows)
        {
            var level = row.Permission == ShareEntity.Write ? FileAccessLevel.Write : FileAccessLevel.Read;
            if (row.ProjectId is { } p) ShareGrants.Raise(grants.Projects, p, level);
            if (row.FileId is { } f) ShareGrants.Raise(grants.Files, f, level);
        }

        // A project in Trash cuts off everything in it, for grantees as for its owner.
        var projects = grants.Projects.Keys.ToList();
        var live = (await db.Projects.AsNoTracking().Where(p => projects.Contains(p.Id) && p.DeletedAt == null).Select(p => p.Id).ToListAsync(ct)).ToHashSet();
        foreach (var dead in projects.Where(p => !live.Contains(p))) grants.Projects.Remove(dead);

        foreach (var folder in rows.Where(r => r.FolderId is not null).GroupBy(r => r.FolderId!.Value))
        {
            var level = folder.Any(r => r.Permission == ShareEntity.Write) ? FileAccessLevel.Write : FileAccessLevel.Read;
            foreach (var id in await SubtreeAsync(folder.Key, ct)) ShareGrants.Raise(grants.Folders, id, level);
        }

        return grants;
    }

    /// <summary>
    /// Every account that reaches a live <paramref name="file"/>: the project's owner and each grantee of a live account
    /// share on the project, on the file's folder or a folder above it, or on the file. These are the members a key
    /// rotation must wrap the new key to (09 §9.6). Link guests are no members, because their key rides the URL fragment.
    /// </summary>
    public async Task<HashSet<Guid>> MembersAsync(FileEntity file, CancellationToken ct)
    {
        var owner = await LiveProjectOwnerAsync(file.ProjectId, ct);
        if (owner is null) return [];
        var folders = file.FolderId is { } folderId ? await AncestorsAsync(db, folderId, ct) : [];
        var now = time.GetUtcNow();
        var grantees = await db.Shares.AsNoTracking()
            .Where(s => s.Kind == ShareEntity.UserGrant && s.GranteeId != null && s.RevokedAt == null && (s.ExpiresAt == null || s.ExpiresAt > now)
                        && (s.ProjectId == file.ProjectId || (s.FolderId != null && folders.Contains(s.FolderId.Value)) || s.FileId == file.Id))
            .Select(s => s.GranteeId!.Value).Distinct().ToListAsync(ct);
        return [owner.Value, .. grantees];
    }

    private IQueryable<ShareEntity> LiveGrants(Guid userId)
    {
        var now = time.GetUtcNow();
        return db.Shares.AsNoTracking().Where(s => s.Kind == ShareEntity.UserGrant && s.GranteeId == userId && s.RevokedAt == null
                                                   && (s.ExpiresAt == null || s.ExpiresAt > now));
    }

    private async Task<FileAccessLevel> GrantLevelAsync(Guid userId, Guid projectId, List<Guid> folders, Guid? fileId, CancellationToken ct)
    {
        var permissions = await LiveGrants(userId)
            .Where(s => s.ProjectId == projectId || (s.FolderId != null && folders.Contains(s.FolderId.Value)) || (fileId != null && s.FileId == fileId))
            .Select(s => s.Permission).ToListAsync(ct);
        return permissions.Contains(ShareEntity.Write) ? FileAccessLevel.Write
            : permissions.Count > 0 ? FileAccessLevel.Read : FileAccessLevel.None;
    }

    private async Task<Guid?> LiveProjectOwnerAsync(Guid projectId, CancellationToken ct) =>
        await db.Projects.AsNoTracking().Where(p => p.Id == projectId && p.DeletedAt == null).Select(p => (Guid?)p.OwnerId).SingleOrDefaultAsync(ct);

    /// <summary>The folder and all its ancestors, nearest first.</summary>
    public static async Task<List<Guid>> AncestorsAsync(NyxiteDbContext db, Guid folderId, CancellationToken ct) =>
        await db.Database.SqlQuery<Guid>($"""
            WITH RECURSIVE up AS (
                SELECT id, parent_folder_id FROM folders WHERE id = {folderId}
                UNION ALL
                SELECT f.id, f.parent_folder_id FROM folders f JOIN up ON f.id = up.parent_folder_id)
            SELECT id AS "Value" FROM up
            """).ToListAsync(ct);

    /// <summary>The live folder and every live folder below it.</summary>
    private async Task<List<Guid>> SubtreeAsync(Guid folderId, CancellationToken ct) =>
        await db.Database.SqlQuery<Guid>($"""
            WITH RECURSIVE sub AS (
                SELECT id FROM folders WHERE id = {folderId} AND deleted_at IS NULL
                UNION ALL
                SELECT f.id FROM folders f JOIN sub ON f.parent_folder_id = sub.id WHERE f.deleted_at IS NULL)
            SELECT id AS "Value" FROM sub
            """).ToListAsync(ct);
}
