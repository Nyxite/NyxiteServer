using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Application.Maintenance;
using Nyxite.Application.Sharing;
using Nyxite.Application.Sync;
using Nyxite.Contracts.Structure;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Domain.Structure;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Structure;

/// <summary>
/// Projects, folders and files as an opaque tree (server 02, 03 §3.3, 04 "structure"). The server keeps ids, parents,
/// content type and timestamps. Names and metadata are NYXC frames it cannot open, sealed with the object's own key,
/// which it stores only wrapped to each member. Ids are allocated by the client, because a name frame is bound to the
/// id of its object and a client must be able to build a subtree while offline.
/// <para>
/// Reach is ownership of the project or a live account share on the project, a folder above the object or the object
/// (09 §9.5, <see cref="ShareAccess"/>). An object the caller cannot reach answers <c>404</c>, like one that does not
/// exist (04 §4.4). Changing the structure stays with the project owner: a grantee reads names and keys, and a write
/// share covers content, so a grantee's structure write answers <c>403 acl_denied</c>. Deleting is always a soft
/// delete (03 §3.3, DL-1).
/// </para>
/// </summary>
public sealed class StructureService(
    NyxiteDbContext db, DeviceGuard guard, IdempotencyStore idempotency, AuditWriter audit, TimeProvider time, ChangeFeed feed,
    ShareAccess access, IOptions<StructureOptions> options, IOptions<RetentionOptions> retention, Content.IRelayAccessEvents relay)
{
    public const string CreateProjectEndpoint = "POST /projects";
    public const string CreateFolderEndpoint = "POST /folders";
    public const string CreateFileEndpoint = "POST /files";

    public const int DefaultPageSize = 50;
    public const int MaxPageSize = 200;

    /// <summary>A wrapped object key: the 32-byte AES key sealed with hybrid HPKE.</summary>
    public const int WrappedKeySize = 32 + HybridHpke.Overhead;

    /// <summary>Most object ids one key lookup may name.</summary>
    public const int MaxKeyLookup = 500;

    public const string Project = "project";
    public const string Folder = "folder";
    public const string File = "file";

    private readonly StructureOptions _options = options.Value;
    private readonly TimeSpan _trashWindow = TimeSpan.FromDays(retention.Value.TrashWindowDays);

    // ---------------------------------------------------------------- projects

    public async Task<PageDto<ProjectDto>> ListProjectsAsync(ClaimsPrincipal principal, string? cursor, int? limit, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        var (after, take) = Page(cursor, limit);
        var rows = await db.Projects.AsNoTracking()
            .Where(p => p.OwnerId == userId && p.DeletedAt == null && p.Id > after)
            .OrderBy(p => p.Id).Take(take + 1).ToListAsync(ct);
        return ToPage(rows, take, r => r.Id, await ProjectMapAsync(rows.Take(take), userId, keys, ct));
    }

    public async Task<ProjectDto> GetProjectAsync(ClaimsPrincipal principal, Guid id, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        return await ToDtoAsync(await ProjectAsync(userId, id, tracked: false, ct), userId, keys, ct);
    }

    public async Task<IdempotentResponse> CreateProjectAsync(ClaimsPrincipal principal, CreateProjectRequest body, string? idempotencyKey, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var (key, hash) = IdempotencyKey(idempotencyKey, body);
        if (await idempotency.FindAsync(userId, CreateProjectEndpoint, key, hash, ct) is { } replay) return replay;

        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var (name, nameKeyId) = Name(body.NameEnc, required: true);
        var metadata = Metadata(body.MetadataEnc);
        var policy = Policy(body.SyncPolicy) ?? SyncPolicies.ServerDefault;
        var wrap = OwnerWrap(body.OwnerWrappedKey, userId, nameKeyId, metadata);
        NewId(body.Id);
        if (await db.Projects.AnyAsync(p => p.Id == body.Id, ct)) throw AuthException.Conflict("id is already in use.");

        var now = time.GetUtcNow();
        var project = new ProjectEntity
        {
            Id = body.Id, OwnerId = userId, NameEnc = name!, MetadataEnc = metadata, SyncPolicy = policy, CreatedAt = now, UpdatedAt = now,
        };
        db.Projects.Add(project);
        db.StructureKeys.Add(new StructureKeyEntity
        {
            Id = Guid.CreateVersion7(now), ProjectId = project.Id, MemberId = userId, KeyId = wrap.KeyId, WrappedKey = wrap.Ciphertext,
            Generation = 1, AlgId = wrap.AlgId, CreatedAt = now,
        });
        await feed.ProjectAsync(project, ct);
        var stored = idempotency.Add(userId, CreateProjectEndpoint, key, hash, 201, ToDto(project, wrap.ToDto(userId)));
        await SaveCreateAsync(ct);
        await tx.CommitAsync(ct);
        return stored;
    }

    public async Task<ProjectDto> UpdateProjectAsync(ClaimsPrincipal principal, Guid id, UpdateProjectRequest body, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var project = await ProjectAsync(userId, id, tracked: true, ct, write: true);
        var keyId = await db.StructureKeys.Where(k => k.ProjectId == id && k.Generation == project.KeyGeneration).Select(k => k.KeyId).FirstAsync(ct);

        if (Name(body.NameEnc, required: false, keyId) is { Bytes: { } name }) project.NameEnc = name;
        if (body.MetadataEnc.IsSet) project.MetadataEnc = Metadata(body.MetadataEnc.Value, keyId);
        if (Policy(body.SyncPolicy) is { } policy) project.SyncPolicy = policy;
        project.UpdatedAt = time.GetUtcNow();
        await feed.ProjectAsync(project, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return await ToDtoAsync(project, userId, keys: true, ct);
    }

    /// <summary>Moves the project and everything in it to Trash. What goes along is marked with the project's id, so a restore finds the same set.</summary>
    public async Task<IReadOnlyList<Guid>> DeleteProjectAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var project = await ProjectAsync(userId, id, tracked: true, ct, write: true);
        var now = time.GetUtcNow();
        // The ids, so the relay can close the rooms of what went to Trash.
        var files = await db.Database.SqlQuery<Guid>($"""
            UPDATE files SET deleted_at = {now}, updated_at = {now}, deleted_root_id = {id} WHERE project_id = {id} AND deleted_at IS NULL
            RETURNING id AS "Value"
            """).ToListAsync(ct);
        var folders = await db.Folders.Where(f => f.ProjectId == id && f.DeletedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.DeletedAt, now).SetProperty(f => f.UpdatedAt, now).SetProperty(f => f.DeletedRootId, id), ct);
        project.DeletedAt = now;
        project.UpdatedAt = now;
        // The project's own feed answers 404 while it is in Trash, so its rows need no entry of their own.
        await feed.DeleteAsync(id, Project, id, now, ChangeFeed.Deleted, ct);
        audit.Add("project.delete", userId, request, targetType: "project", targetId: id, detail: new { folders, files = files.Count });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Trashed(tx, files);
    }

    public async Task<WrappedKeysDto> ProjectKeysAsync(ClaimsPrincipal principal, Guid id, CancellationToken ct)
    {
        var userId = principal.UserId();
        await ProjectAsync(userId, id, tracked: false, ct);
        return await StructureKeysAsync(db.StructureKeys.Where(k => k.ProjectId == id), userId, ct);
    }

    // ---------------------------------------------------------------- folders

    public async Task<PageDto<FolderDto>> ListFoldersAsync(ClaimsPrincipal principal, Guid projectId, string? cursor, int? limit, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        var (after, take) = Page(cursor, limit);
        var reach = await ProjectReachAsync(userId, projectId, ct);
        var rows = await db.Folders.AsNoTracking()
            .Where(f => f.ProjectId == projectId && f.DeletedAt == null && f.Id > after && (reach.Whole || reach.Folders.Contains(f.Id)))
            .OrderBy(f => f.Id).Take(take + 1).ToListAsync(ct);
        return ToPage(rows, take, r => r.Id, await FolderMapAsync(rows.Take(take), userId, keys, ct));
    }

    public async Task<FolderDto> GetFolderAsync(ClaimsPrincipal principal, Guid id, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        return await ToDtoAsync(await FolderAsync(userId, id, tracked: false, ct), userId, keys, ct);
    }

    public async Task<IdempotentResponse> CreateFolderAsync(ClaimsPrincipal principal, CreateFolderRequest body, string? idempotencyKey, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var (key, hash) = IdempotencyKey(idempotencyKey, body);
        if (await idempotency.FindAsync(userId, CreateFolderEndpoint, key, hash, ct) is { } replay) return replay;

        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var stored = idempotency.Add(userId, CreateFolderEndpoint, key, hash, 201, await InsertFolderAsync(userId, body, ct));
        await SaveCreateAsync(ct);
        await tx.CommitAsync(ct);
        return stored;
    }

    /// <summary>A folder create replayed from a device's outbox (06 §6.3.2): the same checks, without the Idempotency-Key header.</summary>
    internal async Task CreateFolderAsync(ClaimsPrincipal principal, CreateFolderRequest body, CancellationToken ct)
    {
        await InsertFolderAsync(await WriterAsync(principal, ct), body, ct);
        await SaveCreateAsync(ct);
    }

    private async Task<FolderDto> InsertFolderAsync(Guid userId, CreateFolderRequest body, CancellationToken ct)
    {
        var (name, nameKeyId) = Name(body.NameEnc, required: true);
        var metadata = Metadata(body.MetadataEnc);
        var policy = Policy(body.SyncPolicy);
        var wrap = OwnerWrap(body.OwnerWrappedKey, userId, nameKeyId, metadata);
        NewId(body.Id);
        await ProjectAsync(userId, body.ProjectId, tracked: false, ct, write: true);
        if (body.ParentFolderId is { } parentId) await ParentAsync(body.ProjectId, parentId, ct);
        if (await db.Folders.AnyAsync(f => f.Id == body.Id, ct)) throw AuthException.Conflict("id is already in use.");

        var now = time.GetUtcNow();
        var folder = new FolderEntity
        {
            Id = body.Id, ProjectId = body.ProjectId, ParentFolderId = body.ParentFolderId, NameEnc = name!, MetadataEnc = metadata,
            SyncPolicy = policy, CreatedAt = now, UpdatedAt = now,
        };
        db.Folders.Add(folder);
        db.StructureKeys.Add(new StructureKeyEntity
        {
            Id = Guid.CreateVersion7(now), FolderId = folder.Id, MemberId = userId, KeyId = wrap.KeyId, WrappedKey = wrap.Ciphertext,
            Generation = 1, AlgId = wrap.AlgId, CreatedAt = now,
        });
        await feed.FolderAsync(folder, ct);
        return ToDto(folder, wrap.ToDto(userId));
    }

    public async Task<FolderDto> UpdateFolderAsync(ClaimsPrincipal principal, Guid id, UpdateFolderRequest body, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var folder = await FolderAsync(userId, id, tracked: true, ct, write: true);
        var keyId = await db.StructureKeys.Where(k => k.FolderId == id && k.Generation == folder.KeyGeneration).Select(k => k.KeyId).FirstAsync(ct);

        if (Name(body.NameEnc, required: false, keyId) is { Bytes: { } name }) folder.NameEnc = name;
        if (body.MetadataEnc.IsSet) folder.MetadataEnc = Metadata(body.MetadataEnc.Value, keyId);
        if (body.SyncPolicy.IsSet) folder.SyncPolicy = Policy(body.SyncPolicy.Value);
        if (body.ParentFolderId.IsSet && body.ParentFolderId.Value != folder.ParentFolderId)
        {
            // Moves within one project run one after the other: two crossing moves could otherwise each pass the cycle
            // check and together close a loop.
            await db.Database.ExecuteSqlAsync($"SELECT 1 FROM projects WHERE id = {folder.ProjectId} FOR UPDATE", ct);
            if (body.ParentFolderId.Value is { } parentId)
            {
                await ParentAsync(folder.ProjectId, parentId, ct);
                if (FolderRules.WouldCycle(id, await AncestorsAsync(parentId, ct)))
                    throw AuthException.Validation("A folder cannot be moved into itself or one of its subfolders.");
            }

            folder.ParentFolderId = body.ParentFolderId.Value;
        }

        folder.UpdatedAt = time.GetUtcNow();
        await feed.FolderAsync(folder, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return await ToDtoAsync(folder, userId, keys: true, ct);
    }

    /// <summary>Moves the folder and its whole subtree to Trash as one audited event (02 §2.6).</summary>
    public async Task<IReadOnlyList<Guid>> DeleteFolderAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var projectId = (await FolderAsync(userId, id, tracked: false, ct, write: true)).ProjectId;
        var now = time.GetUtcNow();
        // Files first: the subtree is found through live folders, which the second statement then marks.
        var files = await db.Database.SqlQuery<Guid>($"""
            WITH RECURSIVE sub AS (
                SELECT id FROM folders WHERE id = {id}
                UNION ALL
                SELECT f.id FROM folders f JOIN sub ON f.parent_folder_id = sub.id WHERE f.deleted_at IS NULL)
            UPDATE files SET deleted_at = {now}, updated_at = {now}, deleted_root_id = {id} WHERE folder_id IN (SELECT id FROM sub) AND deleted_at IS NULL
            RETURNING id AS "Value"
            """).ToListAsync(ct);
        var folders = await db.Database.SqlQuery<Guid>($"""
            WITH RECURSIVE sub AS (
                SELECT id FROM folders WHERE id = {id}
                UNION ALL
                SELECT f.id FROM folders f JOIN sub ON f.parent_folder_id = sub.id WHERE f.deleted_at IS NULL)
            UPDATE folders SET deleted_at = {now}, updated_at = {now}, deleted_root_id = CASE WHEN id = {id} THEN NULL ELSE {id}::uuid END
            WHERE id IN (SELECT id FROM sub) AND deleted_at IS NULL
            RETURNING id AS "Value"
            """).ToListAsync(ct);
        // One delete per row, like the restore brings back one upsert per row (06 §6.3.2).
        foreach (var folderId in folders) await feed.DeleteAsync(projectId, Folder, folderId, now, ChangeFeed.Deleted, ct);
        foreach (var fileId in files) await feed.DeleteAsync(projectId, File, fileId, now, ChangeFeed.Deleted, ct);
        audit.Add("folder.delete", userId, request, targetType: "folder", targetId: id, detail: new { folders = folders.Count, files = files.Count });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Trashed(tx, files);
    }

    public async Task<WrappedKeysDto> FolderKeysAsync(ClaimsPrincipal principal, Guid id, CancellationToken ct)
    {
        var userId = principal.UserId();
        await FolderAsync(userId, id, tracked: false, ct);
        return await StructureKeysAsync(db.StructureKeys.Where(k => k.FolderId == id), userId, ct);
    }

    // ---------------------------------------------------------------- files

    /// <summary>The files of a project, or with <paramref name="folderId"/> the files directly in that folder.</summary>
    public async Task<PageDto<FileDto>> ListFilesAsync(ClaimsPrincipal principal, Guid? projectId, Guid? folderId, string? cursor, int? limit, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        // Reach of a folder covers every file directly in it; a project listing shows what the caller's shares reach.
        var reach = ProjectReach.All;
        if (folderId is { } fid) projectId = (await FolderAsync(userId, fid, tracked: false, ct)).ProjectId;
        else reach = await ProjectReachAsync(userId, projectId!.Value, ct);

        var (after, take) = Page(cursor, limit);
        var rows = await db.Files.AsNoTracking()
            .Where(f => f.ProjectId == projectId && (folderId == null || f.FolderId == folderId) && f.DeletedAt == null && f.Id > after
                        && (reach.Whole || reach.Files.Contains(f.Id) || (f.FolderId != null && reach.Folders.Contains(f.FolderId.Value))))
            .OrderBy(f => f.Id).Take(take + 1).ToListAsync(ct);
        return ToPage(rows, take, r => r.Id, await FileMapAsync(rows.Take(take), userId, keys, ct));
    }

    public async Task<FileDto> GetFileAsync(ClaimsPrincipal principal, Guid id, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        return await ToDtoAsync(await FileAsync(userId, id, tracked: false, ct), userId, keys, ct);
    }

    public async Task<IdempotentResponse> CreateFileAsync(ClaimsPrincipal principal, CreateFileRequest body, string? idempotencyKey, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        var (key, hash) = IdempotencyKey(idempotencyKey, body);
        if (await idempotency.FindAsync(userId, CreateFileEndpoint, key, hash, ct) is { } replay) return replay;

        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var stored = idempotency.Add(userId, CreateFileEndpoint, key, hash, 201, await InsertFileAsync(userId, body, ct));
        await SaveCreateAsync(ct);
        await tx.CommitAsync(ct);
        return stored;
    }

    /// <summary>A file create replayed from a device's outbox (06 §6.3.2): the same checks, without the Idempotency-Key header.</summary>
    internal async Task CreateFileAsync(ClaimsPrincipal principal, CreateFileRequest body, CancellationToken ct)
    {
        await InsertFileAsync(await WriterAsync(principal, ct), body, ct);
        await SaveCreateAsync(ct);
    }

    private async Task<FileDto> InsertFileAsync(Guid userId, CreateFileRequest body, CancellationToken ct)
    {
        var (name, nameKeyId) = Name(body.NameEnc, required: true);
        var metadata = Metadata(body.MetadataEnc);
        var policy = Policy(body.SyncPolicy) ?? SyncPolicies.ServerDefault;
        if (body.ContentType is not { } contentType || !ContentTypes.All.Contains(contentType))
            throw AuthException.Validation("contentType is not a known content type.");
        if (ContentTypes.IsCrdt(contentType) != body.CrdtDocId.HasValue)
            throw AuthException.Validation("crdtDocId is required for text content types and must be absent for all others.");
        if (body.CrdtDocId is { Version: not 7 }) throw AuthException.Validation("crdtDocId must be a UUIDv7.");
        var wrap = OwnerWrap(body.OwnerWrappedKey, userId, nameKeyId, metadata);
        NewId(body.Id);
        await ProjectAsync(userId, body.ProjectId, tracked: false, ct, write: true);
        if (body.FolderId is { } folderId) await ParentAsync(body.ProjectId, folderId, ct);
        if (await db.Files.AnyAsync(f => f.Id == body.Id, ct)) throw AuthException.Conflict("id is already in use.");

        var now = time.GetUtcNow();
        var file = new FileEntity
        {
            Id = body.Id, ProjectId = body.ProjectId, FolderId = body.FolderId, OwnerId = userId, NameEnc = name!, MetadataEnc = metadata,
            ContentType = contentType, SyncPolicy = policy, CrdtDocId = body.CrdtDocId, CreatedAt = now, UpdatedAt = now,
        };
        db.Files.Add(file);
        db.FileKeys.Add(new FileKeyEntity
        {
            Id = Guid.CreateVersion7(now), FileId = file.Id, MemberId = userId, KeyId = wrap.KeyId, WrappedKey = wrap.Ciphertext,
            Generation = 1, AlgId = wrap.AlgId, CreatedAt = now,
        });
        await feed.FileAsync(file, ct);
        return ToDto(file, wrap.ToDto(userId));
    }

    public async Task<FileDto> UpdateFileAsync(ClaimsPrincipal principal, Guid id, UpdateFileRequest body, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var file = await FileAsync(userId, id, tracked: true, ct, write: true);
        var keyId = await db.FileKeys.Where(k => k.FileId == id && k.Generation == file.KeyGeneration).Select(k => k.KeyId).FirstAsync(ct);

        if (Name(body.NameEnc, required: false, keyId) is { Bytes: { } name }) file.NameEnc = name;
        if (body.MetadataEnc.IsSet) file.MetadataEnc = Metadata(body.MetadataEnc.Value, keyId);
        var now = time.GetUtcNow();
        if (Policy(body.SyncPolicy) is { } policy && policy != file.SyncPolicy)
        {
            // Content already stored is purged after Trash window plus grace window, so switching back in time loses nothing.
            file.ExcludedAt = policy == SyncPolicies.Excluded ? now : null;
            file.SyncPolicy = policy;
        }

        if (body.ParentFolderId.IsSet && body.ParentFolderId.Value != file.FolderId)
        {
            if (body.ParentFolderId.Value is { } folderId) await ParentAsync(file.ProjectId, folderId, ct);
            file.FolderId = body.ParentFolderId.Value;
        }

        file.UpdatedAt = now;
        await feed.FileAsync(file, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return await ToDtoAsync(file, userId, keys: true, ct);
    }

    public async Task<IReadOnlyList<Guid>> DeleteFileAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var file = await FileAsync(userId, id, tracked: true, ct, write: true);
        var now = time.GetUtcNow();
        file.DeletedAt = now;
        file.UpdatedAt = now;
        await feed.DeleteAsync(file.ProjectId, File, id, now, ChangeFeed.Deleted, ct);
        audit.Add("file.delete", userId, request, targetType: "file", targetId: id);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Trashed(tx, [id]);
    }

    /// <summary>
    /// A file in Trash has no reach for anyone, its owner included (05 §5.4), so the relay judges the rooms of what went
    /// to Trash right away. That has to wait for the commit: a delete inside a sync batch joins the batch item's
    /// transaction, and the batch tells the relay once it has committed.
    /// </summary>
    private IReadOnlyList<Guid> Trashed(UnitOfWork tx, IReadOnlyList<Guid> files)
    {
        if (tx.Owned && files.Count > 0) relay.AccessChanged(Content.RelayAccessScope.ForFiles(files));
        return files;
    }

    public async Task<WrappedKeysDto> FileKeysAsync(ClaimsPrincipal principal, Guid id, CancellationToken ct)
    {
        var userId = principal.UserId();
        await FileAsync(userId, id, tracked: false, ct);
        var rows = await db.FileKeys.AsNoTracking().Where(k => k.FileId == id && k.MemberId == userId && k.RevokedAt == null)
            .OrderBy(k => k.Generation).ToListAsync(ct);
        return new WrappedKeysDto(rows.Select(k => new WrappedKeyDto(k.KeyId, k.MemberId, Base64UrlCodec.Encode(k.WrappedKey), k.Generation, k.AlgId)).ToList());
    }

    // ---------------------------------------------------------------- reach

    /// <summary>
    /// A live project the caller reaches. <paramref name="write"/> asks for a structure change, which only the owner
    /// makes: a grantee, who already knows the project, gets <c>403 acl_denied</c>.
    /// </summary>
    private async Task<ProjectEntity> ProjectAsync(Guid userId, Guid id, bool tracked, CancellationToken ct, bool write = false)
    {
        var query = tracked ? db.Projects : db.Projects.AsNoTracking();
        var project = await query.SingleOrDefaultAsync(p => p.Id == id && p.DeletedAt == null, ct) ?? throw AuthException.NotFound();
        if (project.OwnerId == userId) return project;
        if (await access.ProjectLevelAsync(userId, id, ct) == FileAccessLevel.None) throw AuthException.NotFound();
        return write ? throw OwnerOnly() : project;
    }

    private async Task<FolderEntity> FolderAsync(Guid userId, Guid id, bool tracked, CancellationToken ct, bool write = false)
    {
        var query = tracked ? db.Folders : db.Folders.AsNoTracking();
        var folder = await query.SingleOrDefaultAsync(f => f.Id == id && f.DeletedAt == null, ct) ?? throw AuthException.NotFound();
        if (await db.Projects.AnyAsync(p => p.Id == folder.ProjectId && p.OwnerId == userId && p.DeletedAt == null, ct)) return folder;
        if (await access.FolderLevelAsync(userId, folder, ct) == FileAccessLevel.None) throw AuthException.NotFound();
        return write ? throw OwnerOnly() : folder;
    }

    private async Task<FileEntity> FileAsync(Guid userId, Guid id, bool tracked, CancellationToken ct, bool write = false)
    {
        var query = tracked ? db.Files : db.Files.AsNoTracking();
        var file = await query.SingleOrDefaultAsync(f => f.Id == id && f.DeletedAt == null, ct) ?? throw AuthException.NotFound();
        if (await db.Projects.AnyAsync(p => p.Id == file.ProjectId && p.OwnerId == userId && p.DeletedAt == null, ct)) return file;
        if (await access.FileLevelAsync(userId, file, ct) == FileAccessLevel.None) throw AuthException.NotFound();
        return write ? throw OwnerOnly() : file;
    }

    private static AuthException OwnerOnly() =>
        new(403, "acl_denied", "Only the owner changes the structure of a shared project; a write share covers content.");

    /// <summary>What of a project the caller's listing shows: all of it, or only what its shares reach.</summary>
    private sealed record ProjectReach(bool Whole, List<Guid> Folders, List<Guid> Files)
    {
        public static readonly ProjectReach All = new(true, [], []);
    }

    /// <summary>The owner and a grantee of the whole project see everything; a folder or file grantee only its share.</summary>
    private async Task<ProjectReach> ProjectReachAsync(Guid userId, Guid projectId, CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking().SingleOrDefaultAsync(p => p.Id == projectId && p.DeletedAt == null, ct)
                      ?? throw AuthException.NotFound();
        if (project.OwnerId == userId) return ProjectReach.All;
        var grants = await access.GrantsAsync(userId, ct);
        if (grants.ReachesProject(projectId)) return ProjectReach.All;
        var sharedFolders = grants.Folders.Keys.ToList();
        var sharedFiles = grants.Files.Keys.ToList();
        var folders = await db.Folders.AsNoTracking().Where(f => f.ProjectId == projectId && sharedFolders.Contains(f.Id)).Select(f => f.Id).ToListAsync(ct);
        var files = await db.Files.AsNoTracking().Where(f => f.ProjectId == projectId && sharedFiles.Contains(f.Id)).Select(f => f.Id).ToListAsync(ct);
        return folders.Count == 0 && files.Count == 0 ? throw AuthException.NotFound() : new ProjectReach(false, folders, files);
    }

    /// <summary>A folder something is put into: it must be live and in the same project (02 §2.2.4).</summary>
    private async Task ParentAsync(Guid projectId, Guid folderId, CancellationToken ct)
    {
        var parent = await db.Folders.AsNoTracking().Where(f => f.Id == folderId && f.DeletedAt == null).Select(f => new { f.ProjectId }).SingleOrDefaultAsync(ct);
        if (parent is null || parent.ProjectId != projectId) throw AuthException.NotFound();
    }

    /// <summary>The folder and all its ancestors, nearest first.</summary>
    private async Task<List<Guid>> AncestorsAsync(Guid folderId, CancellationToken ct) =>
        await db.Database.SqlQuery<Guid>($"""
            WITH RECURSIVE up AS (
                SELECT id, parent_folder_id FROM folders WHERE id = {folderId}
                UNION ALL
                SELECT f.id, f.parent_folder_id FROM folders f JOIN up ON f.id = up.parent_folder_id)
            SELECT id AS "Value" FROM up
            """).ToListAsync(ct);

    /// <summary>
    /// The caller as someone who may change structure: not blocked (12 §12.6), and on an active device, because only a
    /// device that holds the identity key can have produced the names and wrapped keys it sends.
    /// </summary>
    private async Task<Guid> WriterAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        return status == UserStatus.Blocked ? throw new AuthException(403, "account_blocked", "This account is blocked for changes.") : userId;
    }

    // ---------------------------------------------------------------- validation

    private static (string Key, byte[] Hash) IdempotencyKey(string? header, object body) =>
        (IdempotencyStore.ValidKey(header) ?? throw AuthException.Validation("A valid Idempotency-Key header is required."), IdempotencyStore.Hash(body));

    private static void NewId(Guid id)
    {
        if (id.Version != 7) throw AuthException.Validation("id must be a client-allocated UUIDv7.");
    }

    /// <summary>
    /// A name frame. The server checks what it can without a key: the frame layout, its size, and that it names the
    /// object's current key, so a name sealed with a rotated-out key is refused.
    /// </summary>
    private (byte[]? Bytes, Guid KeyId) Name(string? nameEnc, bool required, Guid? currentKeyId = null)
    {
        if (nameEnc is null && !required) return (null, default);
        if (!Base64UrlCodec.TryDecode(nameEnc, out var bytes) || bytes.Length > _options.NameEncMaxBytes || !NyxcFrame.TryParseHeader(bytes, out var header))
            throw AuthException.Validation("nameEnc must be an NYXC frame within the size limit.");
        if (currentKeyId is { } current && header.KeyId != current) throw AuthException.Validation("nameEnc is not sealed with the object's current key.");
        return (bytes, header.KeyId);
    }

    private byte[]? Metadata(string? metadataEnc, Guid? currentKeyId = null)
    {
        if (metadataEnc is null) return null;
        if (!Base64UrlCodec.TryDecode(metadataEnc, out var bytes) || bytes.Length > _options.MetadataEncMaxBytes || !NyxcFrame.TryParseHeader(bytes, out var header))
            throw AuthException.Validation("metadataEnc must be an NYXC frame within the size limit.");
        if (currentKeyId is { } current && header.KeyId != current) throw AuthException.Validation("metadataEnc is not sealed with the object's current key.");
        return bytes;
    }

    private static string? Policy(string? syncPolicy) =>
        syncPolicy is null || SyncPolicies.IsValid(syncPolicy) ? syncPolicy : throw new AuthException(400, "bad_sync_policy", "syncPolicy is not a known sync policy.");

    private sealed record Wrap(Guid KeyId, byte[] Ciphertext, string AlgId)
    {
        public WrappedKeyDto ToDto(Guid memberId) => new(KeyId, memberId, Base64UrlCodec.Encode(Ciphertext), 1, AlgId);
    }

    /// <summary>The creator's own wrapped key of a new object. It must be the key the name and the metadata are sealed with.</summary>
    private static Wrap OwnerWrap(WrappedKeyRequest? wrap, Guid userId, Guid nameKeyId, byte[]? metadata)
    {
        if (wrap is null) throw AuthException.Validation("ownerWrappedKey is required.");
        if (wrap.MemberId is { } member && member != userId) throw AuthException.Validation("ownerWrappedKey must be wrapped to the caller.");
        if (wrap.Generation != 1) throw AuthException.Validation("ownerWrappedKey.generation must be 1 for a new object.");
        if ((wrap.AlgId ?? CryptoSuite.HpkeAlgId) != CryptoSuite.HpkeAlgId) throw AuthException.Validation("ownerWrappedKey.algId is not a supported suite.");
        if (!Base64UrlCodec.TryDecode(wrap.Ciphertext, out var ciphertext) || ciphertext.Length != WrappedKeySize)
            throw AuthException.Validation("ownerWrappedKey.ciphertext must be a 32-byte key sealed with hybrid HPKE.");
        if (wrap.KeyId != nameKeyId) throw AuthException.Validation("nameEnc is not sealed with the key in ownerWrappedKey.");
        if (metadata is not null && NyxcFrame.TryParseHeader(metadata, out var header) && header.KeyId != wrap.KeyId)
            throw AuthException.Validation("metadataEnc is not sealed with the key in ownerWrappedKey.");
        return new Wrap(wrap.KeyId, ciphertext, CryptoSuite.HpkeAlgId);
    }

    /// <summary>Saves a create. Two creates racing for one id both pass the lookup; the loser answers like a taken id.</summary>
    private async Task SaveCreateAsync(CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException e) when (e.InnerException is Npgsql.PostgresException { SqlState: Npgsql.PostgresErrorCodes.UniqueViolation })
        {
            throw AuthException.Conflict("id is already in use.");
        }
    }

    // ---------------------------------------------------------------- paging and mapping

    /// <summary>Pages run in id order, which for UUIDv7 is creation order. The cursor is the last id, opaque to clients.</summary>
    private static (Guid After, int Take) Page(string? cursor, int? limit)
    {
        if (limit is < 1 or > MaxPageSize) throw AuthException.Validation($"limit must be 1 to {MaxPageSize}.");
        if (cursor is null) return (Guid.Empty, limit ?? DefaultPageSize);
        if (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != 16) throw AuthException.Validation("cursor is malformed.");
        return (new Guid(bytes, bigEndian: true), limit ?? DefaultPageSize);
    }

    private static PageDto<TDto> ToPage<TRow, TDto>(List<TRow> rows, int take, Func<TRow, Guid> id, Func<TRow, TDto> map)
    {
        var page = rows.Take(take).ToList();
        var next = rows.Count > take ? Base64UrlCodec.Encode(id(page[^1]).ToByteArray(bigEndian: true)) : null;
        return new PageDto<TDto>(page.Select(map).ToList(), next);
    }

    private async Task<WrappedKeysDto> StructureKeysAsync(IQueryable<StructureKeyEntity> keys, Guid userId, CancellationToken ct)
    {
        var rows = await keys.AsNoTracking().Where(k => k.MemberId == userId && k.RevokedAt == null).OrderBy(k => k.Generation).ToListAsync(ct);
        return new WrappedKeysDto(rows.Select(k => new WrappedKeyDto(k.KeyId, k.MemberId, Base64UrlCodec.Encode(k.WrappedKey), k.Generation, k.AlgId)).ToList());
    }

    // ---------------------------------------------------------------- keys of many objects

    private sealed record KeyRow(Guid ObjectId, Guid KeyId, Guid? MemberId, byte[] WrappedKey, int Generation, string AlgId)
    {
        public WrappedKeyDto ToDto() => new(KeyId, MemberId, Base64UrlCodec.Encode(WrappedKey), Generation, AlgId);
    }

    /// <summary>The caller's live wraps of the given objects, in one query per kind.</summary>
    private async Task<List<KeyRow>> KeyRowsAsync(string entity, IReadOnlyCollection<Guid> ids, Guid userId, CancellationToken ct)
    {
        if (ids.Count == 0) return [];
        return entity switch
        {
            Project => await db.StructureKeys.AsNoTracking()
                .Where(k => k.ProjectId != null && ids.Contains(k.ProjectId.Value) && k.MemberId == userId && k.RevokedAt == null)
                .Select(k => new KeyRow(k.ProjectId!.Value, k.KeyId, k.MemberId, k.WrappedKey, k.Generation, k.AlgId)).ToListAsync(ct),
            Folder => await db.StructureKeys.AsNoTracking()
                .Where(k => k.FolderId != null && ids.Contains(k.FolderId.Value) && k.MemberId == userId && k.RevokedAt == null)
                .Select(k => new KeyRow(k.FolderId!.Value, k.KeyId, k.MemberId, k.WrappedKey, k.Generation, k.AlgId)).ToListAsync(ct),
            _ => await db.FileKeys.AsNoTracking()
                .Where(k => ids.Contains(k.FileId) && k.MemberId == userId && k.RevokedAt == null)
                .Select(k => new KeyRow(k.FileId, k.KeyId, k.MemberId, k.WrappedKey, k.Generation, k.AlgId)).ToListAsync(ct),
        };
    }

    /// <summary>
    /// The wrap each object is shown with: the caller's wrap of the object's current key generation, which opens its name
    /// and metadata. Empty when the client asked for no keys, because it has them cached.
    /// </summary>
    private async Task<Dictionary<Guid, WrappedKeyDto>> CurrentKeysAsync(string entity, IEnumerable<(Guid Id, int Generation)> objects, Guid userId,
        bool keys, CancellationToken ct)
    {
        if (!keys) return [];
        var generation = objects.ToDictionary(o => o.Id, o => o.Generation);
        return (await KeyRowsAsync(entity, generation.Keys, userId, ct))
            .Where(r => generation[r.ObjectId] == r.Generation)
            .ToDictionary(r => r.ObjectId, r => r.ToDto());
    }

    /// <summary>
    /// The caller's wrapped keys of up to <see cref="MaxKeyLookup"/> objects in one request (04 "structure"), for a client
    /// that listed without keys and misses some. Every live generation is returned. Objects the caller cannot reach
    /// are left out without a trace, like a 404 would. Objects in Trash are included, so the Trash view can show names.
    /// </summary>
    public async Task<KeyLookupDto> LookupKeysAsync(ClaimsPrincipal principal, KeyLookupRequest body, CancellationToken ct)
    {
        var userId = principal.UserId();
        var projects = (body.ProjectIds ?? []).Distinct().ToList();
        var folders = (body.FolderIds ?? []).Distinct().ToList();
        var files = (body.FileIds ?? []).Distinct().ToList();
        if (projects.Count + folders.Count + files.Count > MaxKeyLookup) throw AuthException.Validation($"At most {MaxKeyLookup} ids per lookup.");

        // Owned objects in Trash count, so the Trash view shows names; shared ones only while live (09 §9.5).
        var owned = db.Projects.Where(p => p.OwnerId == userId);
        var grants = await access.GrantsAsync(userId, ct);
        var ownedProjects = await owned.Where(p => projects.Contains(p.Id)).Select(p => p.Id).ToListAsync(ct);
        projects = ownedProjects.Concat(projects.Where(grants.ReachesProject)).Distinct().ToList();
        var folderRows = await db.Folders.AsNoTracking().Where(f => folders.Contains(f.Id)).ToListAsync(ct);
        var ownedFolderProjects = await owned.Where(p => folderRows.Select(f => f.ProjectId).Contains(p.Id)).Select(p => p.Id).ToListAsync(ct);
        folders = folderRows.Where(f => ownedFolderProjects.Contains(f.ProjectId) || (f.DeletedAt == null && grants.FolderLevel(f) != FileAccessLevel.None))
            .Select(f => f.Id).ToList();
        var fileRows = await db.Files.AsNoTracking().Where(f => files.Contains(f.Id)).ToListAsync(ct);
        var ownedFileProjects = await owned.Where(p => fileRows.Select(f => f.ProjectId).Contains(p.Id)).Select(p => p.Id).ToListAsync(ct);
        files = fileRows.Where(f => ownedFileProjects.Contains(f.ProjectId) || (f.DeletedAt == null && grants.FileLevel(f) != FileAccessLevel.None))
            .Select(f => f.Id).ToList();

        var items = new List<ObjectKeysDto>();
        foreach (var (entity, ids) in new[] { (Project, projects), (Folder, folders), (File, files) })
        {
            items.AddRange((await KeyRowsAsync(entity, ids, userId, ct))
                .GroupBy(r => r.ObjectId).OrderBy(g => g.Key)
                .Select(g => new ObjectKeysDto(entity, g.Key, g.OrderBy(r => r.Generation).Select(r => r.ToDto()).ToList())));
        }

        return new KeyLookupDto(items);
    }

    // ---------------------------------------------------------------- trash

    /// <summary>Rows deleted before this moment have left Trash: only an admin restores them (03 §3.3, DL-4).</summary>
    private DateTimeOffset TrashCutoff => time.GetUtcNow() - _trashWindow;

    /// <summary>
    /// The Trash view (03 §3.3, DL-1): what the caller deleted directly and can still restore, newest first. What went to
    /// Trash along with a folder or project is not listed on its own, it is counted on that entry and comes back with it.
    /// </summary>
    public async Task<PageDto<TrashItemDto>> ListTrashAsync(ClaimsPrincipal principal, string? cursor, int? limit, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (limit is < 1 or > MaxPageSize) throw AuthException.Validation($"limit must be 1 to {MaxPageSize}.");
        var take = limit ?? DefaultPageSize;
        var (beforeAt, beforeId) = TrashCursor(cursor);
        var cutoff = TrashCutoff;
        var owned = db.Projects.Where(p => p.OwnerId == userId);

        // Each kind contributes its newest candidates; the page is the newest of all three.
        var projects = await owned.AsNoTracking()
            .Where(p => p.DeletedAt > cutoff && (p.DeletedAt < beforeAt || (p.DeletedAt == beforeAt && p.Id < beforeId)))
            .OrderByDescending(p => p.DeletedAt).ThenByDescending(p => p.Id).Take(take + 1).ToListAsync(ct);
        var folders = await db.Folders.AsNoTracking()
            .Where(f => f.DeletedAt > cutoff && f.DeletedRootId == null && owned.Any(p => p.Id == f.ProjectId)
                        && (f.DeletedAt < beforeAt || (f.DeletedAt == beforeAt && f.Id < beforeId)))
            .OrderByDescending(f => f.DeletedAt).ThenByDescending(f => f.Id).Take(take + 1).ToListAsync(ct);
        var files = await db.Files.AsNoTracking()
            .Where(f => f.DeletedAt > cutoff && f.DeletedRootId == null && owned.Any(p => p.Id == f.ProjectId)
                        && (f.DeletedAt < beforeAt || (f.DeletedAt == beforeAt && f.Id < beforeId)))
            .OrderByDescending(f => f.DeletedAt).ThenByDescending(f => f.Id).Take(take + 1).ToListAsync(ct);

        var merged = projects.Select(p => (At: p.DeletedAt!.Value, p.Id, Row: (object)p))
            .Concat(folders.Select(f => (At: f.DeletedAt!.Value, f.Id, Row: (object)f)))
            .Concat(files.Select(f => (At: f.DeletedAt!.Value, f.Id, Row: (object)f)))
            .OrderByDescending(e => e.At).ThenByDescending(e => e.Id).ToList();
        var page = merged.Take(take).ToList();

        var projectMap = await ProjectMapAsync(page.Select(e => e.Row).OfType<ProjectEntity>(), userId, keys, ct);
        var folderMap = await FolderMapAsync(page.Select(e => e.Row).OfType<FolderEntity>(), userId, keys, ct);
        var fileMap = await FileMapAsync(page.Select(e => e.Row).OfType<FileEntity>(), userId, keys, ct);
        var roots = page.Where(e => e.Row is not FileEntity).Select(e => e.Id).ToList();
        var folderCounts = await db.Folders.Where(f => f.DeletedRootId != null && roots.Contains(f.DeletedRootId.Value))
            .GroupBy(f => f.DeletedRootId!.Value).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(g => g.Key, g => g.Count, ct);
        var fileCounts = await db.Files.Where(f => f.DeletedRootId != null && roots.Contains(f.DeletedRootId.Value))
            .GroupBy(f => f.DeletedRootId!.Value).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(g => g.Key, g => g.Count, ct);

        var items = page.Select(e => new TrashItemDto(
            e.Row switch { ProjectEntity => Project, FolderEntity => Folder, _ => File },
            e.At, e.At + _trashWindow, folderCounts.GetValueOrDefault(e.Id), fileCounts.GetValueOrDefault(e.Id),
            e.Row is ProjectEntity p ? projectMap(p) : null, e.Row is FolderEntity fo ? folderMap(fo) : null, e.Row is FileEntity fi ? fileMap(fi) : null)).ToList();
        string? next = null;
        if (merged.Count > take)
        {
            var last = page[^1];
            var bytes = new byte[24];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, last.At.UtcTicks);
            last.Id.TryWriteBytes(bytes.AsSpan(8), bigEndian: true, out _);
            next = Base64UrlCodec.Encode(bytes);
        }

        return new PageDto<TrashItemDto>(items, next);
    }

    private static (DateTimeOffset At, Guid Id) TrashCursor(string? cursor)
    {
        if (cursor is null) return (DateTimeOffset.MaxValue, Guid.Empty);
        if (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != 24) throw AuthException.Validation("cursor is malformed.");
        var ticks = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(bytes);
        if (ticks < 0 || ticks > DateTimeOffset.MaxValue.UtcTicks) throw AuthException.Validation("cursor is malformed.");
        return (new DateTimeOffset(ticks, TimeSpan.Zero), new Guid(bytes.AsSpan(8), bigEndian: true));
    }

    /// <summary>Brings a project back from Trash, with everything its delete took along. Restoring a live project changes nothing.</summary>
    public async Task<ProjectDto> RestoreProjectAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var cutoff = TrashCutoff;
        var project = await db.Projects.SingleOrDefaultAsync(p => p.Id == id && p.OwnerId == userId && (p.DeletedAt == null || p.DeletedAt > cutoff), ct)
                      ?? throw AuthException.NotFound();
        if (project.DeletedAt is not null)
        {
            project.DeletedAt = null;
            project.UpdatedAt = time.GetUtcNow();
            await feed.ProjectAsync(project, ct);
            var (folders, files) = await RestoreWithAsync(id, ct);
            audit.Add("project.restore", userId, request, targetType: Project, targetId: id, detail: new { folders, files });
            await db.SaveChangesAsync(ct);
        }

        await tx.CommitAsync(ct);
        return await ToDtoAsync(project, userId, keys: true, ct);
    }

    /// <summary>Brings a folder back from Trash with its subtree. What it lies in must be live (04 "structure").</summary>
    public async Task<FolderDto> RestoreFolderAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var cutoff = TrashCutoff;
        var folder = await db.Folders.SingleOrDefaultAsync(f => f.Id == id && (f.DeletedAt == null || f.DeletedAt > cutoff)
                         && db.Projects.Any(p => p.Id == f.ProjectId && p.OwnerId == userId), ct)
                     ?? throw AuthException.NotFound();
        if (folder.DeletedAt is not null)
        {
            await RequireLiveContainerAsync(folder.ProjectId, folder.ParentFolderId, ct);
            folder.DeletedAt = null;
            folder.DeletedRootId = null;
            folder.UpdatedAt = time.GetUtcNow();
            // The folder before its subtree, so a client never sees a row whose parent it does not know yet.
            await feed.FolderAsync(folder, ct);
            var (folders, files) = await RestoreWithAsync(id, ct);
            audit.Add("folder.restore", userId, request, targetType: Folder, targetId: id, detail: new { folders = folders + 1, files });
            await db.SaveChangesAsync(ct);
        }

        await tx.CommitAsync(ct);
        return await ToDtoAsync(folder, userId, keys: true, ct);
    }

    public async Task<FileDto> RestoreFileAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = await WriterAsync(principal, ct);
        await using var tx = await UnitOfWork.BeginAsync(db, ct);
        var cutoff = TrashCutoff;
        var file = await db.Files.SingleOrDefaultAsync(f => f.Id == id && (f.DeletedAt == null || f.DeletedAt > cutoff)
                       && db.Projects.Any(p => p.Id == f.ProjectId && p.OwnerId == userId), ct)
                   ?? throw AuthException.NotFound();
        if (file.DeletedAt is not null)
        {
            await RequireLiveContainerAsync(file.ProjectId, file.FolderId, ct);
            file.DeletedAt = null;
            file.DeletedRootId = null;
            file.UpdatedAt = time.GetUtcNow();
            await feed.FileAsync(file, ct);
            audit.Add("file.restore", userId, request, targetType: File, targetId: id);
            await db.SaveChangesAsync(ct);
        }

        await tx.CommitAsync(ct);
        return await ToDtoAsync(file, userId, keys: true, ct);
    }

    /// <summary>
    /// Nothing is restored into Trash: the folder and the project it lies in must be live, and the caller restores those
    /// first. Moving it to the project root instead was rejected, because it would reappear where nobody put it.
    /// </summary>
    private async Task RequireLiveContainerAsync(Guid projectId, Guid? folderId, CancellationToken ct)
    {
        if (!await db.Projects.AnyAsync(p => p.Id == projectId && p.DeletedAt == null, ct))
            throw AuthException.Conflict("The project is in Trash; restore it first.");
        if (folderId is { } fid && !await db.Folders.AnyAsync(f => f.Id == fid && f.DeletedAt == null, ct))
            throw AuthException.Conflict("The containing folder is in Trash; restore it first.");
    }

    /// <summary>
    /// Restores what the delete of <paramref name="rootId"/> took along. Things deleted on their own before stay in Trash.
    /// Every row that comes back is announced as a full structure upsert (06 §6.3.2).
    /// </summary>
    private async Task<(int Folders, int Files)> RestoreWithAsync(Guid rootId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var folders = await db.Folders.Where(f => f.DeletedRootId == rootId).ToListAsync(ct);
        var files = await db.Files.Where(f => f.DeletedRootId == rootId).ToListAsync(ct);
        foreach (var f in folders)
        {
            f.DeletedAt = null;
            f.DeletedRootId = null;
            f.UpdatedAt = now;
            await feed.FolderAsync(f, ct);
        }

        foreach (var f in files)
        {
            f.DeletedAt = null;
            f.DeletedRootId = null;
            f.UpdatedAt = now;
            await feed.FileAsync(f, ct);
        }

        return (folders.Count, files.Count);
    }

    // ---------------------------------------------------------------- mapping

    private static string? Encode(byte[]? bytes) => bytes is null ? null : Base64UrlCodec.Encode(bytes);

    private async Task<Func<ProjectEntity, ProjectDto>> ProjectMapAsync(IEnumerable<ProjectEntity> rows, Guid userId, bool keys, CancellationToken ct)
    {
        var map = await CurrentKeysAsync(Project, rows.Select(r => (r.Id, r.KeyGeneration)), userId, keys, ct);
        return p => ToDto(p, map.GetValueOrDefault(p.Id));
    }

    private async Task<Func<FolderEntity, FolderDto>> FolderMapAsync(IEnumerable<FolderEntity> rows, Guid userId, bool keys, CancellationToken ct)
    {
        var map = await CurrentKeysAsync(Folder, rows.Select(r => (r.Id, r.KeyGeneration)), userId, keys, ct);
        return f => ToDto(f, map.GetValueOrDefault(f.Id));
    }

    private async Task<Func<FileEntity, FileDto>> FileMapAsync(IEnumerable<FileEntity> rows, Guid userId, bool keys, CancellationToken ct)
    {
        var list = rows.ToList();
        var map = await CurrentKeysAsync(File, list.Select(r => (r.Id, r.KeyGeneration)), userId, keys, ct);
        // The API shows the head as its seq; the row holds the version id (02 §2.2.5).
        var heads = list.Where(r => r.CurrentVersionId != null).Select(r => r.CurrentVersionId!.Value).ToList();
        var seqs = heads.Count == 0
            ? []
            : await db.FileVersions.Where(v => heads.Contains(v.Id)).ToDictionaryAsync(v => v.Id, v => v.Seq, ct);
        var pending = await RotationPendingAsync(list, userId, ct);
        return f => ToDto(f, map.GetValueOrDefault(f.Id), f.CurrentVersionId is { } head ? seqs[head] : null, pending.Contains(f.Id));
    }

    /// <summary>
    /// The files whose pending key rotation (09 §9.6) the caller may perform and so is told about: its own projects' files
    /// and files it reaches with write access. A reader cannot rotate and learns nothing about revocations.
    /// </summary>
    private async Task<HashSet<Guid>> RotationPendingAsync(List<FileEntity> rows, Guid userId, CancellationToken ct)
    {
        var marked = rows.Where(r => r.RotationPendingAt is not null).ToList();
        if (marked.Count == 0) return [];
        var projectIds = marked.Select(r => r.ProjectId).Distinct().ToList();
        var owned = (await db.Projects.AsNoTracking().Where(p => projectIds.Contains(p.Id) && p.OwnerId == userId).Select(p => p.Id).ToListAsync(ct)).ToHashSet();
        var grants = marked.All(r => owned.Contains(r.ProjectId)) ? null : await access.GrantsAsync(userId, ct);
        return marked.Where(r => owned.Contains(r.ProjectId) || grants!.FileLevel(r) == FileAccessLevel.Write).Select(r => r.Id).ToHashSet();
    }

    private async Task<ProjectDto> ToDtoAsync(ProjectEntity p, Guid userId, bool keys, CancellationToken ct) => (await ProjectMapAsync([p], userId, keys, ct))(p);

    private async Task<FolderDto> ToDtoAsync(FolderEntity f, Guid userId, bool keys, CancellationToken ct) => (await FolderMapAsync([f], userId, keys, ct))(f);

    private async Task<FileDto> ToDtoAsync(FileEntity f, Guid userId, bool keys, CancellationToken ct) => (await FileMapAsync([f], userId, keys, ct))(f);

    private static ProjectDto ToDto(ProjectEntity p, WrappedKeyDto? key) =>
        new(p.Id, p.OwnerId, Base64UrlCodec.Encode(p.NameEnc), Encode(p.MetadataEnc), p.SyncPolicy, p.KeyGeneration, p.CreatedAt, p.UpdatedAt, p.DeletedAt, key);

    private static FolderDto ToDto(FolderEntity f, WrappedKeyDto? key) =>
        new(f.Id, f.ProjectId, f.ParentFolderId, Base64UrlCodec.Encode(f.NameEnc), Encode(f.MetadataEnc), f.SyncPolicy, f.KeyGeneration,
            f.CreatedAt, f.UpdatedAt, f.DeletedAt, key);

    private static FileDto ToDto(FileEntity f, WrappedKeyDto? key, long? currentVersionSeq = null, bool rotationPending = false) =>
        new(f.Id, f.ProjectId, f.FolderId, f.OwnerId, Base64UrlCodec.Encode(f.NameEnc), Encode(f.MetadataEnc), f.ContentType, f.SyncPolicy,
            currentVersionSeq, f.CrdtDocId, f.KeyGeneration, f.CreatedAt, f.UpdatedAt, f.DeletedAt, key, rotationPending);
}
