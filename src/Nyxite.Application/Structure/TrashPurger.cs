using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Content;
using Nyxite.Application.Maintenance;
using Nyxite.Application.Sync;
using Nyxite.BlobStore;
using Nyxite.Domain.Identity;
using Nyxite.Domain.Structure;
using Nyxite.Persistence;

namespace Nyxite.Application.Structure;

/// <summary>
/// The last stage of the deletion lifecycle (03 §3.3, DL-2, DL-5): an object deleted longer ago than Trash window plus
/// grace window is hard-deleted together with everything its delete took along, its wrapped keys, its whole version
/// history, its update log and then its ciphertext. Every delete runs the full timeline, there is no earlier purge.
/// </summary>
/// <remarks>
/// Each deleted root is purged in its own transaction, so one failure does not hold back the rest. What a delete took
/// along is found through <c>deleted_root_id</c>, the same mark a restore uses. An object deleted on its own earlier
/// is an older root and is purged before the folder around it, because roots are purged oldest first.
/// </remarks>
public sealed class TrashPurger(
    NyxiteDbContext db, BlobCollector collector, AuditWriter audit, TimeProvider time, ChangeFeed feed, IOptions<RetentionOptions> options,
    ILogger<TrashPurger> logger)
{
    private sealed record Root(string Kind, Guid Id, DateTimeOffset DeletedAt);

    /// <summary>Purges every root past the timeline. Returns how many roots it purged.</summary>
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var cutoff = Cutoff;
        var roots = await db.Database.SqlQuery<Root>($"""
            SELECT 'project' AS "Kind", id AS "Id", deleted_at AS "DeletedAt" FROM projects WHERE deleted_at < {cutoff}
            UNION ALL
            SELECT 'folder', id, deleted_at FROM folders WHERE deleted_at < {cutoff} AND deleted_root_id IS NULL
            UNION ALL
            SELECT 'file', id, deleted_at FROM files WHERE deleted_at < {cutoff} AND deleted_root_id IS NULL
            ORDER BY "DeletedAt", "Id"
            LIMIT 1000
            """).ToListAsync(ct);

        var purged = 0;
        foreach (var root in roots)
        {
            try
            {
                if (await PurgeAsync(root, cutoff, ct)) purged++;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                db.ChangeTracker.Clear();
                logger.LogWarning(e, "Purging {Kind} {Id} failed.", root.Kind, root.Id);
            }
        }

        if (purged > 0) logger.LogInformation("Purged {Count} deleted objects past their grace window.", purged);
        return purged;
    }

    private const string Folder = "folder";
    private const string File = "file";

    /// <summary>
    /// Purges the stored content of files that were switched to <c>excluded</c> longer ago than Trash window plus grace
    /// window (06 §6.2): every version with its ciphertext and the update log. The file itself stays, it only has no
    /// server copy any more. Switching it back starts a new initial upload from the device that holds it.
    /// </summary>
    public async Task<int> PurgeExcludedContentAsync(CancellationToken ct)
    {
        var cutoff = Cutoff;
        var candidates = await db.Files.Where(f => f.SyncPolicy == SyncPolicies.Excluded && f.ExcludedAt < cutoff)
            .OrderBy(f => f.ExcludedAt).Select(f => f.Id).Take(1000).ToListAsync(ct);
        var purged = 0;
        foreach (var fileId in candidates)
        {
            try
            {
                if (await PurgeContentAsync(fileId, cutoff, ct)) purged++;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                db.ChangeTracker.Clear();
                logger.LogWarning(e, "Purging the content of excluded file {Id} failed.", fileId);
            }
        }

        if (purged > 0) logger.LogInformation("Purged the stored content of {Count} excluded files.", purged);
        return purged;
    }

    private async Task<bool> PurgeContentAsync(Guid fileId, DateTimeOffset cutoff, CancellationToken ct)
    {
        List<string> blobRefs;
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            // Locked and checked again: the owner may have switched it back in the meantime.
            var still = await db.Database.SqlQuery<Guid>(
                $"SELECT id AS \"Value\" FROM files WHERE id = {fileId} AND sync_policy = 'excluded' AND excluded_at < {cutoff} FOR UPDATE SKIP LOCKED")
                .ToListAsync(ct);
            if (still.Count == 0) return false;

            blobRefs = await db.FileVersions.Where(v => v.FileId == fileId).Select(v => v.BlobRef).Distinct().ToListAsync(ct);
            await db.Database.ExecuteSqlAsync(
                $"UPDATE files SET current_version_id = NULL, pending_restore_seq = NULL, excluded_at = NULL WHERE id = {fileId}", ct);
            var updates = await db.Database.ExecuteSqlAsync(
                $"DELETE FROM crdt_updates WHERE crdt_doc_id = (SELECT crdt_doc_id FROM files WHERE id = {fileId})", ct);
            var versions = await db.Database.ExecuteSqlAsync($"DELETE FROM file_versions WHERE file_id = {fileId}", ct);
            audit.Add("content.excluded_purged", null, RequestInfo.None, ActorKind.System, targetType: File, targetId: fileId,
                detail: new { versions, updates });
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        foreach (var hex in blobRefs)
        {
            if (BlobAddress.TryParseHex(hex, out var address)) await collector.CollectAsync(address, ct);
        }

        return true;
    }

    private DateTimeOffset Cutoff =>
        time.GetUtcNow() - TimeSpan.FromDays(options.Value.TrashWindowDays) - TimeSpan.FromDays(options.Value.GraceWindowDays);

    private async Task<bool> PurgeAsync(Root root, DateTimeOffset cutoff, CancellationToken ct)
    {
        List<string> blobRefs;
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            // Locked and checked again: an admin restore during the grace window may have won the race.
            var still = root.Kind switch
            {
                "project" => await db.Database.SqlQuery<Guid>($"SELECT id AS \"Value\" FROM projects WHERE id = {root.Id} AND deleted_at < {cutoff} FOR UPDATE SKIP LOCKED").ToListAsync(ct),
                "folder" => await db.Database.SqlQuery<Guid>($"SELECT id AS \"Value\" FROM folders WHERE id = {root.Id} AND deleted_at < {cutoff} FOR UPDATE SKIP LOCKED").ToListAsync(ct),
                _ => await db.Database.SqlQuery<Guid>($"SELECT id AS \"Value\" FROM files WHERE id = {root.Id} AND deleted_at < {cutoff} FOR UPDATE SKIP LOCKED").ToListAsync(ct),
            };
            if (still.Count == 0) return false;

            var fileIds = root.Kind switch
            {
                "project" => await db.Files.Where(f => f.ProjectId == root.Id).Select(f => f.Id).ToArrayAsync(ct),
                "folder" => await db.Files.Where(f => f.DeletedRootId == root.Id).Select(f => f.Id).ToArrayAsync(ct),
                _ => [root.Id],
            };
            var folderIds = root.Kind switch
            {
                "project" => await db.Folders.Where(f => f.ProjectId == root.Id).Select(f => f.Id).ToArrayAsync(ct),
                "folder" => await db.Folders.Where(f => f.Id == root.Id || f.DeletedRootId == root.Id).Select(f => f.Id).ToArrayAsync(ct),
                _ => [],
            };
            var projectId = root.Kind switch
            {
                "project" => root.Id,
                "folder" => await db.Folders.Where(f => f.Id == root.Id).Select(f => f.ProjectId).SingleAsync(ct),
                _ => await db.Files.Where(f => f.Id == root.Id).Select(f => f.ProjectId).SingleAsync(ct),
            };
            var owner = root.Kind switch
            {
                "project" => await db.Projects.Where(p => p.Id == root.Id).Select(p => p.OwnerId).SingleAsync(ct),
                "folder" => await db.Projects.Where(p => db.Folders.Any(f => f.Id == root.Id && f.ProjectId == p.Id)).Select(p => p.OwnerId).SingleAsync(ct),
                _ => await db.Files.Where(f => f.Id == root.Id).Select(f => f.OwnerId).SingleAsync(ct),
            };

            blobRefs = await db.FileVersions.Where(v => fileIds.Contains(v.FileId)).Select(v => v.BlobRef).Distinct().ToListAsync(ct);
            // The head pointer and the version rows point at each other, so the pointer goes first.
            await db.Database.ExecuteSqlAsync($"UPDATE files SET current_version_id = NULL WHERE id = ANY({fileIds})", ct);
            var updates = await db.Database.ExecuteSqlAsync(
                $"DELETE FROM crdt_updates WHERE crdt_doc_id IN (SELECT crdt_doc_id FROM files WHERE id = ANY({fileIds}) AND crdt_doc_id IS NOT NULL)", ct);
            var versions = await db.Database.ExecuteSqlAsync($"DELETE FROM file_versions WHERE file_id = ANY({fileIds})", ct);
            await db.Database.ExecuteSqlAsync($"DELETE FROM file_keys WHERE file_id = ANY({fileIds})", ct);
            await db.Database.ExecuteSqlAsync($"DELETE FROM files WHERE id = ANY({fileIds})", ct);
            await db.Database.ExecuteSqlAsync($"DELETE FROM structure_keys WHERE folder_id = ANY({folderIds})", ct);
            await db.Database.ExecuteSqlAsync($"DELETE FROM folders WHERE id = ANY({folderIds})", ct);
            if (root.Kind == "project")
            {
                // Nobody can read the feed of a project that is gone, and its rows point at the project.
                await db.Database.ExecuteSqlAsync($"DELETE FROM change_log WHERE project_id = {root.Id}", ct);
                await db.Database.ExecuteSqlAsync($"DELETE FROM structure_keys WHERE project_id = {root.Id}", ct);
                await db.Database.ExecuteSqlAsync($"DELETE FROM projects WHERE id = {root.Id}", ct);
            }

            else
            {
                // The project lives on, so its devices learn that these rows are gone for good and drop their copies.
                var now = time.GetUtcNow();
                foreach (var id in folderIds) await feed.DeleteAsync(projectId, Folder, id, now, ChangeFeed.Purged, ct);
                foreach (var id in fileIds) await feed.DeleteAsync(projectId, File, id, now, ChangeFeed.Purged, ct);
            }

            audit.Add("trash.purged", null, RequestInfo.None, ActorKind.System, targetType: root.Kind, targetId: root.Id,
                detail: new { owner, deletedAt = root.DeletedAt, folders = folderIds.Length, files = fileIds.Length, versions, updates });
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        // After the commit: the rows are gone, so nothing references these blobs any more. A blob address is scoped to
        // its file, so no other file can share one. A failure here leaves the blob to the sweep.
        foreach (var hex in blobRefs)
        {
            if (BlobAddress.TryParseHex(hex, out var address)) await collector.CollectAsync(address, ct);
        }

        return true;
    }
}
