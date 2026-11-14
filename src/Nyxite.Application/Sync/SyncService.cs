using System.Buffers.Binary;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Keys;
using Nyxite.Application.Maintenance;
using Nyxite.Application.Structure;
using Nyxite.Contracts.Structure;
using Nyxite.Contracts.Sync;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Domain.Structure;
using Nyxite.Persistence;

namespace Nyxite.Application.Sync;

/// <summary>
/// Reconciliation over ciphertext and structure (server 06 §6.3): a per-project manifest that (re)establishes state,
/// and a cursor-based delta that carries a device's offline structure edits up and the project's changes down. Both
/// are opaque: ids, sequence numbers, hashes and sealed frames. Search is not here and nowhere on the server, because
/// clients build their index from these manifests and the ciphertext they decrypt (11).
/// </summary>
public sealed class SyncService(
    NyxiteDbContext db, StructureService structure, ChangeFeed feed, IdempotencyStore idempotency, DeviceGuard guard, TimeProvider time,
    IOptions<RetentionOptions> retention)
{
    public const string ChangesEndpoint = "POST /sync/changes";

    public const int DefaultLimit = 500;
    public const int MaxLimit = 1000;
    public const int MaxLocalChanges = 200;

    private const int CursorSize = 16;

    // ---------------------------------------------------------------- manifest

    /// <summary>
    /// One page of the project's files, Trash included, in id order. Every page carries the delta cursor of the moment it
    /// was produced; the client keeps the one from page 1 and continues from it after the last page, so changes made
    /// while it paged arrive again by delta, where every change is an idempotent upsert.
    /// </summary>
    public async Task<ManifestDto> ManifestAsync(ClaimsPrincipal principal, Guid projectId, string? cursor, int? limit, bool keys, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (limit is < 1 or > MaxLimit) throw AuthException.Validation($"limit must be 1 to {MaxLimit}.");
        var take = limit ?? DefaultLimit;
        var after = Guid.Empty;
        if (cursor is not null)
        {
            if (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != 16) throw AuthException.Validation("cursor is malformed.");
            after = new Guid(bytes, bigEndian: true);
        }

        await RequireProjectAsync(userId, projectId, ct);
        var syncCursor = await HeadCursorAsync(projectId, ct);

        var rows = await db.Files.AsNoTracking()
            .Where(f => f.ProjectId == projectId && f.Id > after)
            .OrderBy(f => f.Id)
            .Select(f => new { File = f, Head = db.FileVersions.FirstOrDefault(v => v.Id == f.CurrentVersionId) })
            .Take(take + 1).ToListAsync(ct);
        var page = rows.Take(take).ToList();
        var ids = page.Select(r => r.File.Id).ToList();
        var wraps = await db.FileKeys.AsNoTracking().Where(k => ids.Contains(k.FileId) && k.RevokedAt == null).ToListAsync(ct);

        var items = page.Select(r =>
        {
            var f = r.File;
            var current = wraps.Where(k => k.FileId == f.Id && k.Generation == f.KeyGeneration).ToList();
            var mine = current.FirstOrDefault(k => k.MemberId == userId);
            var wrapped = keys && mine is not null
                ? new WrappedKeyDto(mine.KeyId, mine.MemberId, Base64UrlCodec.Encode(mine.WrappedKey), mine.Generation, mine.AlgId)
                : null;
            return new ManifestItemDto(
                f.Id, f.FolderId, f.ContentType, f.SyncPolicy, r.Head?.Seq, r.Head is null ? null : Base64UrlCodec.Encode(r.Head.ContentHash),
                r.Head?.Layout ?? "single", r.Head?.SizeCipher ?? 0, (mine ?? current.FirstOrDefault())?.KeyId ?? Guid.Empty, f.KeyGeneration,
                f.CrdtDocId is null ? null : f.CrdtHeadSeq, f.CrdtDocId, wrapped, f.UpdatedAt, f.DeletedAt);
        }).ToList();
        var next = rows.Count > take ? Base64UrlCodec.Encode(page[^1].File.Id.ToByteArray(bigEndian: true)) : null;
        return new ManifestDto(projectId, syncCursor, items, next);
    }

    // ---------------------------------------------------------------- delta

    /// <summary>
    /// Applies the device's structure edits in order, each in its own transaction, then returns the project's changes
    /// after <see cref="ChangesRequest.Since"/>. The client's own edits come back in the feed too, which is harmless
    /// because a structure change is a full-row upsert.
    /// </summary>
    public async Task<ChangesDto> ChangesAsync(ClaimsPrincipal principal, ChangesRequest body, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (body.Limit is < 1 or > MaxLimit) throw AuthException.Validation($"limit must be 1 to {MaxLimit}.");
        var take = body.Limit ?? DefaultLimit;
        var local = body.LocalChanges ?? [];
        if (local.Count > MaxLocalChanges) throw AuthException.Validation($"At most {MaxLocalChanges} localChanges per request.");
        var since = ReadCursor(body.Since);
        await RequireProjectAsync(userId, body.ProjectId, ct);

        var results = new List<LocalChangeResultDto>(local.Count);
        if (local.Count > 0)
        {
            await RequireWriterAsync(principal, userId, ct);
            foreach (var change in local) results.Add(await ApplyAsync(principal, userId, body.ProjectId, change, request, ct));
        }

        var (rows, position, issuedAt) = await ReadFeedAsync(body.ProjectId, since, take, ct);
        var changes = await ToChangesAsync(rows.Take(take).ToList(), userId, body.Keys ?? true, ct);
        return new ChangesDto(results, changes, WriteCursor(position, issuedAt), rows.Count > take);
    }

    /// <summary>
    /// Reads the feed under the project's reader lock (<see cref="ChangeFeed"/>), so no write with a lower number can
    /// commit after the cursor moved past it. The position is the last row returned, or the old one when nothing is new.
    /// The moment is taken while the lock is held, so every row after the position carries a later <c>at</c>.
    /// </summary>
    private async Task<(List<Persistence.Entities.ChangeLogEntity> Rows, long Position, DateTimeOffset IssuedAt)> ReadFeedAsync(
        Guid projectId, long since, int take, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await feed.ReaderLockAsync(projectId, ct);
        var rows = await db.ChangeLog.AsNoTracking().Where(c => c.ProjectId == projectId && c.Seq > since)
            .OrderBy(c => c.Seq).Take(take + 1).ToListAsync(ct);
        var issuedAt = time.GetUtcNow();
        await tx.CommitAsync(ct);
        return (rows, rows.Count == 0 ? since : rows[Math.Min(rows.Count, take) - 1].Seq, issuedAt);
    }

    /// <summary>The delta cursor at the project's newest change, taken under the reader lock like a delta read.</summary>
    private async Task<string> HeadCursorAsync(Guid projectId, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await feed.ReaderLockAsync(projectId, ct);
        var head = await db.ChangeLog.Where(c => c.ProjectId == projectId).MaxAsync(c => (long?)c.Seq, ct) ?? 0;
        var issuedAt = time.GetUtcNow();
        await tx.CommitAsync(ct);
        return WriteCursor(head, issuedAt);
    }

    private async Task<List<ServerChangeDto>> ToChangesAsync(List<Persistence.Entities.ChangeLogEntity> rows, Guid userId, bool keys, CancellationToken ct)
    {
        var changes = new List<ServerChangeDto>(rows.Count);
        foreach (var row in rows)
        {
            var reference = JsonNode.Parse(row.Ref)!.AsObject();
            // Consecutive updates to one file are one change: the client fetches the log range once.
            if (row.Kind == ChangeFeed.Crdt && changes.Count > 0 && changes[^1] is { Kind: ChangeFeed.Crdt } last
                && last.Ref["fileId"]!.GetValue<Guid>() == reference["fileId"]!.GetValue<Guid>())
            {
                reference["fromSeq"] = last.Ref["fromSeq"]!.GetValue<long>();
                changes[^1] = new ServerChangeDto(row.Seq, row.At, row.Kind, reference);
                continue;
            }

            changes.Add(new ServerChangeDto(row.Seq, row.At, row.Kind, reference));
        }

        if (keys) await AddWrappedKeysAsync(changes.Where(c => c.Kind == ChangeFeed.Structure).ToList(), userId, ct);
        return changes;
    }

    /// <summary>
    /// Adds the caller's wrap of the key the change's name is sealed with. That is the key of the change's own moment,
    /// not necessarily the current one, so an old rename still opens after a later key rotation.
    /// </summary>
    private async Task AddWrappedKeysAsync(List<ServerChangeDto> changes, Guid userId, CancellationToken ct)
    {
        if (changes.Count == 0) return;
        var wanted = changes.Select(c => (Entity: c.Ref["entity"]!.GetValue<string>(), Id: c.Ref["id"]!.GetValue<Guid>(),
            KeyId: NyxcFrame.TryParseHeader(Base64UrlCodec.Decode(c.Ref["nameEnc"]!.GetValue<string>()), out var h) ? h.KeyId : Guid.Empty)).ToList();
        var structureIds = wanted.Where(w => w.Entity != StructureService.File).Select(w => w.Id).Distinct().ToList();
        var fileIds = wanted.Where(w => w.Entity == StructureService.File).Select(w => w.Id).Distinct().ToList();

        var found = new Dictionary<(Guid Id, Guid KeyId), WrappedKeyDto>();
        foreach (var k in await db.StructureKeys.AsNoTracking()
                     .Where(k => ((k.ProjectId != null && structureIds.Contains(k.ProjectId.Value)) || (k.FolderId != null && structureIds.Contains(k.FolderId.Value)))
                                 && k.MemberId == userId && k.RevokedAt == null).ToListAsync(ct))
            found[((k.ProjectId ?? k.FolderId)!.Value, k.KeyId)] = new WrappedKeyDto(k.KeyId, k.MemberId, Base64UrlCodec.Encode(k.WrappedKey), k.Generation, k.AlgId);
        foreach (var k in await db.FileKeys.AsNoTracking()
                     .Where(k => fileIds.Contains(k.FileId) && k.MemberId == userId && k.RevokedAt == null).ToListAsync(ct))
            found[(k.FileId, k.KeyId)] = new WrappedKeyDto(k.KeyId, k.MemberId, Base64UrlCodec.Encode(k.WrappedKey), k.Generation, k.AlgId);

        for (var i = 0; i < changes.Count; i++)
        {
            if (found.TryGetValue((wanted[i].Id, wanted[i].KeyId), out var wrap))
                changes[i].Ref["wrappedKey"] = JsonSerializer.SerializeToNode(wrap, JsonSerializerOptions.Web);
        }
    }

    // ---------------------------------------------------------------- local changes

    /// <summary>
    /// One outbox item, applied through the same code path as the matching REST call, in its own transaction together
    /// with its idempotency record, so a replayed <c>clientChangeId</c> returns the stored result and is never applied
    /// twice. A rejection is stored as well: the replay of an item answers what the first attempt answered.
    /// </summary>
    private async Task<LocalChangeResultDto> ApplyAsync(ClaimsPrincipal principal, Guid userId, Guid projectId, LocalChange change,
        RequestInfo request, CancellationToken ct)
    {
        var key = change.ClientChangeId.ToString();
        var hash = IdempotencyStore.Hash(change);
        try
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            if (await idempotency.FindAsync(userId, ChangesEndpoint, key, hash, ct) is { } replay)
                return JsonSerializer.Deserialize<LocalChangeResultDto>(replay.Json, JsonSerializerOptions.Web)!;

            await DispatchAsync(principal, projectId, change, request, ct);
            var applied = new LocalChangeResultDto(change.ClientChangeId, "applied", null);
            idempotency.Add(userId, ChangesEndpoint, key, hash, 200, applied);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            return applied;
        }
        catch (AuthException e)
        {
            db.ChangeTracker.Clear();
            var rejected = new LocalChangeResultDto(change.ClientChangeId, "rejected", e.Code);
            // The same id with a different item is the client's mistake, not an outcome of this item.
            if (e.Code == "idempotency_conflict") return rejected;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            idempotency.Add(userId, ChangesEndpoint, key, hash, 200, rejected);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            return rejected;
        }
    }

    private async Task DispatchAsync(ClaimsPrincipal principal, Guid projectId, LocalChange change, RequestInfo request, CancellationToken ct)
    {
        var r = change.Ref ?? throw AuthException.Validation("ref is required.");
        var entity = r.Entity is StructureService.Project or StructureService.Folder or StructureService.File
            ? r.Entity
            : throw AuthException.Validation("ref.entity must be project, folder or file.");

        switch (change.Kind, r.Op)
        {
            case ("delete", _):
                await RequireInProjectAsync(entity, r.Id, projectId, ct);
                if (entity == StructureService.Project) await structure.DeleteProjectAsync(principal, r.Id, request, ct);
                else if (entity == StructureService.Folder) await structure.DeleteFolderAsync(principal, r.Id, request, ct);
                else await structure.DeleteFileAsync(principal, r.Id, request, ct);
                break;

            case ("structure", "create"):
                // The batch is scoped to a project that exists, so a new project goes through POST /projects.
                if (entity == StructureService.Project) throw AuthException.Validation("A project is created with POST /projects, not in a sync batch.");
                if (entity == StructureService.Folder)
                    await structure.CreateFolderAsync(principal, new CreateFolderRequest(
                        r.Id, projectId, r.ParentFolderId.Value, r.NameEnc, r.MetadataEnc.Value, r.SyncPolicy.Value, r.OwnerWrappedKey), ct);
                else
                    await structure.CreateFileAsync(principal, new CreateFileRequest(
                        r.Id, projectId, r.ParentFolderId.Value, r.NameEnc, r.ContentType, r.SyncPolicy.Value, r.MetadataEnc.Value, r.CrdtDocId,
                        r.OwnerWrappedKey), ct);
                break;

            case ("structure", "update"):
                await RequireInProjectAsync(entity, r.Id, projectId, ct);
                if (entity == StructureService.Project)
                    await structure.UpdateProjectAsync(principal, r.Id, new UpdateProjectRequest(r.NameEnc, r.MetadataEnc, r.SyncPolicy.Value), ct);
                else if (entity == StructureService.Folder)
                    await structure.UpdateFolderAsync(principal, r.Id, new UpdateFolderRequest(r.NameEnc, r.ParentFolderId, r.MetadataEnc, r.SyncPolicy), ct);
                else
                    await structure.UpdateFileAsync(principal, r.Id, new UpdateFileRequest(r.NameEnc, r.SyncPolicy.Value, r.ParentFolderId, r.MetadataEnc), ct);
                break;

            default:
                throw AuthException.Validation("kind must be structure (op create or update) or delete.");
        }
    }

    /// <summary>The object must belong to the batch's project; one outside it answers like one that does not exist.</summary>
    private async Task RequireInProjectAsync(string entity, Guid id, Guid projectId, CancellationToken ct)
    {
        var inProject = entity switch
        {
            StructureService.Project => id == projectId,
            StructureService.Folder => await db.Folders.AnyAsync(f => f.Id == id && f.ProjectId == projectId, ct),
            _ => await db.Files.AnyAsync(f => f.Id == id && f.ProjectId == projectId, ct),
        };
        if (!inProject) throw AuthException.NotFound();
    }

    // ---------------------------------------------------------------- reach and cursors

    /// <summary>A live project the caller can reach. Until shares exist (Phase 2.2) that is a project they own.</summary>
    private async Task RequireProjectAsync(Guid userId, Guid projectId, CancellationToken ct)
    {
        if (!await db.Projects.AnyAsync(p => p.Id == projectId && p.OwnerId == userId && p.DeletedAt == null, ct)) throw AuthException.NotFound();
    }

    /// <summary>Checked once per batch: a device that may not write gets one answer, not a rejection stored per item.</summary>
    private async Task RequireWriterAsync(ClaimsPrincipal principal, Guid userId, CancellationToken ct)
    {
        await guard.RequireActiveDeviceAsync(principal, ct);
        var status = await db.Users.Where(u => u.Id == userId).Select(u => u.Status).SingleAsync(ct);
        if (status == UserStatus.Blocked) throw new AuthException(403, "account_blocked", "This account is blocked for changes.");
    }

    /// <summary>
    /// A cursor is the feed position and the moment it was handed out. Rows after the position were all written after
    /// that moment (the reader lock guarantees it), so once the moment is older than the retention, rows the client has
    /// not seen may be pruned and the cursor has expired. A cursor handed out again with no news renews the moment, so an
    /// idle project never expires for a device that keeps syncing.
    /// </summary>
    private static string WriteCursor(long position, DateTimeOffset issuedAt)
    {
        var bytes = new byte[CursorSize];
        BinaryPrimitives.WriteInt64BigEndian(bytes, position);
        BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(8), issuedAt.UtcTicks);
        return Base64UrlCodec.Encode(bytes);
    }

    /// <summary>
    /// The position after which to read. <c>since: null</c> starts at the beginning of the retained feed; it is meant only
    /// for right after a manifest, whose <c>syncCursor</c> a client should send instead.
    /// </summary>
    private long ReadCursor(string? cursor)
    {
        if (cursor is null) return 0;
        if (!Base64UrlCodec.TryDecode(cursor, out var bytes) || bytes.Length != CursorSize) throw AuthException.Validation("since is malformed.");
        var position = BinaryPrimitives.ReadInt64BigEndian(bytes);
        var ticks = BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(8));
        if (position < 0 || ticks < 0 || ticks > DateTimeOffset.MaxValue.UtcTicks) throw AuthException.Validation("since is malformed.");
        if (new DateTimeOffset(ticks, TimeSpan.Zero) < time.GetUtcNow() - TimeSpan.FromDays(retention.Value.ChangeLogDays))
            throw new AuthException(410, "cursor_expired", "The sync cursor is older than the change log; run the manifest again.");
        return position;
    }
}

/// <summary>Deletes <c>change_log</c> rows older than <see cref="RetentionOptions.ChangeLogDays"/> (06 §6.3.2).</summary>
public sealed class ChangeLogPruner(NyxiteDbContext db, TimeProvider time, IOptions<RetentionOptions> options)
{
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var cutoff = time.GetUtcNow() - TimeSpan.FromDays(options.Value.ChangeLogDays);
        return await db.ChangeLog.Where(c => c.At < cutoff).ExecuteDeleteAsync(ct);
    }
}
