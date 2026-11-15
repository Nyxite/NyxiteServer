using System.Buffers.Binary;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Nyxite.Crypto;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sync;

/// <summary>
/// A transaction a write either starts itself or joins, so one structure change can run on its own and also as one item
/// of a delta-sync batch, where the batch item's idempotency record must commit together with the change.
/// </summary>
public sealed class UnitOfWork : IAsyncDisposable
{
    private readonly IDbContextTransaction? _owned;

    private UnitOfWork(IDbContextTransaction? owned) => _owned = owned;

    public static async Task<UnitOfWork> BeginAsync(NyxiteDbContext db, CancellationToken ct) =>
        new(db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null);

    /// <summary>True when this unit started the transaction, so its commit is the one that makes the change visible.</summary>
    public bool Owned => _owned is not null;

    /// <summary>Commits when this unit started the transaction; a joined transaction is committed by whoever started it.</summary>
    public Task CommitAsync(CancellationToken ct) => _owned?.CommitAsync(ct) ?? Task.CompletedTask;

    public ValueTask DisposeAsync() => _owned?.DisposeAsync() ?? ValueTask.CompletedTask;
}

/// <summary>
/// Writes the delta-sync feed (<c>change_log</c>, 03 §3.3, 06 §6.3.2). Every change is recorded in the transaction of
/// the write it describes, so the feed can never miss or invent a write. A ref holds only what a <c>ServerChange</c>
/// exposes: ids, sequence numbers, hashes and the opaque name and metadata frames. The caller's wrapped key is added
/// when the feed is read, because it differs per reader.
/// </summary>
/// <remarks>
/// <para>
/// Sequence numbers come from an identity column, so they are handed out at insert time and a transaction may commit
/// after one that started later. A reader that moved its cursor past a number still in flight would skip that change
/// for good. Writers therefore hold a shared advisory lock on the project from recording until commit, and a reader
/// takes it exclusively: while it reads, no write to the project is in flight, and every later write gets a higher
/// number. Writers do not wait for each other.
/// </para>
/// <para>The lock is transaction-scoped, so recording requires an open transaction (<see cref="UnitOfWork"/>).</para>
/// </remarks>
public sealed class ChangeFeed(NyxiteDbContext db, TimeProvider time)
{
    public const string Structure = "structure";
    public const string Blob = "blob";
    public const string Crdt = "crdt";
    public const string Delete = "delete";
    public const string KeyRotate = "keyrotate";

    public const string Deleted = "deleted";
    public const string Purged = "purged";
    public const string AccessRevoked = "access_revoked";

    /// <summary>Distinguishes these locks from other advisory locks; the two-int form has its own key space per class.</summary>
    private const int LockClass = 0x4E59_5343; // "NYSC"

    private static int LockKey(Guid projectId)
    {
        Span<byte> bytes = stackalloc byte[16];
        projectId.TryWriteBytes(bytes, bigEndian: true, out _);
        return BinaryPrimitives.ReadInt32BigEndian(bytes) ^ BinaryPrimitives.ReadInt32BigEndian(bytes[4..])
             ^ BinaryPrimitives.ReadInt32BigEndian(bytes[8..]) ^ BinaryPrimitives.ReadInt32BigEndian(bytes[12..]);
    }

    /// <summary>Taken by every writer of the project's feed, held until its transaction ends.</summary>
    private async Task WriterLockAsync(Guid projectId, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("A change is recorded inside the transaction of the write.");
        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock_shared({LockClass}, {LockKey(projectId)})", ct);
    }

    /// <summary>Taken by a reader inside its own transaction: once it holds the lock, no write to the project is in flight.</summary>
    internal async Task ReaderLockAsync(Guid projectId, CancellationToken ct) =>
        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({LockClass}, {LockKey(projectId)})", ct);

    private async Task AddAsync(Guid projectId, string kind, string entity, Guid entityId, JsonObject reference, CancellationToken ct)
    {
        await WriterLockAsync(projectId, ct);
        db.ChangeLog.Add(new ChangeLogEntity
        {
            ProjectId = projectId, Kind = kind, Entity = entity, EntityId = entityId, Ref = reference.ToJsonString(), At = time.GetUtcNow(),
        });
    }

    private static string? Encode(byte[]? bytes) => bytes is null ? null : Base64UrlCodec.Encode(bytes);

    // ---------------------------------------------------------------- structure

    public Task ProjectAsync(ProjectEntity p, CancellationToken ct) =>
        AddAsync(p.Id, Structure, "project", p.Id, new JsonObject
        {
            ["entity"] = "project", ["id"] = p.Id, ["parentFolderId"] = null, ["nameEnc"] = Encode(p.NameEnc),
            ["metadataEnc"] = Encode(p.MetadataEnc), ["syncPolicy"] = p.SyncPolicy, ["updatedAt"] = p.UpdatedAt,
        }, ct);

    public Task FolderAsync(FolderEntity f, CancellationToken ct) =>
        AddAsync(f.ProjectId, Structure, "folder", f.Id, new JsonObject
        {
            ["entity"] = "folder", ["id"] = f.Id, ["parentFolderId"] = f.ParentFolderId, ["nameEnc"] = Encode(f.NameEnc),
            ["metadataEnc"] = Encode(f.MetadataEnc), ["syncPolicy"] = f.SyncPolicy, ["updatedAt"] = f.UpdatedAt,
        }, ct);

    public Task FileAsync(FileEntity f, CancellationToken ct) =>
        AddAsync(f.ProjectId, Structure, "file", f.Id, new JsonObject
        {
            ["entity"] = "file", ["id"] = f.Id, ["parentFolderId"] = f.FolderId, ["contentType"] = f.ContentType, ["crdtDocId"] = f.CrdtDocId,
            ["nameEnc"] = Encode(f.NameEnc), ["metadataEnc"] = Encode(f.MetadataEnc), ["syncPolicy"] = f.SyncPolicy,
            ["rotationPending"] = f.RotationPendingAt is not null, ["updatedAt"] = f.UpdatedAt,
        }, ct);

    /// <summary>A soft delete, a purge or lost reach of one row.</summary>
    public Task DeleteAsync(Guid projectId, string entity, Guid id, DateTimeOffset deletedAt, string reason, CancellationToken ct) =>
        AddAsync(projectId, Delete, entity, id, new JsonObject
        {
            ["entity"] = entity, ["id"] = id, ["deletedAt"] = deletedAt, ["reason"] = reason,
        }, ct);

    // ---------------------------------------------------------------- content

    /// <summary>A new version: a blob, a text file's snapshot, or a losing sibling (<c>isHead</c> false).</summary>
    public Task VersionAsync(FileEntity file, FileVersionEntity v, bool isHead, CancellationToken ct) =>
        AddAsync(file.ProjectId, Blob, "file", file.Id, new JsonObject
        {
            ["fileId"] = file.Id, ["seq"] = v.Seq, ["contentHash"] = Base64UrlCodec.Encode(v.ContentHash), ["layout"] = v.Layout,
            ["sizeCipher"] = v.SizeCipher, ["keyId"] = v.KeyId, ["isHead"] = isHead, ["parentSeq"] = v.ParentSeq,
            ["url"] = $"/api/v1/files/{file.Id}/versions/{v.Seq}/blob",
        }, ct);

    /// <summary>A committed key rotation: the file's current key is now <paramref name="keyId"/> of <paramref name="generation"/> (06 §6.3.2).</summary>
    public Task KeyRotateAsync(FileEntity file, Guid keyId, int generation, CancellationToken ct) =>
        AddAsync(file.ProjectId, KeyRotate, "file", file.Id, new JsonObject
        {
            ["fileId"] = file.Id, ["keyId"] = keyId, ["generation"] = generation,
        }, ct);

    /// <summary>Updates <paramref name="fromSeq"/> to <paramref name="toSeq"/> were appended to the file's log.</summary>
    public Task UpdatesAsync(FileEntity file, long fromSeq, long toSeq, CancellationToken ct) =>
        AddAsync(file.ProjectId, Crdt, "file", file.Id, new JsonObject
        {
            ["fileId"] = file.Id, ["fromSeq"] = fromSeq, ["toSeq"] = toSeq,
        }, ct);
}
