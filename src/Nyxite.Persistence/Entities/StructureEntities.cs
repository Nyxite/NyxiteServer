namespace Nyxite.Persistence.Entities;

/// <summary><c>projects</c> (03 §3.3). The name is ciphertext; the server keeps the graph, not the titles.</summary>
public sealed class ProjectEntity
{
    public Guid Id { get; set; }
    public Guid OwnerId { get; set; }
    public required byte[] NameEnc { get; set; }
    public byte[]? MetadataEnc { get; set; }
    public required string SyncPolicy { get; set; }
    public int KeyGeneration { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}

/// <summary><c>folders</c> (03 §3.3). A null <c>sync_policy</c> follows the parent, resolved by the clients.</summary>
public sealed class FolderEntity
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public Guid? ParentFolderId { get; set; }
    public required byte[] NameEnc { get; set; }
    public byte[]? MetadataEnc { get; set; }
    public string? SyncPolicy { get; set; }
    public int KeyGeneration { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }

    /// <summary>The folder or project whose delete took this row to Trash with it; null when it was deleted itself.</summary>
    public Guid? DeletedRootId { get; set; }
}

/// <summary><c>files</c> (03 §3.3). <c>current_version_id</c> gets its FK with <c>file_versions</c> (Phase 1.1).</summary>
public sealed class FileEntity
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public Guid? FolderId { get; set; }
    public Guid OwnerId { get; set; }
    public required byte[] NameEnc { get; set; }
    public required string ContentType { get; set; }
    public required string SyncPolicy { get; set; }
    public Guid? CurrentVersionId { get; set; }
    public Guid? CrdtDocId { get; set; }

    /// <summary>The last <c>file_versions.seq</c> handed out for this file. A counter, so a purged version never frees its number.</summary>
    public long VersionSeq { get; set; }

    /// <summary>The last <c>crdt_updates.seq</c> handed out for this file's document. A counter, so pruning never moves it back.</summary>
    public long CrdtHeadSeq { get; set; }

    /// <summary>Set by a recorded restore: the version the restoring account's next version is a restore of (10 §10.5).</summary>
    public long? PendingRestoreSeq { get; set; }

    /// <summary>The account that recorded <see cref="PendingRestoreSeq"/>. Only its own next version takes the link (10 §10.5).</summary>
    public Guid? PendingRestoreBy { get; set; }

    /// <summary>
    /// When <see cref="PendingRestoreSeq"/> was recorded. The mark lapses once it is older than
    /// <c>Limits:RestoreMarkLifetime</c> without a version of the restoring account (10 §10.5).
    /// </summary>
    public DateTimeOffset? PendingRestoreAt { get; set; }

    /// <summary>
    /// Set when the owner revoked a share that reached this file, cleared by the next committed key rotation (09 §9.6).
    /// It tells every member with write reach that the second layer of revocation is still due.
    /// </summary>
    public DateTimeOffset? RotationPendingAt { get; set; }
    public int KeyGeneration { get; set; } = 1;
    public byte[]? MetadataEnc { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }

    /// <summary>The folder or project whose delete took this row to Trash with it; null when it was deleted itself.</summary>
    public Guid? DeletedRootId { get; set; }

    /// <summary>
    /// When the file was switched from <c>server-default</c> to <c>excluded</c>; null while it syncs. Its stored content is
    /// purged once this is older than Trash window plus grace window (06 §6.2), so a mistaken switch can still be undone.
    /// </summary>
    public DateTimeOffset? ExcludedAt { get; set; }
}

/// <summary>
/// <c>file_keys</c> (03 §3.3): a file key wrapped to one member. Link shares add no row here, because their key rides
/// the URL fragment (09 §9.4); <c>share_id</c> stays for a link key relayed wrapped to an ephemeral share keypair.
/// </summary>
public sealed class FileKeyEntity
{
    public Guid Id { get; set; }
    public Guid FileId { get; set; }
    public Guid? MemberId { get; set; }
    public Guid? ShareId { get; set; }
    public Guid KeyId { get; set; }
    public required byte[] WrappedKey { get; set; }
    public int Generation { get; set; } = 1;
    public required string AlgId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary>
/// <c>structure_keys</c> (03 §3.3): the key of one project or one folder, wrapped to one member. It encrypts that
/// object's name and metadata, the same way a file key does for a file.
/// </summary>
public sealed class StructureKeyEntity
{
    public Guid Id { get; set; }
    public Guid? ProjectId { get; set; }
    public Guid? FolderId { get; set; }
    public Guid? MemberId { get; set; }
    public Guid? ShareId { get; set; }
    public Guid KeyId { get; set; }
    public required byte[] WrappedKey { get; set; }
    public int Generation { get; set; } = 1;
    public required string AlgId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
