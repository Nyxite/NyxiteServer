namespace Nyxite.Persistence.Entities;

/// <summary>
/// <c>file_versions</c> (03 §3.3): one immutable encrypted snapshot of a file. For a text file it is a client-made
/// snapshot of the merged CRDT document and <see cref="CrdtSeq"/> says which updates it covers. A version that lost a
/// concurrent write stays as a row that is not the head.
/// </summary>
public sealed class FileVersionEntity
{
    public Guid Id { get; set; }
    public Guid FileId { get; set; }
    public long Seq { get; set; }
    public required byte[] ContentHash { get; set; }
    public required string BlobRef { get; set; }
    public long SizeCipher { get; set; }
    public Guid KeyId { get; set; }
    public required string Layout { get; set; }
    public Guid? AuthorId { get; set; }
    public long? CrdtSeq { get; set; }
    public long? RestoredFromSeq { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary><c>crdt_updates</c> (03 §3.3): the encrypted update log the relay stores and forwards and never reads.</summary>
public sealed class CrdtUpdateEntity
{
    public long Id { get; set; }
    public Guid CrdtDocId { get; set; }
    public long Seq { get; set; }
    public required byte[] UpdateEnc { get; set; }
    public Guid KeyId { get; set; }
    public Guid? AuthorId { get; set; }

    /// <summary>The id the client gave the update, so a resent update gets its old sequence number instead of a second row.</summary>
    public Guid? ClientUpdateId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// <c>change_log</c> (03 §3.3, 06 §6.3.2): the delta-sync feed of one project. Written in the transaction of the change it
/// describes. <see cref="Ref"/> is the <c>ServerChange</c> ref as JSON, structural and opaque fields only, never content.
/// </summary>
public sealed class ChangeLogEntity
{
    public long Seq { get; set; }
    public Guid ProjectId { get; set; }
    public required string Kind { get; set; }
    public required string Entity { get; set; }
    public Guid EntityId { get; set; }
    public required string Ref { get; set; }
    public DateTimeOffset At { get; set; }
}

/// <summary>
/// <c>file_rotation_heads</c> (03 §3.3, 09 §9.6): the head of a file re-encrypted under the key a rotation is about to
/// commit, uploaded before the commit and not yet a version. The commit turns it into the head version in the same
/// transaction that switches the key, so the new head is written before anything points to it (write-then-swap). A
/// staged head that no commit takes expires and its blob becomes an orphan for the garbage collector.
/// </summary>
public sealed class FileRotationHeadEntity
{
    public Guid FileId { get; set; }

    /// <summary>The proposed new key, which the file does not have yet. One staged head per file and proposed key.</summary>
    public Guid KeyId { get; set; }
    public required byte[] ContentHash { get; set; }
    public required string BlobRef { get; set; }
    public long SizeCipher { get; set; }

    /// <summary>Text files: the last update the staged snapshot contains.</summary>
    public long? CrdtSeq { get; set; }

    /// <summary>Blob files: the head version the staged head re-encrypts, 0 when the file had none.</summary>
    public long? ParentSeq { get; set; }
    public Guid? AuthorId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
