namespace Nyxite.Persistence.Entities;

/// <summary>
/// <c>kt_leaves</c> — one row per directory key event, append-only (17 §17.6). <c>subject_id</c> has no FK, because the
/// log outlives account and group deletion.
/// </summary>
public sealed class KtLeafEntity
{
    public long LeafIndex { get; set; }
    public short EntryType { get; set; }
    public Guid SubjectId { get; set; }
    public Guid KeyId { get; set; }
    public required byte[] LeafData { get; set; }
    public required byte[] LeafHash { get; set; }
    public DateTimeOffset LoggedAt { get; set; }
}

/// <summary><c>kt_state</c> — the single row that serializes appends (17 §17.6).</summary>
public sealed class KtStateEntity
{
    public bool Id { get; set; } = true;
    public long TreeSize { get; set; }
}
