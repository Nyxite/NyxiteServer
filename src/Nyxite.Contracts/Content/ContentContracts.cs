namespace Nyxite.Contracts.Content;

// Wire shapes of the content endpoints (openapi/v1.yaml, tags "content" and "versions"), shared with the desktop client.
// Blob and snapshot bodies are raw NYXC frames and not JSON; their metadata travels in headers.

/// <summary>One immutable encrypted version of a file. <c>CrdtSeq</c> is set on a text snapshot: the last update it covers.</summary>
public sealed record VersionDto(long Seq, string ContentHash, string Layout, long SizeCipher, Guid KeyId, bool IsHead, Guid? AuthorId,
    long? RestoredFromSeq, long? CrdtSeq, DateTimeOffset CreatedAt);

public sealed record SubmitUpdateItem(Guid ClientUpdateId, Guid KeyId, string? UpdateEnc);

public sealed record SubmitUpdatesRequest(IReadOnlyList<SubmitUpdateItem>? Updates);

public sealed record UpdateAckDto(Guid ClientUpdateId, long Seq);

public sealed record UpdateAcksDto(IReadOnlyList<UpdateAckDto> Acks);

public sealed record CrdtUpdateDto(long Seq, Guid KeyId, string UpdateEnc, Guid? AuthorId, DateTimeOffset CreatedAt);

public sealed record CrdtUpdatesDto(IReadOnlyList<CrdtUpdateDto> Items, bool HasMore);

public sealed record RestoreRequest(long Seq);

/// <summary>
/// When a client in a document room makes a snapshot (05 §5.6, P1.1-CORE-1). Shared by all clients and pinned by the
/// conformance vector <c>snapshot-triggers.json</c>, so no client snapshots far more or far less often than the others.
/// The server makes no snapshot itself, because it cannot read the document.
/// </summary>
public static class SnapshotTriggers
{
    /// <summary>A snapshot is due once this many updates arrived since the last one.</summary>
    public const int UpdateCount = 200;

    /// <summary>A snapshot is due once this much time passed since the last one while updates arrived.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    /// <summary>The last participant leaving the room snapshots when anything changed since the last one.</summary>
    public const bool OnLastParticipantLeaving = true;
}

