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
