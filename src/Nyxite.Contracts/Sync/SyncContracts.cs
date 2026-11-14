using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Nyxite.Contracts.Structure;

namespace Nyxite.Contracts.Sync;

// Wire shapes of the sync endpoints (openapi/v1.yaml, tag "sync", server 06 §6.3), shared with the desktop client.
// Cursors are opaque base64url; clients store and send them back, never parse them.

/// <summary>One file of a project as the server sees it: structure and opaque content pointers, no name, no content.</summary>
public sealed record ManifestItemDto(
    Guid FileId, Guid? FolderId, string ContentType, string SyncPolicy, long? CurrentVersionSeq, string? ContentHash, string Layout,
    long SizeCipher, Guid KeyId, int KeyGeneration, long? CrdtHeadSeq, Guid? CrdtDocId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] WrappedKeyDto? WrappedKey,
    DateTimeOffset UpdatedAt, DateTimeOffset? DeletedAt);

/// <summary>
/// One page of a project's manifest. <see cref="SyncCursor"/> is the delta cursor to continue from after the last page;
/// <see cref="NextCursor"/> pages the manifest itself.
/// </summary>
public sealed record ManifestDto(Guid ProjectId, string SyncCursor, IReadOnlyList<ManifestItemDto> Items, string? NextCursor);

/// <summary>
/// A structure edit replayed from a device's outbox, or a delete. Fields absent on an update leave the value unchanged,
/// which is why the fields where null is a value of its own are <see cref="Patch{T}"/>.
/// </summary>
public sealed record LocalChangeRef(
    string? Entity, Guid Id, string? Op, Patch<Guid?> ParentFolderId, string? ContentType, Guid? CrdtDocId, string? NameEnc,
    Patch<string?> MetadataEnc, Patch<string?> SyncPolicy, WrappedKeyRequest? OwnerWrappedKey);

public sealed record LocalChange(Guid ClientChangeId, string? Kind, LocalChangeRef? Ref);

public sealed record ChangesRequest(Guid ProjectId, string? Since, int? Limit, bool? Keys, IReadOnlyList<LocalChange>? LocalChanges);

public sealed record LocalChangeResultDto(Guid ClientChangeId, string Status, string? Error);

/// <summary>One entry of the feed. <see cref="Ref"/> has the shape its <see cref="Kind"/> names (06 §6.3.2).</summary>
public sealed record ServerChangeDto(long Seq, DateTimeOffset At, string Kind, JsonObject Ref);

public sealed record ChangesDto(IReadOnlyList<LocalChangeResultDto> Results, IReadOnlyList<ServerChangeDto> ServerChanges, string NextCursor, bool HasMore);
