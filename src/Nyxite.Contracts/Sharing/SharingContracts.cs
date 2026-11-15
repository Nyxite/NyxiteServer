using Nyxite.Contracts.Structure;

namespace Nyxite.Contracts.Sharing;

// Wire shapes of the share, wrapped-key and public-share endpoints (openapi/v1.yaml, tags "shares", "keys",
// "public-share"; server 04, 09). Wrapped keys and names are client-side ciphertext, base64url without padding. No
// field of any of these carries a link token or a fragment key: a link share sends only the token's SHA-256.

/// <summary>
/// <c>POST /shares</c>. An account share (<c>user_grant</c>) carries the target's own key wrapped to the grantee; a link
/// share carries <see cref="LinkTokenHash"/>, the SHA-256 of the ASCII token, and the file key stays in the URL fragment.
/// </summary>
public sealed record CreateShareRequest(
    string? TargetType, Guid TargetId, string? Kind, Guid? GranteeId, string? Permission,
    IReadOnlyList<WrappedKeyRequest>? WrappedKeys, string? LinkTokenHash, DateTimeOffset? ExpiresAt);

/// <summary><c>PATCH /shares/{id}</c>: a new permission and/or expiry; <c>expiresAt: null</c> removes the expiry.</summary>
public sealed record UpdateShareRequest(string? Permission, Patch<DateTimeOffset?> ExpiresAt);

/// <summary>A share. <see cref="FrozenGeneration"/> is set on a link a rotation kept: it serves that generation's content only.</summary>
public sealed record ShareDto(
    Guid Id, string TargetType, Guid TargetId, string Kind, Guid? GranteeId, string Permission, Guid CreatedBy,
    DateTimeOffset? ExpiresAt, DateTimeOffset CreatedAt, int? FrozenGeneration = null);

/// <summary><c>POST /files/{id}/keys</c>: wraps of this file's keys for members who reach it.</summary>
public sealed record UploadFileKeysRequest(IReadOnlyList<WrappedKeyRequest>? WrappedKeys);

/// <summary>
/// <c>POST /files/{id}/keys/rotate</c> (09 §9.6): the new key of the next generation, wrapped to every member who reaches
/// the file, the name and metadata sealed again with it, and <see cref="NewHeadRef"/>, the content hash of the head
/// staged under the new key through <c>PUT /files/{id}/keys/rotate/head</c>, absent when the file has no content yet or
/// is excluded from sync. <see cref="Links"/> is the rotating account's choice for the file's links: <c>revoke</c>, the
/// default when absent, or <c>keep</c>, which freezes them at the old generation.
/// </summary>
public sealed record RotateFileKeyRequest(
    Guid NewKeyId, int Generation, IReadOnlyList<WrappedKeyRequest>? WrappedKeys, string? NewHeadRef, string? NameEnc, string? MetadataEnc,
    string? Links = null);

/// <summary>
/// <c>GET /files/{id}/keys/rotate/members</c>: the accounts a rotation must wrap the new key to, for an account with write
/// reach. Account ids only, nothing about how each reaches the file. <see cref="RotationPending"/> is true while a
/// revocation by the owner waits for its rotation.
/// </summary>
public sealed record RotationMembersDto(int Generation, bool RotationPending, IReadOnlyList<Guid> Members);

/// <summary>
/// One wrap of <c>POST /files/keys:batch</c>: exactly one of <see cref="FileId"/> and <see cref="FolderId"/>, because a
/// subtree share must hand out the key of every folder in it as well as of every file (ST-1).
/// </summary>
public sealed record BatchGrant(Guid? FileId, Guid? FolderId, Guid KeyId, Guid MemberId, string? WrappedKey, string? AlgId);

public sealed record BatchGrantRequest(IReadOnlyList<BatchGrant>? Grants);

/// <summary>The outcome of one grant, in request order. <c>applied</c> also answers a wrap that was already stored.</summary>
public sealed record BatchGrantResultDto(Guid? FileId, Guid? FolderId, string Status, string? Error)
{
    public const string Applied = "applied";
    public const string Rejected = "rejected";
}

public sealed record BatchGrantResultsDto(IReadOnlyList<BatchGrantResultDto> Results);

/// <summary>The 15-minute guest share-session token (08 §8.2) and what it reaches.</summary>
public sealed record GuestSessionDto(string GuestToken, DateTimeOffset ExpiresAt, string Permission, string TargetType, Guid TargetId);

/// <summary>
/// The shared file as a guest sees it: ciphertext name and the key the fragment key must match. <see cref="Frozen"/> is
/// true for a link a rotation kept: name, key and head are those of its frozen generation, the link is read only and
/// has no relay room, and the guest opens the head and nothing else.
/// </summary>
public sealed record GuestFileDto(
    Guid Id, string ContentType, string NameEnc, string? MetadataEnc, Guid KeyId, int KeyGeneration, long? CurrentVersionSeq, Guid? CrdtDocId,
    bool Frozen = false);

/// <summary><c>GET /share/{token}</c>: the guest bootstrap, a fresh guest token included.</summary>
public sealed record ShareBootstrapDto(
    string GuestToken, DateTimeOffset ExpiresAt, string Permission, string TargetType, Guid TargetId, DateTimeOffset? ShareExpiresAt,
    GuestFileDto File);
