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

public sealed record ShareDto(
    Guid Id, string TargetType, Guid TargetId, string Kind, Guid? GranteeId, string Permission, Guid CreatedBy,
    DateTimeOffset? ExpiresAt, DateTimeOffset CreatedAt);

/// <summary><c>POST /files/{id}/keys</c>: wraps of this file's keys for members who reach it.</summary>
public sealed record UploadFileKeysRequest(IReadOnlyList<WrappedKeyRequest>? WrappedKeys);

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

/// <summary>The shared file as a guest sees it: ciphertext name and the key the fragment key must match.</summary>
public sealed record GuestFileDto(
    Guid Id, string ContentType, string NameEnc, string? MetadataEnc, Guid KeyId, int KeyGeneration, long? CurrentVersionSeq, Guid? CrdtDocId);

/// <summary><c>GET /share/{token}</c>: the guest bootstrap, a fresh guest token included.</summary>
public sealed record ShareBootstrapDto(
    string GuestToken, DateTimeOffset ExpiresAt, string Permission, string TargetType, Guid TargetId, DateTimeOffset? ShareExpiresAt,
    GuestFileDto File);
