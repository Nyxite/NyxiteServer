namespace Nyxite.Contracts.Keys;

// Wire shapes of the key, device and recovery endpoints (openapi/v1.yaml). Binary fields are base64url without padding.

public sealed record DirectoryKeyDto(Guid KeyId, int Generation, string AlgId, string KemPub, string SigPub, string SelfSig,
    DateTimeOffset LoggedAt, long KtLeafIndex, bool Revoked);

public sealed record DirectoryDto(Guid UserId, IReadOnlyList<DirectoryKeyDto> Keys);

public sealed record PublishKeyRequest(Guid KeyId, int Generation, string? AlgId, string? KemPub, string? SigPub, string? SelfSig);

public sealed record DeviceDto(Guid Id, string? Label, string Status, string PubkeyFingerprint, DateTimeOffset EnrolledAt, DateTimeOffset? RevokedAt);

public sealed record RegisterDeviceRequest(string? Label, string? Pubkey);

public sealed record QrPayloadDto(Guid DeviceId, string PairingCode, string PubkeyFingerprint);

public sealed record RegisteredDeviceDto(Guid DeviceId, string Status, string PairingCode, QrPayloadDto QrPayload);

public sealed record ApproveDeviceRequest(string? PairingCode, string? WrappedIdentityKey);

public sealed record ActivateDeviceRequest(Guid KeyId, string? Sig);

public sealed record EnrollmentDto(string WrappedIdentityKey);

public sealed record KdfParamsDto(string? Alg, int M, int T, int P, string? Salt);

public sealed record RecoveryBlobDto(int Version, KdfParamsDto? Kdf, string? Nonce, string? Ciphertext, string? Tag);
