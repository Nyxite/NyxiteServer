using System.Net;
using Nyxite.Domain.Identity;

namespace Nyxite.Persistence.Entities;

/// <summary><c>users</c> (03 §3.2). Holds account identity and auth verifiers, never content or content keys.</summary>
public sealed class UserEntity
{
    public Guid Id { get; set; }
    public required string Email { get; set; }
    public required string DisplayName { get; set; }
    public byte[]? PasswordVerifier { get; set; }
    public int? PasswordPepperVersion { get; set; }
    public byte[]? TotpSecretEnc { get; set; }

    /// <summary>Last accepted TOTP time step; a code is only accepted for a later step (RFC 6238 §5.2, no replay).</summary>
    public long? TotpLastStep { get; set; }

    /// <summary>When the account proved control of <see cref="Email"/>; NULL = unverified, purged after a while.</summary>
    public DateTimeOffset? EmailVerifiedAt { get; set; }

    /// <summary>When emailed one-time codes were enabled as a second factor; NULL = not enabled.</summary>
    public DateTimeOffset? EmailOtpEnabledAt { get; set; }
    public string? ExternalIdp { get; set; }
    public string? ExternalIdpSub { get; set; }
    public UserRole Role { get; set; } = UserRole.User;
    public UserStatus Status { get; set; } = UserStatus.Active;
    public long? StorageQuotaBytes { get; set; }
    public byte[]? SettingsEnc { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary><c>user_keys</c> — the public-key directory (03 §3.2). Public material only.</summary>
public sealed class UserKeyEntity
{
    public Guid UserId { get; set; }
    public Guid KeyId { get; set; }
    public required byte[] PublicX25519 { get; set; }
    public required byte[] PublicEd25519 { get; set; }
    public required string AlgId { get; set; }
    public int Generation { get; set; } = 1;
    public required byte[] SelfSig { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary><c>devices</c> — per-device enrollment (03 §3.2, 08 §8.3).</summary>
public sealed class DeviceEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string? Label { get; set; }
    public required byte[] Pubkey { get; set; }
    public DeviceStatus Status { get; set; } = DeviceStatus.Pending;
    public byte[]? PendingKeyBlob { get; set; }
    public byte[]? PairingCodeHash { get; set; }
    public DateTimeOffset? PairingExpiresAt { get; set; }
    public int PairingAttempts { get; set; }
    public DateTimeOffset EnrolledAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary><c>recovery_blobs</c> — the client-encrypted, server-opaque recovery blob (03 §3.2, 07 §7.8).</summary>
public sealed class RecoveryBlobEntity
{
    public Guid UserId { get; set; }
    public int Version { get; set; } = 1;
    public required byte[] Blob { get; set; }
    public required string KdfParams { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary><c>audit_log</c> — append-only security events, never content (03 §3.2, 12).</summary>
public sealed class AuditLogEntity
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public Guid? ActorId { get; set; }
    public ActorKind ActorKind { get; set; }
    public required string Action { get; set; }
    public string? TargetType { get; set; }
    public Guid? TargetId { get; set; }
    public string Detail { get; set; } = "{}";
    public IPAddress? Ip { get; set; }
    public string? UserAgent { get; set; }
}
