using System.Net;
using Nyxite.Domain.Identity;

namespace Nyxite.Persistence.Entities;

/// <summary><c>sessions</c> — one row per signed-in client, the refresh-token family (03 §3.2).</summary>
public sealed class SessionEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid? DeviceId { get; set; }
    public ClientKind ClientKind { get; set; }
    public AuthMethod AuthMethod { get; set; }

    /// <summary>Last second factor on this session; NULL = enrollment-limited session (no factor yet).</summary>
    public DateTimeOffset? MfaVerifiedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public IPAddress? LastIp { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public RevokeReason? RevokeReason { get; set; }
}

/// <summary><c>refresh_tokens</c> — rotate-on-use chain; only the SHA-256 of the token is stored (03 §3.2).</summary>
public sealed class RefreshTokenEntity
{
    public Guid Id { get; set; }
    public Guid SessionId { get; set; }
    public Guid? ParentId { get; set; }
    public required byte[] TokenHash { get; set; }
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

/// <summary><c>ephemeral_tokens</c> — single-use short-lived tokens, stored hashed (03 §3.2).</summary>
public sealed class EphemeralTokenEntity
{
    public required byte[] TokenHash { get; set; }
    public EphemeralTokenKind Kind { get; set; }
    public Guid? UserId { get; set; }
    public Guid? SessionId { get; set; }
    public int Attempts { get; set; }
    public string? Detail { get; set; }
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

/// <summary><c>webauthn_credentials</c> — public passkey material only (03 §3.2).</summary>
public sealed class WebAuthnCredentialEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required byte[] CredentialId { get; set; }
    public required byte[] PublicKey { get; set; }
    public long SignCount { get; set; }
    public string? Label { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// <c>backup_codes</c> — single-use second-factor codes for a lost authenticator (08 §8.1). Only an HMAC under a key
/// derived from the versioned pepper is stored, so a DB-only leak cannot brute-force the short codes.
/// </summary>
public sealed class BackupCodeEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required byte[] CodeHash { get; set; }
    public int PepperVersion { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

/// <summary><c>idempotency_keys</c> — replay store for <c>Idempotency-Key</c> (03 §3.2, 04 §4.1).</summary>
public sealed class IdempotencyKeyEntity
{
    /// <summary>The primary key <c>(user_id, endpoint, key)</c>: a violation means a concurrent request with the same key won.</summary>
    public const string PrimaryKey = "PK_idempotency_keys";

    public Guid UserId { get; set; }
    public required string Endpoint { get; set; }
    public required string Key { get; set; }
    public required byte[] RequestHash { get; set; }
    public int StatusCode { get; set; }
    public required byte[] ResponseBody { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
