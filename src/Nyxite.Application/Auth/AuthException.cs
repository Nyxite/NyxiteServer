namespace Nyxite.Application.Auth;

/// <summary>An expected auth failure, rendered as an RFC 9457 problem with a stable <c>code</c> (04 §4.4).</summary>
public sealed class AuthException(int status, string code, string title, TimeSpan? retryAfter = null) : Exception(title)
{
    public int Status { get; } = status;
    public string Code { get; } = code;

    /// <summary>Set on <c>429</c>: rendered as the <c>Retry-After</c> header.</summary>
    public TimeSpan? RetryAfter { get; } = retryAfter;

    public static AuthException Unauthenticated(string title = "Authentication failed.") => new(401, "unauthenticated", title);
    public static AuthException Validation(string title) => new(400, "validation_failed", title);
    public static AuthException SecondFactorRequired(string title = "A second factor is required.") => new(403, "2fa_required", title);
    public static AuthException EmailUnverified() => new(403, "email_unverified", "The email address is not verified yet.");
    public static AuthException AccountBlocked() => new(403, "account_blocked", "This account is blocked for web sessions.");
    public static AuthException RateLimited(TimeSpan retryAfter) => new(429, "rate_limited", "Too many attempts.", retryAfter);
    public static AuthException Conflict(string title) => new(409, "conflict", title);
    public static AuthException NotFound() => new(404, "not_found", "Not found.");
    public static AuthException Unavailable(string title) => new(503, "unavailable", title);
    public static AuthException IdempotencyConflict() => new(409, "idempotency_conflict", "The Idempotency-Key was used with a different request.");
    public static AuthException DeviceNotActive() => new(403, "device_not_active", "This session is not bound to an active device.");
    public static AuthException PairingCodeInvalid() => new(403, "pairing_code_invalid", "The pairing code is wrong.");
    public static AuthException PairingExpired() => new(410, "pairing_expired", "The pairing code has expired; register the device again.");
}
