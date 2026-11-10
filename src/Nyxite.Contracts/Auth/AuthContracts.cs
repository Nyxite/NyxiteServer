using System.Text.Json;

namespace Nyxite.Contracts.Auth;

// Wire shapes of the auth, account-security and /me endpoints (openapi/v1.yaml), shared with the desktop client.
// Request fields are nullable where the server validates them itself and answers 400 validation_failed.

public sealed record RegisterRequest(string? Email, string? DisplayName, string? Password, string? ClientKind);
public sealed record LoginRequest(string? Email, string? Password, string? ClientKind);
public sealed record TotpLoginRequest(string? MfaToken, string? TotpCode);
public sealed record MfaTokenRequest(string? MfaToken);
public sealed record CodeLoginRequest(string? MfaToken, string? Code);
public sealed record TotpCodeRequest(string? TotpCode);
public sealed record CodeRequest(string? Code);
public sealed record StepUpTokenRequest(string? StepUpToken);
public sealed record StepUpRequest(string? Method, string? Code, JsonElement? Credential);
public sealed record PasskeyRegisterRequest(JsonElement Credential, string? Label);
public sealed record AssertOptionsRequest(string? Email);
public sealed record AssertRequest(JsonElement Credential, string? ClientKind);
public sealed record OidcTokenRequest(string? Handoff);
public sealed record RefreshRequest(string? RefreshToken);
public sealed record SecondFactorChallengeDto(string Challenge, string MfaToken, IReadOnlyList<string> Methods, bool Enrollment);
public sealed record TotpEnrollmentDto(string Secret, string OtpauthUri);
public sealed record BackupCodesDto(IReadOnlyList<string> Codes);
public sealed record StepUpDto(string StepUpToken, DateTimeOffset ExpiresAt);
public sealed record TokenPairDto(string AccessToken, string RefreshToken, DateTimeOffset AccessTokenExpiresAt);

/// <summary>Single-use relay socket ticket (08 §8.4).</summary>
public sealed record SocketTicketDto(string Ticket, DateTimeOffset ExpiresAt);
public sealed record ForgotRequest(string? Email);
public sealed record ResetRequest(string? ResetToken, string? NewPassword);
public sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword, string? StepUpToken);
public sealed record FactorsDto(bool EmailVerified, bool Totp, bool EmailOtp, int Passkeys, int BackupCodesRemaining, bool PasswordResetByEmail);
public sealed record PasskeyDto(Guid Id, string? Label, DateTimeOffset CreatedAt);
public sealed record SessionDto(Guid Id, string ClientKind, string AuthMethod, DateTimeOffset CreatedAt, DateTimeOffset LastSeenAt,
    DateTimeOffset ExpiresAt, string? LastIp, string? UserAgent, bool Current);

public sealed record CapabilitiesDto(bool Support, string[] EnterpriseFlags, string LicenseState);

public sealed record MeDto(Guid Id, string Email, string DisplayName, string Role, string Status,
    long? StorageQuotaBytes, long UsageBytes, CapabilitiesDto Capabilities);
