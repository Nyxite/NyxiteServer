using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Nyxite.Application.Audit;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>Outcome of the password step of <c>POST /auth/login</c>.</summary>
public abstract record LoginResult
{
    /// <summary>
    /// Complete with one of <paramref name="Methods"/>. <paramref name="Enrollment"/> is true for an account without any
    /// factor: an emailed code is then the second factor, and the session it yields is limited to factor enrollment.
    /// </summary>
    public sealed record SecondFactorRequired(string MfaToken, IReadOnlyList<string> Methods, bool Enrollment) : LoginResult;
}

public sealed record TotpEnrollment(string Secret, string OtpAuthUri);

/// <summary>
/// Native account auth (08 §8.1(a)): peppered Argon2id password verifier with lazy re-pepper and a mandatory second
/// factor (TOTP, emailed code or a backup code). Nothing here derives a key from the password; a successful check only
/// leads to an API token.
/// </summary>
public sealed class NativeAuthService(
    NyxiteDbContext db,
    PasswordHasher hasher,
    TotpSecretProtector totpProtector,
    TotpCodes totp,
    IEphemeralTokenStore ephemeral,
    SessionService sessions,
    SecondFactors factors,
    FactorChangeGuard guard,
    EmailCodes emailCodes,
    EmailVerificationService emailVerification,
    AuditWriter audit,
    TimeProvider time,
    IOptions<AuthOptions> options,
    ILogger<NativeAuthService> logger)
{
    public const int PasswordMinLength = 12;
    public const int PasswordMaxLength = 1024;
    public const int DisplayNameMaxLength = 200;

    private readonly AuthOptions _options = options.Value;

    public async Task<TokenPair> RegisterAsync(string? email, string? displayName, string? password, ClientKind clientKind,
        RequestInfo request, CancellationToken ct)
    {
        var normalizedEmail = NormalizeEmail(email) ?? throw AuthException.Validation("A valid email is required.");
        displayName = displayName?.Trim();
        if (string.IsNullOrEmpty(displayName) || displayName.Length > DisplayNameMaxLength)
            throw AuthException.Validation($"displayName must be 1-{DisplayNameMaxLength} characters.");
        ValidatePassword(password);

        // An address held by an expired unverified account is free again (no squatting, 08 §8.1).
        await emailVerification.PurgeExpiredAsync(normalizedEmail, ct);

        var now = time.GetUtcNow();
        var (verifier, pepperVersion) = await hasher.HashAsync(password!, ct);
        var user = new UserEntity
        {
            Id = Guid.CreateVersion7(now),
            Email = normalizedEmail,
            DisplayName = displayName,
            PasswordVerifier = verifier,
            PasswordPepperVersion = pepperVersion,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Users.Add(user);
        audit.Add("auth.register", user.Id, request, targetType: "user", targetId: user.Id);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw AuthException.Conflict("An account with this email already exists.");
        }

        var tokens = await sessions.StartAsync(user, clientKind, AuthMethod.PasswordTotp, mfaVerified: false, request, ct);
        // Queued in the outbox: a failing mail relay never fails the registration, the worker retries.
        await emailVerification.SendAsync(user, ct);
        return tokens;
    }

    public async Task<LoginResult> LoginAsync(string? email, string? password, ClientKind clientKind, RequestInfo request, CancellationToken ct)
    {
        var normalizedEmail = NormalizeEmail(email);
        var user = normalizedEmail is null ? null : await db.Users.SingleOrDefaultAsync(u => u.Email == normalizedEmail, ct);
        if (user is not null && emailVerification.IsExpired(user))
        {
            await emailVerification.PurgeExpiredAsync(user.Email, ct);
            user = null;
        }

        if (user?.PasswordVerifier is null || user.PasswordPepperVersion is null || string.IsNullOrEmpty(password))
        {
            await hasher.DummyVerifyAsync(password ?? "", ct);
            await FailAsync(user?.Id, "unknown_account", request, ct);
        }

        var check = await hasher.VerifyAsync(password!, user!.PasswordVerifier!, user.PasswordPepperVersion!.Value, ct);
        if (!check.Valid) await FailAsync(user.Id, "bad_password", request, ct);

        if (check.NeedsRehash)
        {
            var (verifier, version) = await hasher.HashAsync(password!, ct);
            user.PasswordVerifier = verifier;
            user.PasswordPepperVersion = version;
            user.UpdatedAt = time.GetUtcNow();
        }

        if (user.TotpSecretEnc is not null && TotpSecretProtector.VersionOf(user.TotpSecretEnc) != totpProtector.CurrentVersion)
        {
            try
            {
                user.TotpSecretEnc = totpProtector.Protect(totpProtector.Unprotect(user.TotpSecretEnc, user.Id), user.Id);
            }
            catch (CryptographicException e)
            {
                // The pepper version of this secret was removed from the configuration (14): TOTP cannot be checked any
                // more, the other factors still work. Nothing is re-wrapped and the operator sees why.
                logger.LogError(e, "The TOTP secret of user {UserId} needs a pepper version that is no longer configured.", user.Id);
            }
        }
        await db.SaveChangesAsync(ct);

        var methods = await factors.PasswordMethodsAsync(user, ct);
        var enrollment = false;
        if (methods.Count == 0)
        {
            // A passkey-only account has no password second factor: a password alone must not sign it in.
            if (await db.WebAuthnCredentials.AnyAsync(c => c.UserId == user.Id, ct))
                await FailAsync(user.Id, "password_login_without_second_factor", request, ct);

            // No factor yet: the mailbox is the second factor for reaching enrollment, so the password alone can never
            // enroll a factor and take the account over (08 §8.1).
            methods = [SecondFactorMethod.Email];
            enrollment = true;
        }

        var detail = JsonSerializer.Serialize(new { clientKind = AuthDbValue.Of(clientKind) });
        var token = await ephemeral.IssueAsync(EphemeralTokenKind.Mfa, user.Id, null, _options.MfaTokenLifetime, detail, ct);
        audit.Add("auth.2fa_challenge", user.Id, request, detail: new { methods, enrollment });
        await db.SaveChangesAsync(ct);
        return new LoginResult.SecondFactorRequired(token, methods, enrollment);
    }

    public Task<TokenPair> CompleteTotpLoginAsync(string? mfaToken, string? code, RequestInfo request, CancellationToken ct) =>
        CompleteLoginAsync(mfaToken, SecondFactorMethod.Totp, code, request, ct);

    public Task<TokenPair> CompleteEmailLoginAsync(string? mfaToken, string? code, RequestInfo request, CancellationToken ct) =>
        CompleteLoginAsync(mfaToken, SecondFactorMethod.Email, code, request, ct);

    public Task<TokenPair> CompleteBackupCodeLoginAsync(string? mfaToken, string? code, RequestInfo request, CancellationToken ct) =>
        CompleteLoginAsync(mfaToken, SecondFactorMethod.BackupCode, code, request, ct);

    /// <summary>Emails a sign-in code for the password step behind <paramref name="mfaToken"/>; sending again replaces it.</summary>
    public async Task SendLoginEmailCodeAsync(string? mfaToken, RequestInfo request, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(mfaToken)) throw AuthException.Unauthenticated();
        var hash = IEphemeralTokenStore.Hash(mfaToken);
        var row = await ephemeral.FindLiveAsync(EphemeralTokenKind.Mfa, hash, ct);
        if (row?.UserId is null) throw AuthException.Unauthenticated();
        var user = await db.Users.SingleAsync(u => u.Id == row.UserId, ct);
        if (!await EmailCodesAllowedAsync(user, ct)) throw AuthException.Validation("Sign-in codes by email are not enabled for this account.");
        await emailCodes.IssueAsync(EmailCodePurpose.Login, LoginEmailKey(hash), user.Id, null, user.Email, ct);
        audit.Add("auth.email_code_sent", user.Id, request, detail: new { purpose = "login" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Begins TOTP enrollment. The secret is kept pending (encrypted) until <see cref="VerifyTotpAsync"/>.</summary>
    public async Task<TotpEnrollment> BeginTotpEnrollmentAsync(ClaimsPrincipal principal, string? stepUpToken, CancellationToken ct)
    {
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        var secret = TotpCodes.NewSecret();
        var detail = JsonSerializer.Serialize(new { secret = Base64UrlCodec.Encode(totpProtector.Protect(secret, user.Id)) });
        var sessionId = principal.SessionIdOf();
        await ephemeral.PutAsync(PendingTotpKey(sessionId), EphemeralTokenKind.TotpEnroll, user.Id, sessionId,
            _options.TotpEnrollLifetime, detail, ct);
        return new TotpEnrollment(TotpCodes.Base32(secret), TotpCodes.OtpAuthUri(_options.TotpIssuer, user.Email, secret));
    }

    public async Task VerifyTotpAsync(ClaimsPrincipal principal, string? code, RequestInfo request, CancellationToken ct)
    {
        var (user, hadFactor) = await guard.RequireEnrollmentRightAsync(principal, ct);
        var sessionId = principal.SessionIdOf();
        var key = PendingTotpKey(sessionId);
        var row = await ephemeral.RegisterAttemptAsync(EphemeralTokenKind.TotpEnroll, key, _options.MfaMaxAttempts, ct);
        if (row is null || row.UserId != user.Id) throw AuthException.Validation("No pending TOTP enrollment; call /auth/totp/enroll first.");

        var protectedSecret = Base64UrlCodec.Decode(JsonDocument.Parse(row.Detail!).RootElement.GetProperty("secret").GetString()!);
        var secret = totpProtector.Unprotect(protectedSecret, user.Id);
        if (!totp.Verify(secret, code, out var step)) throw AuthException.Validation("The TOTP code is not valid.");
        if (await ephemeral.ConsumeAsync(EphemeralTokenKind.TotpEnroll, key, ct) is null)
            throw AuthException.Validation("No pending TOTP enrollment; call /auth/totp/enroll first.");

        var replaced = user.TotpSecretEnc is not null;
        var now = time.GetUtcNow();
        user.TotpSecretEnc = protectedSecret;
        // The enrollment code is spent: it cannot be used again for a login in the same time step.
        user.TotpLastStep = step;
        user.UpdatedAt = now;
        await MarkSessionVerifiedAsync(sessionId, now, ct);
        audit.Add("auth.totp_enrolled", user.Id, request, targetType: "user", targetId: user.Id, detail: new { replaced });
        // One transaction: the new factor never commits without the other sessions being revoked.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.SaveChangesAsync(ct);
        if (hadFactor) await sessions.RevokeOthersAsync(user.Id, sessionId, RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>Begins turning on emailed sign-in codes: sends a confirmation code to the account address.</summary>
    public async Task BeginEmailOtpEnrollmentAsync(ClaimsPrincipal principal, string? stepUpToken, RequestInfo request, CancellationToken ct)
    {
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        if (user.EmailOtpEnabledAt is not null) throw AuthException.Conflict("Sign-in codes by email are already enabled.");
        var sessionId = principal.SessionIdOf();
        await emailCodes.IssueAsync(EmailCodePurpose.Enrollment, EmailCodes.Key(EmailCodePurpose.Enrollment, sessionId.ToString()),
            user.Id, sessionId, user.Email, ct);
        audit.Add("auth.email_code_sent", user.Id, request, detail: new { purpose = "enrollment" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Confirms the emailed code and enables the email second factor. An account that uses it cannot reset its password
    /// by email, because the mailbox would then stand in for both factors (08 §8.1).
    /// </summary>
    public async Task VerifyEmailOtpAsync(ClaimsPrincipal principal, string? code, RequestInfo request, CancellationToken ct)
    {
        var (user, hadFactor) = await guard.RequireEnrollmentRightAsync(principal, ct);
        var sessionId = principal.SessionIdOf();
        var key = EmailCodes.Key(EmailCodePurpose.Enrollment, sessionId.ToString());
        if (!await emailCodes.VerifyAsync(EmailCodePurpose.Enrollment, key, user.Id, code, ct))
            throw AuthException.Validation("The confirmation code is not valid; request a new one with /auth/email-otp/enroll.");

        var now = time.GetUtcNow();
        user.EmailOtpEnabledAt = now;
        user.UpdatedAt = now;
        await MarkSessionVerifiedAsync(sessionId, now, ct);
        audit.Add("auth.email_otp_enabled", user.Id, request, targetType: "user", targetId: user.Id);
        // One transaction: the new factor never commits without the other sessions being revoked.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.SaveChangesAsync(ct);
        if (hadFactor) await sessions.RevokeOthersAsync(user.Id, sessionId, RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>Replaces the backup codes. Needs a step-up, and revokes the other sessions like any credential change.</summary>
    public async Task<List<string>> RegenerateBackupCodesAsync(ClaimsPrincipal principal, string? stepUpToken, RequestInfo request,
        CancellationToken ct)
    {
        var (user, hadFactor) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        // Backup codes stand in for a lost factor; on their own they are not one.
        if (!hadFactor) throw AuthException.Validation("Enroll TOTP, email codes or a passkey before creating backup codes.");
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var plain = await factors.RegenerateBackupCodesAsync(user, ct);
        audit.Add("auth.backup_codes_generated", user.Id, request, targetType: "user", targetId: user.Id, detail: new { count = plain.Count });
        await db.SaveChangesAsync(ct);
        await sessions.RevokeOthersAsync(user.Id, principal.SessionIdOf(), RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
        return plain;
    }

    public static string? NormalizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > 320) return null;
        var trimmed = email.Trim();
        if (!MailAddress.TryCreate(trimmed, out var parsed) || parsed.Address != trimmed) return null;
        return trimmed.ToLowerInvariant();
    }

    private async Task<TokenPair> CompleteLoginAsync(string? mfaToken, string method, string? code, RequestInfo request, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(mfaToken)) throw AuthException.Unauthenticated();
        var hash = IEphemeralTokenStore.Hash(mfaToken);
        // Count the attempt first, so parallel guesses cannot exceed the cap.
        var row = await ephemeral.RegisterAttemptAsync(EphemeralTokenKind.Mfa, hash, _options.MfaMaxAttempts, ct);
        if (row?.UserId is null) throw AuthException.Unauthenticated();
        var user = await db.Users.SingleAsync(u => u.Id == row.UserId, ct);
        await factors.EnsureNotThrottledAsync(user.Id, ct);

        var ok = method switch
        {
            SecondFactorMethod.Totp => await factors.VerifyTotpAsync(user, code, ct),
            SecondFactorMethod.Email => await EmailCodesAllowedAsync(user, ct) &&
                                        await emailCodes.VerifyAsync(EmailCodePurpose.Login, LoginEmailKey(hash), user.Id, code, ct),
            SecondFactorMethod.BackupCode => await factors.ConsumeBackupCodeAsync(user, code, ct),
            _ => throw new ArgumentOutOfRangeException(nameof(method)),
        };
        if (!ok) await FailAsync(user.Id, "bad_" + (method == SecondFactorMethod.Email ? "email_code" : method), request, ct);

        if (await ephemeral.ConsumeAsync(EphemeralTokenKind.Mfa, hash, ct) is null) throw AuthException.Unauthenticated();
        var authMethod = method switch
        {
            SecondFactorMethod.Email => AuthMethod.PasswordEmail,
            SecondFactorMethod.BackupCode => AuthMethod.PasswordBackupCode,
            _ => AuthMethod.PasswordTotp,
        };
        if (method == SecondFactorMethod.BackupCode)
            audit.Add("auth.backup_code_used", user.Id, request, detail: new { remaining = await factors.UnusedBackupCodesAsync(user.Id, ct) });

        // An emailed code on an account without email codes enabled is the enrollment login: it proves the mailbox (and so
        // verifies the address) but is not an enrolled factor, so the session stays limited to enrollment.
        var enrollment = method == SecondFactorMethod.Email && user.EmailOtpEnabledAt is null;
        if (enrollment && user.EmailVerifiedAt is null)
        {
            user.EmailVerifiedAt = time.GetUtcNow();
            audit.Add("auth.email_verified", user.Id, request, targetType: "user", targetId: user.Id);
        }

        return await sessions.StartAsync(user, ClientKindFromDetail(row.Detail), authMethod, mfaVerified: !enrollment, request, ct);
    }

    /// <summary>Email completes a login when it is an enabled factor, or as the enrollment login of an account without any.</summary>
    private async Task<bool> EmailCodesAllowedAsync(UserEntity user, CancellationToken ct) =>
        user.EmailOtpEnabledAt is not null || !await factors.HasAnyFactorAsync(user, ct);

    private async Task MarkSessionVerifiedAsync(Guid sessionId, DateTimeOffset now, CancellationToken ct)
    {
        var session = await db.Sessions.SingleAsync(s => s.Id == sessionId, ct);
        session.MfaVerifiedAt ??= now;
    }

    internal static void ValidatePassword(string? password)
    {
        if (password is null || password.Length < PasswordMinLength || password.Length > PasswordMaxLength)
            throw AuthException.Validation($"password must be {PasswordMinLength}-{PasswordMaxLength} characters.");
    }

    private static byte[] PendingTotpKey(Guid sessionId) => SHA256.HashData(Encoding.ASCII.GetBytes("totp_enroll:" + sessionId));

    private static byte[] LoginEmailKey(byte[] mfaHash) => EmailCodes.Key(EmailCodePurpose.Login, Base64UrlCodec.Encode(mfaHash));

    private static ClientKind ClientKindFromDetail(string? detail) =>
        AuthDbValue.ParseClientKind(JsonDocument.Parse(detail!).RootElement.GetProperty("clientKind").GetString()!);

    private async Task FailAsync(Guid? userId, string reason, RequestInfo request, CancellationToken ct)
    {
        audit.Add("auth.login_failed", userId, request, detail: new { reason });
        await db.SaveChangesAsync(ct);
        throw AuthException.Unauthenticated();
    }
}
