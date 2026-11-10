using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Email;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

public sealed record FactorStatus(bool EmailVerified, bool Totp, bool EmailOtp, int Passkeys, int BackupCodesRemaining, bool PasswordResetByEmail);

public sealed record PasskeyInfo(Guid Id, string? Label, DateTimeOffset CreatedAt);

public sealed record SessionInfo(Guid Id, ClientKind ClientKind, AuthMethod AuthMethod, DateTimeOffset CreatedAt,
    DateTimeOffset LastSeenAt, DateTimeOffset ExpiresAt, string? LastIp, string? UserAgent, bool Current);

/// <summary>
/// Managing the caller's own sign-in methods (08 §8.1): factor overview, removing a factor, passkeys, own sessions, and
/// the password (change, forgot, reset). Removing a factor or changing the password needs a step-up token like adding
/// one, and the last factor (TOTP, email codes, passkey) can never be removed, so an account cannot fall back to the
/// password alone.
/// </summary>
public sealed class AccountSecurityService(
    NyxiteDbContext db,
    PasswordHasher hasher,
    SecondFactors factors,
    FactorChangeGuard guard,
    SessionService sessions,
    IEphemeralTokenStore ephemeral,
    EmailOutbox outbox,
    EmailVerificationService emailVerification,
    AuditWriter audit,
    TimeProvider time,
    IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    public async Task<FactorStatus> GetFactorsAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var user = await LoadAsync(principal, ct);
        var passkeys = await db.WebAuthnCredentials.CountAsync(c => c.UserId == user.Id, ct);
        return new FactorStatus(user.EmailVerifiedAt is not null, user.TotpSecretEnc is not null, user.EmailOtpEnabledAt is not null,
            passkeys, await factors.UnusedBackupCodesAsync(user.Id, ct), user.EmailOtpEnabledAt is null);
    }

    public async Task<List<PasskeyInfo>> ListPasskeysAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        return await db.WebAuthnCredentials.Where(c => c.UserId == userId).OrderBy(c => c.CreatedAt)
            .Select(c => new PasskeyInfo(c.Id, c.Label, c.CreatedAt)).ToListAsync(ct);
    }

    public async Task DeletePasskeyAsync(ClaimsPrincipal principal, Guid id, string? stepUpToken, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        // Someone else's passkey id answers like an unknown one (existence-hiding, 04 §4.4).
        var credential = await db.WebAuthnCredentials.SingleOrDefaultAsync(c => c.Id == id && c.UserId == userId, ct)
                         ?? throw AuthException.NotFound();
        await using var tx = await LockFactorsAsync(userId, ct);
        await EnsureNotLastFactorAsync(userId, removing: Factor.Passkey, ct);
        await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        db.WebAuthnCredentials.Remove(credential);
        audit.Add("auth.passkey_removed", userId, request, targetType: "user", targetId: userId);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task DisableTotpAsync(ClaimsPrincipal principal, string? stepUpToken, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        await using var tx = await LockFactorsAsync(userId, ct);
        await EnsureNotLastFactorAsync(userId, removing: Factor.Totp, ct);
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        user.TotpSecretEnc = null;
        user.TotpLastStep = null;
        user.UpdatedAt = time.GetUtcNow();
        audit.Add("auth.totp_removed", user.Id, request, targetType: "user", targetId: user.Id);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task DisableEmailOtpAsync(ClaimsPrincipal principal, string? stepUpToken, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        await using var tx = await LockFactorsAsync(userId, ct);
        await EnsureNotLastFactorAsync(userId, removing: Factor.Email, ct);
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        user.EmailOtpEnabledAt = null;
        user.UpdatedAt = time.GetUtcNow();
        audit.Add("auth.email_otp_disabled", user.Id, request, targetType: "user", targetId: user.Id);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<List<SessionInfo>> ListSessionsAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        var current = principal.SessionIdOf();
        var now = time.GetUtcNow();
        var rows = await db.Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.LastSeenAt).ToListAsync(ct);
        return rows.Select(s => new SessionInfo(s.Id, s.ClientKind, s.AuthMethod, s.CreatedAt, s.LastSeenAt, s.ExpiresAt,
            s.LastIp?.ToString(), s.UserAgent, s.Id == current)).ToList();
    }

    /// <summary>Signs out one of the caller's own sessions. Another user's session id answers <c>404</c>.</summary>
    public async Task RevokeSessionAsync(ClaimsPrincipal principal, Guid sessionId, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (!await db.Sessions.AnyAsync(s => s.Id == sessionId && s.UserId == userId, ct)) throw AuthException.NotFound();
        await sessions.RevokeAsync(sessionId, userId, RevokeReason.Logout, request, ct);
    }

    /// <summary>
    /// Changes the password: the current password plus a step-up token. The other sessions are revoked, because whoever
    /// changes the password may be someone who should not keep the owner's sessions alive.
    /// </summary>
    public async Task ChangePasswordAsync(ClaimsPrincipal principal, string? currentPassword, string? newPassword, string? stepUpToken,
        RequestInfo request, CancellationToken ct)
    {
        NativeAuthService.ValidatePassword(newPassword);
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        var valid = user.PasswordVerifier is not null && user.PasswordPepperVersion is not null && currentPassword is not null &&
                    (await hasher.VerifyAsync(currentPassword, user.PasswordVerifier, user.PasswordPepperVersion.Value, ct)).Valid;
        if (!valid)
        {
            audit.Add("auth.password_change_failed", user.Id, request);
            await db.SaveChangesAsync(ct);
            throw AuthException.Validation("The current password is not correct.");
        }

        await SetPasswordAsync(user, newPassword!, ct);
        audit.Add("auth.password_changed", user.Id, request, targetType: "user", targetId: user.Id);
        // One transaction: the new password never commits without the other sessions being revoked.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.SaveChangesAsync(ct);
        await DeleteResetTokensAsync(user.Id, ct);
        await sessions.RevokeOthersAsync(user.Id, principal.SessionIdOf(), RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// Emails a reset token when the account may be reset by email: verified, and not using email codes as a second
    /// factor, because the mailbox would then hold both factors (08 §8.1). The caller always gets the same answer.
    /// </summary>
    public async Task ForgotPasswordAsync(string? address, RequestInfo request, CancellationToken ct)
    {
        var normalized = NativeAuthService.NormalizeEmail(address);
        if (normalized is null) return;
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == normalized, ct);
        if (user is null || user.EmailVerifiedAt is null || user.PasswordVerifier is null || emailVerification.IsExpired(user)) return;
        if (user.EmailOtpEnabledAt is not null)
        {
            audit.Add("auth.password_reset_refused", user.Id, request, detail: new { reason = "email_second_factor" });
            await db.SaveChangesAsync(ct);
            return;
        }

        // Per account, not per caller: the per-IP limit alone would let many addresses flood one mailbox.
        var since = time.GetUtcNow() - _options.PasswordResetEmailWindow;
        var recent = await db.AuditLog.CountAsync(
            a => a.ActorId == user.Id && a.Action == "auth.password_reset_requested" && a.OccurredAt > since, ct);
        if (recent >= _options.PasswordResetEmailLimit)
        {
            audit.Add("auth.password_reset_refused", user.Id, request, detail: new { reason = "too_many_requests" });
            await db.SaveChangesAsync(ct);
            return;
        }

        var lifetime = _options.Lifetimes.PasswordReset;
        var token = await ephemeral.IssueAsync(EphemeralTokenKind.PasswordReset, user.Id, null, lifetime, null, ct);
        audit.Add("auth.password_reset_requested", user.Id, request);

        var minutes = (int)Math.Ceiling(lifetime.TotalMinutes);
        var link = string.IsNullOrWhiteSpace(_options.PasswordResetUrl)
            ? $"Your reset code is:\n\n{token}"
            : $"Open this link to choose a new password:\n\n{_options.PasswordResetUrl.Replace("{token}", Uri.EscapeDataString(token))}";
        outbox.Enqueue(user.Email, "Reset your Nyxite password",
            $"{link}\n\nIt expires in {minutes} minutes and works once. A new password restores sign-in only: your notes still " +
            "open with your recovery phrase or an enrolled device. If you did not ask for this, ignore this email.", lifetime);
        await db.SaveChangesAsync(ct);
        outbox.Notify();
    }

    /// <summary>Sets a new password from a reset token and revokes every session of the account. The second factor stays.</summary>
    public async Task ResetPasswordAsync(string? resetToken, string? newPassword, RequestInfo request, CancellationToken ct)
    {
        NativeAuthService.ValidatePassword(newPassword);
        if (string.IsNullOrEmpty(resetToken)) throw ResetExpired();
        // One transaction from consuming the token to revoking the sessions: a failure in between leaves the token usable.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var row = await ephemeral.ConsumeAsync(EphemeralTokenKind.PasswordReset, IEphemeralTokenStore.Hash(resetToken), ct);
        if (row?.UserId is null) throw ResetExpired();
        var user = await db.Users.SingleAsync(u => u.Id == row.UserId, ct);
        // Email codes enabled after the token was sent: the mailbox must not reset such an account.
        if (user.EmailOtpEnabledAt is not null) throw ResetExpired();

        await SetPasswordAsync(user, newPassword!, ct);
        audit.Add("auth.password_reset", user.Id, request, targetType: "user", targetId: user.Id);
        await db.SaveChangesAsync(ct);
        await DeleteResetTokensAsync(user.Id, ct);
        await sessions.RevokeOthersAsync(user.Id, Guid.Empty, RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
    }

    private enum Factor { Totp, Email, Passkey }

    /// <summary>
    /// Opens a transaction holding the user row lock, so two parallel removals of different factors are checked one after
    /// the other and cannot both pass the last-factor rule.
    /// </summary>
    private async Task<Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction> LockFactorsAsync(Guid userId, CancellationToken ct)
    {
        var tx = await db.Database.BeginTransactionAsync(ct);
        await db.Database.ExecuteSqlAsync($"SELECT 1 FROM users WHERE id = {userId} FOR UPDATE", ct);
        return tx;
    }

    private async Task EnsureNotLastFactorAsync(Guid userId, Factor removing, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId, ct) ?? throw AuthException.Unauthenticated();
        var passkeys = await db.WebAuthnCredentials.CountAsync(c => c.UserId == userId, ct);
        var has = removing switch
        {
            Factor.Totp => user.TotpSecretEnc is not null,
            Factor.Email => user.EmailOtpEnabledAt is not null,
            _ => passkeys > 0,
        };
        if (!has) throw AuthException.NotFound();
        var remaining = (user.TotpSecretEnc is not null ? 1 : 0) + (user.EmailOtpEnabledAt is not null ? 1 : 0) + passkeys - 1;
        if (remaining == 0) throw AuthException.Conflict("The last second factor cannot be removed; add another one first.");
    }

    private async Task SetPasswordAsync(UserEntity user, string password, CancellationToken ct)
    {
        var (verifier, version) = await hasher.HashAsync(password, ct);
        user.PasswordVerifier = verifier;
        user.PasswordPepperVersion = version;
        user.UpdatedAt = time.GetUtcNow();
    }

    private Task DeleteResetTokensAsync(Guid userId, CancellationToken ct) =>
        db.EphemeralTokens.Where(t => t.UserId == userId && t.Kind == EphemeralTokenKind.PasswordReset).ExecuteDeleteAsync(ct);

    private static AuthException ResetExpired() => new(410, "link_expired", "The reset link is invalid or has expired.");

    private async Task<UserEntity> LoadAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var id = principal.UserId();
        return await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct) ?? throw AuthException.Unauthenticated();
    }
}
