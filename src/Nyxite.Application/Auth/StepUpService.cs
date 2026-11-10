using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

public sealed record StepUpToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>
/// Step-up (08 §8.2): a full session proves an existing second factor again and receives a single-use token, bound to
/// the session and short-lived, that authorizes exactly one factor change (<see cref="FactorChangeGuard"/>). The proof
/// is required on the change itself rather than through a recent-factor window, because a token stolen right after a
/// login would pass any window but cannot produce a fresh factor.
/// </summary>
public sealed class StepUpService(
    NyxiteDbContext db,
    SecondFactors factors,
    EmailCodes emailCodes,
    PasskeyService passkeys,
    IEphemeralTokenStore ephemeral,
    AuditWriter audit,
    TimeProvider time,
    IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    /// <summary>Emails a step-up code. Only for accounts that use email codes, so email never weakens a TOTP-only account.</summary>
    public async Task SendEmailCodeAsync(ClaimsPrincipal principal, RequestInfo request, CancellationToken ct)
    {
        var user = await LoadAsync(principal, ct);
        if (user.EmailOtpEnabledAt is null) throw AuthException.Validation("Sign-in codes by email are not enabled for this account.");
        var sessionId = principal.SessionIdOf();
        await emailCodes.IssueAsync(EmailCodePurpose.StepUp, Key(sessionId), user.Id, sessionId, user.Email, ct);
        audit.Add("auth.email_code_sent", user.Id, request, detail: new { purpose = "step_up" });
        await db.SaveChangesAsync(ct);
    }

    public Task<string> BeginPasskeyAsync(ClaimsPrincipal principal, CancellationToken ct) => passkeys.BeginStepUpAsync(principal, ct);

    public async Task<StepUpToken> IssueAsync(ClaimsPrincipal principal, string? method, string? code, JsonElement? credential,
        RequestInfo request, CancellationToken ct)
    {
        var user = await LoadAsync(principal, ct);
        var sessionId = principal.SessionIdOf();
        await factors.EnsureNotThrottledAsync(user.Id, ct);
        var ok = method switch
        {
            SecondFactorMethod.Totp => await factors.VerifyTotpAsync(user, code, ct),
            SecondFactorMethod.Email => user.EmailOtpEnabledAt is not null &&
                                        await emailCodes.VerifyAsync(EmailCodePurpose.StepUp, Key(sessionId), user.Id, code, ct),
            SecondFactorMethod.BackupCode => await factors.ConsumeBackupCodeAsync(user, code, ct),
            SecondFactorMethod.Passkey => await passkeys.VerifyStepUpAsync(principal, credential, ct),
            _ => throw AuthException.Validation("method must be one of totp, email, backup_code, passkey."),
        };
        if (!ok)
        {
            audit.Add(SecondFactors.StepUpFailedAction, user.Id, request, detail: new { method });
            await db.SaveChangesAsync(ct);
            throw AuthException.SecondFactorRequired("The second factor is not valid.");
        }

        var token = await ephemeral.IssueAsync(EphemeralTokenKind.StepUp, user.Id, sessionId, _options.StepUpLifetime, null, ct);
        audit.Add("auth.step_up", user.Id, request, targetType: "session", targetId: sessionId, detail: new { method });
        await db.SaveChangesAsync(ct);
        return new StepUpToken(token, time.GetUtcNow() + _options.StepUpLifetime);
    }

    private static byte[] Key(Guid sessionId) => EmailCodes.Key(EmailCodePurpose.StepUp, sessionId.ToString());

    private async Task<UserEntity> LoadAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var id = principal.UserId();
        return await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct) ?? throw AuthException.Unauthenticated();
    }
}
