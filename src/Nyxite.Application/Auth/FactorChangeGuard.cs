using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>
/// Who may add or change a second factor (08 §8.2). An account without any factor may enroll its first one from any
/// session, but only after its email is verified. Once a factor exists, a change needs a full session and, on the
/// request that starts the change, a single-use step-up token minted by <c>POST /auth/step-up</c> for this session.
/// A stolen access token therefore cannot add a factor, because it cannot produce the step-up proof.
/// </summary>
public sealed class FactorChangeGuard(NyxiteDbContext db, SecondFactors factors, IEphemeralTokenStore ephemeral)
{
    /// <summary>The basic right, used by the second step of a change (verify / finish) that a first step already authorized.</summary>
    public async Task<(UserEntity User, bool HadFactor)> RequireEnrollmentRightAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct) ?? throw AuthException.Unauthenticated();
        if (user.EmailVerifiedAt is null) throw AuthException.EmailUnverified();
        var hadFactor = await factors.HasAnyFactorAsync(user, ct);
        if (hadFactor && !principal.HasSecondFactor()) throw AuthException.SecondFactorRequired();
        return (user, hadFactor);
    }

    /// <summary>The right to start a change: on an account with a factor it consumes a step-up token of this session.</summary>
    public async Task<(UserEntity User, bool HadFactor)> AuthorizeChangeAsync(ClaimsPrincipal principal, string? stepUpToken,
        CancellationToken ct)
    {
        var (user, hadFactor) = await RequireEnrollmentRightAsync(principal, ct);
        if (!hadFactor) return (user, false);
        if (string.IsNullOrEmpty(stepUpToken))
            throw AuthException.SecondFactorRequired("Changing a sign-in method needs a step-up token from /auth/step-up.");
        var row = await ephemeral.ConsumeAsync(EphemeralTokenKind.StepUp, IEphemeralTokenStore.Hash(stepUpToken), ct);
        if (row is null || row.UserId != user.Id || row.SessionId != principal.SessionIdOf())
            throw AuthException.SecondFactorRequired("The step-up token is not valid for this session.");
        return (user, true);
    }
}
