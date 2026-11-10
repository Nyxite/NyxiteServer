using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>
/// Proof of control of the account email (08 §8.1). Registration emails a code. Until it is confirmed, the account can
/// only verify, resend and sign out: enrolling a factor waits, so an unverified account never becomes usable. Accounts
/// still unverified after <see cref="AuthOptions.UnverifiedAccountLifetime"/> are purged, so whoever registered someone
/// else's address cannot hold it.
/// </summary>
public sealed class EmailVerificationService(
    NyxiteDbContext db, EmailCodes emailCodes, SecondFactors factors, AuditWriter audit, TimeProvider time, IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    public bool IsExpired(UserEntity user) =>
        user.EmailVerifiedAt is null && user.CreatedAt <= time.GetUtcNow() - _options.UnverifiedAccountLifetime;

    public Task SendAsync(UserEntity user, CancellationToken ct) =>
        emailCodes.IssueAsync(EmailCodePurpose.Verification, Key(user.Id), user.Id, null, user.Email, ct);

    /// <summary>Sends a new code, replacing the old one. A no-op once the address is verified.</summary>
    public async Task ResendAsync(ClaimsPrincipal principal, RequestInfo request, CancellationToken ct)
    {
        var user = await LoadAsync(principal, ct);
        if (user.EmailVerifiedAt is not null) return;
        await SendAsync(user, ct);
        audit.Add("auth.email_code_sent", user.Id, request, detail: new { purpose = "verification" });
        await db.SaveChangesAsync(ct);
    }

    public async Task VerifyAsync(ClaimsPrincipal principal, string? code, RequestInfo request, CancellationToken ct)
    {
        var user = await LoadAsync(principal, ct);
        if (user.EmailVerifiedAt is not null) return;
        await factors.EnsureNotThrottledAsync(user.Id, ct);
        if (!await emailCodes.VerifyAsync(EmailCodePurpose.Verification, Key(user.Id), user.Id, code, ct))
        {
            audit.Add(SecondFactors.EmailVerifyFailedAction, user.Id, request);
            await db.SaveChangesAsync(ct);
            throw AuthException.Validation("The verification code is not valid; request a new one with /auth/email/verify/resend.");
        }

        var now = time.GetUtcNow();
        user.EmailVerifiedAt = now;
        user.UpdatedAt = now;
        audit.Add("auth.email_verified", user.Id, request, targetType: "user", targetId: user.Id);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Deletes accounts that stayed unverified past their lifetime, optionally only the one holding <paramref name="email"/>.
    /// Such an account never had a factor, keys or content, so only its auth rows go with it. Returns the number purged.
    /// </summary>
    public async Task<int> PurgeExpiredAsync(string? email, CancellationToken ct)
    {
        var cutoff = time.GetUtcNow() - _options.UnverifiedAccountLifetime;
        var query = db.Users.Where(u => u.EmailVerifiedAt == null && u.CreatedAt <= cutoff);
        if (email is not null) query = query.Where(u => u.Email == email);
        var ids = await query.Select(u => u.Id).ToListAsync(ct);
        if (ids.Count == 0) return 0;

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.EphemeralTokens.Where(t => t.UserId != null && ids.Contains(t.UserId.Value)).ExecuteDeleteAsync(ct);
        await db.Sessions.Where(s => ids.Contains(s.UserId)).ExecuteDeleteAsync(ct);
        await db.WebAuthnCredentials.Where(c => ids.Contains(c.UserId)).ExecuteDeleteAsync(ct);
        await db.Users.Where(u => ids.Contains(u.Id) && u.EmailVerifiedAt == null).ExecuteDeleteAsync(ct);
        foreach (var id in ids)
            audit.Add("auth.unverified_account_purged", null, RequestInfo.None, ActorKind.System, targetType: "user", targetId: id);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return ids.Count;
    }

    private static byte[] Key(Guid userId) => EmailCodes.Key(EmailCodePurpose.Verification, userId.ToString());

    private async Task<UserEntity> LoadAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var id = principal.UserId();
        return await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct) ?? throw AuthException.Unauthenticated();
    }
}
