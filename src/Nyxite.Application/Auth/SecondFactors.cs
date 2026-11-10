using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>The second factors a password can be completed with (08 §8.1(a)), as named on the wire.</summary>
public static class SecondFactorMethod
{
    public const string Totp = "totp";
    public const string Email = "email";
    public const string BackupCode = "backup_code";
    public const string Passkey = "passkey";
}

/// <summary>
/// Checks second-factor codes against the account: TOTP with replay protection, backup codes, and the account-wide
/// failure cap that applies across every <c>mfaToken</c>, step-up and email verification.
/// </summary>
public sealed class SecondFactors(
    NyxiteDbContext db, TotpCodes totp, TotpSecretProtector totpProtector, OneTimeCodes codes, TimeProvider time,
    IOptions<AuthOptions> options, ILogger<SecondFactors> logger)
{
    private const string BackupPurpose = "backup_code";

    /// <summary>Audit actions and login-failure reasons that count as a wrong second-factor code.</summary>
    public static readonly string[] FailureReasons = ["bad_totp", "bad_email_code", "bad_backup_code"];

    public const string StepUpFailedAction = "auth.step_up_failed";
    public const string EmailVerifyFailedAction = "auth.email_verify_failed";

    private readonly AuthOptions _options = options.Value;

    /// <summary>True when the account has a factor that completes a password login or a passkey.</summary>
    public async Task<bool> HasAnyFactorAsync(UserEntity user, CancellationToken ct) =>
        user.TotpSecretEnc is not null || user.EmailOtpEnabledAt is not null ||
        await db.WebAuthnCredentials.AnyAsync(c => c.UserId == user.Id, ct);

    /// <summary>The methods that can complete a password login for this account, in a stable order.</summary>
    public async Task<List<string>> PasswordMethodsAsync(UserEntity user, CancellationToken ct)
    {
        var methods = new List<string>();
        if (user.TotpSecretEnc is not null) methods.Add(SecondFactorMethod.Totp);
        if (user.EmailOtpEnabledAt is not null) methods.Add(SecondFactorMethod.Email);
        if (await db.BackupCodes.AnyAsync(c => c.UserId == user.Id && c.UsedAt == null, ct)) methods.Add(SecondFactorMethod.BackupCode);
        return methods;
    }

    /// <summary>
    /// Verifies a TOTP code and records its time step, so the same code is never accepted twice (RFC 6238 §5.2). The
    /// conditional update makes two concurrent uses of one code race: exactly one wins.
    /// </summary>
    public async Task<bool> VerifyTotpAsync(UserEntity user, string? code, CancellationToken ct)
    {
        if (user.TotpSecretEnc is null) return false;
        byte[] secret;
        try
        {
            secret = totpProtector.Unprotect(user.TotpSecretEnc, user.Id);
        }
        catch (CryptographicException e)
        {
            // Its pepper version is no longer configured (14): the code cannot be checked, which counts as a wrong code.
            logger.LogError(e, "The TOTP secret of user {UserId} cannot be decrypted.", user.Id);
            return false;
        }

        if (!totp.Verify(secret, code, out var step)) return false;
        var won = await db.Users.Where(u => u.Id == user.Id && (u.TotpLastStep == null || u.TotpLastStep < step))
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.TotpLastStep, step), ct);
        if (won != 1) return false;
        user.TotpLastStep = step;
        db.Entry(user).Property(u => u.TotpLastStep).IsModified = false;
        return true;
    }

    /// <summary>Consumes a matching unused backup code. Each code works once.</summary>
    public async Task<bool> ConsumeBackupCodeAsync(UserEntity user, string? code, CancellationToken ct)
    {
        var normalized = OneTimeCodes.NormalizeBackupCode(code);
        var unused = await db.BackupCodes.AsNoTracking().Where(c => c.UserId == user.Id && c.UsedAt == null).ToListAsync(ct);
        // Compare against every row so the time taken does not reveal which code matched.
        BackupCodeEntity? match = null;
        foreach (var row in unused)
        {
            if (normalized is not null && codes.Verify(BackupPurpose, normalized, row.CodeHash, row.PepperVersion)) match ??= row;
        }

        if (match is null) return false;
        var now = time.GetUtcNow();
        return await db.BackupCodes.Where(c => c.Id == match.Id && c.UsedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.UsedAt, now), ct) == 1;
    }

    /// <summary>Replaces the account's backup codes with a new set and returns the codes, which are never shown again.</summary>
    public async Task<List<string>> RegenerateBackupCodesAsync(UserEntity user, CancellationToken ct)
    {
        await db.BackupCodes.Where(c => c.UserId == user.Id).ExecuteDeleteAsync(ct);
        var now = time.GetUtcNow();
        var plain = new List<string>();
        for (var i = 0; i < _options.BackupCodeCount; i++)
        {
            var code = OneTimeCodes.NewBackupCode();
            var (hash, version) = codes.Hash(BackupPurpose, OneTimeCodes.NormalizeBackupCode(code)!);
            db.BackupCodes.Add(new BackupCodeEntity
            {
                Id = Guid.CreateVersion7(now), UserId = user.Id, CodeHash = hash, PepperVersion = version, CreatedAt = now,
            });
            plain.Add(code);
        }

        return plain;
    }

    public Task<int> UnusedBackupCodesAsync(Guid userId, CancellationToken ct) =>
        db.BackupCodes.CountAsync(c => c.UserId == userId && c.UsedAt == null, ct);

    /// <summary>
    /// Refuses further code attempts once the account collected <see cref="AuthOptions.SecondFactorFailureLimit"/> wrong
    /// codes within the window. The per-<c>mfaToken</c> cap alone does not bound guessing, because whoever has the
    /// password can open new <c>mfaToken</c>s. The count comes from <c>audit_log</c>, where every failure is recorded.
    /// </summary>
    public async Task EnsureNotThrottledAsync(Guid userId, CancellationToken ct)
    {
        var since = time.GetUtcNow() - _options.SecondFactorFailureWindow;
        var oldest = await db.Database.SqlQuery<DateTimeOffset>($"""
            SELECT occurred_at AS "Value" FROM audit_log
            WHERE actor_id = {userId} AND occurred_at > {since}
              AND ((action = 'auth.login_failed' AND detail->>'reason' = ANY({FailureReasons}))
                   OR action IN ({StepUpFailedAction}, {EmailVerifyFailedAction}))
            ORDER BY occurred_at DESC
            LIMIT {_options.SecondFactorFailureLimit}
            """).ToListAsync(ct);
        if (oldest.Count < _options.SecondFactorFailureLimit) return;
        var retry = oldest.Min() + _options.SecondFactorFailureWindow - time.GetUtcNow();
        throw AuthException.RateLimited(retry > TimeSpan.Zero ? retry : TimeSpan.FromSeconds(1));
    }
}
