using Nyxite.Application.Auth;
using Nyxite.Contracts.Auth;
using Nyxite.Domain.Identity;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>
/// Managing the caller's own sign-in methods and sessions, and the password (08 §8.1, §8.7). A DELETE carries its step-up
/// token in the <c>Nyxite-Step-Up</c> header, because request bodies on DELETE are dropped by some clients and proxies,
/// and a token in the URL would land in access logs.
/// </summary>
public static class AccountSecurityEndpoints
{
    public const string StepUpHeader = "Nyxite-Step-Up";

    public static RouteGroupBuilder MapAccountSecurityEndpoints(this RouteGroupBuilder api)
    {
        var auth = api.MapGroup("/auth");

        auth.MapGet("/factors", async (AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            var f = await account.GetFactorsAsync(http.User, ct);
            return Results.Ok(new FactorsDto(f.EmailVerified, f.Totp, f.EmailOtp, f.Passkeys, f.BackupCodesRemaining, f.PasswordResetByEmail));
        }).RequireAuthorization(AuthSetup.Enrollment);

        auth.MapDelete("/totp", async (AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.DisableTotpAsync(http.User, StepUp(http), http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization();

        auth.MapDelete("/email-otp", async (AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.DisableEmailOtpAsync(http.User, StepUp(http), http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization();

        auth.MapGet("/passkeys", async (AccountSecurityService account, HttpContext http, CancellationToken ct) =>
            Results.Ok((await account.ListPasskeysAsync(http.User, ct)).Select(p => new PasskeyDto(p.Id, p.Label, p.CreatedAt))))
            .RequireAuthorization();

        auth.MapDelete("/passkeys/{id:guid}", async (Guid id, AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.DeletePasskeyAsync(http.User, id, StepUp(http), http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization();

        auth.MapGet("/sessions", async (AccountSecurityService account, HttpContext http, CancellationToken ct) =>
            Results.Ok((await account.ListSessionsAsync(http.User, ct)).Select(s => new SessionDto(s.Id, AuthDbValue.Of(s.ClientKind),
                AuthDbValue.Of(s.AuthMethod), s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.LastIp, s.UserAgent, s.Current))))
            .RequireAuthorization();

        auth.MapDelete("/sessions/{id:guid}", async (Guid id, AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.RevokeSessionAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization();

        auth.MapPost("/password/change", async (ChangePasswordRequest body, AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.ChangePasswordAsync(http.User, body.CurrentPassword, body.NewPassword, body.StepUpToken, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization().RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/password/forgot", async (ForgotRequest body, AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.ForgotPasswordAsync(body.Email, http.Info(), ct);
            return Results.Accepted();
        }).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/password/reset", async (ResetRequest body, AccountSecurityService account, HttpContext http, CancellationToken ct) =>
        {
            await account.ResetPasswordAsync(body.ResetToken, body.NewPassword, http.Info(), ct);
            return Results.NoContent();
        }).RequireRateLimiting(RateLimiting.Auth);

        return api;
    }

    private static string? StepUp(HttpContext http) =>
        http.Request.Headers.TryGetValue(StepUpHeader, out var v) && !string.IsNullOrEmpty(v) ? v.ToString() : null;
}
