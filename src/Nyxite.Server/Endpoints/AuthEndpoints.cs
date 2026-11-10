using System.Text.Json;
using Nyxite.Application.Auth;
using Nyxite.Contracts.Auth;
using Nyxite.Domain.Identity;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>Native auth endpoints under <c>/api/v1/auth</c> (08 §8.1, 04).</summary>
public static class AuthEndpoints
{

    private static TokenPairDto Dto(TokenPair t) => new(t.AccessToken, t.RefreshToken, t.AccessTokenExpiresAt);

    public static RouteGroupBuilder MapAuthEndpoints(this RouteGroupBuilder api)
    {
        var auth = api.MapGroup("/auth");

        // ---- sign-in (rate-limited per IP, 13 §13.5)

        auth.MapPost("/register", async (RegisterRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            var tokens = await native.RegisterAsync(body.Email, body.DisplayName, body.Password, ParseClientKind(body.ClientKind), http.Info(), ct);
            return Results.Json(Dto(tokens), statusCode: StatusCodes.Status201Created);
        }).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/login", async (LoginRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            var result = await native.LoginAsync(body.Email, body.Password, ParseClientKind(body.ClientKind), http.Info(), ct);
            return result switch
            {
                LoginResult.SecondFactorRequired s =>
                    Results.Ok(new SecondFactorChallengeDto("second_factor_required", s.MfaToken, s.Methods, s.Enrollment)),
                _ => throw new InvalidOperationException(),
            };
        }).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/login/totp", async (TotpLoginRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
            Results.Ok(Dto(await native.CompleteTotpLoginAsync(body.MfaToken, body.TotpCode, http.Info(), ct))))
            .RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/login/email/send", async (MfaTokenRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            await native.SendLoginEmailCodeAsync(body.MfaToken, http.Info(), ct);
            return Results.NoContent();
        }).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/login/email", async (CodeLoginRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
            Results.Ok(Dto(await native.CompleteEmailLoginAsync(body.MfaToken, body.Code, http.Info(), ct))))
            .RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/login/backup-code", async (CodeLoginRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
            Results.Ok(Dto(await native.CompleteBackupCodeLoginAsync(body.MfaToken, body.Code, http.Info(), ct))))
            .RequireRateLimiting(RateLimiting.Auth);

        // ---- email verification (any session of the account, 08 §8.1)

        auth.MapPost("/email/verify", async (CodeRequest body, EmailVerificationService verification, HttpContext http, CancellationToken ct) =>
        {
            await verification.VerifyAsync(http.User, body.Code, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/email/verify/resend", async (EmailVerificationService verification, HttpContext http, CancellationToken ct) =>
        {
            await verification.ResendAsync(http.User, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment).RequireRateLimiting(RateLimiting.Auth);

        // ---- second factors; a change on an account that already has one needs a step-up token (08 §8.2)

        auth.MapPost("/totp/enroll", async (StepUpTokenRequest? body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            var e = await native.BeginTotpEnrollmentAsync(http.User, body?.StepUpToken, ct);
            return Results.Ok(new TotpEnrollmentDto(e.Secret, e.OtpAuthUri));
        }).RequireAuthorization(AuthSetup.Enrollment);

        auth.MapPost("/totp/verify", async (TotpCodeRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            await native.VerifyTotpAsync(http.User, body.TotpCode, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment);

        auth.MapPost("/email-otp/enroll", async (StepUpTokenRequest? body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            await native.BeginEmailOtpEnrollmentAsync(http.User, body?.StepUpToken, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment).RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/email-otp/verify", async (CodeRequest body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
        {
            await native.VerifyEmailOtpAsync(http.User, body.Code, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment);

        auth.MapPost("/backup-codes", async (StepUpTokenRequest? body, NativeAuthService native, HttpContext http, CancellationToken ct) =>
            Results.Ok(new BackupCodesDto(await native.RegenerateBackupCodesAsync(http.User, body?.StepUpToken, http.Info(), ct))))
            .RequireAuthorization();

        auth.MapPost("/step-up", async (StepUpRequest body, StepUpService stepUp, HttpContext http, CancellationToken ct) =>
        {
            var token = await stepUp.IssueAsync(http.User, body.Method, body.Code, body.Credential, http.Info(), ct);
            return Results.Ok(new StepUpDto(token.Token, token.ExpiresAt));
        }).RequireAuthorization().RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/step-up/email", async (StepUpService stepUp, HttpContext http, CancellationToken ct) =>
        {
            await stepUp.SendEmailCodeAsync(http.User, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization().RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/step-up/passkey/options", async (StepUpService stepUp, HttpContext http, CancellationToken ct) =>
            Results.Content(await stepUp.BeginPasskeyAsync(http.User, ct), "application/json"))
            .RequireAuthorization();

        auth.MapPost("/webauthn/register/options", async (StepUpTokenRequest? body, PasskeyService passkeys, HttpContext http, CancellationToken ct) =>
            Results.Content(await passkeys.BeginRegistrationAsync(http.User, body?.StepUpToken, ct), "application/json"))
            .RequireAuthorization(AuthSetup.Enrollment);

        auth.MapPost("/webauthn/register", async (PasskeyRegisterRequest body, PasskeyService passkeys, HttpContext http, CancellationToken ct) =>
        {
            await passkeys.FinishRegistrationAsync(http.User, body.Credential, body.Label, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment);

        // ---- passkey sign-in

        // The optional email is accepted for contract compatibility but ignored: credentials are discoverable, and
        // answering per email would reveal which accounts have passkeys.
        auth.MapPost("/webauthn/assert/options", async (AssertOptionsRequest? body, PasskeyService passkeys, CancellationToken ct) =>
            Results.Content(await passkeys.BeginAssertionAsync(ct), "application/json"))
            .RequireRateLimiting(RateLimiting.Auth);

        auth.MapPost("/webauthn/assert", async (AssertRequest body, PasskeyService passkeys, HttpContext http, CancellationToken ct) =>
            Results.Ok(Dto(await passkeys.FinishAssertionAsync(body.Credential, ParseClientKind(body.ClientKind), http.Info(), ct))))
            .RequireRateLimiting(RateLimiting.Auth);

        // ---- enterprise OIDC (stub)

        auth.MapGet("/oidc/authorize", async (string? client, string? redirectUri, ExternalIdentityProviderResolver idp, CancellationToken ct) =>
        {
            var provider = idp.Current ?? throw AuthException.NotFound();
            return Results.Redirect((await provider.BeginAsync(client ?? "", redirectUri ?? "", ct)).ToString());
        });

        auth.MapGet("/oidc/callback", async (string? code, string? state, ExternalIdentityProviderResolver idp, CancellationToken ct) =>
        {
            var provider = idp.Current ?? throw AuthException.NotFound();
            await provider.CompleteAsync(code ?? "", state ?? "", ct);
            throw AuthException.Unavailable("Enterprise OIDC sign-in is not implemented yet.");
        });

        auth.MapPost("/oidc/token", (OidcTokenRequest body, ExternalIdentityProviderResolver idp) =>
        {
            _ = idp.Current ?? throw AuthException.NotFound();
            throw AuthException.Unavailable("Enterprise OIDC sign-in is not implemented yet.");
        }).RequireRateLimiting(RateLimiting.Auth);

        // ---- sessions

        auth.MapPost("/refresh", async (RefreshRequest body, SessionService sessions, HttpContext http, CancellationToken ct) =>
        {
            if (string.IsNullOrEmpty(body.RefreshToken)) throw AuthException.Unauthenticated();
            return Results.Ok(Dto(await sessions.RefreshAsync(body.RefreshToken, http.Info(), ct)));
        });

        auth.MapPost("/logout", async (SessionService sessions, HttpContext http, CancellationToken ct) =>
        {
            await sessions.RevokeAsync(http.User.SessionIdOf(), http.User.UserId(), RevokeReason.Logout, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization(AuthSetup.Enrollment);

        return api;
    }

    private static ClientKind ParseClientKind(string? value) =>
        AuthDbValue.TryParseClientKind(value, out var kind)
            ? kind
            : throw AuthException.Validation("clientKind must be one of desktop, android, web, admin.");
}
