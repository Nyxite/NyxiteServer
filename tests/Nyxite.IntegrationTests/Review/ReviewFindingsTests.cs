using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Review;

/// <summary>
/// Reproductions for the server review (REVIEW-server-2026-11-03.md). Traits "issue" and "scope" assert the specified
/// behaviour and failed on the reviewed implementation. Trait "decision" documents the consequence of a design decision;
/// D1 now asserts the email verification that replaced the squattable registration.
/// </summary>
public sealed class ReviewFindingsTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync(IDictionary<string, string?>? overrides = null)
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: overrides);
        return (app, new AuthDriver(app));
    }

    private static Task<HttpResponseMessage> Refresh(AuthDriver auth, string token) =>
        auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = token });

    private static async Task<HttpResponseMessage> RegisterPasskeyAsync(AuthDriver auth, string accessToken, VirtualAuthenticator authenticator,
        string? stepUpToken = null)
    {
        var client = auth.Client().WithBearer(accessToken);
        var options = await client.PostJsonAsync("/api/v1/auth/webauthn/register/options", stepUpToken is null ? null : new { stepUpToken });
        if (options.StatusCode != HttpStatusCode.OK) return options;
        return await client.PostAsJsonAsync("/api/v1/auth/webauthn/register",
            new { credential = authenticator.Create(await options.JsonAsync()), label = "added key" });
    }

    // R1 -- 12 §12.6 / 09 §9.5: a blocked account must not get a web-client session.
    [Fact, Trait("review", "issue")]
    public async Task R1_blocked_account_cannot_start_a_web_session()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET status = 'blocked' WHERE email = @e", ("e", account.Email));

        var password = await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" });
        HttpResponseMessage final = password;
        if (password.StatusCode == HttpStatusCode.OK)
        {
            var mfa = (await password.JsonAsync()).GetProperty("mfaToken").GetString()!;
            final = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp",
                new { mfaToken = mfa, totpCode = auth.Code(account.TotpSecret!) });
        }

        Assert.NotEqual(HttpStatusCode.OK, final.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM sessions WHERE client_kind = 'web'"));
    }

    // R2 -- RFC 6238 §5.2: a TOTP code accepted once must not be accepted again.
    [Fact, Trait("review", "issue")]
    public async Task R2_totp_code_cannot_be_replayed_for_a_second_login()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var code = auth.Code(account.TotpSecret!);

        var first = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp",
            new { mfaToken = await auth.PasswordStepAsync(account.Email), totpCode = code });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Same clock, same code, fresh password step: an observer of the code gets in.
        var replay = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp",
            new { mfaToken = await auth.PasswordStepAsync(account.Email), totpCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    // R3 -- 08 §8.9, 13 §13.5: auth/login is limited to 10/min/IP and answers 429 rate_limited + Retry-After.
    [Fact, Trait("review", "issue")]
    public async Task R3_login_is_rate_limited()
    {
        var (app, auth) = await StartAsync(new Dictionary<string, string?> { ["RateLimiting:Auth:PermitLimit"] = "10" });
        await using var _ = app;
        var client = auth.Client();

        HttpResponseMessage last = null!;
        for (var i = 0; i < 11; i++)
            last = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { email = "victim@example.org", password = "guess number " + i, clientKind = "web" });

        Assert.Equal(HttpStatusCode.TooManyRequests, last.StatusCode);
        Assert.Equal("rate_limited", await last.ProblemCodeAsync());
        Assert.True(last.Headers.Contains("Retry-After"));
    }

    // R4a -- 08 §8.2 step-up: adding a passkey is a sensitive account action and needs a recent second factor.
    [Fact, Trait("review", "issue")]
    public async Task R4a_adding_a_passkey_requires_a_recent_second_factor()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        // 13 days later the session is still alive through refresh; its second factor is 13 days old.
        app.Clock.Advance(TimeSpan.FromDays(13));
        var refreshed = AuthDriver.TokensOf(await (await Refresh(auth, account.Tokens.RefreshToken)).JsonAsync());

        using var attacker = new VirtualAuthenticator();
        var add = await RegisterPasskeyAsync(auth, refreshed.AccessToken, attacker);
        Assert.Equal(HttpStatusCode.Forbidden, add.StatusCode);
        Assert.Equal("2fa_required", await add.ProblemCodeAsync());
    }

    // R4b -- 08 §8.2 step-up: replacing the TOTP secret needs a recent second factor.
    [Fact, Trait("review", "issue")]
    public async Task R4b_replacing_totp_requires_a_recent_second_factor()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        app.Clock.Advance(TimeSpan.FromDays(13));
        var refreshed = AuthDriver.TokensOf(await (await Refresh(auth, account.Tokens.RefreshToken)).JsonAsync());

        var enroll = await auth.Client().WithBearer(refreshed.AccessToken).PostAsync("/api/v1/auth/totp/enroll", null);
        Assert.Equal(HttpStatusCode.Forbidden, enroll.StatusCode);
        Assert.Equal("2fa_required", await enroll.ProblemCodeAsync());
    }

    // R5 -- 03 §3.2: "a password/TOTP/passkey change" revokes the sessions; TOTP does it, passkeys do not.
    [Fact, Trait("review", "issue")]
    public async Task R5_adding_a_passkey_to_an_enrolled_account_revokes_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);

        using var authenticator = new VirtualAuthenticator();
        var stepUp = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!);
        Assert.Equal(HttpStatusCode.NoContent, (await RegisterPasskeyAsync(auth, account.Tokens.AccessToken, authenticator, stepUp)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(auth, other.RefreshToken)).StatusCode);
    }

    // S1 -- P0.1-SRV-5 / 04 §4.1: the contract-first document is served as /openapi/v1.json (the YAML is embedded, but unused).
    // S2 -- P0.1-SRV-5 / 14: /health/live and /health/ready exist.
    [Theory, Trait("review", "scope")]
    [InlineData("/openapi/v1.json")]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    public async Task S_phase_0_1_operational_endpoints_are_served(string path)
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        Assert.Equal(HttpStatusCode.OK, (await auth.Client().GetAsync(path)).StatusCode);
    }

    // D1 -- email verification: an unverified registration cannot enroll a factor, and once it expires the real owner
    // can register the address.
    [Fact, Trait("review", "decision")]
    public async Task D1_unverified_registration_cannot_hold_an_address()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var squatter = await auth.RegisterAsync("owner@example.org", verifyEmail: false);
        var enroll = await auth.Client().WithBearer(squatter.AccessToken).PostAsync("/api/v1/auth/totp/enroll", null);
        Assert.Equal(HttpStatusCode.Forbidden, enroll.StatusCode);
        Assert.Equal("email_unverified", await enroll.ProblemCodeAsync());

        var owner = new { email = "owner@example.org", displayName = "Real Owner", password = "the owners own password", clientKind = "web" };
        Assert.Equal(HttpStatusCode.Conflict, (await auth.Client().PostAsJsonAsync("/api/v1/auth/register", owner)).StatusCode);

        app.Clock.Advance(TimeSpan.FromHours(24));
        Assert.Equal(HttpStatusCode.Created, (await auth.Client().PostAsJsonAsync("/api/v1/auth/register", owner)).StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users"));
    }

    // D2 -- before the first factor exists, the password alone must not reach enrollment: the login needs an emailed
    // code, so whoever only has the password cannot enroll a factor and take the account over.
    [Fact, Trait("review", "decision")]
    public async Task D2_password_alone_cannot_take_over_an_account_that_has_not_enrolled_yet()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var owner = await auth.RegisterAsync("slow@example.org");

        var login = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = "slow@example.org", password = AuthDriver.Password, clientKind = "web" })).JsonAsync();
        Assert.False(login.TryGetProperty("accessToken", out var _));
        Assert.True(login.GetProperty("enrollment").GetBoolean());
        var guess = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email",
            new { mfaToken = login.GetProperty("mfaToken").GetString(), code = "12345678" });
        Assert.Equal(HttpStatusCode.Unauthorized, guess.StatusCode);

        // The owner, who reads the mailbox, enrolls normally.
        await auth.EnrollTotpAsync(owner.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(auth, owner.RefreshToken)).StatusCode);
    }
}
