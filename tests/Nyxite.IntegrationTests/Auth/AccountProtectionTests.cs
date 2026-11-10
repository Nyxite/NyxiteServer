using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>
/// Account-level protections: blocked accounts (12 §12.6), TOTP replay (RFC 6238 §5.2), the account-wide cap on wrong
/// second-factor codes, and session revocation when a passkey is added (03 §3.2).
/// </summary>
public sealed class AccountProtectionTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync(IDictionary<string, string?>? overrides = null)
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: overrides);
        return (app, new AuthDriver(app));
    }

    private static Task Block(NyxiteApp app, string email) =>
        Sql.ExecAsync(app.ConnectionString, "UPDATE users SET status = 'blocked' WHERE email = @e", ("e", email));

    private static Task<HttpResponseMessage> TotpLogin(AuthDriver auth, string mfaToken, string code) =>
        auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken, totpCode = code });

    [Fact]
    public async Task Blocked_account_gets_no_web_session_but_keeps_desktop_access()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        await Block(app, account.Email);

        var web = await TotpLogin(auth, await auth.PasswordStepAsync(account.Email), auth.Code(account.TotpSecret!));
        Assert.Equal(HttpStatusCode.Forbidden, web.StatusCode);
        Assert.Equal("account_blocked", await web.ProblemCodeAsync());
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'auth.login_failed' AND detail->>'reason' = 'account_blocked'"));

        var desktop = await TotpLogin(auth, await auth.PasswordStepAsync(account.Email, clientKind: "desktop"), auth.Code(account.TotpSecret!));
        Assert.Equal(HttpStatusCode.OK, desktop.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE client_kind = 'web'"));
    }

    [Fact]
    public async Task Blocking_ends_an_existing_web_session_at_its_next_refresh()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var web = await auth.LoginAsync(account.Email, account.TotpSecret!);
        await Block(app, account.Email);

        var refresh = await auth.Refresh(web.RefreshToken);
        Assert.Equal(HttpStatusCode.Forbidden, refresh.StatusCode);
        Assert.Equal("account_blocked", await refresh.ProblemCodeAsync());
        Assert.Equal("user_blocked", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT revoke_reason FROM sessions WHERE client_kind = 'web'"));
        // The desktop session from registration keeps refreshing.
        Assert.Equal(HttpStatusCode.OK, (await auth.Refresh(account.Tokens.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Blocked_account_gets_no_web_session_through_a_passkey()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var limited = await auth.RegisterAsync("blockedpk@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);
        var options = await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync();
        await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(options) });
        await Block(app, "blockedpk@example.org");

        var assertOptions = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { })).JsonAsync();
        var login = await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert",
            new { credential = authenticator.Get(assertOptions), clientKind = "web" });
        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
        Assert.Equal("account_blocked", await login.ProblemCodeAsync());
    }

    [Fact]
    public async Task The_totp_code_that_completed_enrollment_cannot_be_used_to_sign_in()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var login = await TotpLogin(auth, await auth.PasswordStepAsync(account.Email), auth.CurrentCode(account.TotpSecret!));
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task Two_concurrent_logins_with_one_totp_code_yield_at_most_one_session()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var code = auth.Code(account.TotpSecret!);
        var tokens = new[] { await auth.PasswordStepAsync(account.Email), await auth.PasswordStepAsync(account.Email) };

        var results = await Task.WhenAll(tokens.Select(t => TotpLogin(auth, t, code)));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE client_kind = 'web'"));
    }

    [Fact]
    public async Task Wrong_codes_across_many_mfa_tokens_hit_the_account_cap()
    {
        var (app, auth) = await StartAsync(new Dictionary<string, string?>
        {
            ["Auth:SecondFactorFailureLimit"] = "6",
            ["Auth:SecondFactorFailureWindow"] = "00:15:00",
        });
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        // Three password steps, two wrong codes each: no single mfaToken reaches its own cap of 5.
        for (var i = 0; i < 3; i++)
        {
            var mfa = await auth.PasswordStepAsync(account.Email);
            for (var j = 0; j < 2; j++) Assert.Equal(HttpStatusCode.Unauthorized, (await TotpLogin(auth, mfa, auth.WrongCode(account.TotpSecret!))).StatusCode);
        }

        var capped = await TotpLogin(auth, await auth.PasswordStepAsync(account.Email), auth.Code(account.TotpSecret!));
        Assert.Equal(HttpStatusCode.TooManyRequests, capped.StatusCode);
        Assert.Equal("rate_limited", await capped.ProblemCodeAsync());
        Assert.True(int.Parse(capped.Headers.GetValues("Retry-After").Single()) is > 0 and <= 900);

        // Other accounts are unaffected, and the cap lifts once the window has passed.
        var otherAccount = await auth.RegisterWithTotpAsync();
        Assert.Equal(HttpStatusCode.OK, (await TotpLogin(auth, await auth.PasswordStepAsync(otherAccount.Email), auth.Code(otherAccount.TotpSecret!))).StatusCode);
        app.Clock.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(HttpStatusCode.OK, (await TotpLogin(auth, await auth.PasswordStepAsync(account.Email), auth.Code(account.TotpSecret!))).StatusCode);
    }

    [Fact]
    public async Task First_passkey_on_a_new_account_keeps_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var first = await auth.RegisterAsync("twoclients@example.org");
        var second = await auth.EnrollmentLoginAsync("twoclients@example.org");

        var client = auth.Client().WithBearer(first.AccessToken);
        var options = await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(options) })).StatusCode);

        // The second limited session is not revoked, but it cannot become full without its own factor proof.
        var refreshed = await auth.Refresh(second.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auth.MeAsync(AuthDriver.TokensOf(await refreshed.JsonAsync()).AccessToken)).StatusCode);
    }
}
