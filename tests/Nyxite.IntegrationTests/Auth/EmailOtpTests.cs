using System.Net;
using System.Net.Http.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Emailed one-time codes as a password second factor (08 §8.1(a)).</summary>
public sealed class EmailOtpTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    [Fact]
    public async Task Email_codes_as_the_first_factor_then_password_plus_emailed_code_login()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithEmailOtpAsync("mail@example.org");
        Assert.Equal(HttpStatusCode.OK, (await auth.MeAsync(account.Tokens.AccessToken)).StatusCode);

        var login = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" })).JsonAsync();
        Assert.Equal("second_factor_required", login.GetProperty("challenge").GetString());
        Assert.Equal(["email"], login.GetProperty("methods").EnumerateArray().Select(m => m.GetString()));
        var mfa = login.GetProperty("mfaToken").GetString()!;

        var code = await auth.SendLoginEmailCodeAsync(mfa, account.Email);
        var done = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code });
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var tokens = AuthDriver.TokensOf(await done.JsonAsync());
        Assert.Equal(["pwd", "otp", "mfa"], new JsonWebToken(tokens.AccessToken).Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE auth_method = 'password_email'"));
    }

    [Fact]
    public async Task Enrollment_needs_the_emailed_confirmation_code()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("confirm@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/email-otp/enroll", null)).StatusCode);

        var wrong = await client.PostAsJsonAsync("/api/v1/auth/email-otp/verify", new { code = "12345678x" });
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE email_otp_enabled_at IS NOT NULL"));
        // Still limited: the session gained no second factor.
        Assert.Equal(HttpStatusCode.Forbidden, (await auth.MeAsync(limited.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task Emailed_code_is_bound_to_its_mfa_token_and_single_use()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithEmailOtpAsync();

        var first = await auth.PasswordStepAsync(account.Email);
        var code = await auth.SendLoginEmailCodeAsync(first, account.Email);
        var second = await auth.PasswordStepAsync(account.Email);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = second, code })).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = first, code })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = first, code })).StatusCode);
        Assert.DoesNotContain(code, await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT string_agg(detail::text, ' ') FROM ephemeral_tokens WHERE kind = 'email_code'") ?? "");
    }

    [Fact]
    public async Task Wrong_emailed_codes_share_the_mfa_token_attempt_cap()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithEmailOtpAsync();
        var mfa = await auth.PasswordStepAsync(account.Email);
        var code = await auth.SendLoginEmailCodeAsync(mfa, account.Email);
        var wrong = code == "11111111" ? "22222222" : "11111111";

        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code = wrong })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code })).StatusCode);
        Assert.Equal(5L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'auth.login_failed' AND detail->>'reason' = 'bad_email_code'"));
    }

    [Fact]
    public async Task Email_codes_are_refused_for_an_account_that_did_not_enable_them()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var mfa = await auth.PasswordStepAsync(account.Email);

        var send = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email/send", new { mfaToken = mfa });
        Assert.Equal(HttpStatusCode.BadRequest, send.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code = "12345678" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email/send", new { mfaToken = "not-a-token" })).StatusCode);
    }

    [Fact]
    public async Task Adding_email_codes_to_a_totp_account_needs_step_up_and_revokes_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);

        var bare = await auth.Client().WithBearer(account.Tokens.AccessToken).PostAsync("/api/v1/auth/email-otp/enroll", null);
        Assert.Equal(HttpStatusCode.Forbidden, bare.StatusCode);
        Assert.Equal("2fa_required", await bare.ProblemCodeAsync());

        var stepUp = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!);
        await auth.EnableEmailOtpAsync(account.Tokens.AccessToken, account.Email, stepUp);

        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Refresh(other.RefreshToken)).StatusCode);
        var methods = (await (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" })).JsonAsync()).GetProperty("methods");
        Assert.Equal(["totp", "email"], methods.EnumerateArray().Select(m => m.GetString()));

        var again = await auth.Client().WithBearer(account.Tokens.AccessToken).PostJsonAsync("/api/v1/auth/email-otp/enroll",
            new { stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }
}
