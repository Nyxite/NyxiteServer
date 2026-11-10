using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>P0.1-TC-3 (server half): native account, required TOTP, 2fa_required on a limited session.</summary>
public sealed class NativeAuthTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    [Fact]
    public async Task Register_returns_enrollment_limited_session_that_gets_2fa_required()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;

        var tokens = await auth.RegisterAsync("alice@example.org");
        Assert.Equal(["pwd"], new JsonWebToken(tokens.AccessToken).Claims.Where(c => c.Type == "amr").Select(c => c.Value));

        var me = await auth.MeAsync(tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, me.StatusCode);
        Assert.Equal("2fa_required", await me.ProblemCodeAsync());
    }

    [Fact]
    public async Task Totp_enrollment_then_refresh_yields_a_full_session()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;

        var account = await auth.RegisterWithTotpAsync("bob@example.org");
        var me = await auth.MeAsync(account.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var json = await me.JsonAsync();
        Assert.Equal("bob@example.org", json.GetProperty("email").GetString());
        Assert.Equal("community", json.GetProperty("capabilities").GetProperty("licenseState").GetString());
    }

    [Fact]
    public async Task Password_plus_totp_login_yields_full_token()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var tokens = await auth.LoginAsync(account.Email, account.TotpSecret!);
        Assert.Contains("mfa", new JsonWebToken(tokens.AccessToken).Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        Assert.Equal(HttpStatusCode.OK, (await auth.MeAsync(tokens.AccessToken)).StatusCode);
        // The registration session was 'desktop'; the login carried clientKind 'web' through the mfaToken.
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM sessions WHERE client_kind = 'web' AND auth_method = 'password_totp' AND mfa_verified_at IS NOT NULL"));
    }

    [Fact]
    public async Task Login_email_is_case_insensitive()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync("Carol@Example.org");
        Assert.Equal("carol@example.org", account.Email.ToLowerInvariant());
        await auth.PasswordStepAsync("CAROL@example.ORG");
    }

    [Fact]
    public async Task Wrong_password_and_unknown_account_get_the_same_401()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var wrong = await auth.Client().PostAsJsonAsync("/api/v1/auth/login", new { email = account.Email, password = "wrong password!!", clientKind = "web" });
        var unknown = await auth.Client().PostAsJsonAsync("/api/v1/auth/login", new { email = "nobody@example.org", password = "wrong password!!", clientKind = "web" });

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(await wrong.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Wrong_totp_is_rejected_and_mfa_token_dies_at_the_attempt_cap()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var mfa = await auth.PasswordStepAsync(account.Email);

        for (var i = 0; i < 4; i++)
        {
            var bad = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa, totpCode = auth.WrongCode(account.TotpSecret!) });
            Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        }

        // Fifth attempt is still allowed and succeeds.
        var ok = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa, totpCode = auth.Code(account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var mfa2 = await auth.PasswordStepAsync(account.Email);
        for (var i = 0; i < 5; i++)
            await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa2, totpCode = auth.WrongCode(account.TotpSecret!) });
        var afterCap = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa2, totpCode = auth.Code(account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.Unauthorized, afterCap.StatusCode);
    }

    [Fact]
    public async Task Mfa_token_is_single_use_and_expires()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var mfa = await auth.PasswordStepAsync(account.Email);
        var body = new { mfaToken = mfa, totpCode = auth.Code(account.TotpSecret!) };
        Assert.Equal(HttpStatusCode.OK, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", body)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", body)).StatusCode);

        var mfa2 = await auth.PasswordStepAsync(account.Email);
        app.Clock.Advance(TimeSpan.FromMinutes(6));
        var late = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa2, totpCode = auth.Code(account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.Unauthorized, late.StatusCode);
    }

    [Fact]
    public async Task Account_without_a_factor_gets_a_limited_session_only_after_an_emailed_code()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("dave@example.org");

        var access = (await auth.EnrollmentLoginAsync("dave@example.org", clientKind: "android")).AccessToken;
        Assert.Equal(["pwd"], new JsonWebToken(access).Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        Assert.Equal("2fa_required", await (await auth.MeAsync(access)).ProblemCodeAsync());

        // The limited session can still enroll the missing factor.
        await auth.EnrollTotpAsync(access);
    }

    [Fact]
    public async Task Password_alone_never_yields_a_session_for_an_account_without_a_factor()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("nofactor@example.org");
        var sessionsBefore = await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions");

        var mfa = await auth.PasswordStepAsync("nofactor@example.org");
        var wrong = await auth.Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code = "12345678" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        // TOTP and backup codes do not apply to an account without them.
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa, totpCode = "123456" })).StatusCode);
        Assert.Equal(sessionsBefore, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions"));
    }

    [Fact]
    public async Task The_enrollment_login_code_verifies_an_unverified_address()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("lostsession@example.org", verifyEmail: false);

        var access = (await auth.EnrollmentLoginAsync("lostsession@example.org")).AccessToken;
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE email_verified_at IS NOT NULL"));
        await auth.EnrollTotpAsync(access);
    }

    [Fact]
    public async Task Limited_session_cannot_replace_an_existing_factor()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var first = await auth.RegisterAsync("erin@example.org");
        var second = (await auth.EnrollmentLoginAsync("erin@example.org")).AccessToken;

        await auth.EnrollTotpAsync(first.AccessToken);

        var hijack = await auth.Client().WithBearer(second).PostAsync("/api/v1/auth/totp/enroll", null);
        Assert.Equal(HttpStatusCode.Forbidden, hijack.StatusCode);
        Assert.Equal("2fa_required", await hijack.ProblemCodeAsync());
    }

    [Fact]
    public async Task Replacing_totp_from_a_full_session_revokes_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);

        var stepUp = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!);
        await auth.EnrollTotpAsync(account.Tokens.AccessToken, stepUp);

        var refresh = await auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = other.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
        Assert.Equal("credential_change", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT revoke_reason FROM sessions WHERE revoked_at IS NOT NULL"));
    }

    [Fact]
    public async Task Wrong_enrollment_code_is_400_and_secret_is_not_stored()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("frank@example.org");
        var client = auth.Client().WithBearer(tokens.AccessToken);
        await client.PostAsync("/api/v1/auth/totp/enroll", null);

        var verify = await client.PostAsJsonAsync("/api/v1/auth/totp/verify", new { totpCode = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE totp_secret_enc IS NOT NULL"));
    }

    [Fact]
    public async Task Totp_verify_without_enroll_is_400()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("gina@example.org");
        var verify = await auth.Client().WithBearer(tokens.AccessToken).PostAsJsonAsync("/api/v1/auth/totp/verify", new { totpCode = "123456" });
        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
        Assert.Equal("validation_failed", await verify.ProblemCodeAsync());
    }

    [Theory]
    [InlineData("not-an-email", "Test", "long enough password", "desktop")]
    [InlineData("h@example.org", "", "long enough password", "desktop")]
    [InlineData("h@example.org", "Test", "short", "desktop")]
    [InlineData("h@example.org", "Test", "long enough password", "toaster")]
    [InlineData("h@example.org", "Test", "long enough password", null)]
    public async Task Register_validates_input(string email, string displayName, string password, string? clientKind)
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var response = await auth.Client().PostAsJsonAsync("/api/v1/auth/register", new { email, displayName, password, clientKind });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", await response.ProblemCodeAsync());
    }

    [Fact]
    public async Task Malformed_json_is_a_400_problem()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var response = await auth.Client().PostAsync("/api/v1/auth/register", new StringContent("{nope", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("validation_failed", await response.ProblemCodeAsync());
    }

    [Fact]
    public async Task Duplicate_email_is_409()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("ivan@example.org");
        var again = await auth.Client().PostAsJsonAsync("/api/v1/auth/register",
            new { email = "IVAN@example.org", displayName = "x", password = AuthDriver.Password, clientKind = "web" });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Equal("conflict", await again.ProblemCodeAsync());
    }

    [Fact]
    public async Task Server_stores_no_password_and_no_plain_totp_secret()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var verifier = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT password_verifier FROM users");
        var totpEnc = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT totp_secret_enc FROM users");
        Assert.StartsWith("$argon2id$v=19$", Encoding.ASCII.GetString(verifier!));
        Assert.DoesNotContain(AuthDriver.Password, Encoding.UTF8.GetString(verifier!));
        Assert.Equal(-1, totpEnc!.AsSpan().IndexOf(account.TotpSecret));
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT password_pepper_version FROM users"));
    }

    [Fact]
    public async Task Pepper_rotation_repeppers_lazily_at_next_login()
    {
        var cs = await pg.CreateDatabaseAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        AuthDriver.Account account;
        await using (var v1 = new NyxiteApp(cs, clock))
            account = await new AuthDriver(v1).RegisterWithTotpAsync();
        var oldVerifier = await Sql.ScalarAsync<byte[]>(cs, "SELECT password_verifier FROM users");

        // Each app gets its own driver; moving to the next TOTP step keeps the code from counting as a replay.
        clock.Advance(TimeSpan.FromSeconds(30));
        var rotated = new Dictionary<string, string?> { ["Auth:PasswordPepper"] = $"1:{NyxiteApp.Key(1)};2:{NyxiteApp.Key(2)}" };
        await using (var v2 = new NyxiteApp(cs, clock, rotated))
            await new AuthDriver(v2).LoginAsync(account.Email, account.TotpSecret!);

        Assert.Equal(2, await Sql.ScalarAsync<int>(cs, "SELECT password_pepper_version FROM users"));
        Assert.NotEqual(oldVerifier, await Sql.ScalarAsync<byte[]>(cs, "SELECT password_verifier FROM users"));
        var totpEnc = await Sql.ScalarAsync<byte[]>(cs, "SELECT totp_secret_enc FROM users");
        Assert.Equal(new byte[] { 0, 0, 0, 2 }, totpEnc![..4]);

        // Once version 1 is retired, the re-peppered account still signs in.
        clock.Advance(TimeSpan.FromSeconds(30));
        var only2 = new Dictionary<string, string?> { ["Auth:PasswordPepper"] = $"2:{NyxiteApp.Key(2)}" };
        await using var v3 = new NyxiteApp(cs, clock, only2);
        await new AuthDriver(v3).LoginAsync(account.Email, account.TotpSecret!);
    }

    [Fact]
    public async Task Login_events_are_audited_without_secrets()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        await auth.Client().PostAsJsonAsync("/api/v1/auth/login", new { email = account.Email, password = "wrong password!!", clientKind = "web" });
        await auth.LoginAsync(account.Email, account.TotpSecret!);

        var actions = await Sql.ListAsync<string>(app.ConnectionString, "SELECT action FROM audit_log ORDER BY id");
        Assert.Contains("auth.register", actions);
        Assert.Contains("auth.login_failed", actions);
        Assert.Contains("auth.2fa_challenge", actions);
        Assert.Contains("auth.totp_enrolled", actions);
        Assert.Contains("auth.login", actions);
        var details = string.Join("\n", await Sql.ListAsync<string>(app.ConnectionString, "SELECT detail::text FROM audit_log"));
        Assert.DoesNotContain(account.Email, details);
        Assert.DoesNotContain(AuthDriver.Password, details);
    }

    [Fact]
    public async Task Oidc_endpoints_are_absent_without_the_enterprise_profile()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var authorize = await auth.Client().GetAsync("/api/v1/auth/oidc/authorize?client=web&redirectUri=https://x");
        var token = await auth.Client().PostAsJsonAsync("/api/v1/auth/oidc/token", new { handoff = "x" });
        Assert.Equal(HttpStatusCode.NotFound, authorize.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, token.StatusCode);
        Assert.Equal("not_found", await token.ProblemCodeAsync());
    }

    [Fact]
    public async Task Oidc_stub_reports_unavailable_with_the_enterprise_profile()
    {
        var cs = await pg.CreateDatabaseAsync();
        await using var app = new NyxiteApp(cs, overrides: new Dictionary<string, string?> { ["Auth:Enterprise:Enabled"] = "true" });
        var response = await app.CreateClient().PostAsJsonAsync("/api/v1/auth/oidc/token", new { handoff = "x" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("unavailable", await response.ProblemCodeAsync());
    }

    [Theory]
    [InlineData("Auth:TokenSigningKey")]
    [InlineData("Auth:PasswordPepper")]
    public async Task Server_refuses_to_start_without_its_auth_secrets(string key)
    {
        var cs = await pg.CreateDatabaseAsync();
        await using var app = new NyxiteApp(cs, overrides: new Dictionary<string, string?> { [key] = null });
        var error = Assert.ThrowsAny<Exception>(() => app.CreateClient());
        Assert.Contains(key, error.ToString());
    }
}
