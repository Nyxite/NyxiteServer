using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>
/// Paths of the existing auth code that had no test before the 2026-11 review: passkey input validation, challenge
/// expiry and type separation, pending-enrollment expiry, the /me body, and request metadata on sessions and audit rows.
/// </summary>
public sealed class EdgeCaseTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    private static async Task<JsonElementAndClient> RegistrationOptionsAsync(AuthDriver auth, string accessToken)
    {
        var client = auth.Client().WithBearer(accessToken);
        return new(await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync(), client);
    }

    private sealed record JsonElementAndClient(System.Text.Json.JsonElement Options, HttpClient Client);

    [Fact]
    public async Task Passkey_label_longer_than_100_characters_is_400()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var limited = await auth.RegisterAsync("label@example.org");
        var (options, client) = await RegistrationOptionsAsync(auth, limited.AccessToken);

        var finish = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register",
            new { credential = authenticator.Create(options), label = new string('x', 101) });
        Assert.Equal(HttpStatusCode.BadRequest, finish.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM webauthn_credentials"));
    }

    [Fact]
    public async Task Passkey_registration_challenge_of_another_session_is_refused()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var first = await auth.RegisterAsync("chal@example.org");
        var second = await auth.EnrollmentLoginAsync("chal@example.org");

        var (options, _) = await RegistrationOptionsAsync(auth, first.AccessToken);
        var finish = await auth.Client().WithBearer(second.AccessToken).PostAsJsonAsync("/api/v1/auth/webauthn/register",
            new { credential = authenticator.Create(options) });
        Assert.Equal(HttpStatusCode.BadRequest, finish.StatusCode);
    }

    [Fact]
    public async Task Malformed_or_unrequested_passkey_registration_is_400()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("malformed@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);

        var notAnObject = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = "text" });
        Assert.Equal(HttpStatusCode.BadRequest, notAnObject.StatusCode);
        Assert.Equal("validation_failed", await notAnObject.ProblemCodeAsync());

        // A well-formed response to a challenge the server never issued.
        using var authenticator = new VirtualAuthenticator();
        var fakeOptions = System.Text.Json.JsonDocument.Parse(
            """{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","user":{"id":"AAAAAAAAAAAAAAAAAAAAAA"}}""").RootElement;
        var unrequested = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(fakeOptions) });
        Assert.Equal(HttpStatusCode.BadRequest, unrequested.StatusCode);
    }

    [Fact]
    public async Task The_same_passkey_cannot_be_registered_twice()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);

        for (var i = 0; i < 2; i++)
        {
            var options = await (await client.PostJsonAsync("/api/v1/auth/webauthn/register/options",
                new { stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!) })).JsonAsync();
            var finish = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(options) });
            Assert.Equal(i == 0 ? HttpStatusCode.NoContent : HttpStatusCode.BadRequest, finish.StatusCode);
        }

        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM webauthn_credentials"));
    }

    [Fact]
    public async Task Passkey_login_challenge_expires_and_a_registration_challenge_cannot_sign_in()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var limited = await auth.RegisterAsync("expire@example.org");
        var (registerOptions, client) = await RegistrationOptionsAsync(auth, limited.AccessToken);
        await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(registerOptions) });

        var assertOptions = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { })).JsonAsync();
        app.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        var late = await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert",
            new { credential = authenticator.Get(assertOptions), clientKind = "web" });
        Assert.Equal(HttpStatusCode.Unauthorized, late.StatusCode);

        // A challenge issued for registration is a different type and does not sign anyone in.
        var fresh = AuthDriver.TokensOf(await (await auth.Refresh(limited.RefreshToken)).JsonAsync());
        var stepUp = await StepUpTests.StepUpWithPasskeyAsync(auth, fresh.AccessToken, authenticator);
        var createOptions = await (await auth.Client().WithBearer(fresh.AccessToken).PostJsonAsync("/api/v1/auth/webauthn/register/options",
            new { stepUpToken = stepUp })).JsonAsync();
        var mixed = await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert",
            new { credential = authenticator.Get(createOptions), clientKind = "web" });
        Assert.Equal(HttpStatusCode.Unauthorized, mixed.StatusCode);
    }

    [Fact]
    public async Task Pending_totp_enrollment_expires()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("pending@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);
        var enroll = await (await client.PostAsync("/api/v1/auth/totp/enroll", null)).JsonAsync();
        var secret = OtpNet.Base32Encoding.ToBytes(enroll.GetProperty("secret").GetString()!);

        app.Clock.Advance(TimeSpan.FromMinutes(4));
        var refreshed = AuthDriver.TokensOf(await (await auth.Refresh(limited.RefreshToken)).JsonAsync());
        app.Clock.Advance(TimeSpan.FromMinutes(6) + TimeSpan.FromSeconds(1));
        var verify = await auth.Client().WithBearer(AuthDriver.TokensOf(await (await auth.Refresh(refreshed.RefreshToken)).JsonAsync()).AccessToken)
            .PostAsJsonAsync("/api/v1/auth/totp/verify", new { totpCode = auth.Code(secret) });
        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE totp_secret_enc IS NOT NULL"));
    }

    [Fact]
    public async Task Me_returns_the_account_without_any_secret()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync("me@example.org");

        var me = await (await auth.MeAsync(account.Tokens.AccessToken)).JsonAsync();
        Assert.Equal("me@example.org", me.GetProperty("email").GetString());
        Assert.Equal("Test User", me.GetProperty("displayName").GetString());
        Assert.Equal("user", me.GetProperty("role").GetString());
        Assert.Equal("active", me.GetProperty("status").GetString());
        Assert.Equal("community", me.GetProperty("capabilities").GetProperty("licenseState").GetString());
        var text = me.GetRawText();
        foreach (var forbidden in new[] { "password", "totp", "verifier", "secret" })
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Sessions_and_audit_rows_record_the_user_agent_truncated_to_512_characters()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var client = auth.Client();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Nyxite/" + new string('9', 700));
        var response = await client.PostAsJsonAsync("/api/v1/auth/register",
            new { email = "ua@example.org", displayName = "UA", password = AuthDriver.Password, clientKind = "desktop" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        Assert.Equal(512, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT length(user_agent) FROM sessions"));
        Assert.Equal(512, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT max(length(user_agent)) FROM audit_log"));
    }

    [Fact]
    public async Task Refresh_without_a_token_is_401()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var response = await auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = "" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("unauthenticated", await response.ProblemCodeAsync());
    }
}
