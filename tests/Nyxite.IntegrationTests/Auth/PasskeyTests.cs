using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>P0.1-TC-3 passkey half: WebAuthn registration and passwordless, sufficient-alone login.</summary>
public sealed class PasskeyTests(PostgresFixture pg)
{
    private static async Task RegisterPasskeyAsync(AuthDriver auth, string accessToken, VirtualAuthenticator authenticator)
    {
        var client = auth.Client().WithBearer(accessToken);
        var options = await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync();
        var finish = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register",
            new { credential = authenticator.Create(options), label = "test key" });
        Assert.Equal(HttpStatusCode.NoContent, finish.StatusCode);
    }

    private static async Task<HttpResponseMessage> AssertAsync(AuthDriver auth, VirtualAuthenticator authenticator,
        bool corrupt = false, Func<JsonObject, JsonObject>? tamper = null)
    {
        var options = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { })).JsonAsync();
        var credential = authenticator.Get(options, corrupt);
        return await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert",
            new { credential = tamper?.Invoke(credential) ?? credential, clientKind = "web" });
    }

    [Fact]
    public async Task Passkey_registration_on_a_new_account_then_passwordless_login()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();

        var limited = await auth.RegisterAsync("pk@example.org");
        await RegisterPasskeyAsync(auth, limited.AccessToken, authenticator);

        // Registering the passkey completes the limited session's second factor.
        var refreshed = await auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = limited.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, (await auth.MeAsync(AuthDriver.TokensOf(await refreshed.JsonAsync()).AccessToken)).StatusCode);

        var login = await AssertAsync(auth, authenticator);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var tokens = AuthDriver.TokensOf(await login.JsonAsync());
        Assert.Equal(["hwk", "user", "mfa"], new JsonWebToken(tokens.AccessToken).Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        Assert.Equal(HttpStatusCode.OK, (await auth.MeAsync(tokens.AccessToken)).StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM sessions WHERE auth_method = 'passkey' AND client_kind = 'web' AND mfa_verified_at IS NOT NULL"));
        Assert.Equal(2L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT sign_count FROM webauthn_credentials"));
    }

    [Fact]
    public async Task Only_public_credential_material_is_stored()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();
        await RegisterPasskeyAsync(auth, (await auth.RegisterAsync("pk2@example.org")).AccessToken, authenticator);

        Assert.Equal(authenticator.CredentialId, await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT credential_id FROM webauthn_credentials"));
        Assert.Equal("test key", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT label FROM webauthn_credentials"));
    }

    [Fact]
    public async Task Bad_signature_unknown_credential_and_replayed_challenge_are_rejected()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();
        await RegisterPasskeyAsync(auth, (await auth.RegisterAsync("pk3@example.org")).AccessToken, authenticator);

        Assert.Equal(HttpStatusCode.Unauthorized, (await AssertAsync(auth, authenticator, corrupt: true)).StatusCode);

        using var stranger = new VirtualAuthenticator();
        Assert.Equal(HttpStatusCode.Unauthorized, (await AssertAsync(auth, stranger)).StatusCode);

        var options = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { })).JsonAsync();
        var credential = authenticator.Get(options);
        Assert.Equal(HttpStatusCode.OK, (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert", new { credential, clientKind = "web" })).StatusCode);
        var replay = await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert", new { credential, clientKind = "web" });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Wrong_origin_is_rejected()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();
        await RegisterPasskeyAsync(auth, (await auth.RegisterAsync("pk4@example.org")).AccessToken, authenticator);

        using var phishing = new VirtualAuthenticator(origin: "https://evil.test");
        var limited = await auth.RegisterAsync("pk5@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);
        var options = await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync();
        var finish = await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = phishing.Create(options) });
        Assert.Equal(HttpStatusCode.BadRequest, finish.StatusCode);
    }

    [Fact]
    public async Task Assert_options_reveal_nothing_about_the_email()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();
        await RegisterPasskeyAsync(auth, (await auth.RegisterAsync("known@example.org")).AccessToken, authenticator);

        var known = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { email = "known@example.org" })).JsonAsync();
        var unknown = await (await auth.Client().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { email = "nobody@example.org" })).JsonAsync();
        Assert.Equal(known.TryGetProperty("allowCredentials", out var a) ? a.GetArrayLength() : 0,
            unknown.TryGetProperty("allowCredentials", out var b) ? b.GetArrayLength() : 0);
        Assert.Equal(0, known.TryGetProperty("allowCredentials", out var c) ? c.GetArrayLength() : 0);
    }

    [Fact]
    public async Task Password_alone_cannot_sign_in_a_passkey_only_account()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var auth = new AuthDriver(app);
        using var authenticator = new VirtualAuthenticator();
        await RegisterPasskeyAsync(auth, (await auth.RegisterAsync("pk6@example.org")).AccessToken, authenticator);

        var login = await auth.Client().PostAsJsonAsync("/api/v1/auth/login", new { email = "pk6@example.org", password = AuthDriver.Password, clientKind = "web" });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task Passkeys_are_unavailable_until_configured()
    {
        var cs = await pg.CreateDatabaseAsync();
        await using var app = new NyxiteApp(cs, overrides: new Dictionary<string, string?> { ["Auth:WebAuthn:RelyingPartyId"] = null });
        var response = await app.CreateClient().PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("unavailable", await response.ProblemCodeAsync());
    }
}
