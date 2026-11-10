using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Sessions, refresh rotation with reuse detection, logout and bearer validation (03 §3.2, 08 §8.2, §8.7).</summary>
public sealed class SessionTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth, AuthDriver.Account Account)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        return (app, auth, await auth.RegisterWithTotpAsync());
    }

    private static Task<HttpResponseMessage> Refresh(AuthDriver auth, string token) =>
        auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = token });

    [Fact]
    public async Task Refresh_rotates_and_the_new_token_works()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        var first = await Refresh(auth, account.Tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var next = AuthDriver.TokensOf(await first.JsonAsync());
        Assert.NotEqual(account.Tokens.RefreshToken, next.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await Refresh(auth, next.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Reusing_a_refresh_token_revokes_the_whole_session()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        var next = AuthDriver.TokensOf(await (await Refresh(auth, account.Tokens.RefreshToken)).JsonAsync());
        var replay = await Refresh(auth, account.Tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("unauthenticated", await replay.ProblemCodeAsync());

        // The legitimate child token dies with the session.
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(auth, next.RefreshToken)).StatusCode);
        Assert.Equal("reuse_detected", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT revoke_reason FROM sessions WHERE revoked_at IS NOT NULL"));
        Assert.Contains("auth.refresh_reuse", await Sql.ListAsync<string>(app.ConnectionString, "SELECT action FROM audit_log"));
    }

    [Fact]
    public async Task Refresh_tokens_are_stored_only_as_hashes()
    {
        var (app, _, account) = await StartAsync();
        await using var __ = app;
        var hashes = await Sql.ListAsync<byte[]>(app.ConnectionString, "SELECT token_hash FROM refresh_tokens");
        Assert.All(hashes, h => Assert.Equal(32, h.Length));
        Assert.Contains(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(account.Tokens.RefreshToken)), hashes);
    }

    [Fact]
    public async Task Concurrent_refreshes_of_one_token_produce_at_most_one_child()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Refresh(auth, account.Tokens.RefreshToken)));
        Assert.True(results.Count(r => r.StatusCode == HttpStatusCode.OK) <= 1);
        var parent = await Sql.ScalarAsync<Guid>(app.ConnectionString,
            "SELECT id FROM refresh_tokens WHERE token_hash = @h",
            ("h", System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(account.Tokens.RefreshToken))));
        Assert.True(await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM refresh_tokens WHERE parent_id = @p", ("p", parent)) <= 1);
    }

    [Fact]
    public async Task Refresh_token_idle_and_absolute_lifetimes_are_enforced()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        app.Clock.Advance(TimeSpan.FromDays(15));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(auth, account.Tokens.RefreshToken)).StatusCode);

        var tokens = await auth.LoginAsync(account.Email, account.TotpSecret!);
        for (var i = 0; i < 6; i++) // 78 days, each step inside the 14-day idle window
        {
            app.Clock.Advance(TimeSpan.FromDays(13));
            var r = await Refresh(auth, tokens.RefreshToken);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            tokens = AuthDriver.TokensOf(await r.JsonAsync());
        }

        app.Clock.Advance(TimeSpan.FromDays(13)); // 91 days > 90-day absolute lifetime
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(auth, tokens.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_the_session()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        var logout = await auth.Client().WithBearer(account.Tokens.AccessToken).PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(auth, account.Tokens.RefreshToken)).StatusCode);
        Assert.Equal("logout", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT revoke_reason FROM sessions WHERE revoked_at IS NOT NULL"));
    }

    [Fact]
    public async Task Expired_access_token_is_401_token_expired()
    {
        var (app, auth, account) = await StartAsync();
        await using var _ = app;

        app.Clock.Advance(TimeSpan.FromMinutes(6));
        var me = await auth.MeAsync(account.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
        Assert.Equal("token_expired", await me.ProblemCodeAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("garbage")]
    [InlineData("eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ4In0.")]
    public async Task Missing_or_invalid_bearer_is_401_unauthenticated(string? token)
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await using var _ = app;
        var client = app.CreateClient();
        if (token is not null) client.WithBearer(token);
        var me = await client.GetAsync("/api/v1/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
        Assert.Equal("unauthenticated", await me.ProblemCodeAsync());
    }

    [Fact]
    public async Task Token_signed_with_rotated_out_key_is_rejected_and_previous_key_accepted()
    {
        var cs = await pg.CreateDatabaseAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        AuthDriver.Account account;
        await using (var v1 = new NyxiteApp(cs, clock))
            account = await new AuthDriver(v1).RegisterWithTotpAsync();

        var both = new Dictionary<string, string?> { ["Auth:TokenSigningKey"] = $"1:{NyxiteApp.Key(9)};2:{NyxiteApp.Key(10)}" };
        await using (var rolled = new NyxiteApp(cs, clock, both))
            Assert.Equal(HttpStatusCode.OK, (await new AuthDriver(rolled).MeAsync(account.Tokens.AccessToken)).StatusCode);

        var only2 = new Dictionary<string, string?> { ["Auth:TokenSigningKey"] = $"2:{NyxiteApp.Key(10)}" };
        await using var retired = new NyxiteApp(cs, clock, only2);
        Assert.Equal(HttpStatusCode.Unauthorized, (await new AuthDriver(retired).MeAsync(account.Tokens.AccessToken)).StatusCode);
    }
}
