using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Maintenance;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Http;

/// <summary>Production hardening: encrypted mail outbox, mail throttling, row cleanup, secure headers and CORS (13, 14).</summary>
public sealed class HardeningTests(PostgresFixture pg)
{
    [Fact]
    public async Task Queued_mail_is_encrypted_at_rest_and_deleted_once_sent()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        const string email = "outbox@example.org";
        await auth.RegisterAsync(email, verifyEmail: false);

        var payloads = await Sql.ListAsync<byte[]>(app.ConnectionString, "SELECT payload_enc FROM email_outbox");
        var payload = Assert.Single(payloads);
        Assert.DoesNotContain("outbox@example.org", Encoding.Latin1.GetString(payload));
        Assert.DoesNotContain("verification code", Encoding.Latin1.GetString(payload));

        Assert.Matches("^[0-9]{8}$", app.Email.LastCode(email));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM email_outbox"));
    }

    [Fact]
    public async Task A_mail_whose_code_expired_is_dropped_instead_of_sent_late()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        await auth.RegisterAsync("late@example.org", verifyEmail: false);

        app.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Empty(app.Email.To("late@example.org"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM email_outbox"));
    }

    [Fact]
    public async Task Password_reset_mail_is_capped_per_account()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var account = await auth.RegisterWithTotpAsync();
        await app.FlushOutboxAsync();
        var before = app.Email.Sent.Count;

        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Accepted,
                (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = account.Email })).StatusCode);
        await app.FlushOutboxAsync();
        Assert.Equal(before + 3, app.Email.Sent.Count);

        // The window is per account and passes.
        app.Clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = account.Email });
        await app.FlushOutboxAsync();
        Assert.Equal(before + 4, app.Email.Sent.Count);
    }

    [Fact]
    public async Task Maintenance_deletes_expired_tokens_and_long_dead_sessions_only()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var old = await auth.RegisterWithTotpAsync();
        await auth.Client().WithBearer(old.Tokens.AccessToken).PostAsync("/api/v1/auth/logout", null);

        async Task<int> Clean()
        {
            await using var scope = app.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<ExpiredRowCleaner>().RunAsync(CancellationToken.None);
        }

        // Freshly revoked: kept for the retention period.
        await Clean();
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL"));

        app.Clock.Advance(TimeSpan.FromDays(31));
        var live = await auth.RegisterWithTotpAsync();
        Assert.True(await Clean() > 0);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM refresh_tokens r LEFT JOIN sessions s ON s.id = r.session_id WHERE s.id IS NULL"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM ephemeral_tokens WHERE expires_at <= @now", ("now", app.Clock.Now)));
        Assert.Equal(HttpStatusCode.OK, (await auth.Refresh(live.Tokens.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Responses_carry_secure_headers_and_a_request_id()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var response = await app.CreateClient().GetAsync("/api/v1/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        Assert.NotEmpty(response.Headers.GetValues("Nyxite-Request-Id").Single());
    }

    [Fact]
    public async Task Request_metrics_are_collected_without_any_url_value()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        await app.CreateClient().GetAsync("/api/v1/devices/01890a5d-ac96-774b-bcce-b302099a8057");

        var text = app.Services.GetRequiredService<Nyxite.Server.Http.MetricsRegistry>().Render();
        Assert.Contains("http_server_request_duration_count{", text);
        Assert.Contains("http_response_status_code=\"401\"", text);
        Assert.DoesNotContain("01890a5d", text);
    }

    [Fact]
    public async Task Cors_allows_only_the_configured_origins()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?>
        {
            ["Network:CorsOrigins:0"] = "https://app.nyxite.test",
        });

        async Task<HttpResponseMessage> Preflight(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Options, "/api/v1/auth/login");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "content-type");
            return await app.CreateClient().SendAsync(request);
        }

        var allowed = await Preflight("https://app.nyxite.test");
        Assert.Equal("https://app.nyxite.test", allowed.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False((await Preflight("https://evil.example")).Headers.Contains("Access-Control-Allow-Origin"));
    }
}
