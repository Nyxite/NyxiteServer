using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Http;

/// <summary>P0.1-SRV-5 and 13 §13.5: OpenAPI document, health endpoints, contract drift, rate limiting, proxy trust.</summary>
public sealed class OperationsTests(PostgresFixture pg)
{
    [Fact]
    public async Task Openapi_document_is_served_as_typed_json()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var response = await app.CreateClient().GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var doc = await response.JsonAsync();
        Assert.Equal("3.1.0", doc.GetProperty("openapi").GetString());
        var register = doc.GetProperty("paths").GetProperty("/auth/register").GetProperty("post");
        Assert.Equal(JsonValueKind.Array, register.GetProperty("security").ValueKind);
        var password = register.GetProperty("requestBody").GetProperty("content").GetProperty("application/json")
            .GetProperty("schema").GetProperty("properties").GetProperty("password");
        Assert.Equal(12, password.GetProperty("minLength").GetInt32());
        Assert.True(register.GetProperty("requestBody").GetProperty("required").GetBoolean());
        Assert.True(register.GetProperty("responses").TryGetProperty("201", out _));
    }

    /// <summary>04 §4.1 contract drift: every route the server maps must be described, with its method, in openapi/v1.yaml.</summary>
    [Fact]
    public async Task Every_mapped_route_is_in_the_openapi_contract()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var doc = await (await app.CreateClient().GetAsync("/openapi/v1.json")).JsonAsync();
        var paths = doc.GetProperty("paths");

        var missing = new List<string>();
        foreach (var endpoint in app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>())
        {
            // Route constraints ({id:guid}) are server detail; the contract names the bare parameter ({id}).
            var route = "/" + System.Text.RegularExpressions.Regex.Replace(endpoint.RoutePattern.RawText!.TrimStart('/'), @"\{(\w+):[^}]*\}", "{$1}");
            var path = route.StartsWith("/api/v1/", StringComparison.Ordinal) ? route["/api/v1".Length..] : route;
            // The relay is a SignalR hub and not a REST surface; the contract leaves it out by design (05).
            if (route.StartsWith("/hubs/", StringComparison.Ordinal)) continue;
            var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? ["GET"];
            foreach (var method in methods)
            {
                if (!paths.TryGetProperty(path, out var item) || !item.TryGetProperty(method.ToLowerInvariant(), out _))
                    missing.Add($"{method} {path}");
            }
        }

        Assert.Empty(missing);
    }

    /// <summary>04 §4.1 contract drift: every JSON body the server reads has the property names and types the contract documents.</summary>
    [Fact]
    public async Task Every_request_body_matches_the_openapi_contract()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var drift = new List<string>();
        var checkedBodies = 0;
        foreach (var endpoint in app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>())
        {
            if (endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Http.Metadata.IAcceptsMetadata>() is not { RequestType: { } body }) continue;
            foreach (var method in endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [])
            {
                // A route the contract lacks is reported by Every_mapped_route_is_in_the_openapi_contract.
                if (OpenApiContract.OperationOfRoute(method, endpoint.RoutePattern.RawText!) is not { } operation) continue;
                checkedBodies++;
                drift.AddRange(OpenApiContract.CheckRequestType(operation, body).Select(e => $"{method} {endpoint.RoutePattern.RawText}: {e}"));
            }
        }

        Assert.Empty(drift);
        Assert.True(checkedBodies > 20, $"Only {checkedBodies} request bodies were found, the endpoint metadata is not what this test expects.");
    }

    [Fact]
    public async Task Health_live_and_ready_answer_200_on_a_migrated_database()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var client = app.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready")).StatusCode);
    }

    [Fact]
    public async Task Ready_is_503_while_migrations_are_pending_and_live_stays_200()
    {
        await using var app = new NyxiteApp(await pg.CreateEmptyDatabaseAsync());
        var client = app.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
        var ready = await client.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        Assert.DoesNotContain("Host=", await ready.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Auth_bucket_is_shared_by_sign_in_endpoints_and_spares_refresh()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?> { ["RateLimiting:Auth:PermitLimit"] = "3" });
        var client = app.CreateClient();
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email = "a@example.org", password = "x", clientKind = "web" });
        await client.PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = "x", totpCode = "123456" });
        await client.PostAsJsonAsync("/api/v1/auth/webauthn/assert/options", new { });

        var limited = await client.PostAsJsonAsync("/api/v1/auth/register", new { email = "b@example.org", displayName = "B", password = AuthDriver.Password, clientKind = "web" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("rate_limited", await limited.ProblemCodeAsync());
        Assert.True(limited.Headers.Contains("Retry-After"));

        // Refresh presents a 256-bit token: nothing to guess, so it is not in the auth bucket.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = "x" })).StatusCode);
    }

    [Fact]
    public async Task Forwarded_client_ip_is_trusted_only_from_a_known_proxy()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?>
        {
            ["RateLimiting:Auth:PermitLimit"] = "1",
            ["Network:KnownProxies:0"] = "10.0.0.1",
        });
        await using var host = app.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton<IStartupFilter>(new RemoteIpFilter())));

        async Task<HttpStatusCode> Login(string remote, string forwardedFor)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
            {
                Content = JsonContent.Create(new { email = "a@example.org", password = "x", clientKind = "web" }),
            };
            request.Headers.Add(RemoteIpFilter.Header, remote);
            request.Headers.Add("X-Forwarded-For", forwardedFor);
            return (await host.CreateClient().SendAsync(request)).StatusCode;
        }

        // Behind the trusted proxy, two clients get a bucket each.
        Assert.Equal(HttpStatusCode.Unauthorized, await Login("10.0.0.1", "198.51.100.1"));
        Assert.Equal(HttpStatusCode.Unauthorized, await Login("10.0.0.1", "198.51.100.2"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Login("10.0.0.1", "198.51.100.1"));

        // An untrusted sender cannot pick a fresh IP through the header.
        Assert.Equal(HttpStatusCode.Unauthorized, await Login("203.0.113.9", "198.51.100.3"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Login("203.0.113.9", "198.51.100.4"));
    }

    /// <summary>TestServer has no socket, so this sets the connection's remote IP from a test header before the app runs.</summary>
    private sealed class RemoteIpFilter : IStartupFilter
    {
        public const string Header = "X-Test-Remote-Ip";

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (HttpContext context, RequestDelegate nextMiddleware) =>
            {
                if (context.Request.Headers.TryGetValue(Header, out var ip)) context.Connection.RemoteIpAddress = IPAddress.Parse(ip!);
                await nextMiddleware(context);
            });
            next(app);
        };
    }
}
