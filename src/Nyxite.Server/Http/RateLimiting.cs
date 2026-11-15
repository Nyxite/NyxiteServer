using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Nyxite.Server.Http;

/// <summary><c>NYXITE__RateLimiting__{Bucket}__*</c> (14): the fixed window of one bucket.</summary>
public sealed class RateLimitOptions
{
    public int PermitLimit { get; set; } = 10;
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>
/// Request rate limits (13 §13.5). The <see cref="Auth"/> policy is a fixed window per client IP on every endpoint that
/// checks a password or a code, answered with <c>429 rate_limited</c> and <c>Retry-After</c>. The client IP is only
/// correct behind a proxy when its forwarded headers are trusted (<see cref="ForwardedHeadersSetup"/>).
/// <para>
/// The per-IP buckets of credentials that cost a database lookup, <see cref="ShareAccess"/> and
/// <see cref="RelayTicket"/>, run ahead of authentication (<see cref="UseNyxitePreAuthenticationRateLimiting"/>), so a
/// request with a missing, wrong or foreign token or ticket is counted like any other. The endpoint policies run after
/// authorization, because the per-user ones partition by the authenticated subject.
/// </para>
/// </summary>
public static class RateLimiting
{
    public const string Auth = "auth";

    /// <summary>Per-user bucket of <c>GET /keys/directory</c>, against social-graph probing (13 §13.5).</summary>
    public const string Directory = "directory";

    /// <summary>Per-user bucket of <c>POST /devices</c>; every pending device holds a guessable pairing code (13 §13.5).</summary>
    public const string DeviceEnrollment = "device-enrollment";

    /// <summary>Per-user bucket of <c>POST /shares</c> (13 §13.5).</summary>
    public const string Shares = "shares";

    /// <summary>Per-IP bucket of every public <c>/share/{token}…</c> request, the guest relay's handshake included (13 §13.5).</summary>
    public const string ShareAccess = "share-access";

    /// <summary>Per-IP bucket of every <c>/hubs/relay</c> request that carries a socket ticket (08 §8.4, 13 §13.5).</summary>
    public const string RelayTicket = "relay-ticket";

    public static IServiceCollection AddNyxiteRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var auth = configuration.GetSection("RateLimiting:Auth").Get<RateLimitOptions>() ?? new RateLimitOptions();
        var directory = configuration.GetSection("RateLimiting:Directory").Get<RateLimitOptions>() ?? new RateLimitOptions { PermitLimit = 60 };
        var enrollment = configuration.GetSection("RateLimiting:DeviceEnrollment").Get<RateLimitOptions>()
                         ?? new RateLimitOptions { PermitLimit = 5, Window = TimeSpan.FromHours(1) };
        var shares = configuration.GetSection("RateLimiting:Shares").Get<RateLimitOptions>() ?? new RateLimitOptions { PermitLimit = 30 };
        var shareAccess = configuration.GetSection("RateLimiting:ShareAccess").Get<RateLimitOptions>() ?? new RateLimitOptions { PermitLimit = 30 };
        var relayTicket = configuration.GetSection("RateLimiting:RelayTicket").Get<RateLimitOptions>() ?? new RateLimitOptions { PermitLimit = 120 };
        services.AddSingleton(new PreAuthenticationLimiter(PartitionedRateLimiter.Create<HttpContext, string>(context =>
            context.Request.Path.StartsWithSegments(Endpoints.PublicShareEndpoints.Prefix) ? PerIp(context, shareAccess, ShareAccess)
            : CarriesRelayTicket(context.Request) ? PerIp(context, relayTicket, RelayTicket)
            : RateLimitPartition.GetNoLimiter(""))));
        services.AddRateLimiter(o =>
        {
            o.AddPolicy(Auth, context => PerIp(context, auth));
            o.AddPolicy(Directory, context => PerUser(context, directory));
            o.AddPolicy(DeviceEnrollment, context => PerUser(context, enrollment));
            o.AddPolicy(Shares, context => PerUser(context, shares));
            o.OnRejected = (context, _) => RejectAsync(context.HttpContext, context.Lease, auth.Window);
        });
        return services;
    }

    /// <summary>
    /// Runs the per-IP buckets of <see cref="ShareAccess"/> and <see cref="RelayTicket"/> before authentication, with the
    /// same <c>429 rate_limited</c> and <c>Retry-After</c> as every other bucket.
    /// </summary>
    public static IApplicationBuilder UseNyxitePreAuthenticationRateLimiting(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        using var lease = context.RequestServices.GetRequiredService<PreAuthenticationLimiter>().Limiter.AttemptAcquire(context);
        if (!lease.IsAcquired)
        {
            await RejectAsync(context, lease, TimeSpan.FromMinutes(1));
            return;
        }

        await next(context);
    });

    private static async ValueTask RejectAsync(HttpContext context, RateLimitLease lease, TimeSpan fallback)
    {
        var retry = lease.TryGetMetadata(MetadataName.RetryAfter, out var after) ? after : fallback;
        context.Response.Headers.RetryAfter = ((int)Math.Ceiling(retry.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        await Problems.WriteAsync(context, StatusCodes.Status429TooManyRequests, "rate_limited", "Too many requests.");
    }

    /// <summary>
    /// A relay request whose credential is a socket ticket (no dots, unlike a JWT), which the bearer scheme redeems
    /// with a database lookup (08 §8.4). A request with an access token costs only a signature check and is not counted,
    /// so long polling, which sends one request per poll, stays unlimited here.
    /// </summary>
    private static bool CarriesRelayTicket(HttpRequest request)
    {
        if (!request.Path.StartsWithSegments(Realtime.RelayHub.Path)) return false;
        var token = request.Query["access_token"].ToString();
        if (token.Length == 0 && request.Headers.Authorization.ToString() is { } header && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            token = header["Bearer ".Length..].Trim();
        return token.Length > 0 && !token.Contains('.');
    }

    /// <summary>Partitions by the client IP, which is only right behind a proxy whose forwarded headers are trusted.</summary>
    private static RateLimitPartition<string> PerIp(HttpContext context, RateLimitOptions limit, string bucket = "") =>
        RateLimitPartition.GetFixedWindowLimiter(
            bucket + ":" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit.PermitLimit, Window = limit.Window, QueueLimit = 0 });

    /// <summary>Partitions by the authenticated user (<c>sub</c>); these endpoints all require a session.</summary>
    private static RateLimitPartition<string> PerUser(HttpContext context, RateLimitOptions limit) =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.FindFirst(Nyxite.Application.Auth.AuthClaims.Subject)?.Value ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit.PermitLimit, Window = limit.Window, QueueLimit = 0 });
}

/// <summary>The per-IP limiter that runs before authentication (<see cref="RateLimiting.UseNyxitePreAuthenticationRateLimiting"/>).</summary>
public sealed class PreAuthenticationLimiter(PartitionedRateLimiter<HttpContext> limiter) : IDisposable
{
    public PartitionedRateLimiter<HttpContext> Limiter { get; } = limiter;

    public void Dispose() => Limiter.Dispose();
}
