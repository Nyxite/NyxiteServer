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
/// </summary>
public static class RateLimiting
{
    public const string Auth = "auth";

    /// <summary>Per-user bucket of <c>GET /keys/directory</c>, against social-graph probing (13 §13.5).</summary>
    public const string Directory = "directory";

    /// <summary>Per-user bucket of <c>POST /devices</c>; every pending device holds a guessable pairing code (13 §13.5).</summary>
    public const string DeviceEnrollment = "device-enrollment";

    public static IServiceCollection AddNyxiteRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var auth = configuration.GetSection("RateLimiting:Auth").Get<RateLimitOptions>() ?? new RateLimitOptions();
        var directory = configuration.GetSection("RateLimiting:Directory").Get<RateLimitOptions>() ?? new RateLimitOptions { PermitLimit = 60 };
        var enrollment = configuration.GetSection("RateLimiting:DeviceEnrollment").Get<RateLimitOptions>()
                         ?? new RateLimitOptions { PermitLimit = 5, Window = TimeSpan.FromHours(1) };
        services.AddRateLimiter(o =>
        {
            o.AddPolicy(Auth, context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = auth.PermitLimit, Window = auth.Window, QueueLimit = 0 }));
            o.AddPolicy(Directory, context => PerUser(context, directory));
            o.AddPolicy(DeviceEnrollment, context => PerUser(context, enrollment));
            o.OnRejected = async (context, ct) =>
            {
                var retry = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var after) ? after : auth.Window;
                context.HttpContext.Response.Headers.RetryAfter =
                    ((int)Math.Ceiling(retry.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                await Problems.WriteAsync(context.HttpContext, StatusCodes.Status429TooManyRequests, "rate_limited", "Too many requests.");
            };
        });
        return services;
    }

    /// <summary>Partitions by the authenticated user (<c>sub</c>); these endpoints all require a session.</summary>
    private static RateLimitPartition<string> PerUser(HttpContext context, RateLimitOptions limit) =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.FindFirst(Nyxite.Application.Auth.AuthClaims.Subject)?.Value ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit.PermitLimit, Window = limit.Window, QueueLimit = 0 });
}
