using Nyxite.Application.Auth;

namespace Nyxite.Server.Http;

/// <summary>
/// Response hardening of 13 §13.6: secure headers on every response and strict CORS for the known client origins.
/// TLS ends at the reverse proxy (14 §14.6), so HSTS is sent whenever the request arrived over HTTPS as seen through
/// the trusted forwarded headers.
/// </summary>
public static class Hardening
{
    public const string RequestIdHeader = "Nyxite-Request-Id";
    private const string CorsPolicy = "clients";

    /// <summary><c>NYXITE__Network__CorsOrigins__&lt;n&gt;</c>: browser origins allowed to call the API. None = same-origin only.</summary>
    public static IServiceCollection AddNyxiteCors(this IServiceCollection services, IConfiguration configuration)
    {
        var origins = configuration.GetSection("Network:CorsOrigins").Get<string[]>() ?? [];
        services.AddCors(o => o.AddPolicy(CorsPolicy, p =>
        {
            if (origins.Length == 0) return;
            p.WithOrigins(origins)
                .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE")
                .WithHeaders("Authorization", "Content-Type", "Idempotency-Key", "If-Match", "Nyxite-Step-Up")
                .WithExposedHeaders("Retry-After", "ETag", RequestIdHeader)
                .SetPreflightMaxAge(TimeSpan.FromHours(1));
        }));
        return services;
    }

    public static IApplicationBuilder UseNyxiteHardening(this IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            // The API serves JSON only; nothing it returns may load or run anything in a browser.
            headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
            headers.CacheControl = "no-store";
            if (context.Request.IsHttps) headers.StrictTransportSecurity = "max-age=63072000; includeSubDomains";
            // The correlation id of the structured logs, so a client report can be matched to its log lines.
            headers[RequestIdHeader] = System.Diagnostics.Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;
            await next();
        });
        return app.UseCors(CorsPolicy);
    }

    /// <summary>Expected failures are answers, not incidents: only an unexpected exception is logged as an error.</summary>
    public static bool IsExpected(Exception e) =>
        e is AuthException or BadHttpRequestException or OperationCanceledException;
}
