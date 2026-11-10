using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Nyxite.Server.Http;

/// <summary>
/// Trusts <c>X-Forwarded-For</c>/<c>-Proto</c> only from the configured proxy hops (14 §14.6), so rate limiting and
/// audit see the real client IP behind nginx and Cloudflare. Without configured hops the headers are ignored, because
/// trusting them from anyone would let a client pick its own IP and escape every per-IP limit.
/// </summary>
public static class ForwardedHeadersSetup
{
    /// <summary><c>NYXITE__Network__KnownProxies__&lt;n&gt;</c> (IP addresses) and <c>__KnownNetworks__&lt;n&gt;</c> (CIDR).</summary>
    public static IApplicationBuilder UseNyxiteForwardedHeaders(this IApplicationBuilder app, IConfiguration configuration)
    {
        var proxies = configuration.GetSection("Network:KnownProxies").Get<string[]>() ?? [];
        var networks = configuration.GetSection("Network:KnownNetworks").Get<string[]>() ?? [];
        if (proxies.Length == 0 && networks.Length == 0)
        {
            // Behind a reverse proxy every client then shares the proxy's address and with it one rate-limit bucket.
            app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("Nyxite.Server.Network").LogWarning(
                "No trusted proxy is configured (Network:KnownProxies / Network:KnownNetworks): forwarded headers are ignored. " +
                "Behind a reverse proxy all clients then share one address for rate limiting and audit.");
            return app;
        }

        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            // Walk back through every trusted hop (Cloudflare, then nginx) to the first untrusted address.
            ForwardLimit = null,
        };
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var p in proxies) options.KnownProxies.Add(IPAddress.Parse(p));
        foreach (var n in networks) options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(n));
        return app.UseForwardedHeaders(options);
    }
}
