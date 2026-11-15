using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Nyxite.Application.Auth;
using Nyxite.Application.Sharing;

namespace Nyxite.Server.Http;

public static class AuthSetup
{
    /// <summary>Policy for factor-enrollment endpoints: any valid session, including an enrollment-limited one.</summary>
    public const string Enrollment = "enrollment";

    /// <summary>Scheme and policy of the link guest's share-session token (08 §8.2), accepted only on <c>/share/{token}/…</c>.</summary>
    public const string GuestScheme = "guest";

    public const string Guest = "guest";

    public static IServiceCollection AddNyxiteBearer(this IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer().AddJwtBearer(GuestScheme);
        services.AddOptions<JwtBearerOptions>(GuestScheme).Configure<GuestTokenService, TimeProvider>(ConfigureGuest);
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<AccessTokenService, TimeProvider>((o, tokens, time) =>
            {
                o.MapInboundClaims = false;
                var parameters = tokens.ValidationParameters();
                parameters.LifetimeValidator = (notBefore, expires, _, p) =>
                {
                    var now = time.GetUtcNow().UtcDateTime;
                    return expires is not null && expires.Value > now - p.ClockSkew && (notBefore is null || notBefore.Value <= now + p.ClockSkew);
                };
                o.TokenValidationParameters = parameters;
                o.Events = new JwtBearerEvents
                {
                    // A browser cannot set a header on a WebSocket upgrade, so the relay also takes its credential as the
                    // access_token query value. That credential is either an access token (a JWT, with dots) or a socket
                    // ticket (08 §8.4, base64url without dots), which is swapped here for a short access token so the
                    // rest of the pipeline sees an ordinary bearer.
                    OnMessageReceived = async context =>
                    {
                        var request = context.HttpContext.Request;
                        if (!request.Path.StartsWithSegments(Realtime.RelayHub.Path)) return;
                        var token = request.Query["access_token"].ToString();
                        if (token.Length == 0 && request.Headers.Authorization.ToString() is { } header
                            && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                            token = header["Bearer ".Length..].Trim();
                        if (token.Length == 0) return;
                        if (token.Contains('.'))
                        {
                            context.Token = token;
                            return;
                        }

                        var negotiate = request.Path.StartsWithSegments(Realtime.RelayHub.Path + "/negotiate");
                        var sessions = context.HttpContext.RequestServices.GetRequiredService<SessionService>();
                        var access = await sessions.RedeemSocketTicketAsync(token, consume: !negotiate, context.HttpContext.RequestAborted);
                        if (access is null) context.Fail("Unknown or used socket ticket.");
                        else context.Token = access;
                    },
                    OnChallenge = async context =>
                    {
                        context.HandleResponse();
                        context.Response.Headers.WWWAuthenticate = "Bearer";
                        var expired = context.AuthenticateFailure is SecurityTokenExpiredException or SecurityTokenInvalidLifetimeException;
                        await Problems.WriteAsync(context.HttpContext, 401, expired ? "token_expired" : "unauthenticated",
                            expired ? "The access token has expired." : "Authentication required.");
                    },
                };
            });

        var full = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim(AuthClaims.Amr, AuthClaims.Mfa)
            .Build();
        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(full)
            .AddPolicy(Enrollment, p => p.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme).RequireAuthenticatedUser())
            .AddPolicy(Guest, p => p.AddAuthenticationSchemes(GuestScheme).RequireAuthenticatedUser().RequireClaim(AuthClaims.ShareId));
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, ProblemAuthorizationResultHandler>();
        return services;
    }

    /// <summary>
    /// The guest token's scheme. It reads the bearer header on every <c>/share/{token}/…</c> path, and on the guest relay
    /// also the <c>access_token</c> query value, which a browser can only send as a guest socket ticket (08 §8.4): the
    /// negotiate request checks it, the WebSocket upgrade uses it up. A validated token must belong to the link whose
    /// token is in the path, so a guest token is good on its own link only.
    /// </summary>
    private static void ConfigureGuest(JwtBearerOptions o, GuestTokenService tokens, TimeProvider time)
    {
        o.MapInboundClaims = false;
        var parameters = tokens.ValidationParameters();
        parameters.LifetimeValidator = (notBefore, expires, _, p) =>
        {
            var now = time.GetUtcNow().UtcDateTime;
            return expires is not null && expires.Value > now - p.ClockSkew && (notBefore is null || notBefore.Value <= now + p.ClockSkew);
        };
        o.TokenValidationParameters = parameters;
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived = async context =>
            {
                var request = context.HttpContext.Request;
                if (ShareToken(request.Path) is not ({ } _, var relay))
                {
                    context.NoResult();
                    return;
                }

                var token = request.Headers.Authorization.ToString() is { } header && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                    ? header["Bearer ".Length..].Trim()
                    : "";
                if (token.Length == 0 && relay) token = request.Query["access_token"].ToString();
                if (token.Length == 0) return;
                if (token.Contains('.'))
                {
                    context.Token = token;
                    return;
                }

                if (!relay)
                {
                    context.Fail("A socket ticket is good on the relay only.");
                    return;
                }

                var negotiate = request.Path.Value!.EndsWith("/ws/negotiate", StringComparison.Ordinal);
                var guests = context.HttpContext.RequestServices.GetRequiredService<GuestShareService>();
                var access = await guests.RedeemTicketAsync(token, consume: !negotiate, context.HttpContext.RequestAborted);
                if (access is null) context.Fail("Unknown or used socket ticket.");
                else context.Token = access;
            },
            OnTokenValidated = async context =>
            {
                var guests = context.HttpContext.RequestServices.GetRequiredService<GuestShareService>();
                if (context.Principal?.GuestShareId() is not { } shareId
                    || !await guests.PathMatchesAsync(ShareToken(context.HttpContext.Request.Path)?.Token, shareId, context.HttpContext.RequestAborted))
                    context.Fail("The guest token belongs to another link.");
            },
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.Headers.WWWAuthenticate = "Bearer";
                var expired = context.AuthenticateFailure is SecurityTokenExpiredException or SecurityTokenInvalidLifetimeException;
                await Problems.WriteAsync(context.HttpContext, 401, expired ? "token_expired" : "unauthenticated",
                    expired ? "The guest token has expired." : "Authentication required.");
            },
        };
    }

    /// <summary>The link token of a <c>/share/{token}/…</c> path, and whether the path is the guest relay.</summary>
    private static (string Token, bool Relay)? ShareToken(PathString path)
    {
        var segments = (path.Value ?? "").Split('/');
        if (segments.Length < 3 || segments[0].Length != 0 || segments[1] != "share" || segments[2].Length == 0) return null;
        return (segments[2], segments.Length >= 4 && segments[3] == "ws");
    }
}
