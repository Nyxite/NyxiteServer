using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Nyxite.Application.Auth;

namespace Nyxite.Server.Http;

public static class AuthSetup
{
    /// <summary>Policy for factor-enrollment endpoints: any valid session, including an enrollment-limited one.</summary>
    public const string Enrollment = "enrollment";

    public static IServiceCollection AddNyxiteBearer(this IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
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
            .AddPolicy(Enrollment, p => p.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme).RequireAuthenticatedUser());
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, ProblemAuthorizationResultHandler>();
        return services;
    }
}
