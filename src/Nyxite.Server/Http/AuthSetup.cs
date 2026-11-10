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
                    // A browser cannot set a header on a WebSocket upgrade, so the relay also takes the token as a query value.
                    OnMessageReceived = context =>
                    {
                        if (context.HttpContext.Request.Path.StartsWithSegments(Realtime.RelayHub.Path)
                            && context.Request.Query["access_token"].ToString() is { Length: > 0 } token)
                            context.Token = token;
                        return Task.CompletedTask;
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
