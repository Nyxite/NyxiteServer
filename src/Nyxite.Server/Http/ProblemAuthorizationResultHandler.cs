using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Authorization.Policy;
using Nyxite.Application.Auth;

namespace Nyxite.Server.Http;

/// <summary>
/// Turns authorization failures into problems: a signed-in session that lacks a second factor gets
/// <c>403 2fa_required</c> (08 §8.2); other forbidden results get <c>403 acl_denied</c>.
/// </summary>
public sealed class ProblemAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();

    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult result)
    {
        if (!result.Forbidden) return _default.HandleAsync(next, context, policy, result);
        var missingFactor = result.AuthorizationFailure?.FailedRequirements
            .OfType<ClaimsAuthorizationRequirement>().Any(r => r.ClaimType == AuthClaims.Amr) == true;
        return missingFactor
            ? Problems.WriteAsync(context, 403, "2fa_required", "A second factor is required.")
            : Problems.WriteAsync(context, 403, "acl_denied", "Access denied.");
    }
}
