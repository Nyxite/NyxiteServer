using Microsoft.Extensions.Options;

namespace Nyxite.Application.Auth;

/// <summary>An identity established by an external IdP, before it is mapped onto a native <c>users</c> row.</summary>
public sealed record ExternalIdentity(string Provider, string Subject, string? Email, string? DisplayName);

/// <summary>
/// The pluggable IdP seam (08 §8.1). Native password + TOTP and passkeys are built in; an external provider (enterprise
/// Keycloak/OIDC) plugs in here. Every provider ends in <see cref="SessionService.StartAsync"/>, so the rest of the API
/// only ever sees the server's own token and never which IdP authenticated the user.
/// </summary>
public interface IExternalIdentityProvider
{
    string Name { get; }

    /// <summary>Builds the IdP authorization redirect (state, nonce and PKCE verifier kept in <c>oidc_state</c>).</summary>
    Task<Uri> BeginAsync(string client, string redirectUri, CancellationToken ct);

    /// <summary>Validates the IdP callback and returns the authenticated external identity.</summary>
    Task<ExternalIdentity> CompleteAsync(string code, string state, CancellationToken ct);
}

/// <summary>
/// Enterprise Keycloak/OIDC provider stub (Phase 0.1 ships only the seam). Active only when
/// <c>Auth:Enterprise:Enabled</c> is set; every call reports the provider as not available yet.
/// </summary>
public sealed class KeycloakOidcProvider : IExternalIdentityProvider
{
    public string Name => "keycloak";

    public Task<Uri> BeginAsync(string client, string redirectUri, CancellationToken ct) =>
        throw AuthException.Unavailable("Enterprise OIDC sign-in is not implemented yet.");

    public Task<ExternalIdentity> CompleteAsync(string code, string state, CancellationToken ct) =>
        throw AuthException.Unavailable("Enterprise OIDC sign-in is not implemented yet.");
}

/// <summary>Resolves the configured external IdP; <c>null</c> in the default (community/native) deployment.</summary>
public sealed class ExternalIdentityProviderResolver(IOptions<AuthOptions> options, KeycloakOidcProvider keycloak)
{
    public IExternalIdentityProvider? Current => options.Value.Enterprise.Enabled ? keycloak : null;
}
