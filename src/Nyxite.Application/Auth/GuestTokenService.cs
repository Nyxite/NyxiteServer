using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Nyxite.Application.Auth;

/// <summary>
/// Issues the guest share-session token (08 §8.2): JWT, header <c>{alg: HS256, typ: nyx-guest+jwt, kid}</c>, claims
/// <c>iss aud sub share_id perm iat exp jti</c>, signed with the server's token-signing key. It is not stored: every
/// renewal re-checks the share row instead (03 §3.2), and it never carries a key, because the guest's key is the URL
/// fragment the server never sees.
/// </summary>
public sealed class GuestTokenService(AccessTokenService access, IOptions<AuthOptions> options, TimeProvider time)
{
    private readonly AuthOptions _options = options.Value;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TimeSpan Lifetime => _options.Lifetimes.GuestSession;

    public (string Token, DateTimeOffset ExpiresAt) Issue(Guid shareId, string permission)
    {
        var now = time.GetUtcNow();
        var expires = now + Lifetime;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            TokenType = AuthClaims.GuestTokenType,
            SigningCredentials = new SigningCredentials(access.CurrentSigningKey, SecurityAlgorithms.HmacSha256),
            Claims = new Dictionary<string, object>
            {
                // Stable across renewals and tickets, so the relay sees one guest on negotiate and upgrade; never a
                // UUID, so it can never be read as an account id.
                [AuthClaims.Subject] = "share:" + shareId,
                [AuthClaims.ShareId] = shareId.ToString(),
                [AuthClaims.Permission] = permission,
                ["jti"] = Guid.CreateVersion7(now).ToString(),
            },
        };
        return (_handler.CreateToken(descriptor), expires);
    }

    /// <summary>The access token's rules with the guest <c>typ</c> as the only accepted type.</summary>
    public TokenValidationParameters ValidationParameters()
    {
        var parameters = access.ValidationParameters();
        parameters.ValidTypes = [AuthClaims.GuestTokenType];
        parameters.NameClaimType = AuthClaims.ShareId;
        return parameters;
    }
}
