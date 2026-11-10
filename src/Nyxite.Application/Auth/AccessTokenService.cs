using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Nyxite.Domain.Identity;

namespace Nyxite.Application.Auth;

/// <summary>
/// Issues the server's own access token (08 §8.2): JWT, header <c>{alg: HS256, typ: at+jwt, kid: version}</c>,
/// claims <c>iss aud sub sid role amr iat exp jti</c> and nothing else (no email or display name).
/// </summary>
public sealed class AccessTokenService
{
    private readonly AuthOptions _options;
    private readonly VersionedSecret _keys;
    private readonly TimeProvider _time;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public AccessTokenService(IOptions<AuthOptions> options, TimeProvider time)
    {
        _options = options.Value;
        _keys = VersionedSecret.Parse(_options.TokenSigningKey, "Auth:TokenSigningKey");
        _time = time;
    }

    /// <summary>Every configured key version, for validation during a rollover.</summary>
    public IEnumerable<SecurityKey> ValidationKeys =>
        _keys.Versions.Select(v => new SymmetricSecurityKey(_keys.TryGet(v, out var k) ? k : []) { KeyId = v.ToString() });

    public (string Token, DateTimeOffset ExpiresAt) Issue(Guid userId, Guid sessionId, UserRole role, AuthMethod method, bool mfaVerified)
    {
        var now = _time.GetUtcNow();
        var expires = now + _options.AccessTokenLifetime;
        var key = new SymmetricSecurityKey(_keys.Current) { KeyId = _keys.CurrentVersion.ToString() };
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            TokenType = AuthClaims.AccessTokenType,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
            Claims = new Dictionary<string, object>
            {
                [AuthClaims.Subject] = userId.ToString(),
                [AuthClaims.SessionId] = sessionId.ToString(),
                [AuthClaims.Role] = DbValue.Of(role),
                [AuthClaims.Amr] = AuthClaims.AmrFor(method, mfaVerified),
                ["jti"] = Guid.CreateVersion7(now).ToString(),
            },
        };
        return (_handler.CreateToken(descriptor), expires);
    }

    /// <summary>Validation rules shared by the bearer handler: HS256 only, <c>typ: at+jwt</c> only, short skew.</summary>
    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidIssuer = _options.Issuer,
        ValidAudience = _options.Audience,
        IssuerSigningKeys = ValidationKeys.ToList(),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ValidTypes = [AuthClaims.AccessTokenType],
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = AuthClaims.Subject,
        RoleClaimType = AuthClaims.Role,
    };
}
