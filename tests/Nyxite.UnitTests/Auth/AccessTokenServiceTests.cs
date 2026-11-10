using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Nyxite.Application.Auth;
using Nyxite.Domain.Identity;

namespace Nyxite.UnitTests.Auth;

public sealed class AccessTokenServiceTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static readonly Guid User = Guid.CreateVersion7();
    private static readonly Guid Session = Guid.CreateVersion7();

    private static AccessTokenService Service(string? signing = null) =>
        new(TestAuthOptions.Create(signing: signing), new ManualTimeProvider(Now));

    [Fact]
    public void Header_and_claims_follow_the_token_model()
    {
        var (token, expires) = Service().Issue(User, Session, UserRole.Admin, AuthMethod.PasswordTotp, mfaVerified: true);
        var jwt = new JsonWebToken(token);

        Assert.Equal("HS256", jwt.Alg);
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.Equal("1", jwt.Kid);
        Assert.Equal("https://nyxite.test", jwt.Issuer);
        Assert.Equal(["nyxite-test"], jwt.Audiences);
        Assert.Equal(User.ToString(), jwt.Subject);
        Assert.Equal(Session.ToString(), jwt.GetClaim("sid").Value);
        Assert.Equal("admin", jwt.GetClaim("role").Value);
        Assert.Equal(["pwd", "otp", "mfa"], jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        Assert.NotEmpty(jwt.Id);
        Assert.Equal(Now.AddMinutes(5).ToUnixTimeSeconds(), expires.ToUnixTimeSeconds());

        var allowed = new[] { "iss", "aud", "sub", "sid", "role", "amr", "iat", "exp", "jti" };
        Assert.All(jwt.Claims, c => Assert.Contains(c.Type, allowed));
    }

    [Fact]
    public void Limited_session_carries_no_mfa()
    {
        var (token, _) = Service().Issue(User, Session, UserRole.User, AuthMethod.PasswordTotp, mfaVerified: false);
        Assert.Equal(["pwd"], new JsonWebToken(token).Claims.Where(c => c.Type == "amr").Select(c => c.Value));
    }

    [Fact]
    public async Task Token_validates_with_the_shared_parameters()
    {
        var service = Service();
        var (token, _) = service.Issue(User, Session, UserRole.User, AuthMethod.Passkey, mfaVerified: true);
        var p = service.ValidationParameters();
        p.LifetimeValidator = (_, _, _, _) => true;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, p);
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task Previous_key_version_still_validates_during_rollover()
    {
        var old = Service(signing: $"1:{TestAuthOptions.Key(9)}");
        var rolled = Service(signing: $"1:{TestAuthOptions.Key(9)};2:{TestAuthOptions.Key(10)}");
        var (token, _) = old.Issue(User, Session, UserRole.User, AuthMethod.Passkey, true);
        Assert.Equal("2", new JsonWebToken(rolled.Issue(User, Session, UserRole.User, AuthMethod.Passkey, true).Token).Kid);

        var p = rolled.ValidationParameters();
        p.LifetimeValidator = (_, _, _, _) => true;
        Assert.True((await new JsonWebTokenHandler().ValidateTokenAsync(token, p)).IsValid);
    }

    [Fact]
    public async Task Wrong_type_none_algorithm_and_foreign_key_are_rejected()
    {
        var service = Service();
        var p = service.ValidationParameters();
        p.LifetimeValidator = (_, _, _, _) => true;
        var handler = new JsonWebTokenHandler();
        var claims = new Dictionary<string, object> { ["sub"] = User.ToString() };

        var wrongTyp = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://nyxite.test", Audience = "nyxite-test", Claims = claims, TokenType = "nyx-guest+jwt",
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Convert.FromBase64String(TestAuthOptions.Key(9))) { KeyId = "1" }, SecurityAlgorithms.HmacSha256),
        });
        var foreignKey = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://nyxite.test", Audience = "nyxite-test", Claims = claims, TokenType = "at+jwt",
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Convert.FromBase64String(TestAuthOptions.Key(7))) { KeyId = "1" }, SecurityAlgorithms.HmacSha256),
        });
        var header = Base64UrlEncoder.Encode("""{"alg":"none","typ":"at+jwt"}""");
        var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes($$"""{"iss":"https://nyxite.test","aud":"nyxite-test","sub":"{{User}}"}"""));
        var unsigned = $"{header}.{payload}.";

        foreach (var token in new[] { wrongTyp, foreignKey, unsigned })
            Assert.False((await handler.ValidateTokenAsync(token, p)).IsValid);
    }
}
