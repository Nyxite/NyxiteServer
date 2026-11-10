using Nyxite.Application.Auth;
using Nyxite.Domain.Identity;

namespace Nyxite.UnitTests.Auth;

public sealed class AuthEnumTests
{
    [Fact]
    public void Every_auth_enum_value_round_trips_through_its_db_text()
    {
        foreach (var v in Enum.GetValues<AuthMethod>()) Assert.Equal(v, AuthDbValue.ParseAuthMethod(AuthDbValue.Of(v)));
        foreach (var v in Enum.GetValues<EphemeralTokenKind>()) Assert.Equal(v, AuthDbValue.ParseEphemeralTokenKind(AuthDbValue.Of(v)));
        foreach (var v in Enum.GetValues<RevokeReason>()) Assert.Equal(v, AuthDbValue.ParseRevokeReason(AuthDbValue.Of(v)));
        foreach (var v in Enum.GetValues<ClientKind>()) Assert.Equal(v, AuthDbValue.ParseClientKind(AuthDbValue.Of(v)));
        Assert.Throws<FormatException>(() => AuthDbValue.ParseAuthMethod("sms"));
    }

    [Theory]
    [InlineData(AuthMethod.PasswordTotp, new[] { "pwd", "otp", "mfa" })]
    [InlineData(AuthMethod.PasswordEmail, new[] { "pwd", "otp", "mfa" })]
    [InlineData(AuthMethod.PasswordBackupCode, new[] { "pwd", "otp", "mfa" })]
    [InlineData(AuthMethod.Passkey, new[] { "hwk", "user", "mfa" })]
    [InlineData(AuthMethod.Oidc, new[] { "fed", "mfa" })]
    public void Full_sessions_carry_mfa(AuthMethod method, string[] amr) => Assert.Equal(amr, AuthClaims.AmrFor(method, true));

    [Fact]
    public void A_session_without_a_factor_carries_only_pwd()
    {
        foreach (var m in Enum.GetValues<AuthMethod>()) Assert.Equal(["pwd"], AuthClaims.AmrFor(m, false));
    }
}
