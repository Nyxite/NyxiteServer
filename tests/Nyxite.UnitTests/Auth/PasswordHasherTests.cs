using System.Text;
using Nyxite.Application.Auth;

namespace Nyxite.UnitTests.Auth;

public sealed class PasswordHasherTests
{
    private const string Password = "correct horse battery";

    [Fact]
    public void Hash_produces_phc_argon2id_string_without_the_password()
    {
        var hasher = new PasswordHasher(TestAuthOptions.Create());
        var (verifier, version) = hasher.Hash(Password);
        var text = Encoding.ASCII.GetString(verifier);
        Assert.StartsWith("$argon2id$v=19$m=1024,t=1,p=1$", text);
        Assert.DoesNotContain(Password, text);
        Assert.Equal(1, version);
    }

    [Fact]
    public void Verify_accepts_right_and_rejects_wrong_password()
    {
        var hasher = new PasswordHasher(TestAuthOptions.Create());
        var (verifier, version) = hasher.Hash(Password);
        Assert.Equal(new PasswordCheck(true, false), hasher.Verify(Password, verifier, version));
        Assert.False(hasher.Verify(Password + "!", verifier, version).Valid);
    }

    [Fact]
    public void Same_password_gets_a_fresh_salt_each_time()
    {
        var hasher = new PasswordHasher(TestAuthOptions.Create());
        Assert.NotEqual(hasher.Hash(Password).Verifier, hasher.Hash(Password).Verifier);
    }

    [Fact]
    public void Verifier_is_useless_without_the_pepper()
    {
        var withPepperA = new PasswordHasher(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)}"));
        var withPepperB = new PasswordHasher(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(2)}"));
        var (verifier, version) = withPepperA.Hash(Password);
        Assert.False(withPepperB.Verify(Password, verifier, version).Valid);
    }

    [Fact]
    public void Old_pepper_version_still_verifies_and_asks_for_rehash()
    {
        var v1 = new PasswordHasher(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)}"));
        var v2 = new PasswordHasher(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)};2:{TestAuthOptions.Key(2)}"));
        var (verifier, version) = v1.Hash(Password);

        Assert.Equal(new PasswordCheck(true, true), v2.Verify(Password, verifier, version));
        var (rehashed, newVersion) = v2.Hash(Password);
        Assert.Equal(2, newVersion);
        Assert.Equal(new PasswordCheck(true, false), v2.Verify(Password, rehashed, newVersion));
    }

    [Fact]
    public void Removed_pepper_version_fails_closed()
    {
        var v1 = new PasswordHasher(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)}"));
        var only2 = new PasswordHasher(TestAuthOptions.Create(pepper: $"2:{TestAuthOptions.Key(2)}"));
        var (verifier, version) = v1.Hash(Password);
        Assert.False(only2.Verify(Password, verifier, version).Valid);
    }

    [Fact]
    public void Changed_parameters_ask_for_rehash()
    {
        var weak = new PasswordHasher(TestAuthOptions.Create());
        var options = TestAuthOptions.Create();
        options.Value.PasswordHashing = new(2048, 1, 1);
        var stronger = new PasswordHasher(options);
        var (verifier, version) = weak.Hash(Password);
        Assert.Equal(new PasswordCheck(true, true), stronger.Verify(Password, verifier, version));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain")]
    [InlineData("$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$AAAA")]
    [InlineData("$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Malformed_verifier_fails_without_throwing(string verifier)
    {
        var hasher = new PasswordHasher(TestAuthOptions.Create());
        Assert.False(hasher.Verify(Password, Encoding.ASCII.GetBytes(verifier), 1).Valid);
    }
}
