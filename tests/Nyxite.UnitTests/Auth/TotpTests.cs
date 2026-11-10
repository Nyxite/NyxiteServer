using System.Security.Cryptography;
using Nyxite.Application.Auth;
using OtpNet;

namespace Nyxite.UnitTests.Auth;

public sealed class TotpTests
{
    private static readonly Guid Owner = Guid.Parse("01890000-0000-7000-8000-000000000001");

    [Fact]
    public void Protect_round_trips_and_hides_the_secret()
    {
        var protector = new TotpSecretProtector(TestAuthOptions.Create());
        var secret = TotpCodes.NewSecret();
        var sealedSecret = protector.Protect(secret, Owner);

        Assert.Equal(secret, protector.Unprotect(sealedSecret, Owner));
        Assert.Equal(1, TotpSecretProtector.VersionOf(sealedSecret));
        Assert.Equal(-1, sealedSecret.AsSpan().IndexOf(secret));
    }

    [Fact]
    public void Ciphertext_is_bound_to_its_owner()
    {
        var protector = new TotpSecretProtector(TestAuthOptions.Create());
        var sealedSecret = protector.Protect(TotpCodes.NewSecret(), Owner);
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(sealedSecret, Guid.NewGuid()));
    }

    [Fact]
    public void Old_pepper_version_still_decrypts_after_rotation()
    {
        var v1 = new TotpSecretProtector(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)}"));
        var v12 = new TotpSecretProtector(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)};2:{TestAuthOptions.Key(2)}"));
        var secret = TotpCodes.NewSecret();
        var old = v1.Protect(secret, Owner);
        Assert.Equal(secret, v12.Unprotect(old, Owner));
        Assert.Equal(2, TotpSecretProtector.VersionOf(v12.Protect(secret, Owner)));
    }

    [Fact]
    public void Tampered_ciphertext_fails()
    {
        var protector = new TotpSecretProtector(TestAuthOptions.Create());
        var sealedSecret = protector.Protect(TotpCodes.NewSecret(), Owner);
        sealedSecret[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(sealedSecret, Owner));
    }

    // RFC 6238 Appendix B, SHA-1 seed "12345678901234567890", T = 59 s -> 94287082 (8 digits; 6-digit form 287082).
    [Fact]
    public void Codes_match_rfc6238_vector_and_tolerate_one_step_of_drift()
    {
        var secret = "12345678901234567890"u8.ToArray();
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var codes = new TotpCodes(clock);

        Assert.Equal("287082", codes.Compute(secret));
        Assert.True(codes.Verify(secret, "287082"));
        clock.Now = DateTimeOffset.FromUnixTimeSeconds(59 + 30);
        Assert.True(codes.Verify(secret, "287082"));
        clock.Now = DateTimeOffset.FromUnixTimeSeconds(59 + 90);
        Assert.False(codes.Verify(secret, "287082"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    [InlineData("٢٨٧٠٨٢")]
    public void Malformed_codes_are_rejected(string? code)
    {
        var codes = new TotpCodes(new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59)));
        Assert.False(codes.Verify("12345678901234567890"u8.ToArray(), code));
    }

    [Fact]
    public void OtpAuth_uri_carries_issuer_account_and_base32_secret()
    {
        var secret = "12345678901234567890"u8.ToArray();
        var uri = TotpCodes.OtpAuthUri("Nyxite", "a@b.test", secret);
        Assert.Equal("otpauth://totp/Nyxite:a%40b.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Nyxite&algorithm=SHA1&digits=6&period=30", uri);
        Assert.Equal(secret, Base32Encoding.ToBytes(TotpCodes.Base32(secret)));
    }

    [Fact]
    public void Verify_reports_the_matched_time_step_within_one_step_of_drift()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var clock = new ManualTimeProvider(now);
        var codes = new TotpCodes(clock);
        var secret = TotpCodes.NewSecret();
        var totp = new Totp(secret);
        var step = now.ToUnixTimeSeconds() / 30;

        Assert.True(codes.Verify(secret, totp.ComputeTotp(now.UtcDateTime), out var matched));
        Assert.Equal(step, matched);
        Assert.True(codes.Verify(secret, totp.ComputeTotp(now.AddSeconds(-30).UtcDateTime), out matched));
        Assert.Equal(step - 1, matched);
        Assert.False(codes.Verify(secret, totp.ComputeTotp(now.AddSeconds(-90).UtcDateTime), out _));
    }
}
