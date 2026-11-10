using Nyxite.Application.Auth;

namespace Nyxite.UnitTests.Auth;

public sealed class VersionedSecretTests
{
    private static readonly string K1 = TestAuthOptions.Key(1);
    private static readonly string K2 = TestAuthOptions.Key(2);

    [Fact]
    public void Highest_version_is_current_regardless_of_order()
    {
        var s = VersionedSecret.Parse($"3:{K2}; 1:{K1}", "x");
        Assert.Equal(3, s.CurrentVersion);
        Assert.Equal(Convert.FromBase64String(K2), s.Current);
        Assert.True(s.TryGet(1, out var old));
        Assert.Equal(Convert.FromBase64String(K1), old);
        Assert.False(s.TryGet(2, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("nokey")]
    [InlineData("0:AAAA")]
    [InlineData("x:AAAA")]
    [InlineData("1:not-base64!")]
    [InlineData("1:AAAA")]
    public void Rejects_missing_malformed_or_short_keys(string? value)
    {
        Assert.Throws<InvalidOperationException>(() => VersionedSecret.Parse(value, "x"));
    }

    [Fact]
    public void Rejects_duplicate_versions()
    {
        Assert.Throws<InvalidOperationException>(() => VersionedSecret.Parse($"1:{K1};1:{K2}", "x"));
    }
}
