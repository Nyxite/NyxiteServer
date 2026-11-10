using Nyxite.Application.Auth;

namespace Nyxite.UnitTests.Auth;

public sealed class EmailNormalizationTests
{
    [Theory]
    [InlineData("Alice@Example.ORG", "alice@example.org")]
    [InlineData("  bob@example.org ", "bob@example.org")]
    public void Normalizes_case_and_whitespace(string input, string expected)
    {
        Assert.Equal(expected, NativeAuthService.NormalizeEmail(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("Alice <alice@example.org>")]
    [InlineData("a@b@c")]
    public void Rejects_invalid_addresses(string? input)
    {
        Assert.Null(NativeAuthService.NormalizeEmail(input));
    }
}
