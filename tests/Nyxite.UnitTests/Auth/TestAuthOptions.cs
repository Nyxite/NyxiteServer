using Microsoft.Extensions.Options;
using Nyxite.Application.Auth;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Auth;

internal static class TestAuthOptions
{
    public static string Key(byte fill) => Convert.ToBase64String(Enumerable.Repeat(fill, 32).ToArray());

    public static IOptions<AuthOptions> Create(string? pepper = null, string? signing = null) => Options.Create(new AuthOptions
    {
        Issuer = "https://nyxite.test",
        Audience = "nyxite-test",
        PasswordPepper = pepper ?? $"1:{Key(1)}",
        TokenSigningKey = signing ?? $"1:{Key(9)}",
        PasswordHashing = new Argon2idParameters(1024, 1, 1),
    });
}

/// <summary>A clock the tests move by hand.</summary>
internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
}
