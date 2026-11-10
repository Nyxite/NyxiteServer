using System.Text;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

public sealed class Argon2idTests
{
    // Reference implementation KAT (phc-winner-argon2 src/test.c, Argon2id v0x13, m = 2^16, t = 2, p = 1).
    [Fact]
    public void Matches_reference_implementation_vector()
    {
        var output = Argon2id.Derive("password"u8, "somesalt"u8, new Argon2idParameters(65536, 2, 1));
        Assert.Equal("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", Hex.Of(output));
    }

    [Fact]
    public void Default_parameters_are_the_pinned_v1_values()
    {
        Assert.Equal(new Argon2idParameters(65536, 3, 1), Argon2id.Default);
    }

    [Fact]
    public void Is_deterministic_and_sensitive_to_every_input()
    {
        var p = new Argon2idParameters(1024, 1, 1);
        var salt = Encoding.ASCII.GetBytes("saltsalt");
        var a = Argon2id.Derive("pw"u8, salt, p);

        Assert.Equal(a, Argon2id.Derive("pw"u8, salt, p));
        Assert.NotEqual(a, Argon2id.Derive("pW"u8, salt, p));
        Assert.NotEqual(a, Argon2id.Derive("pw"u8, "saltsalT"u8, p));
        Assert.NotEqual(a, Argon2id.Derive("pw"u8, salt, p with { Iterations = 2 }));
        Assert.NotEqual(a, Argon2id.Derive("pw"u8, salt, p with { MemoryKiB = 2048 }));
    }

    [Fact]
    public void Output_length_is_configurable()
    {
        Assert.Equal(64, Argon2id.Derive("pw"u8, "saltsalt"u8, new Argon2idParameters(1024, 1, 1), 64).Length);
    }

    [Fact]
    public void Rejects_salt_shorter_than_eight_bytes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2id.Derive("pw"u8, "short"u8, new Argon2idParameters(1024, 1, 1)));
    }
}
