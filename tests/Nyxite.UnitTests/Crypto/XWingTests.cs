using System.Text.Json;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

/// <summary>X-Wing against the test vectors of draft-connolly-cfrg-xwing-kem-09, Appendix C (07 §7.3).</summary>
public sealed class XWingTests
{
    private sealed record Vector(string Seed, string Sk, string Pk, string Eseed, string Ct, string Ss);

    public static TheoryData<int> Indexes() => [0, 1, 2];

    private static Vector Load(int index) =>
        JsonSerializer.Deserialize<Vector[]>(Vectors.Read("xwing-kem.json"), JsonSerializerOptions.Web)![index];

    [Theory]
    [MemberData(nameof(Indexes))]
    public void Matches_the_draft_vectors(int index)
    {
        var v = Load(index);
        var seed = Convert.FromHexString(v.Seed);

        Assert.Equal(v.Pk, Convert.ToHexStringLower(XWing.PublicKeyFromSeed(seed)));
        var (secret, ciphertext) = XWing.EncapsulateDerand(Convert.FromHexString(v.Pk), Convert.FromHexString(v.Eseed));
        Assert.Equal(v.Ct, Convert.ToHexStringLower(ciphertext));
        Assert.Equal(v.Ss, Convert.ToHexStringLower(secret));
        Assert.Equal(v.Ss, Convert.ToHexStringLower(XWing.Decapsulate(Convert.FromHexString(v.Ct), seed)));
    }

    [Fact]
    public void Random_encapsulation_round_trips_and_a_tampered_ciphertext_gives_another_secret()
    {
        var seed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var (secret, ciphertext) = XWing.Encapsulate(XWing.PublicKeyFromSeed(seed));

        Assert.Equal(XWing.CiphertextSize, ciphertext.Length);
        Assert.Equal(secret, XWing.Decapsulate(ciphertext, seed));
        ciphertext[0] ^= 1;
        Assert.NotEqual(secret, XWing.Decapsulate(ciphertext, seed));
    }
}
