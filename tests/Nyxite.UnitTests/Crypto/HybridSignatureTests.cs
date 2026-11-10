using System.Security.Cryptography;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

public sealed class HybridSignatureTests
{
    // RFC 8032 §7.1 TEST 1 (empty message).
    private const string Rfc8032Secret = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    private const string Rfc8032Public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private const string Rfc8032Signature =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    private static readonly byte[] MlSeed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly HybridSigningKey Key = HybridSigningKey.FromSeeds(Hex.Bytes(Rfc8032Secret), MlSeed);
    private static readonly byte[] Message = "directory entry"u8.ToArray();

    [Fact]
    public void Ed25519_half_matches_rfc8032_vector()
    {
        Assert.Equal(Rfc8032Public, Hex.Of(Key.PublicKey.AsSpan(0, 32)));
        Assert.Equal(Rfc8032Signature, Hex.Of(Key.Sign([]).AsSpan(0, 64)));
    }

    [Fact]
    public void Sizes_match_the_suite()
    {
        Assert.Equal(CryptoSuite.HybridSignaturePublicKeySize, Key.PublicKey.Length);
        Assert.Equal(CryptoSuite.HybridSignatureSize, Key.Sign(Message).Length);
        Assert.Equal(1984, CryptoSuite.HybridSignaturePublicKeySize);
        Assert.Equal(3373, CryptoSuite.HybridSignatureSize);
        Assert.Equal(1216, CryptoSuite.HybridKemPublicKeySize);
    }

    [Fact]
    public void Signing_is_deterministic_and_seeds_reproduce_the_key()
    {
        var again = HybridSigningKey.FromSeeds(Hex.Bytes(Rfc8032Secret), MlSeed);
        Assert.Equal(Key.PublicKey, again.PublicKey);
        Assert.Equal(Key.Sign(Message), again.Sign(Message));
    }

    [Fact]
    public void Valid_signature_verifies()
    {
        Assert.True(HybridSignature.Verify(Key.PublicKey, Message, Key.Sign(Message)));
    }

    [Fact]
    public void Generated_keys_differ_and_verify()
    {
        var a = HybridSigningKey.Generate();
        var b = HybridSigningKey.Generate();
        Assert.NotEqual(a.PublicKey, b.PublicKey);
        Assert.True(HybridSignature.Verify(a.PublicKey, Message, a.Sign(Message)));
        Assert.False(HybridSignature.Verify(b.PublicKey, Message, a.Sign(Message)));
    }

    [Theory]
    [InlineData(0)]        // Ed25519 half
    [InlineData(63)]       // last Ed25519 byte
    [InlineData(64)]       // first ML-DSA byte
    [InlineData(3372)]     // last ML-DSA byte
    public void Tampering_either_signature_half_fails(int index)
    {
        var sig = Key.Sign(Message);
        sig[index] ^= 0x01;
        Assert.False(HybridSignature.Verify(Key.PublicKey, Message, sig));
    }

    [Fact]
    public void Valid_ed25519_half_with_foreign_mldsa_half_fails()
    {
        var other = HybridSigningKey.FromSeeds(Hex.Bytes(Rfc8032Secret), new byte[32]);
        byte[] mixed = [.. Key.Sign(Message).AsSpan(0, 64), .. other.Sign(Message).AsSpan(64)];
        Assert.False(HybridSignature.Verify(Key.PublicKey, Message, mixed));
        Assert.False(HybridSignature.Verify(other.PublicKey, Message, Key.Sign(Message)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(1983)]
    public void Tampered_public_key_fails(int index)
    {
        var pub = Key.PublicKey.ToArray();
        pub[index] ^= 0x01;
        Assert.False(HybridSignature.Verify(pub, Message, Key.Sign(Message)));
    }

    [Fact]
    public void Different_message_fails()
    {
        Assert.False(HybridSignature.Verify(Key.PublicKey, "directory entrY"u8, Key.Sign(Message)));
    }

    [Theory]
    [InlineData(1983, 3373)]
    [InlineData(1985, 3373)]
    [InlineData(1984, 3372)]
    [InlineData(1984, 3374)]
    [InlineData(0, 0)]
    public void Wrong_lengths_fail_without_throwing(int pubLength, int sigLength)
    {
        Assert.False(HybridSignature.Verify(new byte[pubLength], Message, new byte[sigLength]));
    }

    [Fact]
    public void All_zero_key_and_signature_fail_without_throwing()
    {
        Assert.False(HybridSignature.Verify(new byte[1984], Message, new byte[3373]));
    }

    [Fact]
    public void FromSeeds_rejects_wrong_seed_length()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridSigningKey.FromSeeds(new byte[31], MlSeed));
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridSigningKey.FromSeeds(new byte[32], new byte[33]));
    }

    // Independent implementation cross-check: the platform ML-DSA (OpenSSL 3.5+) must accept BouncyCastle's
    // ML-DSA-65 half and derive the same public key from the same seed.
    [Fact]
    public void MlDsa_half_interoperates_with_platform_implementation()
    {
        Assert.SkipUnless(MLDsa.IsSupported, "Platform ML-DSA not available (needs OpenSSL 3.5+).");
        using var platform = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, MlSeed);
        Assert.Equal(Key.PublicKey.AsSpan(32).ToArray(), platform.ExportMLDsaPublicKey());
        Assert.True(platform.VerifyData(Message, Key.Sign(Message).AsSpan(64)));
    }
}
