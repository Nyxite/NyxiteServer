using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;

namespace Nyxite.Crypto;

/// <summary>
/// X-Wing, the hybrid KEM of X25519 and ML-KEM-768 (draft-connolly-cfrg-xwing-kem, 07 §7.3). It is the KEM behind every
/// public-key wrap. Layouts, all fixed length: decapsulation key = a 32-byte seed,
/// encapsulation key = <c>mlkem768_pk(1184) ‖ x25519_pk(32)</c>, ciphertext = <c>mlkem768_ct(1088) ‖ x25519_share(32)</c>,
/// shared secret = <c>SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")</c>. Only clients run it; the server checks lengths.
/// </summary>
public static class XWing
{
    public const int SeedSize = 32;
    public const int PublicKeySize = CryptoSuite.MlKem768PublicKeySize + CryptoSuite.X25519PublicKeySize;
    public const int CiphertextSize = CryptoSuite.MlKem768CiphertextSize + CryptoSuite.X25519PublicKeySize;
    public const int SharedSecretSize = 32;
    public const int EncapsulationSeedSize = 64;

    private static ReadOnlySpan<byte> Label => "\\.//^\\"u8;

    /// <summary>The encapsulation (public) key of a decapsulation seed.</summary>
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
    {
        var (mlKem, x25519) = Expand(seed);
        var publicKey = new byte[PublicKeySize];
        mlKem.GetPublicKey().GetEncoded().CopyTo(publicKey, 0);
        X25519.ScalarMultBase(x25519, publicKey.AsSpan(CryptoSuite.MlKem768PublicKeySize));
        return publicKey;
    }

    public static (byte[] SharedSecret, byte[] Ciphertext) Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        Span<byte> eseed = stackalloc byte[EncapsulationSeedSize];
        System.Security.Cryptography.RandomNumberGenerator.Fill(eseed);
        return EncapsulateDerand(publicKey, eseed);
    }

    /// <summary>Deterministic encapsulation from a 64-byte seed; only conformance vectors pass a fixed one.</summary>
    public static (byte[] SharedSecret, byte[] Ciphertext) EncapsulateDerand(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> eseed)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(publicKey.Length, PublicKeySize, nameof(publicKey));
        ArgumentOutOfRangeException.ThrowIfNotEqual(eseed.Length, EncapsulationSeedSize, nameof(eseed));
        var mlKemPublic = publicKey[..CryptoSuite.MlKem768PublicKeySize];
        var x25519Public = publicKey[CryptoSuite.MlKem768PublicKeySize..];
        var ephemeral = eseed[32..];

        var ciphertext = new byte[CiphertextSize];
        var shareX = ciphertext.AsSpan(CryptoSuite.MlKem768CiphertextSize);
        X25519.ScalarMultBase(ephemeral, shareX);
        Span<byte> secretX = stackalloc byte[32];
        X25519.ScalarMult(ephemeral, x25519Public, secretX);

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(
            MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, mlKemPublic.ToArray()), new FixedRandom(eseed[..32])));
        var secretM = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, encapsulator.EncapsulationLength, secretM, 0, secretM.Length);

        return (Combine(secretM, secretX, shareX, x25519Public), ciphertext);
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> seed)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(ciphertext.Length, CiphertextSize, nameof(ciphertext));
        var (mlKem, x25519) = Expand(seed);
        var shareX = ciphertext[CryptoSuite.MlKem768CiphertextSize..];

        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(mlKem);
        var secretM = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext[..CryptoSuite.MlKem768CiphertextSize].ToArray(), 0, CryptoSuite.MlKem768CiphertextSize,
            secretM, 0, secretM.Length);

        Span<byte> secretX = stackalloc byte[32];
        X25519.ScalarMult(x25519, shareX, secretX);
        Span<byte> publicX = stackalloc byte[32];
        X25519.ScalarMultBase(x25519, publicX);
        return Combine(secretM, secretX, shareX, publicX);
    }

    /// <summary><c>SHAKE256(seed, 96)</c>: 64 bytes seed the ML-KEM-768 key pair, the last 32 are the X25519 private key.</summary>
    private static (MLKemPrivateKeyParameters MlKem, byte[] X25519) Expand(ReadOnlySpan<byte> seed)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(seed.Length, SeedSize, nameof(seed));
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(seed);
        var expanded = new byte[96];
        shake.OutputFinal(expanded, 0, expanded.Length);
        return (MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, expanded[..64]), expanded[64..]);
    }

    private static byte[] Combine(ReadOnlySpan<byte> secretM, ReadOnlySpan<byte> secretX, ReadOnlySpan<byte> shareX, ReadOnlySpan<byte> publicX)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(secretM);
        sha3.BlockUpdate(secretX);
        sha3.BlockUpdate(shareX);
        sha3.BlockUpdate(publicX);
        sha3.BlockUpdate(Label);
        var secret = new byte[SharedSecretSize];
        sha3.DoFinal(secret, 0);
        return secret;
    }

    /// <summary>Hands ML-KEM its 32 bytes of encapsulation randomness, so encapsulation is reproducible from the seed.</summary>
    private sealed class FixedRandom(ReadOnlySpan<byte> bytes) : SecureRandom
    {
        private readonly byte[] _bytes = bytes.ToArray();
        private int _used;

        public override void NextBytes(byte[] buffer) => NextBytes(buffer.AsSpan());

        public override void NextBytes(byte[] buffer, int offset, int length) => NextBytes(buffer.AsSpan(offset, length));

        public override void NextBytes(Span<byte> buffer)
        {
            if (_used + buffer.Length > _bytes.Length) throw new InvalidOperationException("Encapsulation asked for more randomness than its seed holds.");
            _bytes.AsSpan(_used, buffer.Length).CopyTo(buffer);
            _used += buffer.Length;
        }
    }
}
