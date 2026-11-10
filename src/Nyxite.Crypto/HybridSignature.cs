using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Nyxite.Crypto;

/// <summary>
/// Hybrid dual signature Ed25519 + ML-DSA-65 (07 §7.3; license 01 §1.2).
/// Wire layout, all fixed length: public key = <c>ed25519_pub(32) ‖ mldsa65_pub(1952)</c>,
/// signature = <c>Ed25519_sign(msg)(64) ‖ ML-DSA-65_sign(msg)(3309)</c>, both halves over the same message,
/// ML-DSA in pure mode with an empty context. A signature is valid only if <b>both</b> halves verify.
/// </summary>
public static class HybridSignature
{
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != CryptoSuite.HybridSignaturePublicKeySize) return false;
        if (signature.Length != CryptoSuite.HybridSignatureSize) return false;

        var edPub = publicKey[..CryptoSuite.Ed25519PublicKeySize];
        var mlPub = publicKey[CryptoSuite.Ed25519PublicKeySize..];
        var edSig = signature[..CryptoSuite.Ed25519SignatureSize];
        var mlSig = signature[CryptoSuite.Ed25519SignatureSize..];

        // Evaluate both halves unconditionally so timing does not reveal which one failed.
        var edOk = VerifyEd25519(edPub, message, edSig);
        var mlOk = VerifyMlDsa65(mlPub, message, mlSig);
        return edOk & mlOk;
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> pub, ReadOnlySpan<byte> message, ReadOnlySpan<byte> sig)
    {
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(pub));
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(sig.ToArray());
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool VerifyMlDsa65(ReadOnlySpan<byte> pub, ReadOnlySpan<byte> message, ReadOnlySpan<byte> sig)
    {
        try
        {
            var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
            verifier.Init(false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, pub.ToArray()));
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(sig.ToArray());
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}

/// <summary>
/// A hybrid Ed25519 + ML-DSA-65 signing key. Used by clients (desktop) and by tests/vector generation; the server
/// never holds a user's signing key. Signing is deterministic (Ed25519 always, ML-DSA in its deterministic variant)
/// so conformance vectors are reproducible.
/// </summary>
public sealed class HybridSigningKey
{
    private readonly Ed25519PrivateKeyParameters _ed;
    private readonly MLDsaPrivateKeyParameters _ml;

    private HybridSigningKey(Ed25519PrivateKeyParameters ed, MLDsaPrivateKeyParameters ml)
    {
        _ed = ed;
        _ml = ml;
        PublicKey = [.. ed.GeneratePublicKey().GetEncoded(), .. ml.GetPublicKeyEncoded()];
    }

    /// <summary><c>ed25519_pub ‖ mldsa65_pub</c>.</summary>
    public byte[] PublicKey { get; }

    public static HybridSigningKey Generate()
    {
        var random = new SecureRandom();
        var edSeed = new byte[32];
        var mlSeed = new byte[32];
        random.NextBytes(edSeed);
        random.NextBytes(mlSeed);
        return FromSeeds(edSeed, mlSeed);
    }

    /// <summary>Deterministic construction from two 32-byte seeds (Ed25519 secret, ML-DSA-65 ξ).</summary>
    public static HybridSigningKey FromSeeds(byte[] ed25519Seed, byte[] mlDsaSeed)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(ed25519Seed.Length, 32, nameof(ed25519Seed));
        ArgumentOutOfRangeException.ThrowIfNotEqual(mlDsaSeed.Length, 32, nameof(mlDsaSeed));
        return new HybridSigningKey(
            new Ed25519PrivateKeyParameters(ed25519Seed),
            MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, mlDsaSeed));
    }

    public byte[] Sign(ReadOnlySpan<byte> message)
    {
        var ed = new Ed25519Signer();
        ed.Init(true, _ed);
        ed.BlockUpdate(message);
        var edSig = ed.GenerateSignature();

        var ml = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        ml.Init(true, _ml);
        ml.BlockUpdate(message);
        var mlSig = ml.GenerateSignature();

        return [.. edSig, .. mlSig];
    }
}
