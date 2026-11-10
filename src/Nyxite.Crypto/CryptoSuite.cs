namespace Nyxite.Crypto;

/// <summary>Pinned primitive sizes and suite identifiers of the v1 hybrid suite (07 §7.3, 17 §17.3).</summary>
public static class CryptoSuite
{
    /// <summary>Directory-key suite id: hybrid KEM X25519 + ML-KEM-768 and hybrid signature Ed25519 + ML-DSA-65.</summary>
    public const string DirectoryAlgId = "X25519MLKEM768+Ed25519MLDSA65";

    /// <summary>
    /// HPKE hybrid KEM suite id carried on wrapped-key <c>alg_id</c>. It names X-Wing (<see cref="XWing"/>): public key
    /// <c>mlkem768_pk ‖ x25519_pk</c>, encapsulation <c>mlkem768_ct ‖ x25519_share</c>.
    /// </summary>
    public const string HpkeAlgId = "X25519MLKEM768";

    public const int X25519PublicKeySize = 32;
    public const int MlKem768PublicKeySize = 1184;
    public const int MlKem768CiphertextSize = 1088;
    public const int HybridKemPublicKeySize = X25519PublicKeySize + MlKem768PublicKeySize;

    public const int Ed25519PublicKeySize = 32;
    public const int MlDsa65PublicKeySize = 1952;
    public const int HybridSignaturePublicKeySize = Ed25519PublicKeySize + MlDsa65PublicKeySize;

    public const int Ed25519SignatureSize = 64;
    public const int MlDsa65SignatureSize = 3309;
    public const int HybridSignatureSize = Ed25519SignatureSize + MlDsa65SignatureSize;
}
