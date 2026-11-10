using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Nyxite.Crypto;

/// <summary>
/// HPKE base mode (RFC 9180) with the suite X-Wing / HKDF-SHA256 / AES-256-GCM, ids <c>0x647a / 0x0001 / 0x0002</c>
/// (07 §7.3). Single-shot: one message per encapsulation, which is all a key wrap needs. Wrapped output of 07 §7.4:
/// <c>enc(1120) ‖ ciphertext ‖ tag(16)</c>. A client operation; the server never wraps or unwraps.
/// </summary>
public static class HybridHpke
{
    public const ushort KemId = 0x647a;
    public const ushort KdfId = 0x0001;
    public const ushort AeadId = 0x0002;
    public const int TagSize = 16;
    public const int Overhead = XWing.CiphertextSize + TagSize;

    private static readonly byte[] SuiteId = BuildSuiteId();

    public static byte[] Seal(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
    {
        var (secret, enc) = XWing.Encapsulate(recipientPublicKey);
        return Seal(secret, enc, info, aad, plaintext);
    }

    /// <summary>Deterministic seal from a 64-byte encapsulation seed; only conformance vectors pass a fixed one.</summary>
    public static byte[] SealDerand(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> eseed, ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
    {
        var (secret, enc) = XWing.EncapsulateDerand(recipientPublicKey, eseed);
        return Seal(secret, enc, info, aad, plaintext);
    }

    /// <summary>Opens a wrapped output with the recipient's decapsulation seed; throws <see cref="CryptographicException"/> on tampering.</summary>
    public static byte[] Open(ReadOnlySpan<byte> recipientSeed, ReadOnlySpan<byte> info, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < Overhead) throw new CryptographicException("Not a hybrid HPKE output.");
        var enc = wrapped[..XWing.CiphertextSize];
        var (key, nonce) = KeySchedule(XWing.Decapsulate(enc, recipientSeed), info);
        var plaintext = new byte[wrapped.Length - Overhead];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, wrapped.Slice(XWing.CiphertextSize, plaintext.Length), wrapped[^TagSize..], plaintext, aad);
        return plaintext;
    }

    private static byte[] Seal(byte[] secret, byte[] enc, ReadOnlySpan<byte> info, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
    {
        var (key, nonce) = KeySchedule(secret, info);
        var output = new byte[enc.Length + plaintext.Length + TagSize];
        enc.CopyTo(output, 0);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, output.AsSpan(enc.Length, plaintext.Length), output.AsSpan(enc.Length + plaintext.Length), aad);
        return output;
    }

    /// <summary>RFC 9180 §5.1 KeySchedule for mode_base with the default (empty) psk and psk_id; sequence number 0.</summary>
    private static (byte[] Key, byte[] Nonce) KeySchedule(byte[] sharedSecret, ReadOnlySpan<byte> info)
    {
        var pskIdHash = LabeledExtract([], "psk_id_hash", []);
        var infoHash = LabeledExtract([], "info_hash", info);
        byte[] context = [0x00, .. pskIdHash, .. infoHash];
        var secret = LabeledExtract(sharedSecret, "secret", []);
        return (LabeledExpand(secret, "key", context, 32), LabeledExpand(secret, "base_nonce", context, 12));
    }

    private static byte[] LabeledExtract(ReadOnlySpan<byte> salt, string label, ReadOnlySpan<byte> ikm)
    {
        byte[] labeled = [.. "HPKE-v1"u8, .. SuiteId, .. System.Text.Encoding.ASCII.GetBytes(label), .. ikm];
        return HKDF.Extract(HashAlgorithmName.SHA256, labeled, salt.ToArray());
    }

    private static byte[] LabeledExpand(byte[] prk, string label, ReadOnlySpan<byte> info, int length)
    {
        Span<byte> size = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(size, (ushort)length);
        byte[] labeled = [.. size, .. "HPKE-v1"u8, .. SuiteId, .. System.Text.Encoding.ASCII.GetBytes(label), .. info];
        return HKDF.Expand(HashAlgorithmName.SHA256, prk, length, labeled);
    }

    private static byte[] BuildSuiteId()
    {
        var id = new byte[4 + 6];
        "HPKE"u8.CopyTo(id);
        BinaryPrimitives.WriteUInt16BigEndian(id.AsSpan(4), KemId);
        BinaryPrimitives.WriteUInt16BigEndian(id.AsSpan(6), KdfId);
        BinaryPrimitives.WriteUInt16BigEndian(id.AsSpan(8), AeadId);
        return id;
    }
}
