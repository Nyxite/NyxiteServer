using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Nyxite.Crypto;

/// <summary><c>object_kind</c> of an NYXC frame (07 §7.4).</summary>
public enum ObjectKind : byte
{
    Blob = 1, Snapshot = 2, Crdt = 3, Name = 4, Metadata = 5, Awareness = 6, Settings = 7, Chunk = 8, ChunkManifest = 9,
}

/// <summary>
/// The canonical AES-256-GCM object frame (07 §7.4):
/// <c>magic "NYXC"(4) ‖ version 0x01(1) ‖ key_id(16) ‖ nonce(12) ‖ ciphertext ‖ gcm_tag(16)</c>,
/// <c>AAD = magic ‖ version ‖ key_id ‖ file_id(16) ‖ object_kind(1)</c>. UUIDs are in RFC 9562 (big-endian) byte order.
/// The server only ever <see cref="TryParseHeader"/>s frames; sealing and opening are client operations.
/// </summary>
public static class NyxcFrame
{
    public static ReadOnlySpan<byte> Magic => "NYXC"u8;
    public const byte Version = 0x01;
    public const int KeyIdSize = 16;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int HeaderSize = 4 + 1 + KeyIdSize + NonceSize;
    public const int Overhead = HeaderSize + TagSize;

    public static byte[] BuildAad(Guid keyId, Guid fileId, ObjectKind kind)
    {
        var aad = new byte[4 + 1 + 16 + 16 + 1];
        Magic.CopyTo(aad);
        aad[4] = Version;
        keyId.TryWriteBytes(aad.AsSpan(5, 16), bigEndian: true, out _);
        fileId.TryWriteBytes(aad.AsSpan(21, 16), bigEndian: true, out _);
        aad[37] = (byte)kind;
        return aad;
    }

    /// <summary>Chunk AAD (07 §7.4a): the normal AAD followed by <c>chunk_index(u32) ‖ chunk_count(u32)</c>.</summary>
    public static byte[] BuildChunkAad(Guid keyId, Guid fileId, uint chunkIndex, uint chunkCount)
    {
        var baseAad = BuildAad(keyId, fileId, ObjectKind.Chunk);
        var aad = new byte[baseAad.Length + 8];
        baseAad.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(baseAad.Length), chunkIndex);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(baseAad.Length + 4), chunkCount);
        return aad;
    }

    public static byte[] Seal(ReadOnlySpan<byte> key, Guid keyId, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));
        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceSize, nameof(nonce));
        var frame = new byte[Overhead + plaintext.Length];
        Magic.CopyTo(frame);
        frame[4] = Version;
        keyId.TryWriteBytes(frame.AsSpan(5, 16), bigEndian: true, out _);
        nonce.CopyTo(frame.AsSpan(21, NonceSize));
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, frame.AsSpan(HeaderSize, plaintext.Length), frame.AsSpan(HeaderSize + plaintext.Length), aad);
        return frame;
    }

    public static byte[] Seal(ReadOnlySpan<byte> key, Guid keyId, Guid fileId, ObjectKind kind, ReadOnlySpan<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);
        return Seal(key, keyId, nonce, BuildAad(keyId, fileId, kind), plaintext);
    }

    /// <summary>Opens a frame; throws <see cref="CryptographicException"/> on any tampering.</summary>
    public static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> frame, ReadOnlySpan<byte> aad)
    {
        if (!TryParseHeader(frame, out var header)) throw new CryptographicException("Not an NYXC v1 frame.");
        if (!aad[..21].SequenceEqual(frame[..21])) throw new CryptographicException("AAD does not match the frame header.");
        var ctLength = frame.Length - Overhead;
        var plaintext = new byte[ctLength];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(header.Nonce, frame.Slice(HeaderSize, ctLength), frame[^TagSize..], plaintext, aad);
        return plaintext;
    }

    /// <summary>Structural check only (magic, version, minimum length) — never decrypts.</summary>
    public static bool TryParseHeader(ReadOnlySpan<byte> frame, out NyxcHeader header)
    {
        header = default;
        if (frame.Length < Overhead) return false;
        if (!frame[..4].SequenceEqual(Magic)) return false;
        if (frame[4] != Version) return false;
        header = new NyxcHeader(new Guid(frame.Slice(5, 16), bigEndian: true), frame.Slice(21, NonceSize).ToArray(), frame.Length - Overhead);
        return true;
    }
}

public readonly record struct NyxcHeader(Guid KeyId, byte[] Nonce, int CiphertextLength);
