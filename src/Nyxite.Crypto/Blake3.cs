using Org.BouncyCastle.Crypto.Digests;

namespace Nyxite.Crypto;

/// <summary>BLAKE3-256, the content address of plaintext (07 §7.3). Computed by clients; the server treats it as opaque.</summary>
public static class Blake3
{
    public const int HashSize = 32;

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var digest = new Blake3Digest(HashSize * 8);
        digest.BlockUpdate(data);
        var hash = new byte[HashSize];
        digest.DoFinal(hash, 0);
        return hash;
    }
}
