using System.Buffers.Binary;
using System.Text;

namespace Nyxite.Crypto;

/// <summary>KT leaf <c>entry_type</c> (17 §17.3).</summary>
public enum DirectoryEntryType : byte { UserKeyPublish = 1, UserKeyRevoke = 2, GroupKeyPublish = 3 }

/// <summary>
/// The message covered by a directory self-signature: the KT leaf of 17 §17.3 without <c>logged_at</c> and
/// <c>self_sig</c>. Integers are big-endian, UUIDs in RFC 9562 byte order, variable fields length-prefixed.
/// </summary>
public static class DirectoryEntry
{
    public static ReadOnlySpan<byte> Domain => "NYXKT-LEAF-v1"u8;

    public static byte[] SignedMessage(
        DirectoryEntryType entryType, Guid subjectId, Guid keyId, uint generation, string algId,
        ReadOnlySpan<byte> kemPub, ReadOnlySpan<byte> sigPub)
    {
        var alg = Encoding.ASCII.GetBytes(algId);
        if (alg.Length > ushort.MaxValue) throw new ArgumentException("alg_id too long", nameof(algId));
        var buffer = new byte[Domain.Length + 1 + 16 + 16 + 4 + 2 + alg.Length + 4 + kemPub.Length + 4 + sigPub.Length];
        var s = buffer.AsSpan();
        var o = 0;
        Domain.CopyTo(s); o += Domain.Length;
        s[o++] = (byte)entryType;
        subjectId.TryWriteBytes(s.Slice(o, 16), bigEndian: true, out _); o += 16;
        keyId.TryWriteBytes(s.Slice(o, 16), bigEndian: true, out _); o += 16;
        BinaryPrimitives.WriteUInt32BigEndian(s[o..], generation); o += 4;
        BinaryPrimitives.WriteUInt16BigEndian(s[o..], (ushort)alg.Length); o += 2;
        alg.CopyTo(s[o..]); o += alg.Length;
        BinaryPrimitives.WriteUInt32BigEndian(s[o..], (uint)kemPub.Length); o += 4;
        kemPub.CopyTo(s[o..]); o += kemPub.Length;
        BinaryPrimitives.WriteUInt32BigEndian(s[o..], (uint)sigPub.Length); o += 4;
        sigPub.CopyTo(s[o..]);
        return buffer;
    }

    /// <summary>
    /// The full KT <c>leaf_data</c> of 17 §17.3: the signed message, then <c>logged_at</c> (i64 ms since the Unix epoch)
    /// and the length-prefixed <c>self_sig</c>.
    /// </summary>
    public static byte[] LeafData(ReadOnlySpan<byte> signedMessage, long loggedAtUnixMs, ReadOnlySpan<byte> selfSig)
    {
        var buffer = new byte[signedMessage.Length + 8 + 4 + selfSig.Length];
        var s = buffer.AsSpan();
        signedMessage.CopyTo(s);
        var o = signedMessage.Length;
        BinaryPrimitives.WriteInt64BigEndian(s[o..], loggedAtUnixMs); o += 8;
        BinaryPrimitives.WriteUInt32BigEndian(s[o..], (uint)selfSig.Length); o += 4;
        selfSig.CopyTo(s[o..]);
        return buffer;
    }

    /// <summary><c>SHA-256(0x00 ‖ leaf_data)</c>, the RFC 9162 leaf hash (17 §17.4).</summary>
    public static byte[] LeafHash(ReadOnlySpan<byte> leafData)
    {
        var input = new byte[1 + leafData.Length];
        leafData.CopyTo(input.AsSpan(1));
        return System.Security.Cryptography.SHA256.HashData(input);
    }
}
