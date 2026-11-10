using System.Buffers.Text;

namespace Nyxite.Crypto;

/// <summary>The one binary-in-JSON encoding of the wire contract: base64url without padding (04 §4.1).</summary>
public static class Base64UrlCodec
{
    public static string Encode(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);

    /// <summary>Decodes strictly: padding, '+', '/' and whitespace are rejected.</summary>
    public static bool TryDecode(string? text, out byte[] bytes)
    {
        bytes = [];
        if (text is null) return false;
        foreach (var c in text)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok) return false;
        }

        if (text.Length % 4 == 1) return false;
        try
        {
            bytes = Base64Url.DecodeFromChars(text);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] Decode(string text) =>
        TryDecode(text, out var bytes) ? bytes : throw new FormatException("Not base64url without padding.");
}
