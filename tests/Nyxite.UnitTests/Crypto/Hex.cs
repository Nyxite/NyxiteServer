namespace Nyxite.UnitTests.Crypto;

internal static class Hex
{
    public static byte[] Bytes(string hex) => Convert.FromHexString(hex);
    public static string Of(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
}
