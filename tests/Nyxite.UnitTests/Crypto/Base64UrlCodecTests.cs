using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

public sealed class Base64UrlCodecTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("66", "Zg")]
    [InlineData("666f", "Zm8")]
    [InlineData("666f6f", "Zm9v")]
    [InlineData("fbff", "-_8")]
    public void Encode_produces_unpadded_url_alphabet(string hex, string expected)
    {
        Assert.Equal(expected, Base64UrlCodec.Encode(Hex.Bytes(hex)));
    }

    [Fact]
    public void Round_trips_every_length()
    {
        for (var length = 0; length < 70; length++)
        {
            var data = Enumerable.Range(0, length).Select(i => (byte)(i * 37 + 11)).ToArray();
            Assert.Equal(data, Base64UrlCodec.Decode(Base64UrlCodec.Encode(data)));
        }
    }

    [Theory]
    [InlineData("Zg==")]
    [InlineData("Zm8=")]
    [InlineData("+/8")]
    [InlineData("Zm 9v")]
    [InlineData("Zm9v\n")]
    [InlineData("Z")]
    [InlineData("Zm9vY")]
    public void TryDecode_rejects_non_canonical_input(string text)
    {
        Assert.False(Base64UrlCodec.TryDecode(text, out var bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void TryDecode_rejects_null()
    {
        Assert.False(Base64UrlCodec.TryDecode(null, out _));
    }

    [Fact]
    public void Decode_throws_on_invalid_input()
    {
        Assert.Throws<FormatException>(() => Base64UrlCodec.Decode("Zg=="));
    }
}
