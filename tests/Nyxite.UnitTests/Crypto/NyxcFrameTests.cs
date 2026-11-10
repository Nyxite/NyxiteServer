using System.Security.Cryptography;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

public sealed class NyxcFrameTests
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray();
    private static readonly Guid KeyId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid FileId = Guid.Parse("01020304-0506-0708-090a-0b0c0d0e0f10");
    private static readonly byte[] Nonce = Enumerable.Range(0, 12).Select(i => (byte)(0x10 + i)).ToArray();
    private static readonly byte[] Plaintext = "hello nyxite"u8.ToArray();

    [Fact]
    public void Aad_layout_is_magic_version_keyid_fileid_kind_with_big_endian_uuids()
    {
        var aad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Snapshot);
        Assert.Equal(
            "4e595843" + "01" + "00112233445566778899aabbccddeeff" + "0102030405060708090a0b0c0d0e0f10" + "02",
            Hex.Of(aad));
    }

    [Fact]
    public void Chunk_aad_appends_big_endian_index_and_count()
    {
        var aad = NyxcFrame.BuildChunkAad(KeyId, FileId, 1, 0x01020304);
        Assert.Equal(Hex.Of(NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Chunk)) + "00000001" + "01020304", Hex.Of(aad));
    }

    [Fact]
    public void Frame_layout_is_header_ciphertext_tag()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, Nonce, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob), Plaintext);
        Assert.Equal(NyxcFrame.Overhead + Plaintext.Length, frame.Length);
        Assert.Equal(49, NyxcFrame.Overhead);
        Assert.Equal("4e59584301" + "00112233445566778899aabbccddeeff" + Hex.Of(Nonce), Hex.Of(frame.AsSpan(0, NyxcFrame.HeaderSize)));
    }

    [Fact]
    public void Ciphertext_matches_platform_aes_gcm()
    {
        var aad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob);
        var frame = NyxcFrame.Seal(Key, KeyId, Nonce, aad, Plaintext);

        var ct = new byte[Plaintext.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(Key, 16)) gcm.Encrypt(Nonce, Plaintext, ct, tag, aad);
        Assert.Equal([.. ct, .. tag], frame.AsSpan(NyxcFrame.HeaderSize).ToArray());
    }

    [Fact]
    public void Seal_then_open_round_trips_including_empty_plaintext()
    {
        foreach (var plaintext in new[] { Plaintext, Array.Empty<byte>() })
        {
            var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Metadata, plaintext);
            Assert.Equal(plaintext, NyxcFrame.Open(Key, frame, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Metadata)));
        }
    }

    [Fact]
    public void Random_nonce_differs_between_seals()
    {
        var a = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        var b = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        Assert.NotEqual(a.AsSpan(21, 12).ToArray(), b.AsSpan(21, 12).ToArray());
    }

    [Theory]
    [InlineData(21)]   // nonce
    [InlineData(33)]   // first ciphertext byte
    [InlineData(-1)]   // last tag byte
    public void Open_rejects_tampered_frame(int index)
    {
        var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        frame[index < 0 ? frame.Length + index : index] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() =>
            NyxcFrame.Open(Key, frame, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob)));
    }

    [Fact]
    public void Open_binds_file_id_and_object_kind()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        Assert.ThrowsAny<CryptographicException>(() =>
            NyxcFrame.Open(Key, frame, NyxcFrame.BuildAad(KeyId, Guid.NewGuid(), ObjectKind.Blob)));
        Assert.ThrowsAny<CryptographicException>(() =>
            NyxcFrame.Open(Key, frame, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Snapshot)));
    }

    [Fact]
    public void Open_rejects_aad_with_a_different_key_id_than_the_frame()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        Assert.ThrowsAny<CryptographicException>(() =>
            NyxcFrame.Open(Key, frame, NyxcFrame.BuildAad(Guid.NewGuid(), FileId, ObjectKind.Blob)));
    }

    [Fact]
    public void Open_rejects_wrong_key()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);
        Assert.ThrowsAny<CryptographicException>(() =>
            NyxcFrame.Open(new byte[32], frame, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob)));
    }

    [Fact]
    public void TryParseHeader_reads_key_id_nonce_and_length()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, Nonce, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob), Plaintext);
        Assert.True(NyxcFrame.TryParseHeader(frame, out var header));
        Assert.Equal(KeyId, header.KeyId);
        Assert.Equal(Nonce, header.Nonce);
        Assert.Equal(Plaintext.Length, header.CiphertextLength);
    }

    [Fact]
    public void TryParseHeader_rejects_bad_magic_version_and_short_input()
    {
        var frame = NyxcFrame.Seal(Key, KeyId, FileId, ObjectKind.Blob, Plaintext);

        var badMagic = frame.ToArray(); badMagic[0] = (byte)'X';
        var badVersion = frame.ToArray(); badVersion[4] = 0x02;

        Assert.False(NyxcFrame.TryParseHeader(badMagic, out _));
        Assert.False(NyxcFrame.TryParseHeader(badVersion, out _));
        Assert.False(NyxcFrame.TryParseHeader(frame.AsSpan(0, NyxcFrame.Overhead - 1), out _));
        Assert.True(NyxcFrame.TryParseHeader(frame.AsSpan(0, NyxcFrame.Overhead), out _));
        Assert.Throws<CryptographicException>(() =>
            NyxcFrame.Open(Key, badVersion, NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob)));
    }

    [Fact]
    public void Seal_rejects_wrong_key_and_nonce_lengths()
    {
        var aad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob);
        Assert.Throws<ArgumentOutOfRangeException>(() => NyxcFrame.Seal(new byte[16], KeyId, Nonce, aad, Plaintext));
        Assert.Throws<ArgumentOutOfRangeException>(() => NyxcFrame.Seal(Key, KeyId, new byte[8], aad, Plaintext));
    }
}
