using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

public sealed class DirectoryEntryTests
{
    private static readonly Guid Subject = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid KeyId = Guid.Parse("01020304-0506-0708-090a-0b0c0d0e0f10");

    [Fact]
    public void Message_is_the_kt_leaf_without_logged_at_and_self_sig()
    {
        var message = DirectoryEntry.SignedMessage(
            DirectoryEntryType.UserKeyPublish, Subject, KeyId, 7, "AB", [0xC1, 0xC2], [0xD1]);

        var expected =
            Hex.Of("NYXKT-LEAF-v1"u8)
            + "01"
            + "00112233445566778899aabbccddeeff"
            + "0102030405060708090a0b0c0d0e0f10"
            + "00000007"
            + "0002" + "4142"
            + "00000002" + "c1c2"
            + "00000001" + "d1";
        Assert.Equal(expected, Hex.Of(message));
    }

    [Fact]
    public void Leaf_appends_logged_at_and_the_length_prefixed_self_sig()
    {
        var leaf = DirectoryEntry.LeafData([0xAA, 0xBB], 0x0102030405060708, [0xE1, 0xE2, 0xE3]);
        Assert.Equal("aabb" + "0102030405060708" + "00000003" + "e1e2e3", Hex.Of(leaf));
    }

    [Fact]
    public void Leaf_hash_is_sha256_over_the_rfc9162_leaf_prefix()
    {
        // SHA-256(0x00) for the empty leaf, the RFC 9162 test value.
        Assert.Equal("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", Hex.Of(DirectoryEntry.LeafHash([])));
    }

    [Fact]
    public void Device_activation_message_binds_user_device_key_and_pubkey_hash()
    {
        var message = DeviceActivation.SignedMessage(Subject, KeyId, Subject, "abc"u8);
        var expected =
            Hex.Of("NYXDEV-ACTIVATE-v1"u8)
            + "00112233445566778899aabbccddeeff"
            + "0102030405060708090a0b0c0d0e0f10"
            + "00112233445566778899aabbccddeeff"
            + "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        Assert.Equal(expected, Hex.Of(message));
    }

    [Fact]
    public void Full_size_entry_has_expected_length()
    {
        var message = DirectoryEntry.SignedMessage(
            DirectoryEntryType.UserKeyPublish, Subject, KeyId, 1, CryptoSuite.DirectoryAlgId,
            new byte[CryptoSuite.HybridKemPublicKeySize], new byte[CryptoSuite.HybridSignaturePublicKeySize]);
        Assert.Equal(13 + 1 + 16 + 16 + 4 + 2 + 29 + 4 + 1216 + 4 + 1984, message.Length);
    }

    [Theory]
    [InlineData(DirectoryEntryType.UserKeyPublish, 1)]
    [InlineData(DirectoryEntryType.UserKeyRevoke, 2)]
    [InlineData(DirectoryEntryType.GroupKeyPublish, 3)]
    public void Entry_type_byte_follows_the_domain(DirectoryEntryType type, byte expected)
    {
        var message = DirectoryEntry.SignedMessage(type, Subject, KeyId, 1, "A", [], []);
        Assert.Equal(expected, message[13]);
    }

    [Fact]
    public void Self_signature_over_message_verifies_and_binds_every_field()
    {
        var key = HybridSigningKey.FromSeeds(new byte[32], Enumerable.Repeat((byte)1, 32).ToArray());
        var kem = new byte[CryptoSuite.HybridKemPublicKeySize];
        byte[] Msg(uint generation) => DirectoryEntry.SignedMessage(
            DirectoryEntryType.UserKeyPublish, Subject, KeyId, generation, CryptoSuite.DirectoryAlgId, kem, key.PublicKey);

        var sig = key.Sign(Msg(1));
        Assert.True(HybridSignature.Verify(key.PublicKey, Msg(1), sig));
        Assert.False(HybridSignature.Verify(key.PublicKey, Msg(2), sig));
    }
}
