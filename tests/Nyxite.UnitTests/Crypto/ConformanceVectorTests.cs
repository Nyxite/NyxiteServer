using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

/// <summary>
/// P0.1-CORE-2 and P0.1-CORE-5: the shared conformance vectors. Every file in <c>Resources/vectors</c> must be exactly
/// what this implementation produces from the fixed inputs below, and every client repo checks the same files, so the
/// four codebases agree byte for byte. A deliberate wire-format change regenerates them with
/// <c>NYXITE_WRITE_VECTORS=1</c> and is then a visible diff in every repo.
/// </summary>
public sealed class ConformanceVectorTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true, NewLine = "\n" };

    private static readonly Guid KeyId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057");
    private static readonly Guid FileId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8058");
    private static readonly Guid UserId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8059");
    private static readonly Guid DeviceId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805a");
    private static readonly Guid InstanceId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805b");

    private static byte[] Bytes(int length, int start = 0) => Enumerable.Range(start, length).Select(i => (byte)i).ToArray();
    private static string H(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private static readonly HybridSigningKey UserKey = HybridSigningKey.FromSeeds(Bytes(32, 0x10), Bytes(32, 0x30));
    private static readonly HybridSigningKey VendorKey = HybridSigningKey.FromSeeds(Bytes(32, 0x50), Bytes(32, 0x70));
    private static readonly byte[] KemSeed = Bytes(32, 0x90);

    private static readonly LicensePayload OfflineLicense =
        new(2, InstanceId, "operator@example.org", "commercial", "offline", 1_800_000_000, 1_831_536_000);
    private static readonly LicensePayload OnlineLicense =
        new(2, InstanceId, "operator@example.org", "commercial", "online", 1_800_000_000, null);
    private static readonly LeasePayload Lease = new(InstanceId, "commercial", 1_802_592_000, false);

    /// <summary>Builds every vector file from fixed inputs. All primitives here are deterministic.</summary>
    private static Dictionary<string, string> Generate()
    {
        var key = Bytes(32);
        var nonce = Bytes(12, 0xa0);
        var plaintext = "Nyxite conformance vector"u8.ToArray();
        var aad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Blob);
        var message = "Nyxite hybrid signature vector"u8.ToArray();
        var kemPublic = XWing.PublicKeyFromSeed(KemSeed);
        var eseed = Bytes(64, 0xb0);
        var info = "nyxite conformance info"u8.ToArray();
        var hpkeAad = "nyxite conformance aad"u8.ToArray();
        var fileKey = Bytes(32, 0xc0);
        var directoryMessage = DirectoryEntry.SignedMessage(DirectoryEntryType.UserKeyPublish, UserId, KeyId, 1,
            CryptoSuite.DirectoryAlgId, kemPublic, UserKey.PublicKey);
        var selfSig = UserKey.Sign(directoryMessage);
        var leaf = DirectoryEntry.LeafData(directoryMessage, 1_800_000_000_000, selfSig);
        var activation = DeviceActivation.SignedMessage(UserId, DeviceId, KeyId, kemPublic);
        var salt = Bytes(16, 0xd0);
        var blakeInput = Enumerable.Range(0, 1024).Select(i => (byte)(i % 251)).ToArray();

        return new Dictionary<string, object>
        {
            ["nyxc-frame.json"] = new
            {
                key = H(key), keyId = KeyId, fileId = FileId, objectKind = (int)ObjectKind.Blob, nonce = H(nonce),
                plaintext = H(plaintext), aad = H(aad), frame = H(NyxcFrame.Seal(key, KeyId, nonce, aad, plaintext)),
                chunkIndex = 2, chunkCount = 5, chunkAad = H(NyxcFrame.BuildChunkAad(KeyId, FileId, 2, 5)),
            },
            ["hybrid-signature.json"] = new
            {
                ed25519Seed = H(Bytes(32, 0x10)), mlDsa65Seed = H(Bytes(32, 0x30)), publicKey = H(UserKey.PublicKey),
                message = H(message), signature = H(UserKey.Sign(message)),
            },
            ["hybrid-hpke.json"] = new
            {
                kemId = HybridHpke.KemId, kdfId = HybridHpke.KdfId, aeadId = HybridHpke.AeadId,
                recipientSeed = H(KemSeed), recipientPublicKey = H(kemPublic), encapsulationSeed = H(eseed),
                info = H(info), aad = H(hpkeAad), plaintext = H(fileKey),
                wrapped = H(HybridHpke.SealDerand(kemPublic, eseed, info, hpkeAad, fileKey)),
            },
            ["argon2id.json"] = new
            {
                password = H("correct horse battery staple"u8), salt = H(salt), memoryKiB = 65536, iterations = 3, parallelism = 1,
                output = H(Argon2id.Derive("correct horse battery staple"u8, salt, Argon2id.Default)),
            },
            ["blake3.json"] = new[]
            {
                new { input = "", hash = H(Blake3.Hash([])) },
                new { input = H(blakeInput), hash = H(Blake3.Hash(blakeInput)) },
            },
            ["directory-entry.json"] = new
            {
                entryType = (int)DirectoryEntryType.UserKeyPublish, subjectId = UserId, keyId = KeyId, generation = 1,
                algId = CryptoSuite.DirectoryAlgId, kemPub = H(kemPublic), sigPub = H(UserKey.PublicKey),
                signedMessage = H(directoryMessage), selfSig = H(selfSig), loggedAtUnixMs = 1_800_000_000_000,
                leafData = H(leaf), leafHash = H(DirectoryEntry.LeafHash(leaf)),
            },
            ["device-activation.json"] = new
            {
                userId = UserId, deviceId = DeviceId, keyId = KeyId, devicePubkey = H(kemPublic),
                signedMessage = H(activation), signature = H(UserKey.Sign(activation)), signerPublicKey = H(UserKey.PublicKey),
            },
            ["license-token.json"] = new
            {
                ed25519Seed = H(Bytes(32, 0x50)), mlDsa65Seed = H(Bytes(32, 0x70)), publicKey = H(VendorKey.PublicKey),
                offlineToken = LicenseEnvelope.Sign(OfflineLicense, VendorKey),
                onlineToken = LicenseEnvelope.Sign(OnlineLicense, VendorKey),
                lease = LicenseEnvelope.Sign(Lease, VendorKey),
            },
        }.ToDictionary(kv => kv.Key, kv => JsonSerializer.Serialize(kv.Value, Json) + "\n");
    }

    public static TheoryData<string> Files() => [.. Generate().Keys];

    private static JsonElement Load(string name) => JsonDocument.Parse(Vectors.Read(name)).RootElement;
    private static byte[] B(JsonElement vector, string property) => Convert.FromHexString(vector.GetProperty(property).GetString()!);

    [Theory]
    [MemberData(nameof(Files))]
    public void Vector_file_is_exactly_what_the_implementation_produces(string name)
    {
        var generated = Generate()[name];
        if (Environment.GetEnvironmentVariable("NYXITE_WRITE_VECTORS") == "1")
            File.WriteAllText(Path.Combine(SourceDirectory(), name), generated);

        Assert.Equal(generated, Vectors.Read(name));
    }

    [Fact]
    public void Frame_opens_and_one_perturbed_byte_fails()
    {
        var v = Load("nyxc-frame.json");
        var frame = B(v, "frame");

        Assert.Equal(B(v, "plaintext"), NyxcFrame.Open(B(v, "key"), frame, B(v, "aad")));
        frame[NyxcFrame.HeaderSize] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(B(v, "key"), frame, B(v, "aad")));
    }

    [Fact]
    public void Hybrid_signature_verifies_and_one_perturbed_byte_fails()
    {
        var v = Load("hybrid-signature.json");
        var signature = B(v, "signature");

        Assert.True(HybridSignature.Verify(B(v, "publicKey"), B(v, "message"), signature));
        signature[^1] ^= 1;
        Assert.False(HybridSignature.Verify(B(v, "publicKey"), B(v, "message"), signature));
    }

    [Fact]
    public void Hybrid_hpke_pins_the_suite_ids_and_opens()
    {
        var v = Load("hybrid-hpke.json");
        var wrapped = B(v, "wrapped");

        Assert.Equal(0x647a, v.GetProperty("kemId").GetInt32());
        Assert.Equal(0x0001, v.GetProperty("kdfId").GetInt32());
        Assert.Equal(0x0002, v.GetProperty("aeadId").GetInt32());
        Assert.Equal(B(v, "recipientPublicKey"), XWing.PublicKeyFromSeed(B(v, "recipientSeed")));
        Assert.Equal(B(v, "plaintext"), HybridHpke.Open(B(v, "recipientSeed"), B(v, "info"), B(v, "aad"), wrapped));
        Assert.ThrowsAny<CryptographicException>(() => HybridHpke.Open(B(v, "recipientSeed"), "other info"u8, B(v, "aad"), wrapped));
        wrapped[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => HybridHpke.Open(B(v, "recipientSeed"), B(v, "info"), B(v, "aad"), wrapped));
    }

    [Fact]
    public void Random_hpke_seal_round_trips()
    {
        var wrapped = HybridHpke.Seal(XWing.PublicKeyFromSeed(KemSeed), "info"u8, "aad"u8, "file key"u8);

        Assert.Equal(HybridHpke.Overhead + 8, wrapped.Length);
        Assert.Equal("file key"u8.ToArray(), HybridHpke.Open(KemSeed, "info"u8, "aad"u8, wrapped));
    }

    [Fact]
    public void Blake3_matches_the_official_empty_input_hash()
    {
        // BLAKE3 reference test vector for the empty input.
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", H(Blake3.Hash([])));
    }

    [Fact]
    public void License_token_and_lease_verify_under_the_vector_key()
    {
        var v = Load("license-token.json");
        byte[][] keys = [B(v, "publicKey")];

        Assert.True(LicenseEnvelope.TryVerifyToken(v.GetProperty("offlineToken").GetString(), keys, out var offline));
        Assert.Equal(OfflineLicense, offline);
        Assert.True(LicenseEnvelope.TryVerifyToken(v.GetProperty("onlineToken").GetString(), keys, out var online));
        Assert.Null(online.EntitlementExp);
        Assert.True(LicenseEnvelope.TryVerifyLease(v.GetProperty("lease").GetString(), keys, out var lease));
        Assert.Equal(Lease, lease);
    }

    [Fact]
    public void License_token_with_one_perturbed_byte_or_an_unknown_key_fails()
    {
        var v = Load("license-token.json");
        var token = v.GetProperty("offlineToken").GetString()!;
        byte[][] keys = [B(v, "publicKey")];
        var dot = token.IndexOf('.');
        string Flip(int index) => token[..index] + (token[index] == 'A' ? 'B' : 'A') + token[(index + 1)..];

        Assert.False(LicenseEnvelope.TryVerifyToken(Flip(5), keys, out _));
        Assert.False(LicenseEnvelope.TryVerifyToken(Flip(dot + 5), keys, out _));
        Assert.False(LicenseEnvelope.TryVerifyToken(Flip(token.Length - 5), keys, out _));
        Assert.False(LicenseEnvelope.TryVerifyToken(token, [UserKey.PublicKey], out _));
        Assert.False(LicenseEnvelope.TryVerifyToken(token, [], out _));
        // Second rotation slot: authentic under either key.
        Assert.True(LicenseEnvelope.TryVerifyToken(token, [UserKey.PublicKey, keys[0]], out _));
        // A lease is not a token and the other way round.
        Assert.False(LicenseEnvelope.TryVerifyToken(v.GetProperty("lease").GetString(), keys, out _));
        Assert.False(LicenseEnvelope.TryVerifyLease(token, keys, out _));
    }

    private static string SourceDirectory([CallerFilePath] string file = "") =>
        Path.Combine(Path.GetDirectoryName(file)!, "..", "Resources", "vectors");
}
