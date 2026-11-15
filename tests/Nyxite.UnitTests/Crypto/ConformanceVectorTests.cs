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
            ["object-kinds.json"] = ObjectKinds(key),
            ["text-path.json"] = TextPath(key),
            ["awareness.json"] = Awareness(key),
            ["relay-wire.json"] = RelayWire(key),
            ["snapshot-triggers.json"] = new
            {
                updateCount = Nyxite.Contracts.Content.SnapshotTriggers.UpdateCount,
                intervalSeconds = (int)Nyxite.Contracts.Content.SnapshotTriggers.Interval.TotalSeconds,
                onLastParticipantLeaving = Nyxite.Contracts.Content.SnapshotTriggers.OnLastParticipantLeaving,
            },
            ["sharing.json"] = SharingVectors.Build(kemPublic),
            ["license-token.json"] = new
            {
                ed25519Seed = H(Bytes(32, 0x50)), mlDsa65Seed = H(Bytes(32, 0x70)), publicKey = H(VendorKey.PublicKey),
                offlineToken = LicenseEnvelope.Sign(OfflineLicense, VendorKey),
                onlineToken = LicenseEnvelope.Sign(OnlineLicense, VendorKey),
                lease = LicenseEnvelope.Sign(Lease, VendorKey),
            },
        }.ToDictionary(kv => kv.Key, kv => JsonSerializer.Serialize(kv.Value, Json) + "\n");
    }

    /// <summary>The kinds of the text path besides <c>blob</c>: one frame each, so a client that mixes up a kind fails here.</summary>
    private static object ObjectKinds(byte[] key) =>
        new[] { ObjectKind.Snapshot, ObjectKind.Crdt, ObjectKind.Name, ObjectKind.Metadata, ObjectKind.Awareness }.Select(kind =>
        {
            var nonce = Bytes(12, 0x10 * (int)kind);
            var plaintext = Encoding.UTF8.GetBytes($"Nyxite {kind.ToString().ToLowerInvariant()} vector");
            var aad = NyxcFrame.BuildAad(KeyId, FileId, kind);
            return new
            {
                objectKind = (int)kind, name = kind.ToString().ToLowerInvariant(), key = H(key), keyId = KeyId, fileId = FileId,
                nonce = H(nonce), plaintext = H(plaintext), aad = H(aad), frame = H(NyxcFrame.Seal(key, KeyId, nonce, aad, plaintext)),
            };
        }).ToArray();

    /// <summary>
    /// The text path end to end (P1.1-CORE-1): real Yjs 13.6.33 updates (case <c>insert-and-delete</c> of the CRDT
    /// vectors) sealed as <c>crdt</c> frames in log order, and a snapshot of the first two as a <c>snapshot</c> frame.
    /// A client opens every frame, applies them to an empty document and must reach <c>finalText</c>, both from the
    /// whole log and from the snapshot plus the updates after its <c>crdtSeq</c>.
    /// </summary>
    private static object TextPath(byte[] key)
    {
        string[] updates =
        [
            "01010100040107636f6e74656e741354686520717569636b2062726f776e20666f7800", "000101010406",
            "01010113c40109010a05736c6f772000", "000101010004",
        ];
        const string snapshotState = "01010100040107636f6e74656e741354686520717569636b2062726f776e20666f780101010406";
        var crdtAad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Crdt);
        var snapshotAad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Snapshot);
        var snapshotNonce = Bytes(12, 0xe0);
        var state = Convert.FromHexString(snapshotState);
        return new
        {
            engine = "yjs 13.6.33", encoding = "update v1", textName = "content", key = H(key), keyId = KeyId, fileId = FileId,
            updates = updates.Select((u, i) =>
            {
                var nonce = Bytes(12, 0x40 + i * 12);
                var bytes = Convert.FromHexString(u);
                return new
                {
                    seq = i + 1, clientUpdateId = Guid.Parse($"01890a5d-ac96-774b-bcce-b302099a81{i:x2}"), nonce = H(nonce), update = u,
                    frame = H(NyxcFrame.Seal(key, KeyId, nonce, crdtAad, bytes)),
                };
            }).ToArray(),
            snapshot = new
            {
                crdtSeq = 2, state = snapshotState, text = "The brown fox", contentHash = H(Blake3.Hash(state)), nonce = H(snapshotNonce),
                frame = H(NyxcFrame.Seal(key, KeyId, snapshotNonce, snapshotAad, state)),
            },
            finalText = "slow brown fox",
        };
    }

    /// <summary>
    /// Awareness on the relay (P2.1-CORE-1): real y-protocols 1.0.6 awareness updates (on Yjs 13.6.33) sealed as
    /// <c>awareness</c> frames, <c>object_kind</c> 6. Each entry lists what a decoder must read back: the client id, its
    /// clock and the state as the JSON text the update carries, <c>null</c> for a client that left. The server forwards
    /// the frames unread and stores none of them.
    /// </summary>
    private static object Awareness(byte[] key)
    {
        const string ada = """{"user":{"name":"Ada","color":"#3366ff"},"cursor":{"anchor":3,"head":7}}""";
        const string adaMoved = """{"user":{"name":"Ada","color":"#3366ff"},"cursor":{"anchor":5,"head":5}}""";
        const string grace = """{"user":{"name":"Grace","color":"#ff6633"},"cursor":null}""";
        (string Name, string Update, (int ClientId, int Clock, string State)[] Entries)[] cases =
        [
            ("set", "016501487b2275736572223a7b226e616d65223a22416461222c22636f6c6f72223a2223333336366666227d2c22637572736f72223a7b22616e63686f72223a332c2268656164223a377d7d",
                [(101, 1, ada)]),
            ("move", "016502487b2275736572223a7b226e616d65223a22416461222c22636f6c6f72223a2223333336366666227d2c22637572736f72223a7b22616e63686f72223a352c2268656164223a357d7d",
                [(101, 2, adaMoved)]),
            ("two-clients", "026502487b2275736572223a7b226e616d65223a22416461222c22636f6c6f72223a2223333336366666227d2c22637572736f72223a7b22616e63686f72223a352c2268656164223a357d7dca0101397b2275736572223a7b226e616d65223a224772616365222c22636f6c6f72223a2223666636363333227d2c22637572736f72223a6e756c6c7d",
                [(101, 2, adaMoved), (202, 1, grace)]),
            ("leave", "016503046e756c6c", [(101, 3, "null")]),
        ];
        var aad = NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Awareness);
        return new
        {
            engine = "y-protocols 1.0.6 (yjs 13.6.33)", encoding = "awareness update", objectKind = (int)ObjectKind.Awareness, key = H(key),
            keyId = KeyId, fileId = FileId, aad = H(aad),
            updates = cases.Select((c, i) =>
            {
                var nonce = Bytes(12, 0x60 + i * 12);
                return new
                {
                    name = c.Name, update = c.Update,
                    entries = c.Entries.Select(e => new { clientId = e.ClientId, clock = e.Clock, state = e.State }).ToArray(),
                    nonce = H(nonce), frame = H(NyxcFrame.Seal(key, KeyId, nonce, aad, Convert.FromHexString(c.Update))),
                };
            }).ToArray(),
        };
    }

    /// <summary>
    /// The relay hub's messages as the SignalR MessagePack protocol puts them on the wire (05 §5.3), length prefix
    /// included. A record is a map keyed by its PascalCase property names, <c>KeyId</c> a UUID string and ciphertext
    /// raw bytes. The ciphertexts are the first frames of <c>text-path.json</c> and <c>awareness.json</c>.
    /// </summary>
    private static object RelayWire(byte[] key)
    {
        var protocol = new Microsoft.AspNetCore.SignalR.Protocol.MessagePackHubProtocol();
        string Write(Microsoft.AspNetCore.SignalR.Protocol.HubMessage message)
        {
            var buffer = new System.Buffers.ArrayBufferWriter<byte>();
            protocol.WriteMessage(message, buffer);
            return H(buffer.WrittenSpan);
        }

        var fileId = FileId.ToString();
        var update = new Nyxite.Server.Realtime.EncryptedUpdate(1,
            NyxcFrame.Seal(key, KeyId, Bytes(12, 0x40), NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Crdt),
                Convert.FromHexString("01010100040107636f6e74656e741354686520717569636b2062726f776e20666f7800")),
            KeyId.ToString());
        var awareness = NyxcFrame.Seal(key, KeyId, Bytes(12, 0x60), NyxcFrame.BuildAad(KeyId, FileId, ObjectKind.Awareness),
            Convert.FromHexString("016501487b2275736572223a7b226e616d65223a22416461222c22636f6c6f72223a2223333336366666227d2c22637572736f72223a7b22616e63686f72223a332c2268656164223a377d7d"));
        Nyxite.Server.Realtime.PresenceDto[] roster = [Nyxite.Server.Realtime.PresenceDto.ForUser(UserId, "Ada"), Nyxite.Server.Realtime.PresenceDto.ForGuest()];
        return new
        {
            protocol = "signalr messagepack v1", fileId = FileId, userId = UserId,
            submitUpdate = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("1", "SubmitUpdate", [fileId, update with { Seq = 0 }])),
            submitUpdateResult = Write(Microsoft.AspNetCore.SignalR.Protocol.CompletionMessage.WithResult("1", 1L)),
            onUpdates = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("OnUpdates", [fileId, new[] { update }])),
            submitAwareness = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("SubmitAwareness", [fileId, awareness])),
            onAwareness = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("OnAwareness", [fileId, awareness])),
            onPresence = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("OnPresence", [fileId, roster])),
            onError = Write(new Microsoft.AspNetCore.SignalR.Protocol.InvocationMessage("OnError", [fileId, "not_found", "Not found."])),
        };
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

    [Fact]
    public void Each_object_kind_opens_only_under_its_own_kind()
    {
        var kinds = Load("object-kinds.json").EnumerateArray().ToList();
        Assert.Equal([2, 3, 4, 5, 6], kinds.Select(k => k.GetProperty("objectKind").GetInt32()));
        foreach (var v in kinds)
        {
            Assert.Equal(B(v, "plaintext"), NyxcFrame.Open(B(v, "key"), B(v, "frame"), B(v, "aad")));
            foreach (var other in kinds.Where(o => o.GetProperty("objectKind").GetInt32() != v.GetProperty("objectKind").GetInt32()))
                Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(B(v, "key"), B(v, "frame"), B(other, "aad")));
        }
    }

    [Fact]
    public void Text_path_frames_open_to_the_yjs_updates_and_the_snapshot()
    {
        var v = Load("text-path.json");
        var key = B(v, "key");
        var keyId = v.GetProperty("keyId").GetGuid();
        var fileId = v.GetProperty("fileId").GetGuid();
        var seqs = new List<long>();
        foreach (var u in v.GetProperty("updates").EnumerateArray())
        {
            seqs.Add(u.GetProperty("seq").GetInt64());
            Assert.Equal(B(u, "update"), NyxcFrame.Open(key, B(u, "frame"), NyxcFrame.BuildAad(keyId, fileId, ObjectKind.Crdt)));
        }

        Assert.Equal([1L, 2L, 3L, 4L], seqs);
        var snapshot = v.GetProperty("snapshot");
        Assert.Equal(B(snapshot, "state"), NyxcFrame.Open(key, B(snapshot, "frame"), NyxcFrame.BuildAad(keyId, fileId, ObjectKind.Snapshot)));
        Assert.Equal(B(snapshot, "contentHash"), Blake3.Hash(B(snapshot, "state")));
        // A snapshot frame is not accepted as an update, so a relay mix-up cannot pass as content.
        Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(key, B(snapshot, "frame"), NyxcFrame.BuildAad(keyId, fileId, ObjectKind.Crdt)));
    }

    [Fact]
    public void Snapshot_triggers_are_the_shared_values()
    {
        var v = Load("snapshot-triggers.json");
        Assert.Equal(200, v.GetProperty("updateCount").GetInt32());
        Assert.Equal(300, v.GetProperty("intervalSeconds").GetInt32());
        Assert.True(v.GetProperty("onLastParticipantLeaving").GetBoolean());
    }

    /// <summary>Reads a y-protocols awareness update: a count, then per client its id, clock and state JSON (lib0 varuint and varstring).</summary>
    private static List<(long ClientId, long Clock, string State)> DecodeAwareness(byte[] update)
    {
        var position = 0;
        long VarUint()
        {
            long value = 0;
            for (var shift = 0; ; shift += 7)
            {
                var b = update[position++];
                value |= (long)(b & 0x7f) << shift;
                if (b < 0x80) return value;
            }
        }

        var entries = new List<(long, long, string)>();
        for (var count = VarUint(); count > 0; count--)
        {
            var clientId = VarUint();
            var clock = VarUint();
            var length = (int)VarUint();
            entries.Add((clientId, clock, Encoding.UTF8.GetString(update, position, length)));
            position += length;
        }

        Assert.Equal(update.Length, position);
        return entries;
    }

    [Fact]
    public void Awareness_frames_open_to_the_y_protocols_updates_and_decode_to_their_entries()
    {
        var v = Load("awareness.json");
        var key = B(v, "key");
        var aad = NyxcFrame.BuildAad(v.GetProperty("keyId").GetGuid(), v.GetProperty("fileId").GetGuid(), ObjectKind.Awareness);
        Assert.Equal(6, v.GetProperty("objectKind").GetInt32());
        Assert.Equal(B(v, "aad"), aad);
        foreach (var u in v.GetProperty("updates").EnumerateArray())
        {
            var update = B(u, "update");
            Assert.Equal(update, NyxcFrame.Open(key, B(u, "frame"), aad));
            var expected = u.GetProperty("entries").EnumerateArray()
                .Select(e => (e.GetProperty("clientId").GetInt64(), e.GetProperty("clock").GetInt64(), e.GetProperty("state").GetString()!));
            Assert.Equal(expected, DecodeAwareness(update));
            // An awareness frame is not content: it opens neither as an update nor as a snapshot.
            var fileId = v.GetProperty("fileId").GetGuid();
            var keyId = v.GetProperty("keyId").GetGuid();
            Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(key, B(u, "frame"), NyxcFrame.BuildAad(keyId, fileId, ObjectKind.Crdt)));
            Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(key, B(u, "frame"), NyxcFrame.BuildAad(keyId, fileId, ObjectKind.Snapshot)));
        }

        Assert.Equal("null", DecodeAwareness(B(v.GetProperty("updates")[3], "update"))[0].State);
    }

    [Fact]
    public void Relay_wire_messages_carry_records_as_maps_with_the_contract_names()
    {
        var v = Load("relay-wire.json");
        string Json(string property)
        {
            // A varint length prefix, then exactly one MessagePack array.
            var bytes = B(v, property);
            int length = 0, position = 0;
            for (var shift = 0; ; shift += 7)
            {
                var b = bytes[position++];
                length |= (b & 0x7f) << shift;
                if (b < 0x80) break;
            }

            Assert.Equal(bytes.Length, position + length);
            return MessagePack.MessagePackSerializer.ConvertToJson(bytes.AsMemory(position));
        }

        var userId = v.GetProperty("userId").GetString();
        Assert.Contains($$"""[{"Kind":"user","UserId":"{{userId}}","DisplayName":"Ada"},{"Kind":"guest","UserId":null,"DisplayName":null}]""", Json("onPresence"));
        Assert.Contains($$"""{"Seq":1,"Ciphertext":""", Json("onUpdates"));
        Assert.Contains($$""","KeyId":"01890a5d-ac96-774b-bcce-b302099a8057"}""", Json("onUpdates"));
        Assert.Contains("\"SubmitUpdate\"", Json("submitUpdate"));
        Assert.Contains("\"not_found\"", Json("onError"));
        // The awareness frame passes as one raw byte string, the same in both directions.
        Assert.Equal(Json("submitAwareness").Replace("SubmitAwareness", "OnAwareness"), Json("onAwareness"));
    }

    private static string SourceDirectory([CallerFilePath] string file = "") =>
        Path.Combine(Path.GetDirectoryName(file)!, "..", "Resources", "vectors");
}
