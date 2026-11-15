using System.Security.Cryptography;
using System.Text.Json;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

/// <summary>
/// P2.2-CORE-1 build gate: <c>sharing.json</c> parses, its derived values recompute, the object-key wrap opens with the
/// recipient's seed, and no request fixture carries the URL fragment. The file itself is checked byte for byte with
/// the other vectors in <see cref="ConformanceVectorTests"/>.
/// </summary>
public sealed class SharingFixtureTests
{
    private static readonly JsonElement V = JsonDocument.Parse(Vectors.Read("sharing.json")).RootElement;

    private static byte[] Hex(JsonElement e, string name) => Convert.FromHexString(e.GetProperty(name).GetString()!);

    [Fact]
    public void The_link_token_hash_is_sha256_of_the_ascii_token()
    {
        var link = V.GetProperty("linkToken");
        var token = link.GetProperty("token").GetString()!;
        Assert.Equal(43, token.Length);
        Assert.Equal(Hex(link, "bytes"), Base64UrlCodec.Decode(token));
        Assert.Equal(Hex(link, "sha256"), SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)));
        Assert.Equal(Hex(link, "sha256"), Base64UrlCodec.Decode(link.GetProperty("linkTokenHash").GetString()!));
    }

    [Fact]
    public void The_share_url_carries_the_file_key_in_the_fragment_only()
    {
        var url = V.GetProperty("shareUrl").GetString()!;
        var token = V.GetProperty("linkToken").GetProperty("token").GetString()!;
        Assert.Equal($"{V.GetProperty("origin").GetString()}/share/{token}#k={Base64UrlCodec.Encode(Hex(V, "fileKey"))}", url);
        Assert.Equal("k=" + Base64UrlCodec.Encode(Hex(V, "fileKey")), V.GetProperty("fragment").GetString());
        Assert.Equal($"/share/{token}", V.GetProperty("requestPath").GetString());
        Assert.True(ShareLink.TryParse(url, out var parsedToken, out var key));
        Assert.Equal(token, parsedToken);
        Assert.Equal(Hex(V, "fileKey"), key);
        Assert.False(ShareLink.TryParse(url.Split('#')[0], out _, out _));
    }

    [Fact]
    public void The_object_key_wrap_opens_with_the_recipient_seed_and_is_bound_to_object_and_key()
    {
        var w = V.GetProperty("objectKeyWrap");
        Assert.Equal("nyxite object key v1", w.GetProperty("info").GetString());
        var objectId = w.GetProperty("objectId").GetGuid();
        var keyId = w.GetProperty("keyId").GetGuid();
        Assert.Equal(Hex(w, "aad"), ObjectKeyWrap.Aad(objectId, keyId));
        Assert.Equal(Hex(w, "recipientPublicKey"), XWing.PublicKeyFromSeed(Hex(w, "recipientSeed")));
        Assert.Equal(Hex(w, "objectKey"), ObjectKeyWrap.Open(Hex(w, "recipientSeed"), objectId, keyId, Hex(w, "wrapped")));
        Assert.ThrowsAny<CryptographicException>(() => ObjectKeyWrap.Open(Hex(w, "recipientSeed"), Guid.CreateVersion7(), keyId, Hex(w, "wrapped")));
        Assert.ThrowsAny<CryptographicException>(() => ObjectKeyWrap.Open(Hex(w, "recipientSeed"), objectId, Guid.CreateVersion7(), Hex(w, "wrapped")));
    }

    [Fact]
    public void No_request_fixture_contains_the_fragment_or_the_file_key()
    {
        var key = Hex(V, "fileKey");
        string[] forbidden = ["#", Base64UrlCodec.Encode(key), Convert.ToHexStringLower(key), Convert.ToBase64String(key), V.GetProperty("fragment").GetString()!];
        var requests = V.GetProperty("requests").EnumerateArray().ToList();
        Assert.Equal(12, requests.Count);
        foreach (var request in requests)
        {
            var text = request.GetRawText();
            foreach (var f in forbidden) Assert.DoesNotContain(f, text);
        }
    }

    [Fact]
    public void Account_share_wraps_open_for_the_grantee()
    {
        var seed = Hex(V.GetProperty("objectKeyWrap"), "recipientSeed");
        var share = V.GetProperty("requests").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "createAccountShare").GetProperty("body");
        var wrap = share.GetProperty("wrappedKeys")[0];
        Assert.Equal(Hex(V, "fileKey"), ObjectKeyWrap.Open(seed, share.GetProperty("targetId").GetGuid(), wrap.GetProperty("keyId").GetGuid(),
            Base64UrlCodec.Decode(wrap.GetProperty("ciphertext").GetString()!)));
        var rotate = V.GetProperty("requests").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "rotate").GetProperty("body");
        Assert.Equal(2, rotate.GetProperty("generation").GetInt32());
        Assert.Equal(rotate.GetProperty("newKeyId").GetGuid(), rotate.GetProperty("wrappedKeys")[0].GetProperty("keyId").GetGuid());
    }

    [Fact]
    public void Rotation_stages_the_head_under_the_new_key_and_the_commit_names_it()
    {
        var r = V.GetProperty("rotation");
        var requests = V.GetProperty("requests").EnumerateArray().ToDictionary(e => e.GetProperty("name").GetString()!);
        Assert.Equal(["stageRotationHead", "rotate"], r.GetProperty("order").EnumerateArray().Select(e => e.GetString()));
        var stage = requests["stageRotationHead"];
        var rotate = requests["rotate"].GetProperty("body");
        var newKeyId = rotate.GetProperty("newKeyId").GetGuid();
        var fileId = V.GetProperty("fileId").GetGuid();
        var key = Hex(r, "rotatedKey");

        // The staged frame is sealed with the new key, and newHeadRef is the content hash the stage carried.
        Assert.Equal(newKeyId.ToString(), stage.GetProperty("headers").GetProperty("Nyxite-Key-Id").GetString());
        var frame = Hex(stage, "bodyHex");
        Assert.True(NyxcFrame.TryParseHeader(frame, out var header));
        Assert.Equal(newKeyId, header.KeyId);
        var plaintext = NyxcFrame.Open(key, frame, NyxcFrame.BuildAad(newKeyId, fileId, ObjectKind.Snapshot));
        Assert.Equal(Hex(r, "rotatedHeadPlaintext"), plaintext);
        Assert.Equal(Base64UrlCodec.Encode(Blake3.Hash(plaintext)), rotate.GetProperty("newHeadRef").GetString());
        Assert.Equal(rotate.GetProperty("newHeadRef").GetString(), stage.GetProperty("headers").GetProperty("Nyxite-Content-Hash").GetString());

        // The name is sealed again with the new key, and every member, the owner included, has a wrap that opens to it.
        var name = Base64UrlCodec.Decode(rotate.GetProperty("nameEnc").GetString()!);
        Assert.Equal("plan.md"u8.ToArray(), NyxcFrame.Open(key, name, NyxcFrame.BuildAad(newKeyId, fileId, ObjectKind.Name)));
        var seeds = new[] { Hex(V.GetProperty("objectKeyWrap"), "recipientSeed"), Hex(r, "ownerRecipientSeed") };
        var wraps = rotate.GetProperty("wrappedKeys").EnumerateArray().ToList();
        Assert.Equal(r.GetProperty("members").EnumerateArray().Select(m => m.GetGuid()), wraps.Select(w => w.GetProperty("memberId").GetGuid()));
        for (var i = 0; i < wraps.Count; i++)
        {
            Assert.Equal(2, wraps[i].GetProperty("generation").GetInt32());
            Assert.Equal(key, ObjectKeyWrap.Open(seeds[i], fileId, newKeyId, Base64UrlCodec.Decode(wraps[i].GetProperty("ciphertext").GetString()!)));
        }

        // A wrap opens for its own member only.
        Assert.ThrowsAny<CryptographicException>(() => ObjectKeyWrap.Open(seeds[1], fileId, newKeyId,
            Base64UrlCodec.Decode(wraps[0].GetProperty("ciphertext").GetString()!)));
    }

    [Fact]
    public void Rotation_commits_only_at_the_next_generation()
    {
        var r = V.GetProperty("rotation");
        var current = r.GetProperty("currentGeneration").GetInt32();
        foreach (var c in r.GetProperty("cases").EnumerateArray())
            Assert.Equal(c.GetProperty("submittedGeneration").GetInt32() == current + 1 ? 204 : 409, c.GetProperty("status").GetInt32());
        Assert.Equal(412, r.GetProperty("oldKeyUpdate").GetProperty("afterCommit").GetInt32());
        Assert.Equal("key_generation_stale", r.GetProperty("oldKeyUpdate").GetProperty("code").GetString());
    }
}
