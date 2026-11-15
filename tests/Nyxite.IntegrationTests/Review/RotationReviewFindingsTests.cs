using System.Net;
using System.Security.Cryptography;
using System.Text;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using static Nyxite.IntegrationTests.Sharing.SharingTests;

namespace Nyxite.IntegrationTests.Review;

/// <summary>
/// Reproductions for the review of the Phase 2.3 and Phase 2.4 server (REVIEW-server-2026-11-15-b.md). Trait "issue"
/// asserts the specified behaviour and fails on the reviewed implementation. Trait "decision" asserts the current
/// behaviour and passes, so it documents the consequence of a decision instead of a defect.
/// </summary>
public sealed class RotationReviewFindingsTests(PostgresFixture pg)
{
    private sealed record Key(Guid FileId, Guid KeyId, byte[] Bytes)
    {
        public static Key New(Guid fileId) => new(fileId, Guid.CreateVersion7(), RandomNumberGenerator.GetBytes(32));

        public static Key Of(StructureDriver.Sealed file) => new(file.Id, file.KeyId, file.Key);

        public byte[] Seal(ObjectKind kind, string text) => NyxcFrame.Seal(Bytes, KeyId, FileId, kind, Encoding.UTF8.GetBytes(text));

        public object WrapFor(Guid memberId, byte[] publicKey, int generation) => new
        {
            keyId = KeyId, memberId, ciphertext = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, FileId, KeyId, Bytes)), generation,
            algId = CryptoSuite.HpkeAlgId,
        };
    }

    private static string Hash(string text) => Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(text)));

    private static Task<HttpResponseMessage> SubmitAsync(StructureDriver s, Key key, string text) =>
        s.PostAsync($"/files/{key.FileId}/crdt/log", new
        {
            updates = new[] { new { clientUpdateId = Guid.CreateVersion7(), keyId = key.KeyId, updateEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Crdt, text)) } },
        }, null);

    private static Task<HttpResponseMessage> PutAsync(StructureDriver s, string path, Key key, ObjectKind kind, string text, Action<HttpRequestMessage> headers)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, "/api/v1" + path)
        {
            Content = new ByteArrayContent(key.Seal(kind, text)) { Headers = { ContentType = new("application/octet-stream") } },
        };
        request.Headers.Add("Nyxite-Content-Hash", Hash(text));
        request.Headers.Add("Nyxite-Key-Id", key.KeyId.ToString());
        headers(request);
        return s.Client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> SnapshotAsync(StructureDriver s, Key key, long crdtSeq, string text) =>
        PutAsync(s, $"/files/{key.FileId}/snapshot", key, ObjectKind.Snapshot, text, r => r.Headers.Add("Nyxite-Snapshot-Seq", crdtSeq.ToString()));

    private static Task<HttpResponseMessage> BlobAsync(StructureDriver s, Key key, long parentSeq, string text) =>
        PutAsync(s, $"/files/{key.FileId}/blob", key, ObjectKind.Blob, text, r => r.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString()));

    private static Task<HttpResponseMessage> StageSnapshotAsync(StructureDriver s, Key key, long crdtSeq, string text) =>
        PutAsync(s, $"/files/{key.FileId}/keys/rotate/head", key, ObjectKind.Snapshot, text, r => r.Headers.Add("Nyxite-Snapshot-Seq", crdtSeq.ToString()));

    private static Task<HttpResponseMessage> StageBlobAsync(StructureDriver s, Key key, long parentSeq, string text) =>
        PutAsync(s, $"/files/{key.FileId}/keys/rotate/head", key, ObjectKind.Blob, text, r => r.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString()));

    private static object RotateBody(Key key, IEnumerable<(Guid Id, byte[] PublicKey)> members, string? headText, string name) => new
    {
        newKeyId = key.KeyId, generation = 2, wrappedKeys = members.Select(m => key.WrapFor(m.Id, m.PublicKey, 2)).ToArray(),
        newHeadRef = headText is null ? null : Hash(headText), nameEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Name, name)), metadataEnc = (string?)null,
    };

    // V1 -- 09 §9.6: the staged head exists so that a member added later with the new key only can open the file. A text
    // update that lands between staging and commit stays sealed with the old key behind the new head.
    [Fact, Trait("review", "issue")]
    public async Task V1_a_text_rotation_leaves_no_old_key_update_behind_the_new_head()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var writer = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var oldKey = Key.Of(file);
        var writerKey = await DirectoryKeyAsync(owner, writer.Id);
        var share = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = writer.Id, permission = "write",
            wrappedKeys = new[] { oldKey.WrapFor(writer.Id, writerKey, 1) },
        });
        Assert.Equal(HttpStatusCode.Created, share.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "line one")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, oldKey, 1, "line one")).StatusCode);

        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageSnapshotAsync(owner.S, newKey, 1, "line one")).StatusCode);
        // The collaborator keeps typing while the owner's client rotates.
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(writer.S, oldKey, "line two")).StatusCode);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)), (writer.Id, writerKey) };
        var commit = await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, "line one", "note.md"));

        if (commit.StatusCode == HttpStatusCode.NoContent)
        {
            // Whatever a new-key-only member has to read after the head must be sealed with the new key.
            var behind = await Sql.ListAsync<Guid>(app.ConnectionString, """
                SELECT u.key_id FROM crdt_updates u JOIN files f ON f.crdt_doc_id = u.crdt_doc_id
                JOIN file_versions v ON v.id = f.current_version_id
                WHERE f.id = @f AND u.seq > v.crdt_seq
                """, ("f", file.Id));
            Assert.All(behind, k => Assert.Equal(newKey.KeyId, k));
        }
        else
        {
            Assert.Equal("version_conflict", await commit.ProblemCodeAsync());
        }
    }

    // V2 -- OPEN-DECISIONS (Phase 2.3) and 09 §9.6: a live link "keeps the old key in its fragment and opens nothing
    // written after the rotation". The rotation re-seals the head and the name, so the link opens nothing at all while
    // it still answers as live.
    [Fact, Trait("review", "issue")]
    public async Task V2_a_link_that_stays_live_after_a_rotation_still_opens_its_file()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        var token = ShareLink.NewToken();
        Assert.Equal(HttpStatusCode.Created, (await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(token)),
        })).StatusCode);

        // The owner rotates, for example after removing an unrelated account member.
        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, newKey, 1, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate",
            RotateBody(newKey, [(owner.Id, XWing.PublicKeyFromSeed(owner.Seed))], "page one", "scan.bin"))).StatusCode);

        var guest = app.CreateClient();
        var bootstrap = await guest.GetAsync($"/share/{token}");
        if (bootstrap.StatusCode == HttpStatusCode.OK)
        {
            var body = await bootstrap.JsonAsync();
            // The fragment holds the old key: what the live link serves must open with it.
            Assert.Equal(oldKey.KeyId, body.GetProperty("file").GetProperty("keyId").GetGuid());
            var blob = new HttpRequestMessage(HttpMethod.Get, $"/share/{token}/blob");
            blob.Headers.Authorization = new("Bearer", body.GetProperty("guestToken").GetString());
            var head = await guest.SendAsync(blob);
            Assert.Equal(oldKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
        }
        else
        {
            Assert.Equal(HttpStatusCode.Gone, bootstrap.StatusCode);
        }
    }

    // V3 -- 04 §4.2 idempotency: a key names one request. The restore's idempotency row does not name the file, so the
    // same key and seq on another file is answered 204 as a replay, and nothing is recorded for that file.
    [Fact, Trait("review", "issue")]
    public async Task V3_a_restore_key_reused_on_another_file_is_not_a_silent_replay()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var first = await owner.S.FileAsync(project, "a.bin", contentType: "binary");
        var second = await owner.S.FileAsync(project, "b.bin", contentType: "binary");
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, Key.Of(first), 0, "a one")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, Key.Of(second), 0, "b one")).StatusCode);

        const string key = "restore-key-shared";
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{first.Id}/restore", new { seq = 1 }, key)).StatusCode);
        var other = await owner.S.PostAsync($"/files/{second.Id}/restore", new { seq = 1 }, key);

        if (other.StatusCode == HttpStatusCode.NoContent)
        {
            Assert.Equal(1L, await Sql.ScalarAsync<long?>(app.ConnectionString, "SELECT pending_restore_seq FROM files WHERE id = @f", ("f", second.Id)));
            Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString,
                "SELECT count(*) FROM audit_log WHERE action = 'version.restore' AND target_id = @f", ("f", second.Id)));
        }
        else
        {
            Assert.Equal("idempotency_conflict", await other.ProblemCodeAsync());
        }
    }

    // V4 -- 09 §9.6 and 06 §6.2: a shared file switched to excluded keeps its head until the content purge, up to Trash
    // plus grace window later. Until then the second layer of revocation cannot run for it at all.
    [Fact, Trait("review", "decision")]
    public async Task V4_an_excluded_file_cannot_be_rotated_until_its_content_is_purged()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" })).StatusCode);

        var newKey = Key.New(file.Id);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)) };
        Assert.Equal("excluded_content", await (await StageBlobAsync(owner.S, newKey, 1, "page one")).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate",
            RotateBody(newKey, members, null, "scan.bin"))).ProblemCodeAsync());
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
    }
}
