using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.SignalR.Client;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using static Nyxite.IntegrationTests.Sharing.SharingTests;

namespace Nyxite.IntegrationTests.Review;

/// <summary>
/// Regression tests for V1 to V4 of the review of the Phase 2.3 and Phase 2.4 server (REVIEW-server-2026-11-15-b.md).
/// They reproduced the findings before the fix and now pin the behaviour the user decided on 2026-11-15: a text rotation
/// covers the whole log (V1), a rotation revokes the file's links by default or keeps them frozen at the old generation
/// (V2), a restore's idempotency names its file (V3), and an excluded file rotates without a head (V4).
/// </summary>
public sealed class RotationReviewFindingsTests(PostgresFixture pg)
{
    private sealed record Key(Guid FileId, Guid KeyId, byte[] Bytes)
    {
        public static Key New(Guid fileId) => new(fileId, Guid.CreateVersion7(), RandomNumberGenerator.GetBytes(32));

        public static Key Of(StructureDriver.Sealed file) => new(file.Id, file.KeyId, file.Key);

        public byte[] Seal(ObjectKind kind, string text) => NyxcFrame.Seal(Bytes, KeyId, FileId, kind, Encoding.UTF8.GetBytes(text));

        public string Open(ObjectKind kind, byte[] frame) => Encoding.UTF8.GetString(NyxcFrame.Open(Bytes, frame, NyxcFrame.BuildAad(KeyId, FileId, kind)));

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

    private static object RotateBody(Key key, IEnumerable<(Guid Id, byte[] PublicKey)> members, string? headText, string name, string? links = null) => new
    {
        newKeyId = key.KeyId, generation = 2, wrappedKeys = members.Select(m => key.WrapFor(m.Id, m.PublicKey, 2)).ToArray(),
        newHeadRef = headText is null ? null : Hash(headText), nameEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Name, name)), metadataEnc = (string?)null,
        links,
    };

    private static async Task<string> LinkAsync(Member owner, StructureDriver.Sealed file, string permission = "read")
    {
        var token = ShareLink.NewToken();
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "link", permission, linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(token)),
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return token;
    }

    private static Task<HttpResponseMessage> GuestAsync(HttpClient guest, HttpMethod method, string path, string guestToken)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new("Bearer", guestToken);
        return guest.SendAsync(request);
    }

    // V1 -- 09 §9.6: the staged head exists so that a member added later with the new key only can open the file. A text
    // update that lands between staging and commit would stay sealed with the old key behind the new head, so the commit
    // is a version conflict and the client stages again over the whole log.
    [Fact]
    public async Task V1_a_text_update_after_staging_makes_the_commit_a_version_conflict_and_the_restaged_head_covers_the_log()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var writer = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var oldKey = Key.Of(file);
        var writerKey = await DirectoryKeyAsync(owner, writer.Id);
        Assert.Equal(HttpStatusCode.Created, (await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = writer.Id, permission = "write",
            wrappedKeys = new[] { oldKey.WrapFor(writer.Id, writerKey, 1) },
        })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "line one")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, oldKey, 1, "line one")).StatusCode);

        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageSnapshotAsync(owner.S, newKey, 1, "line one")).StatusCode);
        // The collaborator keeps typing while the owner's client rotates.
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(writer.S, oldKey, "line two")).StatusCode);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)), (writer.Id, writerKey) };
        var commit = await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, "line one", "note.md"));
        Assert.Equal("version_conflict", await commit.ProblemCodeAsync());
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));

        // The client stages again over the whole log and commits.
        Assert.Equal(HttpStatusCode.NoContent, (await StageSnapshotAsync(owner.S, newKey, 2, "line one\nline two")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, "line one\nline two", "note.md"))).StatusCode);
        var behind = await Sql.ListAsync<Guid>(app.ConnectionString, """
            SELECT u.key_id FROM crdt_updates u JOIN files f ON f.crdt_doc_id = u.crdt_doc_id
            JOIN file_versions v ON v.id = f.current_version_id
            WHERE f.id = @f AND u.seq > v.crdt_seq
            """, ("f", file.Id));
        Assert.Empty(behind);
    }

    // V1 -- a text file with updates but no snapshot yet must bring a staged head too, otherwise its whole log would stay
    // sealed with the old key for a member who only gets the new one.
    [Fact]
    public async Task V1_a_text_file_with_updates_but_no_snapshot_needs_a_staged_head()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "only update")).StatusCode);
        var newKey = Key.New(file.Id);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)) };
        Assert.Equal("validation_failed", await (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, null, "note.md"))).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await StageSnapshotAsync(owner.S, newKey, 1, "only update")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, "only update", "note.md"))).StatusCode);
    }

    // V2 -- decision of 2026-11-15: revoking the file's links is the default of a rotation. A revoked link answers as
    // revoked, never as a live link whose ciphertext its key cannot open.
    [Fact]
    public async Task V2_a_rotation_revokes_the_files_links_by_default_and_they_answer_as_revoked()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        var token = await LinkAsync(owner, file);

        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, newKey, 1, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate",
            RotateBody(newKey, [(owner.Id, XWing.PublicKeyFromSeed(owner.Seed))], "page one", "scan.bin"))).StatusCode);

        var bootstrap = await app.CreateClient().GetAsync($"/share/{token}");
        Assert.Equal(HttpStatusCode.Gone, bootstrap.StatusCode);
        Assert.Equal("share_revoked", await bootstrap.ProblemCodeAsync());
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'share.revoke' AND detail->>'by' = 'rotation'"));
        Assert.Equal("revoke", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT detail->>'links' FROM audit_log WHERE action = 'key.rotate'"));
    }

    // V2 -- decision of 2026-11-15: a kept link does not get the new content. It keeps serving the last head, name and
    // metadata its fragment key opens, read only and without a relay room, also after later writes under the new key.
    [Fact]
    public async Task V2_a_kept_link_serves_its_frozen_head_and_name_read_only_and_without_a_relay_room()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        var token = await LinkAsync(owner, file, permission: "write");

        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, newKey, 1, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate",
            RotateBody(newKey, [(owner.Id, XWing.PublicKeyFromSeed(owner.Seed))], "page one", "scan.bin", links: "keep"))).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, newKey, 2, "page two, after the rotation")).StatusCode);

        var guest = app.CreateClient();
        var bootstrap = await guest.GetAsync($"/share/{token}");
        Assert.Equal(HttpStatusCode.OK, bootstrap.StatusCode);
        var body = await bootstrap.JsonAsync();
        var shared = body.GetProperty("file");
        Assert.True(shared.GetProperty("frozen").GetBoolean());
        Assert.Equal("read", body.GetProperty("permission").GetString());
        Assert.Equal(oldKey.KeyId, shared.GetProperty("keyId").GetGuid());
        Assert.Equal(1, shared.GetProperty("keyGeneration").GetInt32());
        Assert.Equal(1, shared.GetProperty("currentVersionSeq").GetInt64());
        Assert.Equal("scan.bin", oldKey.Open(ObjectKind.Name, Base64UrlCodec.Decode(shared.GetProperty("nameEnc").GetString()!)));

        var guestToken = body.GetProperty("guestToken").GetString()!;
        var head = await GuestAsync(guest, HttpMethod.Get, $"/share/{token}/blob", guestToken);
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(oldKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
        Assert.Equal("page one", oldKey.Open(ObjectKind.Blob, await head.Content.ReadAsByteArrayAsync()));
        var ticket = await GuestAsync(guest, HttpMethod.Post, $"/share/{token}/socket-ticket", guestToken);
        Assert.Equal("link_frozen", await ticket.ProblemCodeAsync());

        // The owner sees the link as frozen and cannot make it writable again.
        var listed = Assert.Single((await (await owner.S.GetAsync($"/shares?targetType=file&targetId={file.Id}")).JsonAsync()).GetProperty("items").EnumerateArray());
        Assert.Equal(1, listed.GetProperty("frozenGeneration").GetInt32());
        Assert.Equal("conflict", await (await owner.S.PatchAsync($"/shares/{listed.GetProperty("id").GetGuid()}", new { permission = "write" })).ProblemCodeAsync());
    }

    // V2 -- a kept link of a text file must open the whole document as it was, so the head under the old key must cover
    // every update. A guest connected to the room leaves it at once with link_frozen, since nothing new opens with its key.
    [Fact]
    public async Task V2_keeping_the_links_of_a_text_file_needs_a_covering_old_key_snapshot_and_evicts_its_guests()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "line one")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, oldKey, 1, "line one")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "line two")).StatusCode);
        var token = await LinkAsync(owner, file);
        var guest = app.CreateClient();
        var guestToken = (await (await guest.GetAsync($"/share/{token}")).JsonAsync()).GetProperty("guestToken").GetString()!;
        var ticket = (await (await GuestAsync(guest, HttpMethod.Post, $"/share/{token}/socket-ticket", guestToken)).JsonAsync()).GetProperty("ticket").GetString()!;
        await using var guestPeer = await RelayPeer.ConnectAsync(app, ticket, webSockets: true, path: $"/share/{token}/ws");
        await guestPeer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        var newKey = Key.New(file.Id);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)) };
        Assert.Equal(HttpStatusCode.NoContent, (await StageSnapshotAsync(owner.S, newKey, 2, "line one\nline two")).StatusCode);
        var keep = RotateBody(newKey, members, "line one\nline two", "note.md", links: "keep");
        Assert.Equal("version_conflict", await (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", keep)).ProblemCodeAsync());

        // The client stores a snapshot under the old key that covers the log; the stage still covers it as well.
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, oldKey, 2, "line one\nline two")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", keep)).StatusCode);
        await RelayPeer.UntilAsync(() => guestPeer.Closed);
        Assert.Contains("link_frozen", guestPeer.Errors);

        var shared = (await (await guest.GetAsync($"/share/{token}")).JsonAsync()).GetProperty("file");
        Assert.Equal(2, shared.GetProperty("currentVersionSeq").GetInt64());
        Assert.Equal(oldKey.KeyId, shared.GetProperty("keyId").GetGuid());
        Assert.Equal("link_frozen", await (await GuestAsync(guest, HttpMethod.Post, $"/share/{token}/socket-ticket", guestToken)).ProblemCodeAsync());
    }

    // V3 -- 04 §4.2 idempotency: a key names one request. The restore's idempotency record names the file, so the same
    // key on another file is a conflict, and a retry on the same file answers success with one audit event.
    [Fact]
    public async Task V3_a_restore_key_reused_on_another_file_is_an_idempotency_conflict_and_a_retry_records_once()
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
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{first.Id}/restore", new { seq = 1 }, key)).StatusCode);
        Assert.Equal("idempotency_conflict", await (await owner.S.PostAsync($"/files/{second.Id}/restore", new { seq = 1 }, key)).ProblemCodeAsync());

        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'version.restore' AND target_id = @f", ("f", first.Id)));
        Assert.Equal(0, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'version.restore' AND target_id = @f", ("f", second.Id)));
        Assert.Equal((long?)null, await Sql.ScalarAsync<long?>(app.ConnectionString, "SELECT pending_restore_seq FROM files WHERE id = @f", ("f", second.Id)));
    }

    // V4 -- decision of 2026-11-15: a file switched to excluded rotates without a head. Key, name and metadata move to the
    // new generation at once, and the old content is left to the content purge.
    [Fact]
    public async Task V4_an_excluded_file_rotates_without_a_head_and_leaves_its_content_to_the_purge()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" })).StatusCode);

        var newKey = Key.New(file.Id);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)) };
        // The server still takes no content for it, so there is nothing to stage.
        Assert.Equal("excluded_content", await (await StageBlobAsync(owner.S, newKey, 1, "page one")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/keys/rotate", RotateBody(newKey, members, null, "scan.bin"))).StatusCode);

        Assert.Equal(2, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
        var listed = await (await owner.S.GetAsync($"/files/{file.Id}")).JsonAsync();
        Assert.Equal(2, listed.GetProperty("wrappedKey").GetProperty("generation").GetInt32());
        Assert.Equal("scan.bin", newKey.Open(ObjectKind.Name, Base64UrlCodec.Decode(listed.GetProperty("nameEnc").GetString()!)));
        // The old head stays, sealed with the old key, until the excluded-content purge removes it.
        Assert.Equal(1, listed.GetProperty("currentVersionSeq").GetInt64());
        var head = await owner.S.GetAsync($"/files/{file.Id}/blob");
        Assert.Equal(oldKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
    }
}
