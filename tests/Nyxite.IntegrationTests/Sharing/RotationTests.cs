using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Content;
using Nyxite.Application.Maintenance;
using Nyxite.BlobStore;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Server.Realtime;
using static Nyxite.IntegrationTests.Sharing.SharingTests;

namespace Nyxite.IntegrationTests.Sharing;

/// <summary>
/// Phase 2.3 server (P2.3-SRV-1): the two layers of revocation. The instant ACL cutoff at fetch, join and submit
/// (P2.3-TC-1), and the generation-guarded commit of a client-driven file-key rotation with its staged head, its
/// concurrent loser, the <c>412</c> of in-flight old-key writes and their re-seal (P2.3-TC-2, server side), followed by
/// the "nothing leaks" inspection. The client work is done here the way a client does it: keys are made and wrapped
/// locally, and the server only ever sees frames and wraps.
/// </summary>
public sealed class RotationTests(PostgresFixture pg)
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

    private static Task<HttpResponseMessage> SubmitAsync(StructureDriver s, Key key, string text, Guid? clientUpdateId = null) =>
        s.PostAsync($"/files/{key.FileId}/crdt/log", new
        {
            updates = new[] { new { clientUpdateId = clientUpdateId ?? Guid.CreateVersion7(), keyId = key.KeyId, updateEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Crdt, text)) } },
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

    /// <summary>Stages the head under the new key: a snapshot for a text file, the re-encrypted head for any other.</summary>
    private static Task<HttpResponseMessage> StageAsync(StructureDriver s, Key key, string text, long? crdtSeq = null, long? parentSeq = null) =>
        PutAsync(s, $"/files/{key.FileId}/keys/rotate/head", key, crdtSeq is null ? ObjectKind.Blob : ObjectKind.Snapshot, text, r =>
        {
            if (crdtSeq is { } seq) r.Headers.Add("Nyxite-Snapshot-Seq", seq.ToString());
            if (parentSeq is { } parent) r.Headers.TryAddWithoutValidation("If-Match", parent.ToString());
        });

    private static object RotateBody(Key key, int generation, IEnumerable<(Guid Id, byte[] PublicKey)> members, string? headText, string name,
        Key? nameKey = null) => new
    {
        newKeyId = key.KeyId, generation, wrappedKeys = members.Select(m => key.WrapFor(m.Id, m.PublicKey, generation)).ToArray(),
        newHeadRef = headText is null ? null : Hash(headText),
        nameEnc = Base64UrlCodec.Encode((nameKey ?? key).Seal(ObjectKind.Name, name)),
        metadataEnc = (string?)null,
    };

    private static Task<HttpResponseMessage> RotateAsync(StructureDriver s, Guid fileId, object body, string? idempotencyKey = "auto") =>
        s.PostAsync($"/files/{fileId}/keys/rotate", body, idempotencyKey);

    private static async Task<Guid> ShareAsync(Member owner, StructureDriver.Sealed file, Member grantee, string permission)
    {
        var publicKey = await DirectoryKeyAsync(owner, grantee.Id);
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = grantee.Id, permission,
            wrappedKeys = new[] { Key.Of(file).WrapFor(grantee.Id, publicKey, 1) },
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return (await created.JsonAsync()).GetProperty("id").GetGuid();
    }

    private static async Task<byte[]> UnwrapAsync(Member member, Guid fileId, int generation)
    {
        var items = (await (await member.S.GetAsync($"/files/{fileId}/keys")).JsonAsync()).GetProperty("items").EnumerateArray();
        var wrap = items.Single(i => i.GetProperty("generation").GetInt32() == generation);
        return ObjectKeyWrap.Open(member.Seed, fileId, wrap.GetProperty("keyId").GetGuid(), Base64UrlCodec.Decode(wrap.GetProperty("ciphertext").GetString()!));
    }

    // ---------------------------------------------------------------- P2.3-TC-1

    /// <summary>
    /// P2.3-TC-1: U2 reaches a file through an account share and a guest through a link. U1 deletes both shares, and
    /// both are denied at once at every checkpoint: fetch, relay join, submit, and the room they were in, without
    /// waiting for the periodic re-check.
    /// </summary>
    [Fact]
    public async Task Revoking_a_share_denies_fetch_join_and_submit_at_once()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var grantee = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var key = Key.Of(file);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, key, "first line")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, key, 1, "first line")).StatusCode);
        var shareId = await ShareAsync(owner, file, grantee, "write");

        var token = ShareLink.NewToken();
        var link = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "link", permission = "write", linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(token)),
        });
        var linkId = (await link.JsonAsync()).GetProperty("id").GetGuid();
        var guest = app.CreateClient();
        var guestToken = (await (await guest.GetAsync($"/share/{token}")).JsonAsync()).GetProperty("guestToken").GetString()!;
        var ticketRequest = new HttpRequestMessage(HttpMethod.Post, $"/share/{token}/socket-ticket");
        ticketRequest.Headers.Authorization = new("Bearer", guestToken);
        var ticket = (await (await guest.SendAsync(ticketRequest)).JsonAsync()).GetProperty("ticket").GetString()!;

        await using var peer = await RelayPeer.ConnectAsync(app, grantee.Token);
        await peer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        await using var guestPeer = await RelayPeer.ConnectAsync(app, ticket, webSockets: true, path: $"/share/{token}/ws");
        await guestPeer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        Assert.Equal(HttpStatusCode.OK, (await grantee.S.GetAsync($"/files/{file.Id}/snapshot")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{linkId}")).StatusCode);

        // Fetch: every read of the file is a 404, as if it never existed.
        foreach (var path in new[] { "", "/snapshot", "/crdt/log?since=0", "/keys", "/versions", "/versions/1/blob" })
            Assert.Equal(HttpStatusCode.NotFound, (await grantee.S.GetAsync($"/files/{file.Id}{path}")).StatusCode);
        // Submit, over REST and in the room the grantee is still connected to.
        Assert.Equal(HttpStatusCode.NotFound, (await SubmitAsync(grantee.S, key, "too late")).StatusCode);
        var submit = await Assert.ThrowsAsync<HubException>(() => peer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(),
            new EncryptedUpdate(0, key.Seal(ObjectKind.Crdt, "too late"), key.KeyId.ToString())));
        Assert.Contains("not_found", submit.Message);
        // The open rooms are left at once (the periodic pass is an hour away), and a new join is refused.
        await RelayPeer.UntilAsync(() => peer.Errors.Contains("not_found") && guestPeer.Closed);
        Assert.Contains("share_revoked", guestPeer.Errors);
        await using var again = await RelayPeer.ConnectAsync(app, grantee.Token);
        var join = await Assert.ThrowsAsync<HubException>(() => again.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L));
        Assert.Contains("not_found", join.Message);
        Assert.Equal(HttpStatusCode.Gone, (await guest.GetAsync($"/share/{token}")).StatusCode);
        var blob = new HttpRequestMessage(HttpMethod.Get, $"/share/{token}/blob");
        blob.Headers.Authorization = new("Bearer", guestToken);
        Assert.NotEqual(HttpStatusCode.OK, (await guest.SendAsync(blob)).StatusCode);
        Assert.Equal(0, await RecheckAsync(app));
        // The owner keeps everything.
        Assert.Equal(HttpStatusCode.OK, (await owner.S.GetAsync($"/files/{file.Id}/snapshot")).StatusCode);
    }

    // ---------------------------------------------------------------- P2.3-TC-2

    /// <summary>
    /// P2.3-TC-2, server side: after a share is revoked, a remaining writer's client, here the owner's, rotates the file
    /// key. The new head is staged under the new key and becomes the head with the commit, which succeeds at generation
    /// + 1 only and only while the stage covers the whole log; of two concurrent rotations one wins and the other gets
    /// <c>409</c>. An old-key update is accepted until the commit and is
    /// <c>412 key_generation_stale</c> after it, over REST and the relay, and passes once re-sealed. The remaining member
    /// unwraps the new key and still opens the old versions, while the removed member gets no wrap of the new key, can
    /// fetch nothing, and could not open what was written after the rotation if it had the bytes.
    /// </summary>
    [Fact]
    public async Task Rotation_commits_at_the_next_generation_and_leaves_the_removed_member_without_the_new_key()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = App(await pg.CreateDatabaseAsync(), logs);
        var owner = await MemberAsync(app, "Ada");
        var keeper = await MemberAsync(app, "Grace");
        var leaver = await MemberAsync(app, "Mallory");
        var project = await owner.S.ProjectAsync("Plans");
        var file = await owner.S.FileAsync(project, "rotation-plan.md");
        var oldKey = Key.Of(file);
        await ShareAsync(owner, file, keeper, "write");
        var leaverShare = await ShareAsync(owner, file, leaver, "write");
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, oldKey, "old secret one")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(leaver.S, oldKey, "old secret two")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, oldKey, 2, "old snapshot body")).StatusCode);

        await using var keeperPeer = await RelayPeer.ConnectAsync(app, keeper.Token);
        await keeperPeer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        // Layer one: the revoke. Layer two: the owner's client makes a new key and stages the head sealed with it.
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{leaverShare}")).StatusCode);
        var members = new[] { (owner.Id, XWing.PublicKeyFromSeed(owner.Seed)), (keeper.Id, await DirectoryKeyAsync(owner, keeper.Id)) };
        var first = Key.New(file.Id);
        var second = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, first, "rotated head body", crdtSeq: 2)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, second, "rotated head body", crdtSeq: 2)).StatusCode);
        // Staging changes nothing yet: the head and the generation are the old ones.
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
        Assert.Equal(2, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_rotation_heads WHERE file_id = @f", ("f", file.Id)));

        // An in-flight update sealed with the old key is accepted until the commit, and it makes both stages stale: a
        // commit now would leave an old-key update behind the new head (V1), so it is a version conflict.
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(keeper.S, oldKey, "in flight before commit")).StatusCode);
        var stale = await RotateAsync(owner.S, file.Id, RotateBody(first, 2, members, "rotated head body", "rotation-plan.md"));
        Assert.Equal("version_conflict", await stale.ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, first, "rotated head body", crdtSeq: 3)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, second, "rotated head body", crdtSeq: 3)).StatusCode);

        // Two rotations race for generation 2: exactly one commits, the other is the 409 loser.
        var responses = await Task.WhenAll(
            RotateAsync(owner.S, file.Id, RotateBody(first, 2, members, "rotated head body", "rotation-plan.md")),
            RotateAsync(owner.S, file.Id, RotateBody(second, 2, members, "rotated head body", "rotation-plan.md")));
        Assert.Equal([HttpStatusCode.NoContent, HttpStatusCode.Conflict], responses.Select(r => r.StatusCode).Order());
        var loser = responses.Single(r => r.StatusCode == HttpStatusCode.Conflict);
        Assert.Equal("conflict", await loser.ProblemCodeAsync());
        var newKey = responses[0].StatusCode == HttpStatusCode.NoContent ? first : second;
        var lostKey = newKey == first ? second : first;
        Assert.Equal(2, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
        Assert.Equal(0, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_rotation_heads"));
        Assert.Equal(0, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_keys WHERE key_id = @k", ("k", lostKey.KeyId)));
        // A later attempt at the same or the next-but-one generation loses as well.
        Assert.Equal("conflict", await (await RotateAsync(owner.S, file.Id, RotateBody(lostKey, 2, members, null, "x"))).ProblemCodeAsync());
        Assert.Equal("conflict", await (await RotateAsync(owner.S, file.Id, RotateBody(lostKey, 4, members, null, "x"))).ProblemCodeAsync());

        // The wraps of the new key: one per remaining member, none for the removed one.
        var wrapped = await Sql.ListAsync<Guid>(app.ConnectionString, "SELECT member_id FROM file_keys WHERE key_id = @k AND generation = 2", ("k", newKey.KeyId));
        Assert.Equal(new[] { owner.Id, keeper.Id }.Order(), wrapped.Order());

        // After the commit, old-key writes are 412 on every path; the re-sealed update passes with its old client id.
        var inFlight = Guid.CreateVersion7();
        var staleUpdate = await SubmitAsync(keeper.S, oldKey, "in flight after commit", inFlight);
        Assert.Equal(HttpStatusCode.PreconditionFailed, staleUpdate.StatusCode);
        Assert.Equal("key_generation_stale", await staleUpdate.ProblemCodeAsync());
        var relayStale = await Assert.ThrowsAsync<HubException>(() => keeperPeer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(),
            new EncryptedUpdate(0, oldKey.Seal(ObjectKind.Crdt, "relay after commit"), oldKey.KeyId.ToString())));
        Assert.Contains("key_generation_stale", relayStale.Message);
        Assert.Equal("key_generation_stale", await (await SnapshotAsync(keeper.S, oldKey, 3, "stale snapshot")).ProblemCodeAsync());
        // A stage must be sealed with a key the file does not have yet, so the old key cannot be staged either.
        Assert.Equal("validation_failed", await (await StageAsync(owner.S, oldKey, "stale stage", crdtSeq: 3)).ProblemCodeAsync());

        // The re-seal: the remaining member refetches its wrap of generation 2 and opens the new key off-server.
        Assert.Equal(newKey.Bytes, await UnwrapAsync(keeper, file.Id, 2));
        var ack = await SubmitAsync(keeper.S, newKey, "in flight after commit", inFlight);
        Assert.Equal(HttpStatusCode.OK, ack.StatusCode);
        var relayAck = await keeperPeer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(),
            new EncryptedUpdate(0, newKey.Seal(ObjectKind.Crdt, "relay after commit"), newKey.KeyId.ToString()));
        Assert.True(relayAck > 0);

        // The listing shows the new generation's wrap, and the name was sealed again with the new key.
        var listed = await (await keeper.S.GetAsync($"/files/{file.Id}")).JsonAsync();
        Assert.Equal(2, listed.GetProperty("wrappedKey").GetProperty("generation").GetInt32());
        Assert.Equal("rotation-plan.md", keeper.S.NameOf(listed));

        // The head is the staged snapshot, sealed with the new key and covering the whole log, so no old-key update is
        // left behind it; the old head stays in the history, readable with the old key.
        var head = await keeper.S.GetAsync($"/files/{file.Id}/snapshot");
        Assert.Equal(newKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
        Assert.Equal("3", head.Headers.GetValues("Nyxite-Snapshot-Seq").Single());
        Assert.Equal("rotated head body", newKey.Open(ObjectKind.Snapshot, await head.Content.ReadAsByteArrayAsync()));
        var versions = (await (await keeper.S.GetAsync($"/files/{file.Id}/versions")).JsonAsync()).GetProperty("items").EnumerateArray().ToList();
        Assert.Equal([2L, 1L], versions.Select(v => v.GetProperty("seq").GetInt64()));
        Assert.Equal([newKey.KeyId, oldKey.KeyId], versions.Select(v => v.GetProperty("keyId").GetGuid()));
        var oldHead = await (await keeper.S.GetAsync($"/files/{file.Id}/versions/1/blob")).Content.ReadAsByteArrayAsync();
        Assert.Equal("old snapshot body", (oldKey with { Bytes = await UnwrapAsync(keeper, file.Id, 1) }).Open(ObjectKind.Snapshot, oldHead));
        var log = (await (await keeper.S.GetAsync($"/files/{file.Id}/crdt/log?since=0")).JsonAsync()).GetProperty("items").EnumerateArray().ToList();
        Assert.Equal([oldKey.KeyId, oldKey.KeyId, oldKey.KeyId, newKey.KeyId, newKey.KeyId], log.Select(u => u.GetProperty("keyId").GetGuid()));
        await using var rejoin = await RelayPeer.ConnectAsync(app, keeper.Token);
        await rejoin.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        Assert.Equal((3L, 2L), Assert.Single(rejoin.Snapshots));

        // The removed member: nothing to fetch, no wrap of the new key, and its old key opens nothing written since.
        foreach (var path in new[] { "", "/keys", "/snapshot", "/versions", "/crdt/log?since=0" })
            Assert.Equal(HttpStatusCode.NotFound, (await leaver.S.GetAsync($"/files/{file.Id}{path}")).StatusCode);
        Assert.Equal(0, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_keys WHERE member_id = @m AND generation > 1", ("m", leaver.Id)));
        var keeperWrap = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT wrapped_key FROM file_keys WHERE member_id = @m AND key_id = @k",
            ("m", keeper.Id), ("k", newKey.KeyId));
        Assert.ThrowsAny<CryptographicException>(() => ObjectKeyWrap.Open(leaver.Seed, file.Id, newKey.KeyId, keeperWrap!));
        var afterRotation = Base64UrlCodec.Decode(log[^1].GetProperty("updateEnc").GetString()!);
        Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(oldKey.Bytes, afterRotation, NyxcFrame.BuildAad(newKey.KeyId, file.Id, ObjectKind.Crdt)));
        Assert.ThrowsAny<CryptographicException>(() => NyxcFrame.Open(oldKey.Bytes, afterRotation, NyxcFrame.BuildAad(oldKey.KeyId, file.Id, ObjectKind.Crdt)));

        // The winning body sent again under a new Idempotency-Key is a second attempt at generation 2, and loses.
        var winningBody = RotateBody(newKey, 2, members, "rotated head body", "rotation-plan.md");
        Assert.Equal("conflict", await (await RotateAsync(owner.S, file.Id, winningBody)).ProblemCodeAsync());

        // The feed tells the owner's other devices, and the audit records the rotation without any key.
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM change_log WHERE kind = 'keyrotate' AND entity_id = @f AND (ref->>'generation')::int = 2 AND ref->>'keyId' = @k",
            ("f", file.Id), ("k", newKey.KeyId.ToString())));
        var audit = await Sql.ListAsync<string>(app.ConnectionString, "SELECT detail::text FROM audit_log WHERE action = 'key.rotate' AND target_id = @f", ("f", file.Id));
        var detail = JsonDocument.Parse(Assert.Single(audit)).RootElement;
        Assert.Equal(2, detail.GetProperty("generation").GetInt32());
        Assert.Equal(2, detail.GetProperty("members").GetInt32());

        await AssertNothingLeaksAsync(app, logs, oldKey.Bytes, newKey.Bytes, lostKey.Bytes, owner.Seed, keeper.Seed, leaver.Seed,
            "old secret one"u8.ToArray(), "in flight before commit"u8.ToArray(), "in flight after commit"u8.ToArray(), "rotated head body"u8.ToArray(),
            "old snapshot body"u8.ToArray(), "rotation-plan.md"u8.ToArray());
    }

    /// <summary>The same request under the same <c>Idempotency-Key</c> is the replay of a committed rotation: <c>204</c>, nothing changes.</summary>
    [Fact]
    public async Task A_retried_commit_with_its_idempotency_key_is_answered_like_the_first()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "empty.md");
        var key = Key.New(file.Id);
        var body = RotateBody(key, 2, [(owner.Id, XWing.PublicKeyFromSeed(owner.Seed))], null, "empty.md");
        var idempotencyKey = Guid.NewGuid().ToString();
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(owner.S, file.Id, body, idempotencyKey)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(owner.S, file.Id, body, idempotencyKey)).StatusCode);
        Assert.Equal("idempotency_conflict", await (await RotateAsync(owner.S, file.Id, RotateBody(Key.New(file.Id), 2,
            [(owner.Id, XWing.PublicKeyFromSeed(owner.Seed))], null, "empty.md"), idempotencyKey)).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await RotateAsync(owner.S, file.Id, body, null)).ProblemCodeAsync());
        Assert.Equal(2, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'key.rotate'"));
    }

    /// <summary>
    /// What the commit refuses: a reader and anyone without reach, wraps that miss a member or reach a non-member, a
    /// name not sealed with the new key, a missing or unknown staged head, and a head that moved since it was staged,
    /// which is a <c>409 version_conflict</c> that keeps the newer head. A blob file then rotates, and only new-key blobs
    /// pass.
    /// </summary>
    [Fact]
    public async Task The_commit_needs_write_reach_wraps_exactly_the_members_and_never_replaces_a_head_that_moved()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var writer = await MemberAsync(app, "Grace");
        var reader = await MemberAsync(app, "Rita");
        var stranger = await MemberAsync(app, "Eve");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "sketch.ink", contentType: "ink");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "strokes one")).StatusCode);
        await ShareAsync(owner, file, writer, "write");
        await ShareAsync(owner, file, reader, "read");
        var ownerMember = (owner.Id, XWing.PublicKeyFromSeed(owner.Seed));
        var writerMember = (writer.Id, await DirectoryKeyAsync(owner, writer.Id));
        var readerMember = (reader.Id, await DirectoryKeyAsync(owner, reader.Id));
        var strangerMember = (stranger.Id, await DirectoryKeyAsync(owner, stranger.Id));
        var key = Key.New(file.Id);

        // Staging: write reach, a key the file does not have, the fields of a blob file, the current head as base.
        Assert.Equal("acl_denied", await (await StageAsync(reader.S, key, "strokes one", parentSeq: 1)).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await StageAsync(stranger.S, key, "strokes one", parentSeq: 1)).StatusCode);
        Assert.Equal("validation_failed", await (await StageAsync(owner.S, oldKey, "strokes one", parentSeq: 1)).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await StageAsync(owner.S, key, "strokes one", crdtSeq: 0)).ProblemCodeAsync());
        Assert.Equal("version_conflict", await (await StageAsync(owner.S, key, "strokes one", parentSeq: 0)).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, key, "strokes one", parentSeq: 1)).StatusCode);

        async Task<string> Commit(Member caller, object body) => await (await RotateAsync(caller.S, file.Id, body)).ProblemCodeAsync();
        var good = RotateBody(key, 2, [ownerMember, writerMember, readerMember], "strokes one", "sketch.ink");
        Assert.Equal("acl_denied", await Commit(reader, good));
        Assert.Equal("not_found", await Commit(stranger, good));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember], "strokes one", "sketch.ink")));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember, readerMember, strangerMember], "strokes one", "sketch.ink")));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember, readerMember, writerMember], "strokes one", "sketch.ink")));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember, readerMember], "strokes one", "sketch.ink", nameKey: oldKey)));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember, readerMember], null, "sketch.ink")));
        Assert.Equal("validation_failed", await Commit(owner, RotateBody(key, 2, [ownerMember, writerMember, readerMember], "other strokes", "sketch.ink")));
        Assert.Equal("validation_failed", await Commit(owner, new
        {
            newKeyId = key.KeyId, generation = 2,
            wrappedKeys = new[] { key.WrapFor(owner.Id, ownerMember.Item2, 3), key.WrapFor(writer.Id, writerMember.Item2, 2), key.WrapFor(reader.Id, readerMember.Item2, 2) },
            newHeadRef = Hash("strokes one"), nameEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Name, "sketch.ink")),
        }));
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));

        // A write that lands between staging and commit moves the head: the commit refuses instead of replacing it.
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(writer.S, oldKey, 1, "strokes two")).StatusCode);
        Assert.Equal("version_conflict", await Commit(owner, good));
        var head = await owner.S.GetAsync($"/files/{file.Id}/blob");
        Assert.Equal(oldKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
        Assert.Equal("strokes two", oldKey.Open(ObjectKind.Blob, await head.Content.ReadAsByteArrayAsync()));

        // The client stages the new head again and commits.
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, key, "strokes two", parentSeq: 2)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(owner.S, file.Id, RotateBody(key, 2, [ownerMember, writerMember, readerMember], "strokes two", "sketch.ink"))).StatusCode);
        head = await writer.S.GetAsync($"/files/{file.Id}/blob");
        Assert.Equal(key.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
        Assert.Equal("strokes two", key.Open(ObjectKind.Blob, await head.Content.ReadAsByteArrayAsync()));
        var versions = (await (await writer.S.GetAsync($"/files/{file.Id}/versions")).JsonAsync()).GetProperty("items").EnumerateArray().ToList();
        Assert.Equal([key.KeyId, oldKey.KeyId, oldKey.KeyId], versions.Select(v => v.GetProperty("keyId").GetGuid()));

        // From now on a blob sealed with the old key is 412, one sealed with the new key is the next head.
        Assert.Equal("key_generation_stale", await (await BlobAsync(writer.S, oldKey, 3, "strokes three")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(writer.S, key, 3, "strokes three")).StatusCode);
    }

    /// <summary>
    /// A staged head is referenced: the blob collector keeps it while it waits for its commit. One that no commit takes
    /// expires after the orphan age, and its blob is collected with the next sweep.
    /// </summary>
    [Fact]
    public async Task An_abandoned_staged_head_expires_and_its_blob_is_collected()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "draft.md");
        var key = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageAsync(owner.S, key, "abandoned head", crdtSeq: 0)).StatusCode);
        var blobRef = (await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT blob_ref FROM file_rotation_heads WHERE file_id = @f", ("f", file.Id)))!;
        Assert.True(BlobAddress.TryParseHex(blobRef, out var address));

        app.Clock.Advance(TimeSpan.FromHours(25));
        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<BlobCollector>().SweepAsync(CancellationToken.None);
            Assert.True(await scope.ServiceProvider.GetRequiredService<IBlobStore>().ExistsAsync(address, CancellationToken.None));
        }

        await using (var scope = app.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<ExpiredRowCleaner>().RunAsync(CancellationToken.None) >= 1);
            await scope.ServiceProvider.GetRequiredService<BlobCollector>().SweepAsync(CancellationToken.None);
            Assert.False(await scope.ServiceProvider.GetRequiredService<IBlobStore>().ExistsAsync(address, CancellationToken.None));
        }

        Assert.Equal(0, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_rotation_heads"));
    }

    // ---------------------------------------------------------------- session end

    /// <summary>
    /// A logout closes the session's relay connections at once, not at the next periodic re-check (an hour away here),
    /// while everyone else stays in the room.
    /// </summary>
    [Fact]
    public async Task Ending_a_session_closes_its_relay_connections_at_once()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var reader = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        await ShareAsync(owner, file, reader, "read");

        await using var stays = await RelayPeer.ConnectAsync(app, owner.Token);
        await stays.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        await using var leaves = await RelayPeer.ConnectAsync(app, reader.Token);
        await leaves.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        Assert.Equal(HttpStatusCode.NoContent, (await reader.Auth.Client().WithBearer(reader.Token).PostAsync("/api/v1/auth/logout", null)).StatusCode);
        await RelayPeer.UntilAsync(() => leaves.Closed);
        Assert.Contains("unauthenticated", leaves.Errors);
        Assert.False(stays.Closed);
        Assert.Equal(0, await RecheckAsync(app));
    }
}
