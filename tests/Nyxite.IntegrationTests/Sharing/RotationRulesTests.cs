using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Content;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Persistence.Entities;
using static Nyxite.IntegrationTests.Sharing.SharingTests;

namespace Nyxite.IntegrationTests.Sharing;

/// <summary>
/// The rotation rules the user decided on 2026-11-15 and the coverage V10 of REVIEW-server-2026-11-15-b.md asked for: any
/// remaining writer rotates (W1), with the members it must wrap to, a pending-rotation mark an owner's revoke sets, one
/// winner among concurrent writers and the rotating account in the audit; members reached through folder and project
/// shares; a restore of a version of an older generation; a blocked account; and the fail-closed targeted relay
/// re-check (V7).
/// </summary>
public sealed class RotationRulesTests(PostgresFixture pg)
{
    private sealed record Key(Guid ObjectId, Guid KeyId, byte[] Bytes)
    {
        public static Key New(Guid fileId) => new(fileId, Guid.CreateVersion7(), RandomNumberGenerator.GetBytes(32));

        public static Key Of(StructureDriver.Sealed obj) => new(obj.Id, obj.KeyId, obj.Key);

        public byte[] Seal(ObjectKind kind, string text) => NyxcFrame.Seal(Bytes, KeyId, ObjectId, kind, Encoding.UTF8.GetBytes(text));

        public string Open(ObjectKind kind, byte[] frame) => Encoding.UTF8.GetString(NyxcFrame.Open(Bytes, frame, NyxcFrame.BuildAad(KeyId, ObjectId, kind)));

        public object WrapFor(Guid memberId, byte[] publicKey, int generation) => new
        {
            keyId = KeyId, memberId, ciphertext = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, ObjectId, KeyId, Bytes)), generation,
            algId = CryptoSuite.HpkeAlgId,
        };
    }

    private static string Hash(string text) => Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(text)));

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

    private static Task<HttpResponseMessage> BlobAsync(StructureDriver s, Key key, long parentSeq, string text) =>
        PutAsync(s, $"/files/{key.ObjectId}/blob", key, ObjectKind.Blob, text, r => r.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString()));

    private static Task<HttpResponseMessage> StageBlobAsync(StructureDriver s, Key key, long parentSeq, string text) =>
        PutAsync(s, $"/files/{key.ObjectId}/keys/rotate/head", key, ObjectKind.Blob, text, r => r.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString()));

    private static object RotateBody(Key key, int generation, IEnumerable<(Guid Id, byte[] PublicKey)> members, string? headText, string name) => new
    {
        newKeyId = key.KeyId, generation, wrappedKeys = members.Select(m => key.WrapFor(m.Id, m.PublicKey, generation)).ToArray(),
        newHeadRef = headText is null ? null : Hash(headText), nameEnc = Base64UrlCodec.Encode(key.Seal(ObjectKind.Name, name)), metadataEnc = (string?)null,
    };

    private static Task<HttpResponseMessage> RotateAsync(StructureDriver s, Guid fileId, object body) => s.PostAsync($"/files/{fileId}/keys/rotate", body);

    private static async Task<Guid> ShareAsync(Member owner, StructureDriver.Sealed target, string targetType, Member grantee, string permission)
    {
        var publicKey = await DirectoryKeyAsync(owner, grantee.Id);
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType, targetId = target.Id, kind = "user_grant", granteeId = grantee.Id, permission,
            wrappedKeys = new[] { Key.Of(target).WrapFor(grantee.Id, publicKey, 1) },
        });
        Assert.True(created.StatusCode == HttpStatusCode.Created, await created.Content.ReadAsStringAsync());
        return (await created.JsonAsync()).GetProperty("id").GetGuid();
    }

    private static async Task<(Guid Id, byte[] PublicKey)> MemberKeyAsync(Member caller, Guid memberId) => (memberId, await DirectoryKeyAsync(caller, memberId));

    private static async Task<bool> PendingAsync(Member member, Guid fileId) =>
        (await (await member.S.GetAsync($"/files/{fileId}")).JsonAsync()).GetProperty("rotationPending").GetBoolean();

    /// <summary>
    /// W1: an owner's revoke marks the file as waiting for its rotation, which every member with write reach sees and a
    /// reader does not. A remaining writer, not the owner, then rotates: it reads the members, stages and commits, the
    /// audit names it, and the mark is gone. A reader can neither list the members nor stage nor commit.
    /// </summary>
    [Fact]
    public async Task Any_remaining_writer_rotates_after_the_owner_revoked_and_the_pending_mark_clears()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var writer = await MemberAsync(app, "Grace");
        var reader = await MemberAsync(app, "Rita");
        var leaver = await MemberAsync(app, "Mallory");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        await ShareAsync(owner, file, "file", writer, "write");
        await ShareAsync(owner, file, "file", reader, "read");
        var leaverShare = await ShareAsync(owner, file, "file", leaver, "write");
        Assert.False(await PendingAsync(owner, file.Id));

        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{leaverShare}")).StatusCode);
        Assert.True(await PendingAsync(owner, file.Id));
        Assert.True(await PendingAsync(writer, file.Id));
        Assert.False(await PendingAsync(reader, file.Id));
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM change_log WHERE entity_id = @f AND kind = 'structure' AND (ref->>'rotationPending')::boolean", ("f", file.Id)));

        // The writer's client learns whom to wrap to: account ids only. The reader cannot rotate and is told nothing.
        var membersResponse = await writer.S.GetAsync($"/files/{file.Id}/keys/rotate/members");
        Assert.Equal(HttpStatusCode.OK, membersResponse.StatusCode);
        var listing = await membersResponse.JsonAsync();
        Assert.True(listing.GetProperty("rotationPending").GetBoolean());
        Assert.Equal(1, listing.GetProperty("generation").GetInt32());
        var memberIds = listing.GetProperty("members").EnumerateArray().Select(m => m.GetGuid()).ToList();
        Assert.Equal(new[] { owner.Id, writer.Id, reader.Id }.Order(), memberIds.Order());
        Assert.Equal(["generation", "members", "rotationPending"], listing.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal("acl_denied", await (await reader.S.GetAsync($"/files/{file.Id}/keys/rotate/members")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await leaver.S.GetAsync($"/files/{file.Id}/keys/rotate/members")).StatusCode);

        var members = new List<(Guid, byte[])>();
        foreach (var id in memberIds) members.Add(await MemberKeyAsync(writer, id));
        var newKey = Key.New(file.Id);
        Assert.Equal("acl_denied", await (await StageBlobAsync(reader.S, newKey, 1, "page one")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(writer.S, newKey, 1, "page one")).StatusCode);
        Assert.Equal("acl_denied", await (await RotateAsync(reader.S, file.Id, RotateBody(newKey, 2, members, "page one", "scan.bin"))).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(writer.S, file.Id, RotateBody(newKey, 2, members, "page one", "scan.bin"))).StatusCode);

        Assert.False(await PendingAsync(owner, file.Id));
        Assert.False(await PendingAsync(writer, file.Id));
        var audit = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT json_build_object('actor', actor_id, 'detail', detail)::text FROM audit_log WHERE action = 'key.rotate' AND target_id = @f", ("f", file.Id));
        var entry = JsonDocument.Parse(Assert.Single(audit)).RootElement;
        Assert.Equal(writer.Id, entry.GetProperty("actor").GetGuid());
        Assert.False(entry.GetProperty("detail").GetProperty("byOwner").GetBoolean());
        // The owner opens the head the writer re-sealed with its own wrap of the new key.
        var head = await owner.S.GetAsync($"/files/{file.Id}/blob");
        Assert.Equal(newKey.KeyId.ToString(), head.Headers.GetValues("Nyxite-Key-Id").Single());
    }

    /// <summary>W1: a grantee that removes its own share gives its access up, so nothing waits for a rotation (DL-3).</summary>
    [Fact]
    public async Task A_grantee_leaving_on_its_own_marks_no_rotation()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var grantee = await MemberAsync(app, "Grace");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");
        var share = await ShareAsync(owner, file, "file", grantee, "write");
        Assert.Equal(HttpStatusCode.NoContent, (await grantee.S.DeleteAsync($"/shares/{share}")).StatusCode);
        Assert.False(await PendingAsync(owner, file.Id));
    }

    /// <summary>
    /// W1: two writers rotate the same file at once, each with its own key. The generation guard lets exactly one commit;
    /// the other gets <c>409 conflict</c>, reads the file again and finds the new generation with its own wrap of it.
    /// </summary>
    [Fact]
    public async Task Of_two_writers_rotating_at_once_exactly_one_commits_and_the_other_rereads()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var writer = await MemberAsync(app, "Grace");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, Key.Of(file), 0, "page one")).StatusCode);
        await ShareAsync(owner, file, "file", writer, "write");
        var members = new[] { await MemberKeyAsync(owner, owner.Id), await MemberKeyAsync(owner, writer.Id) };
        var ownerKey = Key.New(file.Id);
        var writerKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, ownerKey, 1, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(writer.S, writerKey, 1, "page one")).StatusCode);

        var responses = await Task.WhenAll(
            RotateAsync(owner.S, file.Id, RotateBody(ownerKey, 2, members, "page one", "scan.bin")),
            RotateAsync(writer.S, file.Id, RotateBody(writerKey, 2, members, "page one", "scan.bin")));
        Assert.Equal([HttpStatusCode.NoContent, HttpStatusCode.Conflict], responses.Select(r => r.StatusCode).Order());
        Assert.Equal("conflict", await responses.Single(r => r.StatusCode == HttpStatusCode.Conflict).ProblemCodeAsync());
        var winner = responses[0].StatusCode == HttpStatusCode.NoContent ? ownerKey : writerKey;
        var reread = await (await writer.S.GetAsync($"/files/{file.Id}")).JsonAsync();
        Assert.Equal(2, reread.GetProperty("keyGeneration").GetInt32());
        Assert.Equal(winner.KeyId, reread.GetProperty("wrappedKey").GetProperty("keyId").GetGuid());
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'key.rotate'"));
    }

    /// <summary>
    /// V10: most files are shared through a folder or the project. The members a rotation must wrap to include every
    /// grantee of a share on the file's folder, on a folder above it and on the project, and leaving one out is refused.
    /// </summary>
    [Fact]
    public async Task A_rotation_wraps_to_members_who_reach_the_file_through_folder_and_project_shares()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var viaProject = await MemberAsync(app, "Grace");
        var viaParent = await MemberAsync(app, "Hedy");
        var viaFolder = await MemberAsync(app, "Joan");
        var outsider = await MemberAsync(app, "Eve");
        var project = await owner.S.ProjectAsync("p");
        var parent = await owner.S.FolderAsync(project, "parent");
        var folder = await owner.S.FolderAsync(project, "child", parent);
        var sibling = await owner.S.FolderAsync(project, "sibling");
        var file = await owner.S.FileAsync(project, "scan.bin", folder, contentType: "binary");
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, Key.Of(file), 0, "page one")).StatusCode);
        await ShareAsync(owner, project, "project", viaProject, "read");
        await ShareAsync(owner, parent, "folder", viaParent, "write");
        await ShareAsync(owner, folder, "folder", viaFolder, "read");
        await ShareAsync(owner, sibling, "folder", outsider, "write");

        var listed = (await (await viaParent.S.GetAsync($"/files/{file.Id}/keys/rotate/members")).JsonAsync()).GetProperty("members")
            .EnumerateArray().Select(m => m.GetGuid()).Order().ToList();
        Assert.Equal(new[] { owner.Id, viaProject.Id, viaParent.Id, viaFolder.Id }.Order(), listed);

        var all = new[]
        {
            await MemberKeyAsync(viaParent, owner.Id), await MemberKeyAsync(viaParent, viaProject.Id), await MemberKeyAsync(viaParent, viaParent.Id),
            await MemberKeyAsync(viaParent, viaFolder.Id),
        };
        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(viaParent.S, newKey, 1, "page one")).StatusCode);
        Assert.Equal("validation_failed", await (await RotateAsync(viaParent.S, file.Id, RotateBody(newKey, 2, all[..3], "page one", "scan.bin"))).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await RotateAsync(viaParent.S, file.Id,
            RotateBody(newKey, 2, [.. all, await MemberKeyAsync(viaParent, outsider.Id)], "page one", "scan.bin"))).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(viaParent.S, file.Id, RotateBody(newKey, 2, all, "page one", "scan.bin"))).StatusCode);
        var wrapped = await Sql.ListAsync<Guid>(app.ConnectionString, "SELECT member_id FROM file_keys WHERE key_id = @k", ("k", newKey.KeyId));
        Assert.Equal(listed, wrapped.Order().ToList());
    }

    /// <summary>
    /// V10 and 10 §10.5: a version sealed with an older generation can be restored after a rotation, but its bytes must
    /// be sealed again with the current key; the old-key upload is <c>412</c>, the re-sealed one carries the link.
    /// </summary>
    [Fact]
    public async Task Restoring_a_version_of_an_older_generation_needs_the_content_sealed_with_the_current_key()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        var oldKey = Key.Of(file);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 0, "page one")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, oldKey, 1, "page two")).StatusCode);
        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, newKey, 2, "page two")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await RotateAsync(owner.S, file.Id,
            RotateBody(newKey, 2, [await MemberKeyAsync(owner, owner.Id)], "page two", "scan.bin"))).StatusCode);

        // Version 1 is still readable with the wrap of its generation.
        var old = await owner.S.GetAsync($"/files/{file.Id}/versions/1/blob");
        Assert.Equal(oldKey.KeyId.ToString(), old.Headers.GetValues("Nyxite-Key-Id").Single());
        Assert.Equal("page one", oldKey.Open(ObjectKind.Blob, await old.Content.ReadAsByteArrayAsync()));

        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.PostAsync($"/files/{file.Id}/restore", new { seq = 1 })).StatusCode);
        Assert.Equal("key_generation_stale", await (await BlobAsync(owner.S, oldKey, 3, "page one")).ProblemCodeAsync());
        var restored = await BlobAsync(owner.S, newKey, 3, "page one");
        Assert.Equal(HttpStatusCode.Created, restored.StatusCode);
        var version = await restored.JsonAsync();
        Assert.Equal(1, version.GetProperty("restoredFromSeq").GetInt64());
        Assert.Equal(3, version.GetProperty("parentSeq").GetInt64());
        Assert.Equal(newKey.KeyId, version.GetProperty("keyId").GetGuid());
    }

    /// <summary>V10: a blocked account is download-only, so it can neither stage nor commit a rotation.</summary>
    [Fact]
    public async Task A_blocked_account_can_neither_stage_nor_commit_a_rotation()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        Assert.Equal(HttpStatusCode.Created, (await BlobAsync(owner.S, Key.Of(file), 0, "page one")).StatusCode);
        var newKey = Key.New(file.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await StageBlobAsync(owner.S, newKey, 1, "page one")).StatusCode);
        var members = new[] { await MemberKeyAsync(owner, owner.Id) };
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET status = 'blocked' WHERE id = @id", ("id", owner.Id));

        Assert.Equal("account_blocked", await (await StageBlobAsync(owner.S, Key.New(file.Id), 1, "page one")).ProblemCodeAsync());
        Assert.Equal("account_blocked", await (await RotateAsync(owner.S, file.Id, RotateBody(newKey, 2, members, "page one", "scan.bin"))).ProblemCodeAsync());
        Assert.Equal(1, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT key_generation FROM files WHERE id = @f", ("f", file.Id)));
    }

    /// <summary>The ACL with a switch that makes the check of one account throw, as a failing database would.</summary>
    private sealed class FailingFileAccess(Nyxite.Application.Sharing.ShareAccess access, FailSwitch fail) : IFileAccess
    {
        public Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct) =>
            fail.UserId == userId ? throw new TimeoutException("simulated database timeout") : access.FileLevelAsync(userId, file, ct);

        public Task<FileAccessLevel> GuestLevelAsync(Guid shareId, FileEntity file, CancellationToken ct) => access.GuestLevelAsync(shareId, file, ct);
    }

    private sealed class FailSwitch
    {
        public volatile object? Boxed;

        public Guid? UserId => Boxed as Guid?;
    }

    /// <summary>
    /// V7: the targeted re-check after a share change fails closed. When the check of the affected account cannot
    /// complete, its connections are disconnected with <c>access_unverified</c> instead of staying until the periodic pass,
    /// and another member of the room stays. The periodic pass keeps the isolation and drops nobody it cannot judge.
    /// </summary>
    [Fact]
    public async Task A_targeted_relay_recheck_that_cannot_complete_disconnects_the_member()
    {
        var fail = new FailSwitch();
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?> { ["Relay:AccessRecheckInterval"] = "01:00:00" },
            configureServices: services =>
            {
                services.AddSingleton(fail);
                services.AddScoped<IFileAccess, FailingFileAccess>();
            });
        var owner = await MemberAsync(app, "Ada");
        var grantee = await MemberAsync(app, "Grace");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");
        var share = await ShareAsync(owner, file, "file", grantee, "write");
        await using var stays = await RelayPeer.ConnectAsync(app, owner.Token);
        await stays.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        await using var judged = await RelayPeer.ConnectAsync(app, grantee.Token);
        await judged.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        fail.Boxed = grantee.Id;
        // The periodic pass logs the failure and leaves the member for the next pass.
        Assert.Equal(0, await RecheckAsync(app));
        Assert.False(judged.Closed);

        // A share change triggers a targeted pass for the grantee, whose check now fails: it is disconnected.
        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/shares/{share}", new { permission = "read" })).StatusCode);
        await RelayPeer.UntilAsync(() => judged.Closed);
        Assert.Contains("access_unverified", judged.Errors);
        Assert.False(stays.Closed);
    }
}
