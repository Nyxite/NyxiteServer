using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Content;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Server.Realtime;

namespace Nyxite.IntegrationTests.Content;

/// <summary>Phase 1.1 server: ciphertext blobs with LWW, version history, the encrypted update log, snapshots, pruning and the relay.</summary>
public sealed class ContentTests(PostgresFixture pg)
{
    private sealed record Session(StructureDriver S, string Token);

    private static async Task<Session> SignedInAsync(NyxiteApp app)
    {
        var auth = new AuthDriver(app);
        var (account, _, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        return new Session(new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken)), account.Tokens.AccessToken);
    }

    private static byte[] Seal(StructureDriver.Sealed file, string plaintext, ObjectKind kind = ObjectKind.Blob) =>
        NyxcFrame.Seal(file.Key, file.KeyId, file.Id, kind, Encoding.UTF8.GetBytes(plaintext));

    private static string Open(StructureDriver.Sealed file, byte[] frame, ObjectKind kind = ObjectKind.Blob) =>
        Encoding.UTF8.GetString(NyxcFrame.Open(file.Key, frame, NyxcFrame.BuildAad(file.KeyId, file.Id, kind)));

    private static Task<HttpResponseMessage> PutAsync(StructureDriver s, StructureDriver.Sealed file, string path, string plaintext,
        Action<HttpRequestHeaders> headers, byte[]? body = null, Guid? keyId = null, ObjectKind kind = ObjectKind.Blob)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/{path}")
        {
            Content = new ByteArrayContent(body ?? Seal(file, plaintext, kind)) { Headers = { ContentType = new("application/octet-stream") } },
        };
        request.Headers.Add("Nyxite-Content-Hash", Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(plaintext))));
        request.Headers.Add("Nyxite-Key-Id", (keyId ?? file.KeyId).ToString());
        headers(request.Headers);
        return s.Client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> PutBlobAsync(StructureDriver s, StructureDriver.Sealed file, long parentSeq, string plaintext,
        byte[]? body = null, Guid? keyId = null) =>
        PutAsync(s, file, "blob", plaintext, h => h.TryAddWithoutValidation("If-Match", parentSeq.ToString()), body, keyId);

    private static Task<HttpResponseMessage> PutSnapshotAsync(StructureDriver s, StructureDriver.Sealed file, long crdtSeq, string plaintext) =>
        PutAsync(s, file, "snapshot", plaintext, h => h.Add("Nyxite-Snapshot-Seq", crdtSeq.ToString()), kind: ObjectKind.Snapshot);

    private static object Updates(StructureDriver.Sealed file, params (Guid Id, string Text)[] updates) => new
    {
        updates = updates.Select(u => new { clientUpdateId = u.Id, keyId = file.KeyId, updateEnc = Base64UrlCodec.Encode(Seal(file, u.Text, ObjectKind.Crdt)) }),
    };

    /// <summary>P1.1-TC-4: concurrent writes, one wins, the other is kept as a version that is not the head.</summary>
    [Fact]
    public async Task Blob_writes_are_last_write_wins_and_the_loser_is_kept()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, _) = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = await s.FileAsync(project, "drawing.ink", contentType: "ink");

        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{file.Id}/blob")).StatusCode);
        var first = await PutBlobAsync(s, file, 0, "first strokes");
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(1, (await first.JsonAsync()).GetProperty("seq").GetInt64());

        // Two devices both edited version 1. The one that arrives first wins.
        var winner = await PutBlobAsync(s, file, 1, "device A");
        var loser = await PutBlobAsync(s, file, 1, "device B");
        Assert.Equal(HttpStatusCode.Created, winner.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, loser.StatusCode);
        var problem = await loser.JsonAsync();
        Assert.Equal("conflict", problem.GetProperty("code").GetString());
        Assert.Equal(2, problem.GetProperty("winner").GetProperty("seq").GetInt64());
        Assert.True(problem.GetProperty("winner").GetProperty("isHead").GetBoolean());
        Assert.Equal(3, problem.GetProperty("sibling").GetProperty("seq").GetInt64());
        Assert.False(problem.GetProperty("sibling").GetProperty("isHead").GetBoolean());

        var head = await s.GetAsync($"/files/{file.Id}/blob");
        Assert.Equal("device A", Open(file, await head.Content.ReadAsByteArrayAsync()));
        Assert.Equal("single", head.Headers.GetValues("Nyxite-Blob-Layout").Single());
        Assert.Equal("device B", Open(file, await (await s.GetAsync($"/files/{file.Id}/versions/3/blob")).Content.ReadAsByteArrayAsync()));
        Assert.Equal("first strokes", Open(file, await (await s.GetAsync($"/files/{file.Id}/versions/1/blob")).Content.ReadAsByteArrayAsync()));

        var versions = await s.ItemsAsync($"/files/{file.Id}/versions?limit=2");
        Assert.Equal([3L, 2L, 1L], versions.Select(v => v.GetProperty("seq").GetInt64()));
        Assert.Equal([false, true, false], versions.Select(v => v.GetProperty("isHead").GetBoolean()));
        Assert.Equal(2, (await (await s.GetAsync($"/files/{file.Id}")).JsonAsync()).GetProperty("currentVersionSeq").GetInt64());
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{file.Id}/versions/9")).StatusCode);

        // A client that holds the head downloads nothing.
        var conditional = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/files/{file.Id}/blob");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", head.Headers.ETag!.Tag);
        Assert.Equal(HttpStatusCode.NotModified, (await s.Client.SendAsync(conditional)).StatusCode);

        // Server inspection: rows and stored blobs are ciphertext.
        var rows = string.Join("\n", await Sql.ListAsync<string>(app.ConnectionString, "SELECT t::text FROM file_versions t"));
        var stored = Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories).Select(File.ReadAllBytes).ToList();
        Assert.Equal(3, stored.Count);
        foreach (var plain in new[] { "device", "strokes" })
        {
            Assert.DoesNotContain(plain, rows);
            Assert.DoesNotContain(stored, b => Encoding.Latin1.GetString(b).Contains(plain));
        }

        var usage = (await (await s.GetAsync("/me")).JsonAsync()).GetProperty("usageBytes").GetInt64();
        Assert.Equal(stored.Sum(b => (long)b.Length), usage);
    }

    [Fact]
    public async Task A_restore_is_recorded_and_linked_to_the_next_head()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, _) = await SignedInAsync(app);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "scan.bin", contentType: "binary");
        await PutBlobAsync(s, file, 0, "v1");
        await PutBlobAsync(s, file, 1, "v2");

        Assert.Equal(HttpStatusCode.NotFound, (await s.PostAsync($"/files/{file.Id}/restore", new { seq = 7 })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await s.PostAsync($"/files/{file.Id}/restore", new { seq = 1 })).StatusCode);
        var restored = await (await PutBlobAsync(s, file, 2, "v1")).JsonAsync();

        Assert.Equal(1, restored.GetProperty("restoredFromSeq").GetInt64());
        Assert.Equal(3, restored.GetProperty("seq").GetInt64());
        // The same content in the same file and key is stored once.
        Assert.Equal(2, Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories).Count());
        Assert.Equal(JsonValueKind.Null, (await (await PutBlobAsync(s, file, 3, "v4")).JsonAsync()).GetProperty("restoredFromSeq").ValueKind);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'version.restore'"));
    }

    [Fact]
    public async Task Uploads_are_checked_for_shape_key_policy_size_quota_and_reach()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?> { ["Limits:MaxInlineBlobBytes"] = "4096" });
        var (s, _) = await SignedInAsync(app);
        var (stranger, _) = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = await s.FileAsync(project, "a.bin", contentType: "binary");
        var text = await s.FileAsync(project, "a.md");

        async Task Expect(HttpStatusCode status, string code, Task<HttpResponseMessage> call)
        {
            var response = await call;
            Assert.Equal(status, response.StatusCode);
            Assert.Equal(code, await response.ProblemCodeAsync());
        }

        await Expect(HttpStatusCode.BadRequest, "validation_failed", PutBlobAsync(s, file, 0, "x", body: Encoding.UTF8.GetBytes("plaintext that is long enough to look like a frame, but is none")));
        await Expect(HttpStatusCode.BadRequest, "validation_failed", PutBlobAsync(s, text, 0, "x"));
        await Expect(HttpStatusCode.BadRequest, "validation_failed", PutBlobAsync(s, file, 0, "x", keyId: Guid.CreateVersion7()));
        await Expect(HttpStatusCode.BadRequest, "validation_failed", PutAsync(s, file, "blob", "x", h => h.TryAddWithoutValidation("If-Match", "latest")));
        var rotated = file with { KeyId = Guid.CreateVersion7() };
        await Expect(HttpStatusCode.PreconditionFailed, "key_generation_stale", PutBlobAsync(s, file, 0, "x", body: Seal(rotated, "x"), keyId: rotated.KeyId));
        await Expect(HttpStatusCode.RequestEntityTooLarge, "payload_too_large", PutBlobAsync(s, file, 0, new string('x', 5000)));
        await Expect(HttpStatusCode.NotFound, "not_found", PutBlobAsync(stranger, file, 0, "x"));
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/files/{file.Id}/versions")).StatusCode);

        await s.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" });
        await Expect(HttpStatusCode.Conflict, "excluded_content", PutBlobAsync(s, file, 0, "x"));
        await s.PatchAsync($"/files/{file.Id}", new { syncPolicy = "server-default" });

        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET storage_quota_bytes = 200 WHERE id = (SELECT owner_id FROM projects)");
        Assert.Equal(HttpStatusCode.Created, (await PutBlobAsync(s, file, 0, new string('a', 100))).StatusCode);
        await Expect(HttpStatusCode.RequestEntityTooLarge, "payload_too_large", PutBlobAsync(s, file, 1, new string('b', 100)));

        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_versions"));
        // Trash hides content like it hides the file.
        await s.DeleteAsync($"/files/{file.Id}");
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{file.Id}/blob")).StatusCode);
    }

    /// <summary>The REST side of P1.1-TC-1 and what P1.1-TC-6 needs: ordered, opaque, and a resend changes nothing.</summary>
    [Fact]
    public async Task Update_log_orders_encrypted_updates_and_a_resend_gets_its_old_number()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, _) = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = await s.FileAsync(project, "note.md");
        var ids = Enumerable.Range(0, 4).Select(_ => Guid.CreateVersion7()).ToArray();

        var first = await (await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(file, (ids[0], "Hello"), (ids[1], " world")), null)).JsonAsync();
        Assert.Equal([1L, 2L], first.GetProperty("acks").EnumerateArray().Select(a => a.GetProperty("seq").GetInt64()));
        // The answer was lost: the client sends the batch again, with one more update.
        var again = await (await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(file, (ids[0], "Hello"), (ids[1], " world"), (ids[2], "!")), null)).JsonAsync();
        Assert.Equal([1L, 2L, 3L], again.GetProperty("acks").EnumerateArray().Select(a => a.GetProperty("seq").GetInt64()));
        Assert.Equal(3L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));

        var log = await (await s.GetAsync($"/files/{file.Id}/crdt/log?since=1&limit=1")).JsonAsync();
        Assert.True(log.GetProperty("hasMore").GetBoolean());
        var item = log.GetProperty("items")[0];
        Assert.Equal(2, item.GetProperty("seq").GetInt64());
        Assert.Equal(" world", Open(file, Base64UrlCodec.Decode(item.GetProperty("updateEnc").GetString()!), ObjectKind.Crdt));
        var rest = await (await s.GetAsync($"/files/{file.Id}/crdt/log?since=2")).JsonAsync();
        Assert.False(rest.GetProperty("hasMore").GetBoolean());
        Assert.Equal(1, rest.GetProperty("items").GetArrayLength());

        var rows = string.Join("\n", await Sql.ListAsync<string>(app.ConnectionString, "SELECT encode(update_enc, 'escape') FROM crdt_updates"));
        Assert.DoesNotContain("Hello", rows);
        Assert.DoesNotContain("world", rows);

        var binary = await s.FileAsync(project, "b.bin", contentType: "binary");
        Assert.Equal("validation_failed", await (await s.PostAsync($"/files/{binary.Id}/crdt/log", Updates(binary, (ids[3], "x")), null)).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await s.PostAsync($"/files/{file.Id}/crdt/log", new { updates = Array.Empty<object>() }, null)).ProblemCodeAsync());
        var stale = file with { KeyId = Guid.CreateVersion7() };
        Assert.Equal("key_generation_stale", await (await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(stale, (ids[3], "x")), null)).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await s.GetAsync($"/files/{file.Id}/crdt/log?since=-1")).ProblemCodeAsync());
    }

    /// <summary>P1.1-TC-3: a snapshot moves the starting point, pruning keeps the safety tail, a late device catches up.</summary>
    [Fact]
    public async Task Snapshot_becomes_the_head_and_pruning_keeps_the_safety_tail()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?> { ["Relay:SafetyTailUpdates"] = "15" });
        var (s, _) = await SignedInAsync(app);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "note.md");
        for (var i = 1; i <= 30; i++)
            await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(file, (Guid.CreateVersion7(), $"u{i}")), null);

        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{file.Id}/snapshot")).StatusCode);
        Assert.Equal("validation_failed", await (await PutSnapshotAsync(s, file, 31, "too far")).ProblemCodeAsync());
        var snapshot = await PutSnapshotAsync(s, file, 20, "merged document up to 20");
        Assert.Equal(HttpStatusCode.Created, snapshot.StatusCode);
        Assert.Equal(20, (await snapshot.JsonAsync()).GetProperty("crdtSeq").GetInt64());
        Assert.Equal("conflict", await (await PutSnapshotAsync(s, file, 10, "older")).ProblemCodeAsync());

        var read = await s.GetAsync($"/files/{file.Id}/snapshot");
        Assert.Equal("20", read.Headers.GetValues("Nyxite-Snapshot-Seq").Single());
        Assert.Equal("merged document up to 20", Open(file, await read.Content.ReadAsByteArrayAsync(), ObjectKind.Snapshot));

        async Task<int> PruneAsync()
        {
            await using var scope = app.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<CrdtLogPruner>().RunAsync(CancellationToken.None);
        }

        // Young updates stay, although the snapshot covers them.
        Assert.Equal(0, await PruneAsync());
        await Sql.ExecAsync(app.ConnectionString, "UPDATE crdt_updates SET created_at = created_at - interval '8 days'");
        // Old enough now, but the newest 15 stay: 1 to 15 go, 16 to 20 stay inside the tail although covered.
        Assert.Equal(15, await PruneAsync());
        Assert.Equal(16L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT min(seq) FROM crdt_updates"));
        Assert.Equal(0, await PruneAsync());

        // A device that was away loads the snapshot and reads the log from its seq on.
        var tail = await (await s.GetAsync($"/files/{file.Id}/crdt/log?since=20")).JsonAsync();
        Assert.Equal(Enumerable.Range(21, 10).Select(i => (long)i), tail.GetProperty("items").EnumerateArray().Select(u => u.GetProperty("seq").GetInt64()));
        // Sequence numbers go on after a prune.
        var next = await (await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(file, (Guid.CreateVersion7(), "u31")), null)).JsonAsync();
        Assert.Equal(31, next.GetProperty("acks")[0].GetProperty("seq").GetInt64());
    }

    /// <summary>P1.1-TC-1, server side: what one device submits reaches the other through the relay, in order and unread.</summary>
    [Fact]
    public async Task Relay_forwards_encrypted_updates_between_devices()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, token) = await SignedInAsync(app);
        var (_, strangerToken) = await SignedInAsync(app);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "note.md");
        var fileId = file.Id.ToString();
        EncryptedUpdate Update(string text) => new(0, Seal(file, text, ObjectKind.Crdt), file.KeyId.ToString());

        await using var d1 = await RelayPeer.ConnectAsync(app, token);
        await using var d2 = await RelayPeer.ConnectAsync(app, token);
        await d1.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await d2.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await RelayPeer.UntilAsync(() => d1.Presence.Count >= 2);
        Assert.Single(d1.Presence[^1]);

        // D1 types. The returned number is the acknowledgement that the update is stored.
        Assert.Equal(1, await d1.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("Hello")));
        Assert.Equal(2, await d1.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update(" world")));
        await RelayPeer.UntilAsync(() => d2.Updates.Count == 2 && d1.Updates.Count == 2);
        Assert.Equal([1L, 2L], d2.Updates.Select(u => u.Seq));
        Assert.Equal("Hello world", string.Concat(d2.Updates.Select(u => Open(file, u.Ciphertext, ObjectKind.Crdt))));
        Assert.Equal(file.KeyId.ToString(), d2.Updates[0].KeyId);

        // An update that arrives over REST reaches the room too.
        await s.PostAsync($"/files/{file.Id}/crdt/log", Updates(file, (Guid.CreateVersion7(), "!")), null);
        await RelayPeer.UntilAsync(() => d2.Updates.Count == 3);

        // Awareness goes to the others only and is not stored.
        await d1.Connection.InvokeAsync("SubmitAwareness", fileId, new byte[] { 1, 2, 3 });
        await RelayPeer.UntilAsync(() => d2.Awareness.Count == 1);
        Assert.Empty(d1.Awareness);

        // A device that joins later starts from the snapshot and its cursor.
        await PutSnapshotAsync(s, file, 2, "Hello world");
        await using var late = await RelayPeer.ConnectAsync(app, token);
        await late.Connection.InvokeAsync("JoinDocument", fileId, 2L);
        await RelayPeer.UntilAsync(() => late.Updates.Count == 1 && late.Snapshots.Count == 1);
        Assert.Equal(3, late.Updates[0].Seq);
        Assert.Equal((2L, 1L), late.Snapshots[0]);

        // Leaving ends delivery.
        await d2.Connection.InvokeAsync("LeaveDocument", fileId);
        await d1.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("?"));
        await RelayPeer.UntilAsync(() => late.Updates.Count == 2);
        Assert.Equal(3, d2.Updates.Count);

        // Someone without reach gets nothing, and a room cannot be written to without joining rights either.
        await using var stranger = await RelayPeer.ConnectAsync(app, strangerToken);
        var denied = await Assert.ThrowsAsync<HubException>(() => stranger.Connection.InvokeAsync("JoinDocument", fileId, 0L));
        Assert.Contains("not_found", denied.Message);
        await Assert.ThrowsAsync<HubException>(() => stranger.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("x")));
        await Assert.ThrowsAsync<HubException>(() => stranger.Connection.InvokeAsync("SubmitAwareness", fileId, new byte[] { 9 }));
        await RelayPeer.UntilAsync(() => stranger.Errors.Count == 3);
        Assert.Empty(stranger.Updates);
        await Assert.ThrowsAnyAsync<Exception>(() => RelayPeer.ConnectAsync(app, null));

        Assert.Equal(4L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));
        Assert.DoesNotContain("Hello", string.Join("", await Sql.ListAsync<string>(app.ConnectionString, "SELECT encode(update_enc, 'escape') FROM crdt_updates")));
    }

    /// <summary>08 §8.4: a browser opens the WebSocket with a single-use ticket instead of putting its access token in the URL.</summary>
    [Fact]
    public async Task A_socket_ticket_opens_one_relay_connection_over_websockets()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var (account, _, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        var s = new StructureDriver(client);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "note.md");

        async Task<string> TicketAsync()
        {
            var response = await client.PostAsync("/api/v1/auth/socket-ticket", null);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.JsonAsync();
            Assert.True(body.GetProperty("expiresAt").GetDateTimeOffset() <= DateTimeOffset.UtcNow.AddSeconds(61));
            return body.GetProperty("ticket").GetString()!;
        }

        // Negotiate and upgrade both carry the ticket, and the upgrade uses it up.
        var ticket = await TicketAsync();
        Assert.DoesNotContain('.', ticket);
        await using (var peer = await RelayPeer.ConnectAsync(app, ticket, webSockets: true))
        {
            await peer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
            Assert.Equal(1, await peer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(),
                new EncryptedUpdate(0, Seal(file, "via ticket", ObjectKind.Crdt), file.KeyId.ToString())));
        }

        await Assert.ThrowsAnyAsync<Exception>(() => RelayPeer.ConnectAsync(app, ticket, webSockets: true));
        await Assert.ThrowsAnyAsync<Exception>(() => RelayPeer.ConnectAsync(app, "not-a-ticket", webSockets: true));

        // The bearer still works on WebSockets, and a ticket dies with its session.
        await (await RelayPeer.ConnectAsync(app, account.Tokens.AccessToken, webSockets: true)).DisposeAsync();
        var orphan = await TicketAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/logout", null)).StatusCode);
        await Assert.ThrowsAnyAsync<Exception>(() => RelayPeer.ConnectAsync(app, orphan, webSockets: true));
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsync("/api/v1/auth/socket-ticket", null)).StatusCode);
    }

    private static List<string> StoredBlobs(NyxiteApp app) =>
        Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories)
            .Where(p => !p.Contains(Path.DirectorySeparatorChar + ".tmp" + Path.DirectorySeparatorChar)).Select(Path.GetFileName).Order().ToList()!;

    private static async Task<int> PurgeAsync(NyxiteApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<Nyxite.Application.Structure.TrashPurger>().RunAsync(CancellationToken.None);
    }

    /// <summary>03 §3.3 DL-2/DL-5: at Trash plus grace a delete is purged with its history, keys and ciphertext, and not earlier.</summary>
    [Fact]
    public async Task Purge_removes_a_deleted_tree_with_its_history_and_ciphertext_after_the_grace_window()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, _) = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "f");
        var inner = await s.FolderAsync(project, "inner", folder);
        var binary = await s.FileAsync(project, "a.bin", inner, contentType: "binary");
        await PutBlobAsync(s, binary, 0, "first");
        await PutBlobAsync(s, binary, 1, "second");
        var note = await s.FileAsync(project, "n.md", folder);
        await s.PostAsync($"/files/{note.Id}/crdt/log", Updates(note, (Guid.CreateVersion7(), "x")), null);
        await PutSnapshotAsync(s, note, 1, "x");
        var alone = await s.FileAsync(project, "b.bin", contentType: "binary");
        await PutBlobAsync(s, alone, 0, "alone");
        var live = await s.FileAsync(project, "c.bin", contentType: "binary");
        await PutBlobAsync(s, live, 0, "live");
        Assert.Equal(5, StoredBlobs(app).Count);

        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/folders/{folder.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/files/{alone.Id}")).StatusCode);
        Assert.Equal(0, await PurgeAsync(app));

        // Past Trash but inside grace: kept for an admin. Past both: purged.
        await Sql.ExecAsync(app.ConnectionString, $"UPDATE files SET deleted_at = now() - interval '45 days' WHERE id = '{alone.Id}'");
        await Sql.ExecAsync(app.ConnectionString, "UPDATE folders SET deleted_at = now() - interval '61 days' WHERE deleted_at IS NOT NULL");
        await Sql.ExecAsync(app.ConnectionString, $"UPDATE files SET deleted_at = now() - interval '61 days' WHERE deleted_root_id = '{folder.Id}'");
        Assert.Equal(1, await PurgeAsync(app));

        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM folders WHERE id IN ('{folder.Id}', '{inner.Id}')"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM files WHERE id IN ('{binary.Id}', '{note.Id}')"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM file_versions WHERE file_id IN ('{binary.Id}', '{note.Id}')"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM file_keys WHERE file_id IN ('{binary.Id}', '{note.Id}')"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM structure_keys WHERE folder_id IN ('{folder.Id}', '{inner.Id}')"));
        Assert.Equal(2, StoredBlobs(app).Count);
        Assert.Equal(HttpStatusCode.NotFound, (await s.PostAsync($"/trash/folders/{folder.Id}/restore", new { }, null)).StatusCode);
        var audit = await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT detail::text FROM audit_log WHERE action = 'trash.purged'");
        Assert.Contains("\"files\": 2", audit);
        Assert.Contains("\"folders\": 2", audit);
        Assert.Contains("\"versions\": 3", audit);

        await Sql.ExecAsync(app.ConnectionString, $"UPDATE files SET deleted_at = now() - interval '61 days' WHERE id = '{alone.Id}'");
        Assert.Equal(1, await PurgeAsync(app));
        Assert.Single(StoredBlobs(app));
        Assert.Equal(HttpStatusCode.OK, (await s.GetAsync($"/files/{live.Id}/blob")).StatusCode);

        // A whole project goes with its keys.
        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/projects/{project.Id}")).StatusCode);
        await Sql.ExecAsync(app.ConnectionString, "UPDATE projects SET deleted_at = now() - interval '61 days'");
        Assert.Equal(1, await PurgeAsync(app));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM projects"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM structure_keys"));
        Assert.Empty(StoredBlobs(app));
        Assert.Equal(0L, (await (await s.GetAsync("/me")).JsonAsync()).GetProperty("usageBytes").GetInt64());
    }

    /// <summary>10 §10.6: the sweep deletes old unreferenced blobs only, and never one a writer holds the address lock on.</summary>
    [Fact]
    public async Task Blob_sweep_removes_old_orphans_and_respects_the_address_lock()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, _) = await SignedInAsync(app);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "a.bin", contentType: "binary");
        await PutBlobAsync(s, file, 0, "kept");
        var store = app.Services.GetRequiredService<Nyxite.BlobStore.IBlobStore>();
        var frame = Seal(file, "orphan");
        Nyxite.BlobStore.BlobAddress Orphan(string name) => Nyxite.BlobStore.BlobAddress.From(Blake3.Hash(Encoding.UTF8.GetBytes(name)));
        await store.PutAsync(frame, Orphan("old"), CancellationToken.None);
        await store.PutAsync(frame, Orphan("locked"), CancellationToken.None);
        await store.PutAsync(frame, Orphan("young"), CancellationToken.None);
        foreach (var path in Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories))
            if (Path.GetFileName(path) != Orphan("young").Hex) File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-2));

        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<Nyxite.Persistence.NyxiteDbContext>();
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            await Nyxite.Application.Content.BlobCollector.LockAddressAsync(db, Orphan("locked"), CancellationToken.None);
            await using var sweep = app.Services.CreateAsyncScope();
            Assert.Equal(1, await sweep.ServiceProvider.GetRequiredService<Nyxite.Application.Content.BlobCollector>().SweepAsync(CancellationToken.None));
        }

        var left = StoredBlobs(app);
        Assert.Equal(3, left.Count);
        Assert.DoesNotContain(Orphan("old").Hex, left);
        Assert.Contains(Orphan("locked").Hex, left);
        Assert.Contains(Orphan("young").Hex, left);
        Assert.Equal(HttpStatusCode.OK, (await s.GetAsync($"/files/{file.Id}/blob")).StatusCode);
    }

    /// <summary>An upload over the limit is cut off while streaming and leaves no staging file behind.</summary>
    [Fact]
    public async Task An_oversized_upload_is_cut_off_without_a_length_header()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?> { ["Limits:MaxInlineBlobBytes"] = "1000" });
        var (s, _) = await SignedInAsync(app);
        var file = await s.FileAsync(await s.ProjectAsync("p"), "a.bin", contentType: "binary");
        var frame = Seal(file, new string('x', 2000));
        var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/blob")
        {
            Content = new StreamContent(new MemoryStream(frame)) { Headers = { ContentType = new("application/octet-stream") } },
        };
        request.Headers.TransferEncodingChunked = true;
        request.Headers.Add("Nyxite-Content-Hash", Base64UrlCodec.Encode(Blake3.Hash("big"u8)));
        request.Headers.Add("Nyxite-Key-Id", file.KeyId.ToString());
        request.Headers.TryAddWithoutValidation("If-Match", "0");

        var response = await s.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal("payload_too_large", await response.ProblemCodeAsync());
        Assert.Empty(Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories));
    }

    /// <summary>
    /// P1.1-CORE-1 through the server: the shared text-path vector frames go into the log and the snapshot and come
    /// back out of REST and the relay byte for byte, which is what lets every client merge them to the same text.
    /// </summary>
    [Fact]
    public async Task Text_path_vector_frames_pass_the_log_snapshot_and_relay_unchanged()
    {
        var v = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Resources", "vectors", "text-path.json"))).RootElement;
        byte[] B(JsonElement e, string name) => Convert.FromHexString(e.GetProperty(name).GetString()!);
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var (s, token) = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = new StructureDriver.Sealed(v.GetProperty("fileId").GetGuid(), v.GetProperty("keyId").GetGuid(), B(v, "key"));
        Assert.Equal(HttpStatusCode.Created, (await s.PostAsync("/files", s.FileBody(file, project, "vector.md"))).StatusCode);
        var updates = v.GetProperty("updates").EnumerateArray().ToList();

        var body = new
        {
            updates = updates.Select(u => new
            {
                clientUpdateId = u.GetProperty("clientUpdateId").GetGuid(), keyId = file.KeyId, updateEnc = Base64UrlCodec.Encode(B(u, "frame")),
            }),
        };
        var acks = (await (await s.PostAsync($"/files/{file.Id}/crdt/log", body, null)).JsonAsync()).GetProperty("acks");
        Assert.Equal(updates.Select(u => u.GetProperty("seq").GetInt64()), acks.EnumerateArray().Select(a => a.GetProperty("seq").GetInt64()));

        var snapshot = v.GetProperty("snapshot");
        var put = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/snapshot")
        {
            Content = new ByteArrayContent(B(snapshot, "frame")) { Headers = { ContentType = new("application/octet-stream") } },
        };
        put.Headers.Add("Nyxite-Content-Hash", Base64UrlCodec.Encode(B(snapshot, "contentHash")));
        put.Headers.Add("Nyxite-Key-Id", file.KeyId.ToString());
        put.Headers.Add("Nyxite-Snapshot-Seq", snapshot.GetProperty("crdtSeq").GetInt64().ToString());
        Assert.Equal(HttpStatusCode.Created, (await s.Client.SendAsync(put)).StatusCode);

        Assert.Equal(B(snapshot, "frame"), await (await s.GetAsync($"/files/{file.Id}/snapshot")).Content.ReadAsByteArrayAsync());
        var log = (await (await s.GetAsync($"/files/{file.Id}/crdt/log?since=0")).JsonAsync()).GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(updates.Select(u => B(u, "frame")), log.Select(i => Base64UrlCodec.Decode(i.GetProperty("updateEnc").GetString()!)));

        // A device joining from the snapshot gets the pointer and exactly the tail after it.
        await using var peer = await RelayPeer.ConnectAsync(app, token);
        await peer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), snapshot.GetProperty("crdtSeq").GetInt64());
        await RelayPeer.UntilAsync(() => peer.Updates.Count == 2 && peer.Snapshots.Count == 1);
        Assert.Equal(updates.Skip(2).Select(u => B(u, "frame")), peer.Updates.Select(u => u.Ciphertext));
        Assert.Equal(2L, peer.Snapshots[0].CrdtSeq);
    }
}
