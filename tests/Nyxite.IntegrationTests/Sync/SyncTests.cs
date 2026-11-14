using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Structure;
using Nyxite.Application.Sync;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Sync;

/// <summary>
/// Phase 1.2 server (P1.2-SRV-1, P1.2-SRV-2): the per-project manifest, the cursor-based delta with offline structure
/// replay, sync-policy enforcement and the purge of excluded content, and the absence of any server search.
/// </summary>
public sealed class SyncTests(PostgresFixture pg)
{
    /// <summary>Lets a test move the clock by months without its token or session running out.</summary>
    private static readonly Dictionary<string, string?> LongSessions = new()
    {
        ["Auth:AccessTokenLifetime"] = "400.00:00:00",
        ["Auth:SessionAbsoluteLifetime"] = "400.00:00:00",
        ["Auth:RefreshTokenIdleLifetime"] = "400.00:00:00",
    };

    private static async Task<StructureDriver> SignedInAsync(NyxiteApp app)
    {
        var auth = new AuthDriver(app);
        var (account, _, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        return new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken));
    }

    private static Task<HttpResponseMessage> PutBlobAsync(StructureDriver s, StructureDriver.Sealed file, long parentSeq, string plaintext,
        string path = "blob", ObjectKind kind = ObjectKind.Blob, long? snapshotSeq = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/{path}")
        {
            Content = new ByteArrayContent(NyxcFrame.Seal(file.Key, file.KeyId, file.Id, kind, Encoding.UTF8.GetBytes(plaintext)))
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/octet-stream") },
            },
        };
        request.Headers.Add("Nyxite-Content-Hash", Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(plaintext))));
        request.Headers.Add("Nyxite-Key-Id", file.KeyId.ToString());
        if (snapshotSeq is { } seq) request.Headers.Add("Nyxite-Snapshot-Seq", seq.ToString());
        else request.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString());
        return s.Client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> SubmitAsync(StructureDriver s, StructureDriver.Sealed file, params string[] texts) =>
        s.PostAsync($"/files/{file.Id}/crdt/log", new
        {
            updates = texts.Select(t => new
            {
                clientUpdateId = Guid.CreateVersion7(), keyId = file.KeyId,
                updateEnc = Base64UrlCodec.Encode(NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Crdt, Encoding.UTF8.GetBytes(t))),
            }),
        }, null);

    private static async Task<JsonElement> ManifestAsync(StructureDriver s, StructureDriver.Sealed project, string query = "") =>
        await (await s.GetAsync($"/sync/manifest?projectId={project.Id}{query}")).JsonAsync();

    private static Task<HttpResponseMessage> PostChangesAsync(StructureDriver s, StructureDriver.Sealed project, string? since,
        object[]? local = null, int? limit = null, bool? keys = null) =>
        s.Client.PostAsJsonAsync("/api/v1/sync/changes", new { projectId = project.Id, since, limit, keys, localChanges = local });

    private static async Task<JsonElement> ChangesAsync(StructureDriver s, StructureDriver.Sealed project, string? since,
        object[]? local = null, int? limit = null, bool? keys = null)
    {
        var response = await PostChangesAsync(s, project, since, local, limit, keys);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.JsonAsync();
    }

    private static List<JsonElement> ServerChanges(JsonElement changes) => changes.GetProperty("serverChanges").EnumerateArray().ToList();

    private static string Cursor(JsonElement changes) => changes.GetProperty("nextCursor").GetString()!;

    private static (string Kind, Guid Id) KindAndId(JsonElement change)
    {
        var r = change.GetProperty("ref");
        return (change.GetProperty("kind").GetString()!, r.TryGetProperty("id", out var id) ? id.GetGuid() : r.GetProperty("fileId").GetGuid());
    }

    private static async Task<string> CursorAfterManifestAsync(StructureDriver s, StructureDriver.Sealed project) =>
        (await ManifestAsync(s, project)).GetProperty("syncCursor").GetString()!;

    private static async Task<T> RunAsync<T>(NyxiteApp app, Func<IServiceProvider, Task<T>> job)
    {
        await using var scope = app.Services.CreateAsyncScope();
        return await job(scope.ServiceProvider);
    }

    private static List<string> StoredBlobs(NyxiteApp app) =>
        Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories)
            .Where(p => !p.Contains(Path.DirectorySeparatorChar + ".tmp" + Path.DirectorySeparatorChar)).ToList();

    // ---------------------------------------------------------------- manifest

    [Fact]
    public async Task Manifest_lists_every_file_with_its_opaque_content_pointers_and_no_name()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var stranger = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "f");
        var ink = await s.FileAsync(project, "a.ink", folder, contentType: "ink");
        await PutBlobAsync(s, ink, 0, "strokes");
        var note = await s.FileAsync(project, "n.md");
        await SubmitAsync(s, note, "Hello", " world");
        var empty = await s.FileAsync(project, "empty.bin", contentType: "binary");
        var trashed = await s.FileAsync(project, "gone.md");
        await s.DeleteAsync($"/files/{trashed.Id}");
        await s.FileAsync(await s.ProjectAsync("other"), "elsewhere.md");

        var manifest = await ManifestAsync(s, project);
        Assert.Equal(project.Id, manifest.GetProperty("projectId").GetGuid());
        Assert.Equal(JsonValueKind.Null, manifest.GetProperty("nextCursor").ValueKind);
        var items = manifest.GetProperty("items").EnumerateArray().ToDictionary(i => i.GetProperty("fileId").GetGuid());
        Assert.Equal(new[] { ink.Id, note.Id, empty.Id, trashed.Id }.Order(), items.Keys.Order());
        Assert.DoesNotContain("nameEnc", manifest.GetRawText());

        var a = items[ink.Id];
        Assert.Equal(folder.Id, a.GetProperty("folderId").GetGuid());
        Assert.Equal(1, a.GetProperty("currentVersionSeq").GetInt64());
        Assert.Equal(Base64UrlCodec.Encode(Blake3.Hash("strokes"u8.ToArray())), a.GetProperty("contentHash").GetString());
        Assert.True(a.GetProperty("sizeCipher").GetInt64() > 0);
        Assert.Equal(ink.KeyId, a.GetProperty("keyId").GetGuid());
        Assert.Equal(ink.KeyId, a.GetProperty("wrappedKey").GetProperty("keyId").GetGuid());
        Assert.Equal(JsonValueKind.Null, a.GetProperty("crdtHeadSeq").ValueKind);

        var n = items[note.Id];
        Assert.Equal(2, n.GetProperty("crdtHeadSeq").GetInt64());
        Assert.NotEqual(JsonValueKind.Null, n.GetProperty("crdtDocId").ValueKind);
        Assert.Equal(JsonValueKind.Null, n.GetProperty("currentVersionSeq").ValueKind);

        var e = items[empty.Id];
        Assert.Equal(JsonValueKind.Null, e.GetProperty("contentHash").ValueKind);
        Assert.Equal(0, e.GetProperty("sizeCipher").GetInt64());
        Assert.Equal(JsonValueKind.Null, items[ink.Id].GetProperty("deletedAt").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, items[trashed.Id].GetProperty("deletedAt").ValueKind);

        // Pages in id order; a warm key cache leaves the keys out.
        var first = await ManifestAsync(s, project, "&limit=3&keys=false");
        Assert.Equal(3, first.GetProperty("items").GetArrayLength());
        Assert.All(first.GetProperty("items").EnumerateArray(), i => Assert.False(i.TryGetProperty("wrappedKey", out _)));
        var second = await ManifestAsync(s, project, $"&limit=3&cursor={first.GetProperty("nextCursor").GetString()}");
        Assert.Single(second.GetProperty("items").EnumerateArray());
        Assert.Equal(JsonValueKind.Null, second.GetProperty("nextCursor").ValueKind);

        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/sync/manifest?projectId={project.Id}")).StatusCode);
        Assert.Equal("validation_failed", await (await s.GetAsync($"/sync/manifest?projectId={project.Id}&limit=1001")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.CreateClient().GetAsync($"/api/v1/sync/manifest?projectId={project.Id}")).StatusCode);
    }

    // ---------------------------------------------------------------- delta: structure

    [Fact]
    public async Task Delta_returns_structure_changes_after_the_cursor_with_a_key_that_opens_the_name()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var cursor = await CursorAfterManifestAsync(s, project);

        var folder = await s.FolderAsync(project, "Drafts");
        var file = await s.FileAsync(project, "a.md", folder);
        await s.PatchAsync($"/files/{file.Id}", new { nameEnc = StructureDriver.Name(file, "b.md") });
        await s.PatchAsync($"/files/{file.Id}", new { parentFolderId = (Guid?)null });
        await s.PatchAsync($"/folders/{folder.Id}", new { syncPolicy = "excluded" });

        var changes = await ChangesAsync(s, project, cursor);
        var server = ServerChanges(changes);
        Assert.Equal([("structure", folder.Id), ("structure", file.Id), ("structure", file.Id), ("structure", file.Id), ("structure", folder.Id)],
            server.Select(KindAndId));
        Assert.False(changes.GetProperty("hasMore").GetBoolean());
        Assert.Empty(changes.GetProperty("results").EnumerateArray());
        Assert.Equal("Drafts", s.NameOf(server[0].GetProperty("ref")));
        Assert.Equal("a.md", s.NameOf(server[1].GetProperty("ref")));
        Assert.Equal("b.md", s.NameOf(server[3].GetProperty("ref")));
        Assert.Equal(JsonValueKind.Null, server[3].GetProperty("ref").GetProperty("parentFolderId").ValueKind);
        Assert.Equal(folder.Id, server[1].GetProperty("ref").GetProperty("parentFolderId").GetGuid());
        Assert.Equal("markdown", server[1].GetProperty("ref").GetProperty("contentType").GetString());
        Assert.Equal("excluded", server[4].GetProperty("ref").GetProperty("syncPolicy").GetString());
        var seqs = server.Select(c => c.GetProperty("seq").GetInt64()).ToList();
        Assert.Equal(seqs.Order(), seqs);

        // Nothing new: the same position, still a valid cursor.
        var idle = await ChangesAsync(s, project, Cursor(changes));
        Assert.Empty(ServerChanges(idle));

        // Paged: every change exactly once.
        var paged = new List<long>();
        var since = cursor;
        JsonElement page;
        do
        {
            page = await ChangesAsync(s, project, since, limit: 2, keys: false);
            Assert.All(ServerChanges(page), c => Assert.False(c.GetProperty("ref").TryGetProperty("wrappedKey", out _)));
            paged.AddRange(ServerChanges(page).Select(c => c.GetProperty("seq").GetInt64()));
            since = Cursor(page);
        } while (page.GetProperty("hasMore").GetBoolean());
        Assert.Equal(seqs, paged);

        // A cursor is per project, and a project of someone else answers like none.
        var stranger = await SignedInAsync(app);
        Assert.Equal(HttpStatusCode.NotFound, (await PostChangesAsync(stranger, project, cursor)).StatusCode);
        Assert.Equal("validation_failed", await (await PostChangesAsync(s, project, "not-a-cursor")).ProblemCodeAsync());
    }

    // ---------------------------------------------------------------- delta: content

    [Fact]
    public async Task Delta_announces_versions_and_coalesces_consecutive_updates_of_one_file()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var ink = await s.FileAsync(project, "a.ink", contentType: "ink");
        var note = await s.FileAsync(project, "n.md");
        var other = await s.FileAsync(project, "o.md");
        var cursor = await CursorAfterManifestAsync(s, project);

        await PutBlobAsync(s, ink, 0, "v1");
        Assert.Equal(HttpStatusCode.Conflict, (await PutBlobAsync(s, ink, 0, "late")).StatusCode);
        await SubmitAsync(s, note, "a", "b");
        await SubmitAsync(s, note, "c");
        await SubmitAsync(s, other, "x");
        await SubmitAsync(s, note, "d");
        await PutBlobAsync(s, note, 0, "abcd", "snapshot", ObjectKind.Snapshot, snapshotSeq: 4);

        var server = ServerChanges(await ChangesAsync(s, project, cursor));
        Assert.Equal([("blob", ink.Id), ("blob", ink.Id), ("crdt", note.Id), ("crdt", other.Id), ("crdt", note.Id), ("blob", note.Id)],
            server.Select(KindAndId));

        var head = server[0].GetProperty("ref");
        Assert.True(head.GetProperty("isHead").GetBoolean());
        Assert.Equal(1, head.GetProperty("seq").GetInt64());
        Assert.Equal($"/api/v1/files/{ink.Id}/versions/1/blob", head.GetProperty("url").GetString());
        Assert.Equal(HttpStatusCode.OK, (await s.Client.GetAsync(head.GetProperty("url").GetString())).StatusCode);
        Assert.False(server[1].GetProperty("ref").GetProperty("isHead").GetBoolean());

        Assert.Equal((1L, 3L), (server[2].GetProperty("ref").GetProperty("fromSeq").GetInt64(), server[2].GetProperty("ref").GetProperty("toSeq").GetInt64()));
        Assert.Equal((4L, 4L), (server[4].GetProperty("ref").GetProperty("fromSeq").GetInt64(), server[4].GetProperty("ref").GetProperty("toSeq").GetInt64()));
        Assert.True(server[5].GetProperty("ref").GetProperty("isHead").GetBoolean());
        Assert.DoesNotContain("nameEnc", string.Join("", server.Select(c => c.GetRawText())));
    }

    [Fact]
    public async Task Delta_carries_deletes_restores_and_purges_of_every_affected_row()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "f");
        var inner = await s.FolderAsync(project, "inner", folder);
        var file = await s.FileAsync(project, "x.md", inner);
        var alone = await s.FileAsync(project, "y.md");
        var cursor = await CursorAfterManifestAsync(s, project);

        await s.DeleteAsync($"/folders/{folder.Id}");
        var deleted = ServerChanges(await ChangesAsync(s, project, cursor));
        Assert.Equal(new[] { folder.Id, inner.Id, file.Id }.Order(), deleted.Select(c => KindAndId(c).Id).Order());
        Assert.All(deleted, c =>
        {
            Assert.Equal("delete", c.GetProperty("kind").GetString());
            Assert.Equal("deleted", c.GetProperty("ref").GetProperty("reason").GetString());
        });

        cursor = await CursorAfterManifestAsync(s, project);
        await s.PostAsync($"/trash/folders/{folder.Id}/restore", new { }, null);
        var restored = ServerChanges(await ChangesAsync(s, project, cursor));
        Assert.Equal(("structure", folder.Id), KindAndId(restored[0]));
        Assert.Equal(new[] { folder.Id, inner.Id, file.Id }.Order(), restored.Select(c => KindAndId(c).Id).Order());
        Assert.All(restored, c => Assert.Equal("structure", c.GetProperty("kind").GetString()));
        Assert.Equal("inner", s.NameOf(restored.Single(c => KindAndId(c).Id == inner.Id).GetProperty("ref")));

        // A purge at the end of the grace window tells devices to drop their copies.
        await s.DeleteAsync($"/files/{alone.Id}");
        await Sql.ExecAsync(app.ConnectionString, $"UPDATE files SET deleted_at = now() - interval '61 days' WHERE id = '{alone.Id}'");
        cursor = await CursorAfterManifestAsync(s, project);
        Assert.Equal(1, await RunAsync(app, p => p.GetRequiredService<TrashPurger>().RunAsync(CancellationToken.None)));
        var purged = ServerChanges(await ChangesAsync(s, project, cursor)).Single();
        Assert.Equal(("delete", alone.Id), KindAndId(purged));
        Assert.Equal("purged", purged.GetProperty("ref").GetProperty("reason").GetString());

        // A project in Trash has no feed; a purged project leaves no feed rows behind.
        await s.DeleteAsync($"/projects/{project.Id}");
        Assert.Equal(HttpStatusCode.NotFound, (await PostChangesAsync(s, project, cursor)).StatusCode);
        await Sql.ExecAsync(app.ConnectionString, $"UPDATE projects SET deleted_at = now() - interval '61 days' WHERE id = '{project.Id}'");
        Assert.Equal(1, await RunAsync(app, p => p.GetRequiredService<TrashPurger>().RunAsync(CancellationToken.None)));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM change_log WHERE project_id = '{project.Id}'"));
    }

    // ---------------------------------------------------------------- delta: local changes

    private static object Item(Guid clientChangeId, string kind, object reference) => new { clientChangeId, kind, @ref = reference };

    [Fact]
    public async Task Local_changes_replay_an_offline_subtree_in_order_and_a_rejected_item_blocks_nothing()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var otherProject = await s.ProjectAsync("other");
        var foreign = await s.FileAsync(otherProject, "elsewhere.md");
        var cursor = await CursorAfterManifestAsync(s, project);

        // Made while offline: a folder, a file inside it, a rename, then a few mistakes.
        var folder = StructureDriver.NewObject();
        var file = StructureDriver.NewObject();
        var ids = Enumerable.Range(0, 7).Select(_ => Guid.CreateVersion7()).ToArray();
        object[] batch =
        [
            Item(ids[0], "structure", new { entity = "folder", id = folder.Id, op = "create", parentFolderId = (Guid?)null, nameEnc = StructureDriver.Name(folder, "Offline"), ownerWrappedKey = s.Wrap(folder) }),
            Item(ids[1], "structure", new { entity = "file", id = file.Id, op = "create", parentFolderId = folder.Id, contentType = "markdown", crdtDocId = Guid.CreateVersion7(), nameEnc = StructureDriver.Name(file, "a.md"), ownerWrappedKey = s.Wrap(file) }),
            Item(ids[2], "structure", new { entity = "file", id = file.Id, op = "update", nameEnc = StructureDriver.Name(file, "renamed.md") }),
            Item(ids[3], "structure", new { entity = "folder", id = folder.Id, op = "update", parentFolderId = folder.Id }),
            Item(ids[4], "delete", new { entity = "file", id = foreign.Id }),
            Item(ids[5], "structure", new { entity = "project", id = Guid.CreateVersion7(), op = "create", nameEnc = "x" }),
            Item(ids[6], "structure", new { entity = "folder", id = folder.Id, op = "update", metadataEnc = StructureDriver.Metadata(folder, "{\"color\":\"red\"}") }),
        ];

        var changes = await ChangesAsync(s, project, cursor, batch);
        var results = changes.GetProperty("results").EnumerateArray().ToList();
        Assert.Equal(ids, results.Select(r => r.GetProperty("clientChangeId").GetGuid()));
        Assert.Equal(["applied", "applied", "applied", "rejected", "rejected", "rejected", "applied"], results.Select(r => r.GetProperty("status").GetString()));
        Assert.Equal([null, null, null, "validation_failed", "not_found", "validation_failed", null], results.Select(r => r.GetProperty("error").GetString()));
        Assert.Equal("renamed.md", await s.ReadNameAsync("files", file.Id));
        Assert.Equal(folder.Id, (await (await s.GetAsync($"/files/{file.Id}")).JsonAsync()).GetProperty("folderId").GetGuid());
        Assert.Equal(HttpStatusCode.OK, (await s.GetAsync($"/files/{foreign.Id}")).StatusCode);

        // The client's own edits come back in the feed, as full-row upserts.
        Assert.Equal([("structure", folder.Id), ("structure", file.Id), ("structure", file.Id), ("structure", folder.Id)], ServerChanges(changes).Select(KindAndId));

        // A replay after a lost answer returns the stored results and applies nothing twice.
        var rows = await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM change_log");
        var replay = await ChangesAsync(s, project, Cursor(changes), batch);
        Assert.Equal(results.Select(r => r.GetRawText()), replay.GetProperty("results").EnumerateArray().Select(r => r.GetRawText()));
        Assert.Equal(rows, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM change_log"));

        // The same id with a different item is refused and not stored.
        var reused = await ChangesAsync(s, project, Cursor(changes),
            [Item(ids[2], "structure", new { entity = "file", id = file.Id, op = "update", nameEnc = StructureDriver.Name(file, "other.md") })]);
        Assert.Equal("idempotency_conflict", reused.GetProperty("results")[0].GetProperty("error").GetString());
        Assert.Equal("renamed.md", await s.ReadNameAsync("files", file.Id));

        // An object of another project is not reachable through this project's batch, and a delete lands in Trash.
        var delete = await ChangesAsync(s, project, Cursor(changes), [Item(Guid.CreateVersion7(), "delete", new { entity = "folder", id = folder.Id })]);
        Assert.Equal("applied", delete.GetProperty("results")[0].GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{file.Id}")).StatusCode);

        var tooMany = Enumerable.Range(0, 201).Select(_ => Item(Guid.CreateVersion7(), "delete", new { entity = "file", id = file.Id })).ToArray();
        Assert.Equal("validation_failed", await (await PostChangesAsync(s, project, null, tooMany)).ProblemCodeAsync());
    }

    // ---------------------------------------------------------------- cursors

    [Fact]
    public async Task A_cursor_older_than_the_change_log_expires_and_an_idle_one_is_renewed_by_syncing()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: LongSessions);
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        await s.FolderAsync(project, "f");
        var stale = await CursorAfterManifestAsync(s, project);
        var kept = stale;

        app.Clock.Advance(TimeSpan.FromDays(60));
        kept = Cursor(await ChangesAsync(s, project, kept));
        app.Clock.Advance(TimeSpan.FromDays(31));

        // 91 days without a sync: changes after it may be pruned, so the device reconciles by manifest.
        var expired = await PostChangesAsync(s, project, stale);
        Assert.Equal(HttpStatusCode.Gone, expired.StatusCode);
        Assert.Equal("cursor_expired", await expired.ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.OK, (await PostChangesAsync(s, project, kept)).StatusCode);

        // The project create and the folder create, both from day 0.
        Assert.Equal(2, await RunAsync(app, p => p.GetRequiredService<ChangeLogPruner>().RunAsync(CancellationToken.None)));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM change_log"));
        // The manifest is authoritative and does not depend on the pruned rows.
        Assert.Equal(HttpStatusCode.OK, (await s.GetAsync($"/sync/manifest?projectId={project.Id}")).StatusCode);
    }

    [Fact]
    public async Task Concurrent_writes_are_never_skipped_by_a_reader_that_polls_meanwhile()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var cursor = await CursorAfterManifestAsync(s, project);

        var writes = Task.WhenAll(Enumerable.Range(0, 40).Select(i => s.FileAsync(project, $"f{i}.md")));
        var seen = new HashSet<Guid>();
        while (!writes.IsCompleted)
        {
            var page = await ChangesAsync(s, project, cursor);
            foreach (var c in ServerChanges(page)) Assert.True(seen.Add(KindAndId(c).Id));
            cursor = Cursor(page);
        }

        var created = await writes;
        JsonElement last;
        do
        {
            last = await ChangesAsync(s, project, cursor);
            foreach (var c in ServerChanges(last)) Assert.True(seen.Add(KindAndId(c).Id));
            cursor = Cursor(last);
        } while (last.GetProperty("hasMore").GetBoolean());

        Assert.Equal(created.Select(f => f.Id).Order(), seen.Order());
    }

    // ---------------------------------------------------------------- sync policy (P1.2-TC-1)

    /// <summary>P1.2-TC-1: an excluded file never uploads, nothing of it is stored, and its server-default sibling syncs normally.</summary>
    [Fact]
    public async Task Excluded_content_never_uploads_while_its_sibling_syncs()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "private");
        await s.PatchAsync($"/folders/{folder.Id}", new { syncPolicy = "excluded" });

        var excludedInk = StructureDriver.NewObject();
        Assert.Equal(HttpStatusCode.Created, (await s.PostAsync("/files", new
        {
            id = excludedInk.Id, projectId = project.Id, folderId = folder.Id, nameEnc = StructureDriver.Name(excludedInk, "secret.ink"),
            contentType = "ink", syncPolicy = "excluded", ownerWrappedKey = s.Wrap(excludedInk),
        })).StatusCode);
        var excludedNote = StructureDriver.NewObject();
        Assert.Equal(HttpStatusCode.Created, (await s.PostAsync("/files", new
        {
            id = excludedNote.Id, projectId = project.Id, folderId = folder.Id, nameEnc = StructureDriver.Name(excludedNote, "secret.md"),
            contentType = "markdown", crdtDocId = Guid.CreateVersion7(), syncPolicy = "excluded", ownerWrappedKey = s.Wrap(excludedNote),
        })).StatusCode);
        var sibling = await s.FileAsync(project, "public.ink", folder, contentType: "ink");

        Assert.Equal("excluded_content", await (await PutBlobAsync(s, excludedInk, 0, "secret strokes")).ProblemCodeAsync());
        Assert.Equal("excluded_content", await (await SubmitAsync(s, excludedNote, "secret text")).ProblemCodeAsync());
        Assert.Equal("excluded_content", await (await PutBlobAsync(s, excludedNote, 0, "secret text", "snapshot", ObjectKind.Snapshot, snapshotSeq: 0)).ProblemCodeAsync());
        Assert.Empty(StoredBlobs(app));
        Assert.Equal(HttpStatusCode.Created, (await PutBlobAsync(s, sibling, 0, "public strokes")).StatusCode);
        Assert.Single(StoredBlobs(app));

        var items = (await ManifestAsync(s, project)).GetProperty("items").EnumerateArray().ToDictionary(i => i.GetProperty("fileId").GetGuid());
        Assert.Equal("excluded", items[excludedInk.Id].GetProperty("syncPolicy").GetString());
        Assert.Equal(JsonValueKind.Null, items[excludedInk.Id].GetProperty("currentVersionSeq").ValueKind);
        Assert.Equal(0, items[excludedNote.Id].GetProperty("crdtHeadSeq").GetInt64());
        Assert.Equal(1, items[sibling.Id].GetProperty("currentVersionSeq").GetInt64());
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            $"SELECT count(*) FROM file_versions WHERE file_id IN ('{excludedInk.Id}', '{excludedNote.Id}')"));
    }

    /// <summary>06 §6.2: content stored before a switch to excluded is purged after Trash plus grace, and a switch back in time keeps it.</summary>
    [Fact]
    public async Task Content_of_a_file_switched_to_excluded_is_purged_after_the_window_unless_it_was_switched_back()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var ink = await s.FileAsync(project, "a.ink", contentType: "ink");
        await PutBlobAsync(s, ink, 0, "v1");
        await PutBlobAsync(s, ink, 1, "v2");
        var note = await s.FileAsync(project, "n.md");
        await SubmitAsync(s, note, "x", "y");
        await PutBlobAsync(s, note, 0, "xy", "snapshot", ObjectKind.Snapshot, snapshotSeq: 2);
        var undone = await s.FileAsync(project, "b.ink", contentType: "ink");
        await PutBlobAsync(s, undone, 0, "keep me");
        Assert.Equal(4, StoredBlobs(app).Count);

        foreach (var f in new[] { ink, note, undone }) await s.PatchAsync($"/files/{f.Id}", new { syncPolicy = "excluded" });
        await s.PatchAsync($"/files/{undone.Id}", new { syncPolicy = "server-default" });
        Task<int> Purge() => RunAsync(app, p => p.GetRequiredService<TrashPurger>().PurgeExcludedContentAsync(CancellationToken.None));

        // Inside the window nothing goes, so a mistaken switch can be undone.
        await Sql.ExecAsync(app.ConnectionString, "UPDATE files SET excluded_at = now() - interval '59 days' WHERE excluded_at IS NOT NULL");
        Assert.Equal(0, await Purge());
        await Sql.ExecAsync(app.ConnectionString, "UPDATE files SET excluded_at = now() - interval '61 days' WHERE excluded_at IS NOT NULL");
        Assert.Equal(2, await Purge());

        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, $"SELECT count(*) FROM file_versions WHERE file_id IN ('{ink.Id}', '{note.Id}')"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));
        Assert.Single(StoredBlobs(app));
        Assert.Equal(HttpStatusCode.OK, (await s.GetAsync($"/files/{undone.Id}/blob")).StatusCode);
        var file = await (await s.GetAsync($"/files/{ink.Id}")).JsonAsync();
        Assert.Equal("excluded", file.GetProperty("syncPolicy").GetString());
        Assert.Equal(JsonValueKind.Null, file.GetProperty("currentVersionSeq").ValueKind);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'content.excluded_purged' AND target_id = @id", ("id", ink.Id)));

        // Switched back, the device uploads it again as the first version of a new history; numbers are never reused.
        await s.PatchAsync($"/files/{ink.Id}", new { syncPolicy = "server-default" });
        var again = await PutBlobAsync(s, ink, 0, "v2");
        Assert.Equal(HttpStatusCode.Created, again.StatusCode);
        Assert.Equal(3, (await again.JsonAsync()).GetProperty("seq").GetInt64());
        Assert.Equal(0, await Purge());
    }

    // ---------------------------------------------------------------- no server search (P1.2-SRV-2, P1.2-TC-3)

    /// <summary>P1.2-SRV-2: the server has no search endpoint, route or index; manifests and ciphertext are all a client indexes.</summary>
    [Fact]
    public async Task The_server_exposes_no_search()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);

        foreach (var path in new[] { "/search?q=x", "/files/search?q=x", "/sync/search?q=x" })
            Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await s.Client.PostAsJsonAsync("/api/v1/search", new { q = "x" })).StatusCode);

        var routes = app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Select(e => e.RoutePattern.RawText ?? "").ToList();
        Assert.NotEmpty(routes);
        Assert.DoesNotContain(routes, r => r.Contains("search", StringComparison.OrdinalIgnoreCase));

        var paths = Nyxite.Server.Http.OpenApiDocument.Load()["paths"]!.AsObject().Select(p => p.Key).ToList();
        Assert.Contains("/sync/manifest", paths);
        Assert.DoesNotContain(paths, p => p.Contains("search", StringComparison.OrdinalIgnoreCase));

        var tables = await Sql.ListAsync<string>(app.ConnectionString, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
        Assert.DoesNotContain(tables, t => t.Contains("search", StringComparison.OrdinalIgnoreCase) || t.Contains("fts", StringComparison.OrdinalIgnoreCase));
        var tsvectors = await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND data_type = 'tsvector'");
        Assert.Equal(0L, tsvectors);
    }
}
