using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nyxite.BlobStore;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Structure;

/// <summary>Phase 0.2: the encrypted structure tree (server 02, 03 §3.3, 04 "structure"; P0.2-TC-1, P0.2-TC-2).</summary>
public sealed class StructureTests(PostgresFixture pg)
{
    private static async Task<StructureDriver> SignedInAsync(NyxiteApp app)
    {
        var auth = new AuthDriver(app);
        var (account, _, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        return new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken));
    }

    /// <summary>P0.2-TC-1: no name reaches the server in plaintext, and a client that holds the key reads it back.</summary>
    [Fact]
    public async Task Names_are_ciphertext_at_rest_and_open_on_the_client()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);

        var project = await s.ProjectAsync("Taxes");
        var folder = await s.FolderAsync(project, "Receipts");
        var file = await s.FileAsync(project, "Payslip.md", folder);

        Assert.Equal("Taxes", await s.ReadNameAsync("projects", project.Id));
        Assert.Equal("Receipts", await s.ReadNameAsync("folders", folder.Id));
        Assert.Equal("Payslip.md", await s.ReadNameAsync("files", file.Id));

        // Server inspection: every row of every structure table, as Postgres prints it and with the bytes decoded.
        foreach (var table in new[] { "projects", "folders", "files", "file_keys", "structure_keys", "idempotency_keys", "audit_log" })
        {
            var rows = string.Join("\n", await Sql.ListAsync<string>(app.ConnectionString, $"SELECT t::text FROM {table} t"));
            var bytes = await Sql.ListAsync<byte[]>(app.ConnectionString,
                table is "projects" or "folders" or "files" ? $"SELECT name_enc FROM {table}" : "SELECT ''::bytea");
            // Names without hex digits only: Postgres prints bytea as hex, where "2025" turns up by chance.
            foreach (var name in new[] { "Taxes", "Receipts", "Payslip" })
            {
                Assert.DoesNotContain(name, rows);
                Assert.DoesNotContain(bytes, b => Encoding.Latin1.GetString(b).Contains(name));
            }
        }

        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM information_schema.columns WHERE table_name IN ('projects','folders','files') AND column_name IN ('name','title','metadata')"));
        Assert.Empty(Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Tree_is_listed_flat_in_creation_order_with_cursor_paging()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);

        var projects = new List<Guid>();
        for (var i = 0; i < 5; i++) projects.Add((await s.ProjectAsync($"p{i}")).Id);
        Assert.Equal(projects, await s.IdsAsync("/projects?limit=2"));
        var first = await (await s.GetAsync("/projects?limit=2")).JsonAsync();
        Assert.Equal(2, first.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.String, first.GetProperty("nextCursor").ValueKind);

        var project = await s.ProjectAsync("tree");
        var a = await s.FolderAsync(project, "a");
        var b = await s.FolderAsync(project, "b", a);
        var root = await s.FileAsync(project, "root.md");
        var inA = await s.FileAsync(project, "a.ink", a, "ink");
        var inB = await s.FileAsync(project, "b.md", b);

        Assert.Equal([a.Id, b.Id], await s.IdsAsync($"/projects/{project.Id}/folders"));
        Assert.Equal([root.Id, inA.Id, inB.Id], await s.IdsAsync($"/projects/{project.Id}/files?limit=1"));
        Assert.Equal([inA.Id], await s.IdsAsync($"/folders/{a.Id}/files"));

        var file = await (await s.GetAsync($"/files/{inA.Id}")).JsonAsync();
        Assert.Equal("ink", file.GetProperty("contentType").GetString());
        Assert.Equal(JsonValueKind.Null, file.GetProperty("crdtDocId").ValueKind);
        Assert.Equal(JsonValueKind.Null, file.GetProperty("currentVersionSeq").ValueKind);
        Assert.Equal("server-default", file.GetProperty("syncPolicy").GetString());
        Assert.Equal(a.Id, file.GetProperty("folderId").GetGuid());

        Assert.Equal("validation_failed", await (await s.GetAsync("/projects?cursor=not-a-cursor")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.BadRequest, (await s.GetAsync("/projects?limit=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await s.GetAsync("/projects?limit=201")).StatusCode);
    }

    /// <summary>P0.2-TC-2: deleting hides the row and keeps it, with its keys.</summary>
    [Fact]
    public async Task Deleting_a_file_is_a_soft_delete()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var keep = await s.FileAsync(project, "keep.md");
        var gone = await s.FileAsync(project, "gone.md");

        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/files/{gone.Id}")).StatusCode);

        Assert.Equal([keep.Id], await s.IdsAsync($"/projects/{project.Id}/files"));
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{gone.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{gone.Id}/keys")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await s.DeleteAsync($"/files/{gone.Id}")).StatusCode);
        Assert.Equal(2L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files"));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files WHERE deleted_at IS NOT NULL AND id = @id", ("id", gone.Id)));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM file_keys WHERE file_id = @id AND revoked_at IS NULL", ("id", gone.Id)));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'file.delete' AND target_id = @id", ("id", gone.Id)));
    }

    [Fact]
    public async Task Deleting_a_folder_trashes_its_subtree_as_one_event_and_a_project_everything_in_it()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var a = await s.FolderAsync(project, "a");
        var b = await s.FolderAsync(project, "b", a);
        var c = await s.FolderAsync(project, "c", b);
        var other = await s.FolderAsync(project, "other");
        await s.FileAsync(project, "a.md", a);
        await s.FileAsync(project, "c.md", c);
        var outside = await s.FileAsync(project, "other.md", other);
        var root = await s.FileAsync(project, "root.md");

        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/folders/{a.Id}")).StatusCode);

        Assert.Equal([other.Id], await s.IdsAsync($"/projects/{project.Id}/folders"));
        Assert.Equal([outside.Id, root.Id], await s.IdsAsync($"/projects/{project.Id}/files"));
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/folders/{c.Id}")).StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(DISTINCT deleted_at) FROM folders WHERE deleted_at IS NOT NULL"));
        Assert.Equal("""{"files": 2, "folders": 3}""", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT detail::text FROM audit_log WHERE action = 'folder.delete'"));

        // Nothing can be put into the trashed folder any more.
        var orphan = StructureDriver.NewObject();
        Assert.Equal(HttpStatusCode.NotFound, (await s.PostAsync("/files", s.FileBody(orphan, project, "late.md", b))).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/projects/{project.Id}")).StatusCode);
        Assert.Empty(await s.IdsAsync("/projects"));
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/files/{root.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await s.GetAsync($"/projects/{project.Id}/folders")).StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT (SELECT count(*) FROM files WHERE deleted_at IS NULL) + (SELECT count(*) FROM folders WHERE deleted_at IS NULL)"));
        Assert.Equal(4L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files"));
        Assert.Equal("""{"files": 2, "folders": 1}""", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT detail::text FROM audit_log WHERE action = 'project.delete'"));
    }

    /// <summary>What P0.2-TC-3 needs from the server: a replayed create changes nothing and answers the same.</summary>
    [Fact]
    public async Task Creates_are_idempotent_and_an_id_is_taken_once()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");

        var folder = StructureDriver.NewObject();
        var body = new { id = folder.Id, projectId = project.Id, nameEnc = StructureDriver.Name(folder, "offline"), ownerWrappedKey = s.Wrap(folder) };
        var first = await s.PostAsync("/folders", body, "key-00000001");
        var replay = await s.PostAsync("/folders", body, "key-00000001");
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, replay.StatusCode);
        Assert.Equal(await first.Content.ReadAsStringAsync(), await replay.Content.ReadAsStringAsync());
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM folders"));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM structure_keys WHERE folder_id IS NOT NULL"));

        var changed = await s.PostAsync("/folders", body with { nameEnc = StructureDriver.Name(folder, "other") }, "key-00000001");
        Assert.Equal("idempotency_conflict", await changed.ProblemCodeAsync());

        var sameId = await s.PostAsync("/folders", body, "key-00000002");
        Assert.Equal(HttpStatusCode.Conflict, sameId.StatusCode);
        Assert.Equal("conflict", await sameId.ProblemCodeAsync());

        Assert.Equal("validation_failed", await (await s.PostAsync("/folders", body, idempotencyKey: null)).ProblemCodeAsync());
    }

    [Fact]
    public async Task Another_account_cannot_see_or_touch_the_tree()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var owner = await SignedInAsync(app);
        var stranger = await SignedInAsync(app);
        var project = await owner.ProjectAsync("p");
        var folder = await owner.FolderAsync(project, "f");
        var file = await owner.FileAsync(project, "x.md", folder);

        Assert.Empty(await stranger.IdsAsync("/projects"));
        foreach (var path in new[]
                 {
                     $"/projects/{project.Id}", $"/projects/{project.Id}/folders", $"/projects/{project.Id}/files", $"/projects/{project.Id}/keys",
                     $"/folders/{folder.Id}", $"/folders/{folder.Id}/files", $"/folders/{folder.Id}/keys", $"/files/{file.Id}", $"/files/{file.Id}/keys",
                 })
        {
            var response = await stranger.GetAsync(path);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await response.ProblemCodeAsync());
        }

        foreach (var path in new[] { $"/projects/{project.Id}", $"/folders/{folder.Id}", $"/files/{file.Id}" })
        {
            Assert.Equal(HttpStatusCode.NotFound, (await stranger.PatchAsync(path, new { syncPolicy = "excluded" })).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await stranger.DeleteAsync(path)).StatusCode);
        }

        var planted = StructureDriver.NewObject();
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.PostAsync("/files", stranger.FileBody(planted, project, "planted.md"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.PostAsync("/folders",
            new { id = planted.Id, projectId = project.Id, nameEnc = StructureDriver.Name(planted, "planted"), ownerWrappedKey = stranger.Wrap(planted) })).StatusCode);

        // A folder of someone else's project is not a valid parent in one's own.
        var mine = await stranger.ProjectAsync("mine");
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.PostAsync("/files", stranger.FileBody(planted, mine, "x.md", folder))).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await app.CreateClient().GetAsync("/api/v1/projects")).StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files"));
    }

    [Fact]
    public async Task Rename_move_metadata_and_policy_follow_the_rules()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var other = await s.ProjectAsync("other");
        var a = await s.FolderAsync(project, "a");
        var b = await s.FolderAsync(project, "b", a);
        var foreign = await s.FolderAsync(other, "foreign");
        var file = await s.FileAsync(project, "old.md", a);

        // Rename: the new name must be sealed with the object's own key.
        Assert.Equal(HttpStatusCode.OK, (await s.PatchAsync($"/files/{file.Id}", new { nameEnc = StructureDriver.Name(file, "new.md") })).StatusCode);
        Assert.Equal("new.md", await s.ReadNameAsync("files", file.Id));
        var wrongKey = file with { KeyId = Guid.CreateVersion7() };
        Assert.Equal("validation_failed", await (await s.PatchAsync($"/files/{file.Id}", new { nameEnc = StructureDriver.Name(wrongKey, "x") })).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.OK, (await s.PatchAsync($"/projects/{project.Id}", new { nameEnc = StructureDriver.Name(project, "renamed") })).StatusCode);
        Assert.Equal("renamed", await s.ReadNameAsync("projects", project.Id));

        // Move a file: into a folder, to the root with null, never across projects.
        var moved = await (await s.PatchAsync($"/files/{file.Id}", new { parentFolderId = b.Id })).JsonAsync();
        Assert.Equal(b.Id, moved.GetProperty("folderId").GetGuid());
        moved = await (await s.PatchAsync($"/files/{file.Id}", new { parentFolderId = (Guid?)null })).JsonAsync();
        Assert.Equal(JsonValueKind.Null, moved.GetProperty("folderId").ValueKind);
        moved = await (await s.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" })).JsonAsync();
        Assert.Equal(JsonValueKind.Null, moved.GetProperty("folderId").ValueKind);
        Assert.Equal("excluded", moved.GetProperty("syncPolicy").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await s.PatchAsync($"/files/{file.Id}", new { parentFolderId = foreign.Id })).StatusCode);
        Assert.Equal("bad_sync_policy", await (await s.PatchAsync($"/files/{file.Id}", new { syncPolicy = "pinned-local" })).ProblemCodeAsync());

        // Move a folder: a folder never ends up inside itself.
        Assert.Equal("validation_failed", await (await s.PatchAsync($"/folders/{a.Id}", new { parentFolderId = b.Id })).ProblemCodeAsync());
        Assert.Equal("validation_failed", await (await s.PatchAsync($"/folders/{a.Id}", new { parentFolderId = a.Id })).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await s.PatchAsync($"/folders/{a.Id}", new { parentFolderId = foreign.Id })).StatusCode);
        var folder = await (await s.PatchAsync($"/folders/{b.Id}", new { parentFolderId = (Guid?)null })).JsonAsync();
        Assert.Equal(JsonValueKind.Null, folder.GetProperty("parentFolderId").ValueKind);
        folder = await (await s.PatchAsync($"/folders/{a.Id}", new { parentFolderId = b.Id })).JsonAsync();
        Assert.Equal(b.Id, folder.GetProperty("parentFolderId").GetGuid());

        // A folder's policy is a default that can be set and handed back to its parent.
        Assert.Equal(JsonValueKind.Null, folder.GetProperty("syncPolicy").ValueKind);
        folder = await (await s.PatchAsync($"/folders/{a.Id}", new { syncPolicy = "excluded" })).JsonAsync();
        Assert.Equal("excluded", folder.GetProperty("syncPolicy").GetString());
        Assert.Equal(b.Id, folder.GetProperty("parentFolderId").GetGuid());
        folder = await (await s.PatchAsync($"/folders/{a.Id}", new { syncPolicy = (string?)null })).JsonAsync();
        Assert.Equal(JsonValueKind.Null, folder.GetProperty("syncPolicy").ValueKind);

        // Metadata is set, kept by other patches, and cleared with null.
        var withMeta = await (await s.PatchAsync($"/folders/{a.Id}", new { metadataEnc = StructureDriver.Metadata(a, "{\"color\":\"red\"}") })).JsonAsync();
        Assert.Equal(JsonValueKind.String, withMeta.GetProperty("metadataEnc").ValueKind);
        withMeta = await (await s.PatchAsync($"/folders/{a.Id}", new { nameEnc = StructureDriver.Name(a, "a2") })).JsonAsync();
        Assert.Equal(JsonValueKind.String, withMeta.GetProperty("metadataEnc").ValueKind);
        withMeta = await (await s.PatchAsync($"/folders/{a.Id}", new { metadataEnc = (string?)null })).JsonAsync();
        Assert.Equal(JsonValueKind.Null, withMeta.GetProperty("metadataEnc").ValueKind);
        Assert.DoesNotContain("color", string.Join("", await Sql.ListAsync<string>(app.ConnectionString, "SELECT t::text FROM folders t")));
    }

    [Fact]
    public async Task Malformed_creates_are_rejected()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var o = StructureDriver.NewObject();
        var name = StructureDriver.Name(o, "n");
        var otherKey = StructureDriver.NewObject();

        async Task Rejected(string path, object body, string code = "validation_failed")
        {
            var response = await s.PostAsync(path, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(code, await response.ProblemCodeAsync());
        }

        // The id must be a client-allocated UUIDv7.
        await Rejected("/projects", new { id = Guid.NewGuid(), nameEnc = name, ownerWrappedKey = s.Wrap(o) });
        await Rejected("/projects", new { nameEnc = name, ownerWrappedKey = s.Wrap(o) });
        // The name must be an NYXC frame within the size limit.
        await Rejected("/projects", new { id = o.Id, ownerWrappedKey = s.Wrap(o) });
        await Rejected("/projects", new { id = o.Id, nameEnc = Base64UrlCodec.Encode("Taxes"u8), ownerWrappedKey = s.Wrap(o) });
        await Rejected("/projects", new { id = o.Id, nameEnc = StructureDriver.Name(o, new string('x', 4000)), ownerWrappedKey = s.Wrap(o) });
        // The wrapped key must be there, well-formed, for the caller, and the key the name is sealed with.
        await Rejected("/projects", new { id = o.Id, nameEnc = name });
        await Rejected("/projects", new { id = o.Id, nameEnc = name, ownerWrappedKey = new { keyId = o.KeyId, ciphertext = Base64UrlCodec.Encode(new byte[40]), generation = 1 } });
        await Rejected("/projects", new { id = o.Id, nameEnc = name, ownerWrappedKey = s.Wrap(otherKey) });
        await Rejected("/projects", new { id = o.Id, nameEnc = name, metadataEnc = StructureDriver.Metadata(otherKey, "m"), ownerWrappedKey = s.Wrap(o) });
        await Rejected("/projects", new { id = o.Id, nameEnc = name, syncPolicy = "sometimes", ownerWrappedKey = s.Wrap(o) }, "bad_sync_policy");
        // A file names a known content type, and a CRDT document id exactly when it is text.
        await Rejected("/files", new { id = o.Id, projectId = project.Id, nameEnc = name, contentType = "video", ownerWrappedKey = s.Wrap(o) });
        await Rejected("/files", new { id = o.Id, projectId = project.Id, nameEnc = name, contentType = "markdown", ownerWrappedKey = s.Wrap(o) });
        await Rejected("/files", new { id = o.Id, projectId = project.Id, nameEnc = name, contentType = "ink", crdtDocId = Guid.CreateVersion7(), ownerWrappedKey = s.Wrap(o) });

        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM projects"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files"));
    }

    [Fact]
    public async Task Changes_need_an_active_device_and_an_account_that_is_not_blocked()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);

        // A session that has not enrolled a device can read, and has nothing to seal names with.
        var noDevice = new StructureDriver(auth.Client().WithBearer((await auth.RegisterWithTotpAsync()).Tokens.AccessToken));
        Assert.Empty(await noDevice.IdsAsync("/projects"));
        var o = StructureDriver.NewObject();
        var denied = await noDevice.PostAsync("/projects", new { id = o.Id, nameEnc = StructureDriver.Name(o, "p"), ownerWrappedKey = noDevice.Wrap(o) });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal("device_not_active", await denied.ProblemCodeAsync());

        // A blocked account keeps reading and cannot change anything (12 §12.6).
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = await s.FileAsync(project, "x.md");
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET status = 'blocked' WHERE id = (SELECT owner_id FROM projects)");
        Assert.Equal("p", await s.ReadNameAsync("projects", project.Id));
        foreach (var response in new[]
                 {
                     await s.PostAsync("/files", s.FileBody(StructureDriver.NewObject(), project, "y.md")),
                     await s.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" }),
                     await s.DeleteAsync($"/files/{file.Id}"),
                 })
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("account_blocked", await response.ProblemCodeAsync());
        }
    }

    /// <summary>A store that stops accepting writes after <paramref name="healthyProbes"/> probes.</summary>
    private sealed class FailingBlobStore(int healthyProbes) : IBlobStore
    {
        private int _probes;

        public Task<StagedBlob> StageAsync(Stream source, long maxBytes, CancellationToken ct) => throw new IOException("read-only");
        public Task<BlobRef> CommitAsync(StagedBlob staged, BlobAddress address, CancellationToken ct) => throw new IOException("read-only");
        public Task<Stream> OpenReadAsync(BlobRef reference, CancellationToken ct) => throw new IOException("read-only");
        public Task<bool> ExistsAsync(BlobAddress address, CancellationToken ct) => Task.FromResult(false);
        public IAsyncEnumerable<StoredBlob> ListAsync(CancellationToken ct) => AsyncEnumerable.Empty<StoredBlob>();
        public Task DeleteAsync(BlobAddress address, CancellationToken ct) => throw new IOException("read-only");
        public Task<int> DeleteStaleStagingAsync(TimeSpan olderThan, CancellationToken ct) => Task.FromResult(0);

        public Task ProbeAsync(CancellationToken ct) =>
            Interlocked.Increment(ref _probes) > healthyProbes ? throw new IOException("/var/lib/nyxite/blobs is read-only") : Task.CompletedTask;
    }

    private static NyxiteApp WithStore(string connectionString, IBlobStore store) => new(connectionString, configureServices: services =>
    {
        services.RemoveAll<IBlobStore>();
        services.AddSingleton(store);
    });

    /// <summary>P0.1-SRV-5 and 14 §14.4: no start without a writable blob store, and readiness follows it afterwards without saying why.</summary>
    [Fact]
    public async Task Blob_store_is_checked_at_startup_and_by_readiness()
    {
        var cs = await pg.CreateDatabaseAsync();

        await using (var unusable = WithStore(cs, new FailingBlobStore(healthyProbes: 0)))
        {
            Assert.ThrowsAny<Exception>(() => unusable.CreateClient());
        }

        // Writable at startup, read-only later.
        await using var app = WithStore(cs, new FailingBlobStore(healthyProbes: 2));
        var client = app.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready")).StatusCode);
        var ready = await client.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        Assert.DoesNotContain("nyxite", await ready.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
    }
}
