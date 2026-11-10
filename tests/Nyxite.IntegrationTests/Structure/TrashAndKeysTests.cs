using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Structure;

/// <summary>Trash and restore (03 §3.3, DL-1 to DL-4) and the ways a client gets many wrapped keys at once (04 "structure").</summary>
public sealed class TrashAndKeysTests(PostgresFixture pg)
{
    private static async Task<StructureDriver> SignedInAsync(NyxiteApp app)
    {
        var auth = new AuthDriver(app);
        var (account, _, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        return new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken));
    }

    private static Guid IdOf(JsonElement trashItem) => trashItem.GetProperty(trashItem.GetProperty("entity").GetString()!).GetProperty("id").GetGuid();

    [Fact]
    public async Task Listed_objects_carry_their_key_unless_the_client_asks_for_none()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("Taxes");
        var folder = await s.FolderAsync(project, "2025");
        await s.FileAsync(project, "W2.md", folder);
        await s.FileAsync(project, "notes.md");

        // A fresh device: one request per list, and every name opens with the key that came along.
        Assert.Equal(["Taxes"], (await s.ItemsAsync("/projects")).Select(s.NameOf));
        Assert.Equal(["2025"], (await s.ItemsAsync($"/projects/{project.Id}/folders")).Select(s.NameOf));
        Assert.Equal(["W2.md", "notes.md"], (await s.ItemsAsync($"/projects/{project.Id}/files")).Select(s.NameOf));
        Assert.Equal("2025", s.NameOf(await (await s.GetAsync($"/folders/{folder.Id}")).JsonAsync()));

        // A device with a warm cache: no key in any object.
        foreach (var path in new[] { "/projects?keys=false", $"/projects/{project.Id}/folders?keys=false", $"/projects/{project.Id}/files?keys=false", $"/folders/{folder.Id}/files?keys=false" })
            Assert.All(await s.ItemsAsync(path), i => Assert.Equal(JsonValueKind.Null, i.GetProperty("wrappedKey").ValueKind));
        Assert.Equal(JsonValueKind.Null, (await (await s.GetAsync($"/projects/{project.Id}?keys=false")).JsonAsync()).GetProperty("wrappedKey").ValueKind);

        // The key belongs to the caller: it is the owner's wrap, and it changes nothing about what is stored.
        var created = await (await s.GetAsync($"/projects/{project.Id}")).JsonAsync();
        Assert.Equal(1, created.GetProperty("wrappedKey").GetProperty("generation").GetInt32());
        Assert.Equal("X25519MLKEM768", created.GetProperty("wrappedKey").GetProperty("algId").GetString());
    }

    [Fact]
    public async Task Key_lookup_returns_the_keys_of_reachable_objects_only()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var stranger = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "f");
        var file = await s.FileAsync(project, "x.md", folder);
        var trashed = await s.FileAsync(project, "gone.md");
        await s.DeleteAsync($"/files/{trashed.Id}");
        var theirs = await stranger.FileAsync(await stranger.ProjectAsync("theirs"), "secret.md");

        var body = new { projectIds = new[] { project.Id }, folderIds = new[] { folder.Id }, fileIds = new[] { file.Id, trashed.Id, theirs.Id, Guid.CreateVersion7(), file.Id } };
        var result = await (await s.Client.PostAsJsonAsync("/api/v1/keys/lookup", body)).JsonAsync();

        var items = result.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal([("project", project.Id), ("folder", folder.Id), ("file", file.Id), ("file", trashed.Id)],
            items.Select(i => (i.GetProperty("entity").GetString()!, i.GetProperty("id").GetGuid())));
        Assert.All(items, i => Assert.Equal(1, i.GetProperty("wrappedKeys").GetArrayLength()));

        // The looked-up key is the one that opens the name of an object listed without keys.
        var listed = (await s.ItemsAsync($"/folders/{folder.Id}/files?keys=false")).Single();
        var wrapped = items.Single(i => i.GetProperty("id").GetGuid() == file.Id).GetProperty("wrappedKeys")[0];
        var withKey = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(listed.GetRawText())!;
        withKey["wrappedKey"] = wrapped;
        Assert.Equal("x.md", s.NameOf(JsonSerializer.SerializeToElement(withKey)));

        Assert.Empty((await (await stranger.Client.PostAsJsonAsync("/api/v1/keys/lookup", body with { fileIds = [file.Id] })).JsonAsync())
            .GetProperty("items").EnumerateArray());
        Assert.Empty((await (await s.Client.PostAsJsonAsync("/api/v1/keys/lookup", new { })).JsonAsync()).GetProperty("items").EnumerateArray());
        var tooMany = await s.Client.PostAsJsonAsync("/api/v1/keys/lookup", new { fileIds = Enumerable.Range(0, 501).Select(_ => Guid.CreateVersion7()) });
        Assert.Equal("validation_failed", await tooMany.ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.CreateClient().PostAsJsonAsync("/api/v1/keys/lookup", body)).StatusCode);
    }

    [Fact]
    public async Task Trash_lists_what_was_deleted_directly_and_restore_brings_back_the_same_set()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero));
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), clock);
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var a = await s.FolderAsync(project, "a");
        var b = await s.FolderAsync(project, "b", a);
        var early = await s.FileAsync(project, "early.md", b);
        var inA = await s.FileAsync(project, "a.md", a);
        var inB = await s.FileAsync(project, "b.md", b);
        var loose = await s.FileAsync(project, "loose.md");

        // The clock does not move between the two deletes: what belongs to which delete must not depend on time.
        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/files/{early.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/folders/{a.Id}")).StatusCode);
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(HttpStatusCode.NoContent, (await s.DeleteAsync($"/files/{loose.Id}")).StatusCode);

        var trash = await s.ItemsAsync("/trash");
        // Newest first; the two entries of the same instant in a stable order.
        Assert.Equal([loose.Id, early.Id, a.Id], trash.Select(IdOf));
        var folderEntry = trash.Single(t => IdOf(t) == a.Id);
        Assert.Equal("folder", folderEntry.GetProperty("entity").GetString());
        Assert.Equal(1, folderEntry.GetProperty("folders").GetInt32());
        Assert.Equal(2, folderEntry.GetProperty("files").GetInt32());
        Assert.Equal("a", s.NameOf(folderEntry.GetProperty("folder")));
        Assert.Equal(JsonValueKind.Null, folderEntry.GetProperty("file").ValueKind);
        Assert.Equal(clock.Now.AddMinutes(-1).AddDays(30), folderEntry.GetProperty("restorableUntil").GetDateTimeOffset());
        Assert.Equal("loose.md", s.NameOf(trash[0].GetProperty("file")));
        Assert.Equal(3, (await s.ItemsAsync("/trash?limit=1")).Count);
        Assert.All(await s.ItemsAsync("/trash?keys=false"), t => Assert.Equal(JsonValueKind.Null, t.GetProperty(t.GetProperty("entity").GetString()!).GetProperty("wrappedKey").ValueKind));

        // A file deleted on its own does not come back into a folder that is still in Trash.
        var refused = await s.PostAsync($"/trash/files/{early.Id}/restore", new { }, idempotencyKey: null);
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Equal("conflict", await refused.ProblemCodeAsync());
        // Something that only went along is restored through what was deleted.
        Assert.Equal(HttpStatusCode.Conflict, (await s.PostAsync($"/trash/folders/{b.Id}/restore", new { }, null)).StatusCode);

        var restored = await s.PostAsync($"/trash/folders/{a.Id}/restore", new { }, null);
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        Assert.Equal("a", s.NameOf(await restored.JsonAsync()));
        Assert.Equal([a.Id, b.Id], await s.IdsAsync($"/projects/{project.Id}/folders"));
        Assert.Equal([inA.Id, inB.Id], await s.IdsAsync($"/projects/{project.Id}/files"));
        Assert.Equal([loose.Id, early.Id], (await s.ItemsAsync("/trash")).Select(IdOf));
        Assert.Equal("""{"files": 2, "folders": 2}""", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT detail::text FROM audit_log WHERE action = 'folder.restore'"));

        // Now its folder is live again, the early file can follow. Restoring twice changes nothing.
        Assert.Equal(HttpStatusCode.OK, (await s.PostAsync($"/trash/files/{early.Id}/restore", new { }, null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await s.PostAsync($"/trash/files/{early.Id}/restore", new { }, null)).StatusCode);
        Assert.Equal(b.Id, (await (await s.GetAsync($"/files/{early.Id}")).JsonAsync()).GetProperty("folderId").GetGuid());
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'file.restore'"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files WHERE deleted_at IS NULL AND deleted_root_id IS NOT NULL"));
    }

    [Fact]
    public async Task A_project_comes_back_whole_and_keeps_what_was_already_in_trash_there()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var s = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var folder = await s.FolderAsync(project, "f");
        var kept = await s.FileAsync(project, "kept.md", folder);
        var before = await s.FileAsync(project, "before.md");
        await s.DeleteAsync($"/files/{before.Id}");

        await s.DeleteAsync($"/projects/{project.Id}");
        var entry = (await s.ItemsAsync("/trash")).Single(t => t.GetProperty("entity").GetString() == "project");
        Assert.Equal((1, 1), (entry.GetProperty("folders").GetInt32(), entry.GetProperty("files").GetInt32()));
        Assert.Equal(HttpStatusCode.Conflict, (await s.PostAsync($"/trash/files/{before.Id}/restore", new { }, null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await s.PostAsync($"/trash/folders/{folder.Id}/restore", new { }, null)).StatusCode);

        Assert.Equal("p", s.NameOf(await (await s.PostAsync($"/trash/projects/{project.Id}/restore", new { }, null)).JsonAsync()));

        Assert.Equal([project.Id], await s.IdsAsync("/projects"));
        Assert.Equal([kept.Id], await s.IdsAsync($"/projects/{project.Id}/files"));
        Assert.Equal([before.Id], (await s.ItemsAsync("/trash")).Select(IdOf));
    }

    [Fact]
    public async Task Trash_ends_after_the_window_and_belongs_to_its_owner()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero));
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), clock, new Dictionary<string, string?> { ["Retention:TrashWindowDays"] = "7" });
        var s = await SignedInAsync(app);
        var stranger = await SignedInAsync(app);
        var project = await s.ProjectAsync("p");
        var file = await s.FileAsync(project, "x.md");
        await s.DeleteAsync($"/files/{file.Id}");

        Assert.Empty(await stranger.ItemsAsync("/trash"));
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.PostAsync($"/trash/files/{file.Id}/restore", new { }, null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await s.PostAsync($"/trash/files/{Guid.CreateVersion7()}/restore", new { }, null)).StatusCode);

        // The delete is moved into the past instead of the clock forward, so the session stays valid.
        await Sql.ExecAsync(app.ConnectionString, "UPDATE files SET deleted_at = deleted_at - interval '7 days' + interval '1 second'");
        Assert.Single(await s.ItemsAsync("/trash"));
        await Sql.ExecAsync(app.ConnectionString, "UPDATE files SET deleted_at = deleted_at - interval '2 seconds'");
        Assert.Empty(await s.ItemsAsync("/trash"));
        Assert.Equal(HttpStatusCode.NotFound, (await s.PostAsync($"/trash/files/{file.Id}/restore", new { }, null)).StatusCode);
        // Past the window the row is still there: the grace period and the purge are the admin's and the system's.
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM files WHERE deleted_at IS NOT NULL"));

        Assert.Equal("validation_failed", await (await s.GetAsync("/trash?cursor=abc")).ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.BadRequest, (await s.GetAsync("/trash?limit=0")).StatusCode);
    }
}
