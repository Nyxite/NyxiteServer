using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Content;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Persistence.Entities;
using Nyxite.Server.Realtime;

namespace Nyxite.IntegrationTests.Realtime;

/// <summary>
/// Stands in for the shares of Phase 2.2, which are the only way a second account reaches a file: grants accounts a
/// level on the files of a project and takes it back, like a share and its revocation would.
/// </summary>
public sealed class ProjectGrants
{
    private readonly ConcurrentDictionary<(Guid User, Guid Project), FileAccessLevel> _grants = new();

    public void Grant(Guid userId, Guid projectId, FileAccessLevel level) => _grants[(userId, projectId)] = level;

    public void Revoke(Guid userId, Guid projectId) => _grants.TryRemove((userId, projectId), out _);

    public FileAccessLevel Of(Guid userId, Guid projectId) => _grants.GetValueOrDefault((userId, projectId));
}

/// <summary>The real ownership check, plus the grants: the maximum over both paths, as 09 §9.5 resolves it.</summary>
public sealed class GrantingFileAccess(OwnerFileAccess owner, ProjectGrants grants) : IFileAccess
{
    public async Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct) =>
        (FileAccessLevel)Math.Max((int)await owner.LevelAsync(userId, file, ct), (int)grants.Of(userId, file.ProjectId));
}

/// <summary>Phase 2.1 server: rooms shared by several accounts and devices, the presence roster, awareness and the ACL re-checks.</summary>
public sealed class CollaborationTests(PostgresFixture pg)
{
    private sealed record User(StructureDriver S, string Token, Guid Id, AuthDriver.Account Account, AuthDriver Auth);

    private static NyxiteApp App(string connectionString, ProjectGrants grants, IDictionary<string, string?>? overrides = null) =>
        new(connectionString, overrides: overrides ?? new Dictionary<string, string?> { ["Relay:AccessRecheckInterval"] = "01:00:00" },
            configureServices: services =>
            {
                services.AddSingleton(grants);
                services.AddScoped<OwnerFileAccess>();
                services.AddScoped<IFileAccess, GrantingFileAccess>();
            });

    private static async Task<User> UserAsync(NyxiteApp app, string displayName)
    {
        var auth = new AuthDriver(app);
        var (account, userId, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET display_name = @name WHERE id = @id", ("name", displayName), ("id", userId));
        return new User(new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken)), account.Tokens.AccessToken, userId, account, auth);
    }

    private static byte[] Seal(StructureDriver.Sealed file, string plaintext) =>
        NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Crdt, Encoding.UTF8.GetBytes(plaintext));

    private static string Open(StructureDriver.Sealed file, byte[] frame) =>
        Encoding.UTF8.GetString(NyxcFrame.Open(file.Key, frame, NyxcFrame.BuildAad(file.KeyId, file.Id, ObjectKind.Crdt)));

    private static async Task<int> RecheckAsync(NyxiteApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RelayAccessCheck>().RunAsync(CancellationToken.None);
    }

    /// <summary>P2.1-TC-1, server side: two accounts with three devices type at once; every peer gets the same ordered, unread stream.</summary>
    [Fact]
    public async Task Two_accounts_co_edit_in_one_room_with_a_roster_of_identities_only()
    {
        var grants = new ProjectGrants();
        await using var app = App(await pg.CreateDatabaseAsync(), grants);
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var reader = await UserAsync(app, "Reader");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();
        grants.Grant(grace.Id, project.Id, FileAccessLevel.Write);
        grants.Grant(reader.Id, project.Id, FileAccessLevel.Read);

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var phone = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        await using var viewer = await RelayPeer.ConnectAsync(app, reader.Token);
        RelayPeer[] peers = [laptop, phone, web, viewer];
        foreach (var peer in peers) await peer.Connection.InvokeAsync("JoinDocument", fileId, 0L);

        // One entry per account, however many devices it has in the room, and nothing but who they are.
        await RelayPeer.UntilAsync(() => laptop.Presence.LastOrDefault()?.Length == 3);
        PresenceDto[] expected = [.. new[] { (ada.Id, "Ada"), (grace.Id, "Grace"), (reader.Id, "Reader") }
            .Select(u => PresenceDto.ForUser(u.Item1, u.Item2)).OrderBy(p => p.UserId, StringComparer.Ordinal)];
        Assert.Equal(expected, laptop.Presence[^1]);
        Assert.All(laptop.Presence[^1], p => Assert.Equal(PresenceDto.User, p.Kind));
        Assert.Equal(["Kind", "UserId", "DisplayName"], typeof(PresenceDto).GetProperties().Select(p => p.Name));

        // Both accounts type at the same time. The server orders, stores and forwards; every peer sees one sequence.
        var sent = new ConcurrentDictionary<string, byte[]>();
        async Task TypeAsync(RelayPeer peer, string who)
        {
            for (var i = 0; i < 5; i++)
            {
                var frame = Seal(file, $"{who}{i}");
                sent[$"{who}{i}"] = frame;
                await peer.Connection.InvokeAsync<long>("SubmitUpdate", fileId, new EncryptedUpdate(0, frame, file.KeyId.ToString()));
            }
        }

        await Task.WhenAll(TypeAsync(laptop, "a"), TypeAsync(web, "g"));
        await RelayPeer.UntilAsync(() => peers.All(p => p.Updates.Count == 10));
        foreach (var peer in peers)
        {
            Assert.Equal(Enumerable.Range(1, 10).Select(i => (long)i), peer.Updates.Select(u => u.Seq));
            Assert.Equal(laptop.Updates.Select(u => u.Ciphertext), peer.Updates.Select(u => u.Ciphertext));
        }

        // What arrives is exactly the ciphertext that was sent.
        Assert.Equal(sent.Keys.Order(), laptop.Updates.Select(u => Open(file, u.Ciphertext)).Order());
        Assert.All(laptop.Updates, u => Assert.Equal(sent[Open(file, u.Ciphertext)], u.Ciphertext));
        Assert.Equal(5L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates WHERE author_id = @id", ("id", grace.Id)));

        // A reader receives and shows a caret, but cannot write.
        var denied = await Assert.ThrowsAsync<HubException>(() =>
            viewer.Connection.InvokeAsync<long>("SubmitUpdate", fileId, new EncryptedUpdate(0, Seal(file, "r"), file.KeyId.ToString())));
        Assert.Contains("acl_denied", denied.Message);
        await viewer.Connection.InvokeAsync("SubmitAwareness", fileId, new byte[] { 7 });
        await RelayPeer.UntilAsync(() => laptop.Awareness.Count == 1 && web.Awareness.Count == 1);
        Assert.Empty(viewer.Awareness);

        // Leaving shrinks the roster; a device leaving keeps its account while another of its devices stays.
        await web.Connection.InvokeAsync("LeaveDocument", fileId);
        await RelayPeer.UntilAsync(() => laptop.Presence[^1].Length == 2);
        await phone.DisposeAsync();
        await Task.Delay(100);
        Assert.Equal(new[] { ada.Id.ToString(), reader.Id.ToString() }.Order(StringComparer.Ordinal), laptop.Presence[^1].Select(p => p.UserId));
    }

    /// <summary>P2.1-TC-1 and phase exit: awareness frames (object_kind 6) pass unchanged and leave no trace in Postgres or the blob store.</summary>
    [Fact]
    public async Task Awareness_is_relayed_byte_for_byte_and_never_stored()
    {
        var v = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Resources", "vectors", "awareness.json"))).RootElement;
        var grants = new ProjectGrants();
        await using var app = App(await pg.CreateDatabaseAsync(), grants);
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var project = await ada.S.ProjectAsync("p");
        var file = new StructureDriver.Sealed(v.GetProperty("fileId").GetGuid(), v.GetProperty("keyId").GetGuid(),
            Convert.FromHexString(v.GetProperty("key").GetString()!));
        Assert.Equal(HttpStatusCode.Created, (await ada.S.PostAsync("/files", ada.S.FileBody(file, project, "vector.md"))).StatusCode);
        grants.Grant(grace.Id, project.Id, FileAccessLevel.Write);
        var fileId = file.Id.ToString();
        var frames = v.GetProperty("updates").EnumerateArray().Select(u => Convert.FromHexString(u.GetProperty("frame").GetString()!)).ToList();

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var phone = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        foreach (var peer in new[] { laptop, phone, web }) await peer.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        foreach (var frame in frames) await laptop.Connection.InvokeAsync("SubmitAwareness", fileId, frame);

        await RelayPeer.UntilAsync(() => web.Awareness.Count == frames.Count && phone.Awareness.Count == frames.Count);
        Assert.Equal(frames, web.Awareness);
        Assert.Equal(frames, phone.Awareness);
        Assert.Empty(laptop.Awareness);
        var key = Convert.FromHexString(v.GetProperty("key").GetString()!);
        Assert.Equal(Convert.FromHexString(v.GetProperty("updates")[0].GetProperty("update").GetString()!),
            NyxcFrame.Open(key, web.Awareness[0], NyxcFrame.BuildAad(file.KeyId, file.Id, ObjectKind.Awareness)));

        // No row of any table holds a frame, and no file of the blob store does.
        var tables = await Sql.ListAsync<string>(app.ConnectionString, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'");
        Assert.Contains("crdt_updates", tables);
        foreach (var frame in frames)
        foreach (var table in tables)
            Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
                $"SELECT count(*) FROM \"{table}\" t WHERE strpos(t::text, @hex) > 0", ("hex", Convert.ToHexStringLower(frame))));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));
        var stored = Directory.Exists(app.BlobRoot) ? Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories).ToList() : [];
        foreach (var path in stored)
        {
            var bytes = await File.ReadAllBytesAsync(path);
            Assert.All(frames, frame => Assert.Equal(-1, bytes.AsSpan().IndexOf(frame)));
        }

        // Too large, or from a connection outside the room, it is refused.
        var tooLarge = await Assert.ThrowsAsync<HubException>(() =>
            laptop.Connection.InvokeAsync("SubmitAwareness", fileId, new byte[64 * 1024 + 1]));
        Assert.Contains("payload_too_large", tooLarge.Message);
        await using var outside = await RelayPeer.ConnectAsync(app, grace.Token);
        var notIn = await Assert.ThrowsAsync<HubException>(() => outside.Connection.InvokeAsync("SubmitAwareness", fileId, frames[0]));
        Assert.Contains("not_found", notIn.Message);
        Assert.Equal(frames.Count, web.Awareness.Count);
    }

    /// <summary>
    /// 05 §5.4, 09 §9.6: reach is checked at join, at submit and periodically. A connection whose account lost reach is
    /// removed from the room, one whose session ended is closed, and the room's roster follows.
    /// </summary>
    [Fact]
    public async Task The_periodic_recheck_removes_connections_that_lost_reach_or_their_session()
    {
        var grants = new ProjectGrants();
        await using var app = App(await pg.CreateDatabaseAsync(), grants);
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();
        EncryptedUpdate Update(string text) => new(0, Seal(file, text), file.KeyId.ToString());
        grants.Grant(grace.Id, project.Id, FileAccessLevel.Write);
        var second = await ada.Auth.LoginAsync(ada.Account.Email, ada.Account.TotpSecret!);

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var tablet = await RelayPeer.ConnectAsync(app, second.AccessToken);
        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        foreach (var peer in new[] { laptop, tablet, web }) await peer.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await RelayPeer.UntilAsync(() => laptop.Presence.LastOrDefault()?.Length == 2);
        Assert.Equal(0, await RecheckAsync(app));

        // The share ends. The next submit is refused at once, but the open connection would go on listening ...
        grants.Revoke(grace.Id, project.Id);
        var refused = await Assert.ThrowsAsync<HubException>(() => web.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("g")));
        Assert.Contains("not_found", refused.Message);
        await laptop.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("1"));
        await RelayPeer.UntilAsync(() => web.Updates.Count == 1);

        // ... until the re-check takes it out of the room and tells the others.
        Assert.Equal(1, await RecheckAsync(app));
        await RelayPeer.UntilAsync(() => web.Errors.Contains("not_found") && laptop.Presence[^1].Length == 1);
        Assert.Equal(ada.Id.ToString(), laptop.Presence[^1][0].UserId);
        await laptop.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update("2"));
        await RelayPeer.UntilAsync(() => laptop.Updates.Count == 2 && tablet.Updates.Count == 2);
        await Assert.ThrowsAsync<HubException>(() => web.Connection.InvokeAsync("SubmitAwareness", fileId, new byte[] { 1 }));
        var rejoin = await Assert.ThrowsAsync<HubException>(() => web.Connection.InvokeAsync("JoinDocument", fileId, 0L));
        Assert.Contains("not_found", rejoin.Message);
        await Task.Delay(100);
        Assert.Single(web.Updates);
        Assert.False(web.Closed);

        // A session that ends closes its connection; the account's other device stays.
        Assert.Equal(HttpStatusCode.NoContent, (await new AuthDriver(app).Client().WithBearer(second.AccessToken).PostAsync("/api/v1/auth/logout", null)).StatusCode);
        Assert.Equal(1, await RecheckAsync(app));
        await RelayPeer.UntilAsync(() => tablet.Closed);
        Assert.Contains("unauthenticated", tablet.Errors);
        Assert.False(laptop.Closed);

        // The owner moving the file to Trash cuts off the owner's own devices too.
        Assert.Equal(HttpStatusCode.NoContent, (await ada.S.DeleteAsync($"/files/{file.Id}")).StatusCode);
        Assert.Equal(1, await RecheckAsync(app));
        await RelayPeer.UntilAsync(() => laptop.Errors.Contains("not_found"));
        Assert.Equal(0, await RecheckAsync(app));
    }

    /// <summary>The re-check runs on its own every <c>Relay:AccessRecheckInterval</c>, without anyone calling it.</summary>
    [Fact]
    public async Task The_recheck_runs_on_its_interval()
    {
        var grants = new ProjectGrants();
        await using var app = App(await pg.CreateDatabaseAsync(), grants,
            new Dictionary<string, string?> { ["Relay:AccessRecheckInterval"] = "00:00:00.200" });
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        grants.Grant(grace.Id, project.Id, FileAccessLevel.Read);

        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        await web.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        grants.Revoke(grace.Id, project.Id);
        await RelayPeer.UntilAsync(() => web.Errors.Contains("not_found"));
    }
}
