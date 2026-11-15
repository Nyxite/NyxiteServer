using System.Collections;
using System.Collections.Concurrent;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Application.Content;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.IntegrationTests.Realtime;
using Nyxite.Persistence.Entities;
using Nyxite.Server.Realtime;

namespace Nyxite.IntegrationTests.Review;

/// <summary>
/// Reproductions for the review of the Phase 2.1 server (REVIEW-server-2026-11-14.md). Traits "issue" and "scope" assert
/// the specified behaviour and fail on the reviewed implementation. Trait "decision" asserts the current behaviour and
/// passes, so it documents the consequence of a decision instead of a defect.
/// </summary>
public sealed class RelayReviewFindingsTests(PostgresFixture pg)
{
    private sealed record User(StructureDriver S, string Token, Guid Id, AuthDriver.Account Account, AuthDriver Auth);

    /// <summary>
    /// Scripted reach for the reproductions: the real ownership, plus per account either a fixed level, a number of
    /// checks that still succeed before reach ends, or a failure like a timed out query.
    /// </summary>
    private sealed class ScriptedAccess
    {
        public ConcurrentDictionary<Guid, FileAccessLevel> Levels { get; } = new();
        public ConcurrentDictionary<Guid, int> RemainingChecks { get; } = new();
        public ConcurrentDictionary<Guid, bool> Failing { get; } = new();
    }

    private sealed class ScriptedFileAccess(ShareFileAccess owner, ScriptedAccess script) : IFileAccess
    {
        public async Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct)
        {
            var own = await owner.LevelAsync(userId, file, ct);
            if (own != FileAccessLevel.None) return own;
            if (script.Failing.ContainsKey(userId)) throw new TimeoutException("A query of the access check timed out.");
            if (script.RemainingChecks.TryGetValue(userId, out var remaining))
                return remaining > 0 && script.RemainingChecks.TryUpdate(userId, remaining - 1, remaining) ? FileAccessLevel.Write : FileAccessLevel.None;
            return script.Levels.GetValueOrDefault(userId);
        }

        public Task<FileAccessLevel> GuestLevelAsync(Guid shareId, FileEntity file, CancellationToken ct) => owner.GuestLevelAsync(shareId, file, ct);
    }

    private static NyxiteApp App(string connectionString, ScriptedAccess script, IDictionary<string, string?>? overrides = null) =>
        new(connectionString, overrides: new Dictionary<string, string?>(overrides ?? new Dictionary<string, string?>()) { ["Relay:AccessRecheckInterval"] = "01:00:00" },
            configureServices: services =>
            {
                services.AddSingleton(script);
                services.AddScoped<ShareFileAccess>();
                services.AddScoped<IFileAccess, ScriptedFileAccess>();
            });

    private static async Task<User> UserAsync(NyxiteApp app, string displayName)
    {
        var auth = new AuthDriver(app);
        var (account, userId, _, _) = await new KeyDriver(auth).AccountWithActiveDeviceAsync();
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET display_name = @name WHERE id = @id", ("name", displayName), ("id", userId));
        return new User(new StructureDriver(auth.Client().WithBearer(account.Tokens.AccessToken)), account.Tokens.AccessToken, userId, account, auth);
    }

    private static EncryptedUpdate Update(StructureDriver.Sealed file, string text) =>
        new(0, NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Crdt, Encoding.UTF8.GetBytes(text)), file.KeyId.ToString());

    private static async Task<int> RecheckAsync(NyxiteApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RelayAccessCheck>().RunAsync(CancellationToken.None);
    }

    // F1 -- 05 §5.4, 09 §9.6: a connection that receives a room's traffic must be one the periodic re-check judges.
    // JoinDocument adds the connection to the SignalR group before it reads the log and before it enters the roster.
    // When the join fails after that point (here: reach ends between the snapshot read and the log read, as a revocation
    // racing the join or a timed out query would), the connection stays in the group, receives every update and every
    // awareness message, and is invisible to the roster and to the re-check, so no later revocation removes it.
    [Fact, Trait("review", "issue")]
    public async Task F1_a_failed_join_leaves_no_listener_outside_the_roster_and_the_recheck()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token);
        await laptop.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        script.RemainingChecks[grace.Id] = 1;
        var failed = await Assert.ThrowsAsync<HubException>(() => web.Connection.InvokeAsync("JoinDocument", fileId, 0L));
        Assert.Contains("not_found", failed.Message);
        Assert.DoesNotContain(app.Services.GetRequiredService<RelayPresence>().Members(), m => m.Member.UserId == grace.Id);
        Assert.Equal(0, await RecheckAsync(app));

        await laptop.Connection.InvokeAsync<long>("SubmitUpdate", fileId, Update(file, "secret"));
        await laptop.Connection.InvokeAsync("SubmitAwareness", fileId,
            NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Awareness, Encoding.UTF8.GetBytes("caret")));
        await RelayPeer.UntilAsync(() => laptop.Updates.Count == 1);
        await Task.Delay(300);
        Assert.Empty(web.Updates);
        Assert.Empty(web.Awareness);
    }

    // F2 -- 05 §5.4: one access check that throws (a timed out query, a row the resolver cannot read) must not end the
    // pass for every other connection. Today the exception leaves RunAsync, so the remaining memberships of that pass
    // are not judged, and a revoked reader whose pair comes after it keeps listening.
    [Fact, Trait("review", "issue")]
    public async Task F2_one_failing_access_check_does_not_stop_the_pass_for_the_others()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var grace = await UserAsync(app, "Grace");
        var reader = await UserAsync(app, "Reader");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();
        script.Levels[grace.Id] = FileAccessLevel.Write;
        script.Levels[reader.Id] = FileAccessLevel.Read;

        await using var web = await RelayPeer.ConnectAsync(app, grace.Token);
        await using var viewer = await RelayPeer.ConnectAsync(app, reader.Token);
        await web.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await viewer.Connection.InvokeAsync("JoinDocument", fileId, 0L);

        script.Failing[grace.Id] = true;
        script.Levels[reader.Id] = FileAccessLevel.None;
        await RecheckAsync(app);
        await RelayPeer.UntilAsync(() => viewer.Errors.Contains("not_found"));
    }

    // F3 -- 05 §5.9: "when empty, the server ... forgets in-memory presence". RelayPresence never removes a room, so the
    // dictionary keeps one entry for every document joined since the process started.
    [Fact, Trait("review", "issue")]
    public async Task F3_an_empty_room_is_forgotten()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var project = await ada.S.ProjectAsync("p");
        var first = await ada.S.FileAsync(project, "a.md");
        var second = await ada.S.FileAsync(project, "b.md");

        var peer = await RelayPeer.ConnectAsync(app, ada.Token);
        await peer.Connection.InvokeAsync("JoinDocument", first.Id.ToString(), 0L);
        await peer.Connection.InvokeAsync("JoinDocument", second.Id.ToString(), 0L);
        await peer.Connection.InvokeAsync("LeaveDocument", first.Id.ToString());
        await peer.DisposeAsync();
        await Task.Delay(300);

        var presence = app.Services.GetRequiredService<RelayPresence>();
        var rooms = (ICollection)typeof(RelayPresence).GetField("_rooms", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(presence)!;
        Assert.Empty(presence.Members());
        Assert.Empty(rooms);
    }

    // F4 -- 05 §5.4 ("no room is open to a dead session"), 09 §9.6: JoinDocument reads through ContentService, which
    // checks reach but not the session, so a connection whose session was logged out can still join rooms and receive
    // the log until the next pass closes it. SubmitUpdate checks the session (DeviceGuard), the join does not.
    [Fact, Trait("review", "issue")]
    public async Task F4_a_connection_of_a_logged_out_session_cannot_join_a_room()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var second = await ada.Auth.LoginAsync(ada.Account.Email, ada.Account.TotpSecret!);

        await using var tablet = await RelayPeer.ConnectAsync(app, second.AccessToken);
        Assert.Equal(System.Net.HttpStatusCode.NoContent,
            (await new AuthDriver(app).Client().WithBearer(second.AccessToken).PostAsync("/api/v1/auth/logout", null)).StatusCode);

        var join = await Assert.ThrowsAsync<HubException>(() => tablet.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L));
        Assert.Contains("unauthenticated", join.Message);
    }

    // F5 -- 05 §5.5 step 4 and the Phase 2.1 exit criterion "relays ciphertext only": awareness is an NYXC frame, and
    // SubmitUpdate already refuses anything that is not one. SubmitAwareness forwards any bytes, so a client that
    // forgets to seal its cursor sends plaintext through the relay and the server cannot tell.
    [Fact, Trait("review", "issue")]
    public async Task F5_awareness_that_is_not_an_nyxc_frame_is_refused()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var phone = await RelayPeer.ConnectAsync(app, ada.Token);
        await laptop.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await phone.Connection.InvokeAsync("JoinDocument", fileId, 0L);

        var plaintext = Encoding.UTF8.GetBytes("""{"user":{"name":"Ada"},"cursor":{"anchor":3,"head":7}}""");
        var refused = await Assert.ThrowsAsync<HubException>(() => laptop.Connection.InvokeAsync("SubmitAwareness", fileId, plaintext));
        Assert.Contains("validation_failed", refused.Message);
        await Task.Delay(200);
        Assert.Empty(phone.Awareness);
    }

    private sealed class CountingScopes(IServiceScopeFactory inner) : IServiceScopeFactory
    {
        public int Created;

        public IServiceScope CreateScope()
        {
            Interlocked.Increment(ref Created);
            return inner.CreateScope();
        }
    }

    private sealed class CountingLogger : ILogger<RelayAccessWorker>
    {
        public int Warnings;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning) Interlocked.Increment(ref Warnings);
        }
    }

    // F6 -- 14 (boot validation, "fail fast"): Relay:AccessRecheckInterval is not validated. Zero makes the worker spin
    // without pause, and a negative value makes Task.Delay throw on every turn, which the catch-all logs and loops on,
    // so one wrong setting burns a core and floods the log instead of stopping the start.
    [Theory, Trait("review", "issue")]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    public async Task F6_a_non_positive_recheck_interval_does_not_spin_the_worker(string interval)
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var scopes = new CountingScopes(app.Services.GetRequiredService<IServiceScopeFactory>());
        var logger = new CountingLogger();
        var worker = new RelayAccessWorker(scopes, TimeProvider.System,
            Options.Create(new RelayOptions { AccessRecheckInterval = TimeSpan.Parse(interval) }), new RelayAccessSignal(), logger);

        await Task.Run(() => worker.StartAsync(CancellationToken.None)).WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(TimeSpan.FromSeconds(1));
        await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(scopes.Created + logger.Warnings < 20, $"{scopes.Created} passes and {logger.Warnings} warnings in one second.");
    }

    // D1 -- decision 7: the re-check skips every member without a session, which today are only guests, which do not
    // exist yet. Such a member is never judged and never removed, so a Phase 2.2 guest whose link is revoked would keep
    // listening until it disconnects, against 09 §9.6 and 08 §8.7 ("live ones within one renewal cycle").
    [Fact, Trait("review", "decision")]
    public async Task D1_a_member_without_a_session_is_never_removed_by_the_recheck()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var presence = app.Services.GetRequiredService<RelayPresence>();

        presence.Join(file.Id, "guest-connection", new RelayMember(PresenceDto.ForGuest(), null, null));
        Assert.Equal(0, await RecheckAsync(app));
        Assert.Contains(presence.Members(), m => m.ConnectionId == "guest-connection");
        Assert.Equal([PresenceDto.ForGuest()], presence.Roster(file.Id));
    }

    // D2 -- no limit of the relay: a member, a reader included, could send awareness as fast as the socket carries it,
    // up to 64 KiB each, and every message was fanned out to everyone else in the room. This test asserted that 500
    // messages in a burst were all relayed. R2 of REVIEW-server-2026-11-15 added the limits, so it now asserts the new
    // behaviour: a budget of Relay:AwarenessPerSecond (default 60, twice the 20 to 30 Hz the clients send) per
    // connection, the excess refused with rate_limited and not forwarded, the connection kept open, and a client that
    // keeps to the 30 Hz of desktop/android/web 09 never limited.
    [Fact, Trait("review", "decision")]
    public async Task D2_awareness_beyond_the_connection_budget_is_refused_with_rate_limited()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script);
        var ada = await UserAsync(app, "Ada");
        var reader = await UserAsync(app, "Reader");
        var project = await ada.S.ProjectAsync("p");
        var file = await ada.S.FileAsync(project, "note.md");
        var fileId = file.Id.ToString();
        script.Levels[reader.Id] = FileAccessLevel.Read;

        await using var laptop = await RelayPeer.ConnectAsync(app, ada.Token, webSockets: true);
        await using var viewer = await RelayPeer.ConnectAsync(app, reader.Token, webSockets: true);
        await laptop.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        await viewer.Connection.InvokeAsync("JoinDocument", fileId, 0L);
        var frame = NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Awareness, new byte[1024 - NyxcFrame.Overhead]);

        // A client at 30 Hz stays within the budget.
        for (var i = 0; i < 45; i++)
        {
            await viewer.Connection.InvokeAsync("SubmitAwareness", fileId, frame);
            await Task.Delay(TimeSpan.FromSeconds(1.0 / 30));
        }

        await RelayPeer.UntilAsync(() => laptop.Awareness.Count == 45);
        Assert.Empty(viewer.Errors);

        // A burst of 500 drains the bucket of one second's worth; the rest is refused and never reaches the room.
        const int burst = 500;
        var refused = 0;
        for (var i = 0; i < burst; i++)
        {
            try
            {
                await viewer.Connection.InvokeAsync("SubmitAwareness", fileId, frame);
            }
            catch (HubException e) when (e.Message.Contains("rate_limited"))
            {
                refused++;
            }
        }

        await Task.Delay(200);
        int relayed;
        lock (laptop.Awareness) relayed = laptop.Awareness.Count - 45;
        Assert.Equal(burst, relayed + refused);
        Assert.InRange(relayed, 60, burst - 1);
        lock (viewer.Errors) Assert.Contains("rate_limited", viewer.Errors);
        Assert.False(viewer.Closed);

        // The bucket refills, and the connection goes on.
        await Task.Delay(TimeSpan.FromSeconds(1));
        await viewer.Connection.InvokeAsync("SubmitAwareness", fileId, frame);
    }

    // R2 of REVIEW-server-2026-11-15: the relay caps connections per room and rooms per connection
    // (Relay:MaxConnectionsPerRoom, Relay:MaxRoomsPerConnection). A join beyond either is refused with room_full or
    // too_many_rooms after the reach check, and a leave frees the slot.
    [Fact, Trait("review", "issue")]
    public async Task R2_joins_beyond_the_room_and_connection_caps_are_refused()
    {
        var script = new ScriptedAccess();
        await using var app = App(await pg.CreateDatabaseAsync(), script, new Dictionary<string, string?>
        {
            ["Relay:MaxConnectionsPerRoom"] = "2",
            ["Relay:MaxRoomsPerConnection"] = "2",
        });
        var ada = await UserAsync(app, "Ada");
        var project = await ada.S.ProjectAsync("p");
        var files = new List<StructureDriver.Sealed>();
        for (var i = 0; i < 3; i++) files.Add(await ada.S.FileAsync(project, $"note{i}.md"));
        var stranger = await UserAsync(app, "Stranger");

        await using var one = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var two = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var three = await RelayPeer.ConnectAsync(app, ada.Token);
        await using var outsider = await RelayPeer.ConnectAsync(app, stranger.Token);
        await one.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L);
        await two.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L);

        var full = await Assert.ThrowsAsync<HubException>(() => three.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L));
        Assert.Contains("room_full", full.Message);
        // Without reach the answer stays not_found, so a full room is no news to someone who cannot open it.
        var hidden = await Assert.ThrowsAsync<HubException>(() => outsider.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L));
        Assert.Contains("not_found", hidden.Message);
        // A member joining its own room again is not counted twice.
        await two.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L);
        await two.Connection.InvokeAsync("LeaveDocument", files[0].Id.ToString());
        await three.Connection.InvokeAsync("JoinDocument", files[0].Id.ToString(), 0L);
        Assert.Equal(2, app.Services.GetRequiredService<RelayPresence>().ConnectionCount(files[0].Id));

        await one.Connection.InvokeAsync("JoinDocument", files[1].Id.ToString(), 0L);
        var many = await Assert.ThrowsAsync<HubException>(() => one.Connection.InvokeAsync("JoinDocument", files[2].Id.ToString(), 0L));
        Assert.Contains("too_many_rooms", many.Message);
        lock (one.Errors) Assert.Contains("too_many_rooms", one.Errors);
        await one.Connection.InvokeAsync("LeaveDocument", files[1].Id.ToString());
        await one.Connection.InvokeAsync("JoinDocument", files[2].Id.ToString(), 0L);
        Assert.Equal(2, app.Services.GetRequiredService<RelayPresence>().RoomCount(one.Connection.ConnectionId!));
    }
}
