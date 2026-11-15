using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Content;
using Nyxite.Application.Sharing;
using Nyxite.Persistence;

namespace Nyxite.Server.Realtime;

/// <summary>
/// The relay's periodic ACL re-check (05 §5.4, 09 §9.6). A connection keeps receiving a room's updates and awareness
/// after its join, so join and submit alone would let a reader whose reach ended listen on. This pass judges every
/// connection again: one whose session ended is closed, and one whose account lost reach to the file is removed from
/// that room with <c>OnError(not_found)</c>, and the others get the new roster. It reads only ACL metadata.
/// </summary>
/// <remarks>
/// Every check is isolated: one that throws, such as a timed out query, is logged and costs that connection or account
/// this pass, while every other membership is still judged. A removal takes the connection out of the group before it
/// takes it out of the presence, so a failure in between leaves a member the next pass sees again, never a listener
/// outside the roster.
/// <para>
/// A targeted pass judges only the members a <see cref="RelayAccessScope"/> names. It runs as soon as a share is revoked
/// or changed or a file goes to Trash (<see cref="RelayAccessSignal"/>), with the same checks and the same order of
/// removal as the periodic pass, which stays the backstop for what no event covers. A targeted pass fails closed: a
/// member whose check cannot complete is disconnected with <c>access_unverified</c>, because the event says its access
/// just changed and the instant cutoff must not wait for the next periodic pass. It may reconnect, and its join is
/// checked again. The periodic pass keeps the isolation above, so a database hiccup does not drop every room at once.
/// </para>
/// </remarks>
public sealed class RelayAccessCheck(
    RelayPresence presence, IHubContext<RelayHub, IRelayClient> hub, ContentService content, NyxiteDbContext db, GuestShareService guests,
    TimeProvider time, ILogger<RelayAccessCheck> logger)
{
    /// <summary>Runs one pass over every member and returns how many room memberships it ended.</summary>
    public Task<int> RunAsync(CancellationToken ct) => RunAsync(null, ct);

    /// <summary>Runs one pass over the members <paramref name="scope"/> names, every member when it is null.</summary>
    public async Task<int> RunAsync(RelayAccessScope? scope, CancellationToken ct)
    {
        var members = presence.Members();
        if (scope is not null) members = members.Where(m => scope.Matches(m.FileId, m.Member.UserId, m.Member.ShareId)).ToList();
        if (members.Count == 0) return 0;
        var failClosed = scope is not null;
        var changed = new HashSet<Guid>();
        var removed = 0;

        var now = time.GetUtcNow();
        var sessionIds = members.Where(m => m.Member.SessionId is not null).Select(m => m.Member.SessionId!.Value).Distinct().ToList();
        HashSet<Guid> live;
        try
        {
            live = (await db.Sessions.AsNoTracking().Where(s => sessionIds.Contains(s.Id) && s.RevokedAt == null && s.ExpiresAt > now)
                .Select(s => s.Id).ToListAsync(ct)).ToHashSet();
        }
        catch (Exception e) when (failClosed && !ct.IsCancellationRequested)
        {
            logger.LogWarning(e, "The targeted relay access re-check could not read sessions; its members are disconnected.");
            removed += await DisconnectAsync(members, changed, ct);
            await RostersAsync(changed, ct);
            return removed;
        }
        foreach (var connection in members.Where(m => m.Member.SessionId is { } sid && !live.Contains(sid)).GroupBy(m => m.ConnectionId))
        {
            try
            {
                foreach (var (fileId, _, _) in connection)
                {
                    await hub.Clients.Client(connection.Key).OnError(fileId.ToString(), "unauthenticated", "The session has ended.");
                    await hub.Groups.RemoveFromGroupAsync(connection.Key, RelayHub.Room(fileId), ct);
                }

                foreach (var fileId in presence.LeaveAll(connection.Key))
                {
                    changed.Add(fileId);
                    removed++;
                }

                presence.Abort(connection.Key);
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check could not close a connection of an ended session.");
            }
        }

        // One query per account and document, however many devices of the account are in the room.
        foreach (var pair in members.Where(m => m.Member.UserId is not null && live.Contains(m.Member.SessionId!.Value))
                     .GroupBy(m => (m.FileId, UserId: m.Member.UserId!.Value)))
        {
            try
            {
                if (await content.AccessLevelAsync(pair.Key.UserId, pair.Key.FileId, ct) != FileAccessLevel.None) continue;
                foreach (var (fileId, connectionId, _) in pair)
                {
                    if (!presence.IsIn(fileId, connectionId)) continue;
                    await hub.Groups.RemoveFromGroupAsync(connectionId, RelayHub.Room(fileId), ct);
                    if (!presence.Leave(fileId, connectionId)) continue;
                    changed.Add(fileId);
                    removed++;
                    await hub.Clients.Client(connectionId).OnError(fileId.ToString(), "not_found", "Not found.");
                }
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check of one account in one room failed.");
                if (failClosed) removed += await DisconnectAsync(pair.ToList(), changed, ct);
            }
        }

        removed += await RecheckGuestsAsync(members, changed, failClosed, ct);
        await RostersAsync(changed, ct);
        return removed;
    }

    /// <summary>
    /// Fail-closed removal of members a targeted pass could not judge: each connection gets
    /// <c>OnError(fileId, "access_unverified", ...)</c> for its rooms, leaves them and is closed, so it reconnects and is
    /// checked again at its join. Every step is isolated, and the group goes before the presence, as everywhere here.
    /// </summary>
    private async Task<int> DisconnectAsync(IReadOnlyCollection<(Guid FileId, string ConnectionId, RelayMember Member)> members, HashSet<Guid> changed,
        CancellationToken ct)
    {
        var removed = 0;
        foreach (var connection in members.GroupBy(m => m.ConnectionId))
        {
            try
            {
                foreach (var (fileId, _, _) in connection)
                {
                    await hub.Groups.RemoveFromGroupAsync(connection.Key, RelayHub.Room(fileId), ct);
                    await hub.Clients.Client(connection.Key).OnError(fileId.ToString(), AccessUnverified, "Access could not be checked; join again.");
                }

                foreach (var fileId in presence.LeaveAll(connection.Key))
                {
                    changed.Add(fileId);
                    removed++;
                }

                presence.Abort(connection.Key);
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check could not disconnect a member it could not judge.");
            }
        }

        return removed;
    }

    public const string AccessUnverified = "access_unverified";

    private async Task RostersAsync(HashSet<Guid> changed, CancellationToken ct)
    {
        foreach (var fileId in changed)
        {
            try
            {
                await hub.Clients.Group(RelayHub.Room(fileId)).OnPresence(fileId.ToString(), presence.Roster(fileId));
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check could not send a roster.");
            }
        }
    }

    /// <summary>
    /// Link guests (05 §5.8): a guest whose share was revoked or expired gets <c>OnError</c> with <c>share_revoked</c> or
    /// <c>link_expired</c> for its rooms and is closed, like a connection of an ended session, because its only credential
    /// is gone. A guest of a link a rotation kept is closed the same way with <c>link_frozen</c>, because nothing the room
    /// carries opens with its key. A guest whose file went to Trash leaves that room with <c>not_found</c>.
    /// </summary>
    private async Task<int> RecheckGuestsAsync(List<(Guid FileId, string ConnectionId, RelayMember Member)> members, HashSet<Guid> changed, bool failClosed,
        CancellationToken ct)
    {
        var guestMembers = members.Where(m => m.Member.ShareId is not null).ToList();
        if (guestMembers.Count == 0) return 0;
        var removed = 0;
        Dictionary<Guid, string> ended;
        try
        {
            ended = await guests.EndedAsync(guestMembers.Select(m => m.Member.ShareId!.Value).Distinct().ToList(), ct);
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(e, "The relay access re-check could not read the link shares of guests.");
            return failClosed ? await DisconnectAsync(guestMembers, changed, ct) : 0;
        }

        foreach (var connection in guestMembers.Where(m => ended.ContainsKey(m.Member.ShareId!.Value)).GroupBy(m => m.ConnectionId))
        {
            try
            {
                foreach (var (fileId, _, member) in connection)
                {
                    await hub.Clients.Client(connection.Key).OnError(fileId.ToString(), ended[member.ShareId!.Value], "The link has ended.");
                    await hub.Groups.RemoveFromGroupAsync(connection.Key, RelayHub.Room(fileId), ct);
                }

                foreach (var fileId in presence.LeaveAll(connection.Key))
                {
                    changed.Add(fileId);
                    removed++;
                }

                presence.Abort(connection.Key);
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check could not close a guest connection of an ended link.");
            }
        }

        foreach (var pair in guestMembers.Where(m => !ended.ContainsKey(m.Member.ShareId!.Value)).GroupBy(m => (m.FileId, ShareId: m.Member.ShareId!.Value)))
        {
            try
            {
                if (await content.GuestAccessLevelAsync(pair.Key.ShareId, pair.Key.FileId, ct) != FileAccessLevel.None) continue;
                foreach (var (fileId, connectionId, _) in pair)
                {
                    if (!presence.IsIn(fileId, connectionId)) continue;
                    await hub.Groups.RemoveFromGroupAsync(connectionId, RelayHub.Room(fileId), ct);
                    if (!presence.Leave(fileId, connectionId)) continue;
                    changed.Add(fileId);
                    removed++;
                    await hub.Clients.Client(connectionId).OnError(fileId.ToString(), "not_found", "Not found.");
                }
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(e, "The relay access re-check of one guest in one room failed.");
                if (failClosed) removed += await DisconnectAsync(pair.ToList(), changed, ct);
            }
        }

        return removed;
    }
}

/// <summary>
/// The queue of access changes (<see cref="IRelayAccessEvents"/>): the services that commit a revocation, a share change
/// or a move to Trash post a scope here, and <see cref="RelayAccessWorker"/> runs a targeted pass for it at once.
/// Posting never blocks or fails, so a request never waits on the relay.
/// </summary>
public sealed class RelayAccessSignal : IRelayAccessEvents
{
    private readonly System.Threading.Channels.Channel<RelayAccessScope> _queue =
        System.Threading.Channels.Channel.CreateUnbounded<RelayAccessScope>(new() { SingleReader = true });

    public System.Threading.Channels.ChannelReader<RelayAccessScope> Reader => _queue.Reader;

    public void AccessChanged(RelayAccessScope scope)
    {
        if (!scope.IsEmpty) _queue.Writer.TryWrite(scope);
    }
}

/// <summary>
/// Runs <see cref="RelayAccessCheck"/> every <c>Relay:AccessRecheckInterval</c> over every member, and a targeted pass
/// whenever <see cref="RelayAccessSignal"/> reports an access change. Both run on this one loop, so passes never overlap,
/// and the changes that queued up during a pass are merged into the next targeted one.
/// </summary>
public sealed class RelayAccessWorker(
    IServiceScopeFactory scopes, TimeProvider time, IOptions<RelayOptions> options, RelayAccessSignal signal, ILogger<RelayAccessWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The options are validated at startup (14 §14.4); this guard keeps a worker built without that validation from
        // running passes without pause or failing on every turn.
        var interval = options.Value.AccessRecheckInterval;
        if (interval <= TimeSpan.Zero)
        {
            logger.LogError("Relay:AccessRecheckInterval must be positive; the relay access re-check does not run.");
            return;
        }

        var timer = Task.Delay(interval, time, stoppingToken);
        Task<bool>? changed = null;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // One wait on the queue at a time: it is kept across turns until it completes.
                changed ??= signal.Reader.WaitToReadAsync(stoppingToken).AsTask();
                var woke = await Task.WhenAny(timer, changed);
                RelayAccessScope? target = null;
                if (woke == changed)
                {
                    var open = await changed;
                    changed = null;
                    if (!open) return;
                    var pending = new List<RelayAccessScope>();
                    while (signal.Reader.TryRead(out var next)) pending.Add(next);
                    if (pending.Count == 0) continue;
                    target = RelayAccessScope.Merge(pending);
                }
                else
                {
                    await timer;
                    timer = Task.Delay(interval, time, stoppingToken);
                }

                await using var scope = scopes.CreateAsyncScope();
                var removed = await scope.ServiceProvider.GetRequiredService<RelayAccessCheck>().RunAsync(target, stoppingToken);
                if (removed > 0) logger.LogInformation("The relay access re-check removed {Count} room memberships.", removed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "The relay access re-check failed.");
            }
        }
    }
}
