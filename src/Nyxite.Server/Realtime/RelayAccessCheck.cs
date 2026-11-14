using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Content;
using Nyxite.Persistence;

namespace Nyxite.Server.Realtime;

/// <summary>
/// The relay's periodic ACL re-check (05 §5.4, 09 §9.6). A connection keeps receiving a room's updates and awareness
/// after its join, so join and submit alone would let a reader whose reach ended listen on. This pass judges every
/// connection again: one whose session ended is closed, and one whose account lost reach to the file is removed from
/// that room with <c>OnError(not_found)</c>, and the others get the new roster. It reads only ACL metadata.
/// </summary>
public sealed class RelayAccessCheck(
    RelayPresence presence, IHubContext<RelayHub, IRelayClient> hub, ContentService content, NyxiteDbContext db, TimeProvider time)
{
    /// <summary>Runs one pass and returns how many room memberships it ended.</summary>
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var members = presence.Members();
        if (members.Count == 0) return 0;
        var changed = new HashSet<Guid>();
        var removed = 0;

        // Guests carry no session here; their link share is re-checked once guest sessions exist (Phase 2.2).
        var now = time.GetUtcNow();
        var sessionIds = members.Where(m => m.Member.SessionId is not null).Select(m => m.Member.SessionId!.Value).Distinct().ToList();
        var live = (await db.Sessions.AsNoTracking().Where(s => sessionIds.Contains(s.Id) && s.RevokedAt == null && s.ExpiresAt > now)
            .Select(s => s.Id).ToListAsync(ct)).ToHashSet();
        foreach (var connection in members.Where(m => m.Member.SessionId is { } sid && !live.Contains(sid)).GroupBy(m => m.ConnectionId))
        {
            foreach (var (fileId, _, _) in connection)
                await hub.Clients.Client(connection.Key).OnError(fileId.ToString(), "unauthenticated", "The session has ended.");
            foreach (var fileId in presence.LeaveAll(connection.Key))
            {
                changed.Add(fileId);
                removed++;
            }

            presence.Abort(connection.Key);
        }

        // One query per account and document, however many devices of the account are in the room.
        foreach (var pair in members.Where(m => m.Member.UserId is not null && live.Contains(m.Member.SessionId!.Value))
                     .GroupBy(m => (m.FileId, UserId: m.Member.UserId!.Value)))
        {
            if (await content.AccessLevelAsync(pair.Key.UserId, pair.Key.FileId, ct) != FileAccessLevel.None) continue;
            foreach (var (fileId, connectionId, _) in pair)
            {
                if (!presence.Leave(fileId, connectionId)) continue;
                await hub.Groups.RemoveFromGroupAsync(connectionId, RelayHub.Room(fileId), ct);
                await hub.Clients.Client(connectionId).OnError(fileId.ToString(), "not_found", "Not found.");
                changed.Add(fileId);
                removed++;
            }
        }

        foreach (var fileId in changed) await hub.Clients.Group(RelayHub.Room(fileId)).OnPresence(fileId.ToString(), presence.Roster(fileId));
        return removed;
    }
}

/// <summary>Runs <see cref="RelayAccessCheck"/> every <c>Relay:AccessRecheckInterval</c>.</summary>
public sealed class RelayAccessWorker(
    IServiceScopeFactory scopes, TimeProvider time, IOptions<RelayOptions> options, ILogger<RelayAccessWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.Value.AccessRecheckInterval, time, stoppingToken);
                await using var scope = scopes.CreateAsyncScope();
                var removed = await scope.ServiceProvider.GetRequiredService<RelayAccessCheck>().RunAsync(stoppingToken);
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
