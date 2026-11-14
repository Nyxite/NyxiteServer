using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Contracts.Content;
using Nyxite.Crypto;
using Nyxite.Persistence;

namespace Nyxite.Server.Realtime;

/// <summary>An encrypted update on the relay wire (05 §5.3). <c>KeyId</c> is a canonical UUID string, <c>Ciphertext</c> raw bytes.</summary>
public sealed record EncryptedUpdate(long Seq, byte[] Ciphertext, string KeyId);

/// <summary>
/// One entry of a room's roster (05 §5.7): an account by id and display name, or a guest without either. Identities
/// only, never content. <c>Kind</c> is <c>user</c> or <c>guest</c>.
/// </summary>
public sealed record PresenceDto(string Kind, string? UserId, string? DisplayName)
{
    public const string User = "user";
    public const string Guest = "guest";

    public static PresenceDto ForUser(Guid userId, string displayName) => new(User, userId.ToString(), displayName);

    public static PresenceDto ForGuest() => new(Guest, null, null);
}

/// <summary>Server to client callbacks. Every payload that carries content is ciphertext.</summary>
public interface IRelayClient
{
    /// <summary>The head snapshot to start from, sent on join before the updates when one exists.</summary>
    Task OnSnapshot(string fileId, long crdtSeq, long versionSeq);
    Task OnUpdates(string fileId, EncryptedUpdate[] updates);
    Task OnUpdate(string fileId, EncryptedUpdate update);
    Task OnAwareness(string fileId, byte[] awarenessCipher);
    Task OnPresence(string fileId, PresenceDto[] peers);
    Task OnError(string fileId, string code, string message);
}

/// <summary>A connection in a room: what the roster shows, and what the periodic re-check needs to judge it again.</summary>
public sealed record RelayMember(PresenceDto Who, Guid? UserId, Guid? SessionId);

/// <summary>Who is connected to which document room. In memory, because v1 runs one node (05 §5.10).</summary>
public sealed class RelayPresence
{
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<string, RelayMember>> _rooms = new();
    private readonly ConcurrentDictionary<string, HubCallerContext> _connections = new();

    public void Connect(HubCallerContext context) => _connections[context.ConnectionId] = context;

    public void Disconnect(string connectionId) => _connections.TryRemove(connectionId, out _);

    /// <summary>Closes a connection from outside the hub, as when its session ended. Its rooms are left by the caller.</summary>
    public void Abort(string connectionId)
    {
        if (_connections.TryRemove(connectionId, out var context)) context.Abort();
    }

    public void Join(Guid fileId, string connectionId, RelayMember member) => _rooms.GetOrAdd(fileId, _ => new())[connectionId] = member;

    public bool Leave(Guid fileId, string connectionId) => _rooms.TryGetValue(fileId, out var room) && room.TryRemove(connectionId, out _);

    public bool IsIn(Guid fileId, string connectionId) => _rooms.TryGetValue(fileId, out var room) && room.ContainsKey(connectionId);

    public List<Guid> LeaveAll(string connectionId) => _rooms.Where(r => r.Value.TryRemove(connectionId, out _)).Select(r => r.Key).ToList();

    /// <summary>Every connection of every room at this moment, for the periodic re-check.</summary>
    public List<(Guid FileId, string ConnectionId, RelayMember Member)> Members() =>
        _rooms.SelectMany(r => r.Value.Select(m => (r.Key, m.Key, m.Value))).ToList();

    /// <summary>
    /// One entry per account, however many devices it has in the room, ordered by id; then one entry per guest
    /// connection, because a guest has no identity to merge by.
    /// </summary>
    public PresenceDto[] Roster(Guid fileId)
    {
        if (!_rooms.TryGetValue(fileId, out var room)) return [];
        var members = room.Values.ToList();
        return members.Where(m => m.Who.Kind == PresenceDto.User).Select(m => m.Who).DistinctBy(p => p.UserId)
            .OrderBy(p => p.UserId, StringComparer.Ordinal)
            .Concat(members.Where(m => m.Who.Kind == PresenceDto.Guest).Select(m => m.Who))
            .ToArray();
    }
}

/// <summary>Forwards updates that were stored over REST into the document's room.</summary>
public sealed class RelayNotifier(IHubContext<RelayHub, IRelayClient> hub) : IRelayNotifier
{
    public Task UpdatesStoredAsync(Guid fileId, IReadOnlyList<CrdtUpdateDto> updates, CancellationToken ct) =>
        hub.Clients.Group(RelayHub.Room(fileId)).OnUpdates(fileId.ToString(), updates.Select(RelayHub.ToWire).ToArray());
}

/// <summary>
/// The blind relay (05): per document a room that hands out the stored encrypted updates on join and forwards new ones.
/// The hub persists through <see cref="ContentService"/>, which also checks reach on every call, and never looks into a
/// payload. An update a client submits here reaches the room through <see cref="RelayNotifier"/>, the sender included,
/// so every client sees every update in sequence order from one source. Several accounts and devices share a room;
/// the ACL is checked at join and at every submit, and <see cref="RelayAccessCheck"/> checks it again periodically.
/// </summary>
[Authorize]
public sealed class RelayHub(ContentService content, RelayPresence presence, NyxiteDbContext db) : Hub<IRelayClient>
{
    public const string Path = "/hubs/relay";

    private const int JoinBatch = 200;

    public static string Room(Guid fileId) => $"file:{fileId}";

    public static EncryptedUpdate ToWire(CrdtUpdateDto u) => new(u.Seq, Base64UrlCodec.Decode(u.UpdateEnc), u.KeyId.ToString());

    public async Task JoinDocument(string fileId, long sinceSeq)
    {
        var id = Parse(fileId);
        await GuardAsync(fileId, async () =>
        {
            var user = Context.User!;
            // Reach is checked by the first read. The room is joined before the log is read, so no update falls in between;
            // a client drops what it gets twice by its sequence number.
            var snapshot = await content.SnapshotPointerAsync(user, id, Context.ConnectionAborted);
            await Groups.AddToGroupAsync(Context.ConnectionId, Room(id), Context.ConnectionAborted);
            if (snapshot is not null) await Clients.Caller.OnSnapshot(fileId, snapshot.CrdtSeq ?? 0, snapshot.Seq);

            var since = Math.Max(0, sinceSeq);
            while (true)
            {
                var page = await content.ReadUpdatesAsync(user, id, since, JoinBatch, Context.ConnectionAborted);
                await Clients.Caller.OnUpdates(fileId, page.Items.Select(ToWire).ToArray());
                if (!page.HasMore) break;
                since = page.Items[^1].Seq;
            }

            var userId = user.UserId();
            var name = await db.Users.Where(u => u.Id == userId).Select(u => u.DisplayName).SingleAsync(Context.ConnectionAborted);
            presence.Join(id, Context.ConnectionId, new RelayMember(PresenceDto.ForUser(userId, name), userId, user.SessionIdOf()));
            await Clients.Group(Room(id)).OnPresence(fileId, presence.Roster(id));
        });
    }

    /// <summary>Persists one encrypted update and returns its sequence number, which is the acknowledgement that it is durable.</summary>
    public async Task<long> SubmitUpdate(string fileId, EncryptedUpdate update)
    {
        var id = Parse(fileId);
        return await GuardAsync(fileId, async () =>
        {
            if (!Guid.TryParse(update.KeyId, out var keyId)) throw AuthException.Validation("keyId is not a UUID.");
            var item = new SubmitUpdateItem(Guid.CreateVersion7(), keyId, Base64UrlCodec.Encode(update.Ciphertext));
            return (await content.SubmitUpdatesAsync(Context.User!, id, [item], Context.ConnectionAborted)).Acks[0].Seq;
        });
    }

    /// <summary>
    /// Forwards encrypted awareness (cursors, selections, a label: <c>object_kind</c> 6) to the others in the room. It is
    /// never stored, in Postgres, the blob store or a log. Only a connection in the room may send, so reach is the one of
    /// its join, kept current by the periodic re-check instead of a query per message at caret rate.
    /// </summary>
    public async Task SubmitAwareness(string fileId, byte[] awarenessCipher)
    {
        var id = Parse(fileId);
        await GuardAsync(fileId, async () =>
        {
            if (!presence.IsIn(id, Context.ConnectionId)) throw AuthException.NotFound();
            if (awarenessCipher.Length > content.MaxAwarenessBytes) throw ContentService.PayloadTooLarge("The awareness message is too large.");
            await Clients.OthersInGroup(Room(id)).OnAwareness(fileId, awarenessCipher);
        });
    }

    public async Task LeaveDocument(string fileId)
    {
        var id = Parse(fileId);
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, Room(id));
        if (presence.Leave(id, Context.ConnectionId)) await Clients.Group(Room(id)).OnPresence(fileId, presence.Roster(id));
    }

    public override Task OnConnectedAsync()
    {
        presence.Connect(Context);
        return base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        presence.Disconnect(Context.ConnectionId);
        foreach (var id in presence.LeaveAll(Context.ConnectionId)) await Clients.Group(Room(id)).OnPresence(id.ToString(), presence.Roster(id));
        await base.OnDisconnectedAsync(exception);
    }

    private static Guid Parse(string fileId) => Guid.TryParse(fileId, out var id) ? id : throw new HubException("validation_failed");

    private Task GuardAsync(string fileId, Func<Task> action) => GuardAsync(fileId, async () =>
    {
        await action();
        return 0;
    });

    /// <summary>An expected failure reaches the caller twice: as <c>OnError</c> for the room UI and as the failed call, whose message is the stable code.</summary>
    private async Task<T> GuardAsync<T>(string fileId, Func<Task<T>> action)
    {
        try
        {
            return await action();
        }
        catch (AuthException e)
        {
            await Clients.Caller.OnError(fileId, e.Code, e.Message);
            throw new HubException(e.Code);
        }
    }
}

public static class RelaySetup
{
    public static IServiceCollection AddNyxiteRelay(this IServiceCollection services)
    {
        services.AddSignalR(o => o.MaximumReceiveMessageSize = 2 * 1024 * 1024).AddMessagePackProtocol();
        services.AddSingleton<RelayPresence>();
        services.AddSingleton<IRelayNotifier, RelayNotifier>();
        services.AddScoped<RelayAccessCheck>();
        services.AddHostedService<RelayAccessWorker>();
        return services;
    }
}
