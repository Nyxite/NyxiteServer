using System.Collections.Concurrent;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Application.Sharing;
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

/// <summary>
/// A connection in a room: what the roster shows, and what the periodic re-check needs to judge it again. An account
/// has its user and session, a link guest only the share it came through.
/// </summary>
public sealed record RelayMember(PresenceDto Who, Guid? UserId, Guid? SessionId, Guid? ShareId = null);

/// <summary>
/// Who is connected to which document room. In memory, because v1 runs one node (05 §5.10). A room that becomes empty
/// is forgotten (05 §5.9), so the map holds only rooms someone is in, and the re-check walks only those.
/// </summary>
public sealed class RelayPresence
{
    /// <summary>
    /// One room's members. <see cref="Closed"/> is set, under the room's lock, when the last member leaves and the room is
    /// taken out of the map, so a join that still holds this instance retries with a fresh one instead of landing in a
    /// room nobody can see.
    /// </summary>
    private sealed class Room
    {
        public readonly ConcurrentDictionary<string, RelayMember> Members = new();
        public bool Closed;
    }

    private readonly ConcurrentDictionary<Guid, Room> _rooms = new();
    private readonly ConcurrentDictionary<string, HubCallerContext> _connections = new();

    public void Connect(HubCallerContext context) => _connections[context.ConnectionId] = context;

    public void Disconnect(string connectionId) => _connections.TryRemove(connectionId, out _);

    /// <summary>Closes a connection from outside the hub, as when its session ended. Its rooms are left by the caller.</summary>
    public void Abort(string connectionId)
    {
        if (_connections.TryRemove(connectionId, out var context)) context.Abort();
    }

    public void Join(Guid fileId, string connectionId, RelayMember member) => TryJoin(fileId, connectionId, member, int.MaxValue);

    /// <summary>
    /// Enters a room unless it already holds <paramref name="maxConnections"/> other connections (13 §13.5). The count
    /// and the entry happen under the room's lock, so concurrent joins cannot overfill it. A connection that is already
    /// in the room always stays.
    /// </summary>
    public bool TryJoin(Guid fileId, string connectionId, RelayMember member, int maxConnections)
    {
        while (true)
        {
            var room = _rooms.GetOrAdd(fileId, _ => new Room());
            lock (room)
            {
                if (room.Closed) continue;
                if (!room.Members.ContainsKey(connectionId) && room.Members.Count >= maxConnections) return false;
                room.Members[connectionId] = member;
                return true;
            }
        }
    }

    /// <summary>How many connections a room holds now.</summary>
    public int ConnectionCount(Guid fileId) => _rooms.TryGetValue(fileId, out var room) ? room.Members.Count : 0;

    /// <summary>
    /// How many rooms a connection is in now. A connection's hub calls run one at a time, so its own joins cannot race
    /// this count; a concurrent removal by the re-check only lowers it.
    /// </summary>
    public int RoomCount(string connectionId) => _rooms.Values.Count(r => r.Members.ContainsKey(connectionId));

    public bool Leave(Guid fileId, string connectionId)
    {
        if (!_rooms.TryGetValue(fileId, out var room)) return false;
        lock (room)
        {
            if (!room.Members.TryRemove(connectionId, out _)) return false;
            // Only this exact empty instance is removed, so a room a concurrent join has already replaced stays.
            if (room.Members.IsEmpty)
            {
                room.Closed = true;
                _rooms.TryRemove(KeyValuePair.Create(fileId, room));
            }

            return true;
        }
    }

    public bool IsIn(Guid fileId, string connectionId) => _rooms.TryGetValue(fileId, out var room) && room.Members.ContainsKey(connectionId);

    public List<Guid> LeaveAll(string connectionId) => _rooms.Keys.Where(fileId => Leave(fileId, connectionId)).ToList();

    /// <summary>Every connection of every room at this moment, for the periodic re-check.</summary>
    public List<(Guid FileId, string ConnectionId, RelayMember Member)> Members() =>
        _rooms.SelectMany(r => r.Value.Members.Select(m => (r.Key, m.Key, m.Value))).ToList();

    /// <summary>
    /// One entry per account, however many devices it has in the room, ordered by id; then one entry per guest
    /// connection, because a guest has no identity to merge by.
    /// </summary>
    public PresenceDto[] Roster(Guid fileId)
    {
        if (!_rooms.TryGetValue(fileId, out var room)) return [];
        var members = room.Members.Values.ToList();
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
/// <para>
/// The same hub serves link guests at <see cref="GuestPath"/> (05 §5.8), so accounts and guests share one room. A guest
/// connection is authenticated by its guest token, reaches only the file of its link share, is shown as a guest
/// without identity, and writes with <c>author_id = null</c>; a read-only link's <c>SubmitUpdate</c> answers
/// <c>acl_denied</c>. Authorization comes from the two endpoint mappings, not from an attribute, because each path
/// takes its own credential.
/// </para>
/// </summary>
public sealed class RelayHub(
    ContentService content, RelayPresence presence, NyxiteDbContext db, DeviceGuard guard, GuestShareService guests, TimeProvider time,
    IOptions<RelayOptions> options)
    : Hub<IRelayClient>
{
    private readonly RelayOptions _limits = options.Value;

    public const string Path = "/hubs/relay";

    /// <summary>The guest relay (04 §4.8): WebSockets only, so the per-IP share-access limit counts one handshake per connection.</summary>
    public const string GuestPath = "/share/{token}/ws";

    private const int JoinBatch = 200;

    public static string Room(Guid fileId) => $"file:{fileId}";

    public static EncryptedUpdate ToWire(CrdtUpdateDto u) => new(u.Seq, Base64UrlCodec.Decode(u.UpdateEnc), u.KeyId.ToString());

    /// <summary>
    /// Joins a room (05 §5.4). The session must be live and the account must reach the file. The connection enters the
    /// group and the presence together before the log is read, so no update falls in between and the periodic re-check
    /// judges it from that moment on; a client drops what it gets twice by its sequence number. When any step after that
    /// fails, both are rolled back, so no connection receives a room's traffic without being one the re-check sees.
    /// </summary>
    public async Task JoinDocument(string fileId, long sinceSeq)
    {
        var id = Parse(fileId);
        await GuardAsync(fileId, async () =>
        {
            var user = Context.User!;
            var ct = Context.ConnectionAborted;
            RelayMember member;
            if (user.GuestShareId() is { } shareId)
            {
                // A guest's share must still be live (410 otherwise) and reaches its one file only.
                var share = await guests.LiveShareAsync(shareId, ct);
                if (share.FileId != id) throw AuthException.NotFound();
                // A link a rotation kept opens nothing the room carries, so it has no room (09 §9.6).
                if (share.FrozenGeneration is not null) throw GuestShareService.Frozen();
                member = new RelayMember(PresenceDto.ForGuest(), null, null, shareId);
            }
            else
            {
                var session = await guard.SessionAsync(user, ct);
                if (session.ExpiresAt <= time.GetUtcNow()) throw AuthException.Unauthenticated();
                var userId = user.UserId();
                var name = await db.Users.Where(u => u.Id == userId).Select(u => u.DisplayName).SingleAsync(ct);
                member = new RelayMember(PresenceDto.ForUser(userId, name), userId, session.Id);
            }

            // Reach is checked by the first read, and the relay limits only after it, so a full room is never news to
            // someone who could not open it. The early check spares a full room the log read; the atomic one decides.
            var snapshot = await content.SnapshotPointerAsync(user, id, ct);
            if (!presence.IsIn(id, Context.ConnectionId))
            {
                if (presence.RoomCount(Context.ConnectionId) >= _limits.MaxRoomsPerConnection) throw TooManyRooms();
                if (presence.ConnectionCount(id) >= _limits.MaxConnectionsPerRoom) throw RoomFull();
            }

            try
            {
                await Groups.AddToGroupAsync(Context.ConnectionId, Room(id), ct);
                if (!presence.TryJoin(id, Context.ConnectionId, member, _limits.MaxConnectionsPerRoom)) throw RoomFull();
                // A disconnect that ran while the join was under way has already left every room, so the join must not stay.
                ct.ThrowIfCancellationRequested();
                if (snapshot is not null) await Clients.Caller.OnSnapshot(fileId, snapshot.CrdtSeq ?? 0, snapshot.Seq);

                var since = Math.Max(0, sinceSeq);
                while (true)
                {
                    var page = await content.ReadUpdatesAsync(user, id, since, JoinBatch, ct);
                    await Clients.Caller.OnUpdates(fileId, page.Items.Select(ToWire).ToArray());
                    if (!page.HasMore) break;
                    since = page.Items[^1].Seq;
                }
            }
            catch
            {
                await LeaveRoomAsync(id);
                throw;
            }

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
    /// its join, kept current by the periodic re-check instead of a query per message at caret rate. A payload that is
    /// not an NYXC frame is refused, so an unsealed cursor never passes the relay; the <c>object_kind</c> sits in the AAD
    /// and cannot be checked here.
    /// <para>
    /// Each connection has a budget of <c>Relay:AwarenessPerSecond</c> messages (13 §13.5), because every message is
    /// copied to everyone in the room and nothing else brakes a member, a read-only guest included. A message beyond it
    /// is refused with <c>rate_limited</c> and not forwarded; the connection stays, because awareness is a stream of
    /// whole states and the next one replaces what was dropped.
    /// </para>
    /// </summary>
    public async Task SubmitAwareness(string fileId, byte[] awarenessCipher)
    {
        var id = Parse(fileId);
        await GuardAsync(fileId, async () =>
        {
            if (!presence.IsIn(id, Context.ConnectionId)) throw AuthException.NotFound();
            if (!Budget().TryTake(time)) throw new AuthException(429, "rate_limited", "Too many awareness messages.");
            if (awarenessCipher.Length > content.MaxAwarenessBytes) throw ContentService.PayloadTooLarge("The awareness message is too large.");
            if (!NyxcFrame.TryParseHeader(awarenessCipher, out _)) throw AuthException.Validation("The awareness message must be an NYXC frame.");
            await Clients.OthersInGroup(Room(id)).OnAwareness(fileId, awarenessCipher);
        });
    }

    public async Task LeaveDocument(string fileId) => await LeaveRoomAsync(Parse(fileId));

    /// <summary>
    /// Takes the caller out of a room: the group first, so a failure in between never leaves a listener the re-check
    /// cannot see, then the presence, and the room gets the new roster when the caller was in it.
    /// </summary>
    private async Task LeaveRoomAsync(Guid id)
    {
        try
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, Room(id), CancellationToken.None);
        }
        finally
        {
            if (presence.Leave(id, Context.ConnectionId)) await Clients.Group(Room(id)).OnPresence(id.ToString(), presence.Roster(id));
        }
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

    public const string RoomFullCode = "room_full";
    public const string TooManyRoomsCode = "too_many_rooms";

    private static AuthException RoomFull() => new(409, RoomFullCode, "This document has as many connections as the relay allows.");

    private static AuthException TooManyRooms() => new(409, TooManyRoomsCode, "This connection is in as many documents as the relay allows.");

    /// <summary>The connection's awareness budget, kept with the connection for its lifetime.</summary>
    private AwarenessBudget Budget()
    {
        const string key = "nyxite.awareness";
        if (Context.Items.TryGetValue(key, out var existing)) return (AwarenessBudget)existing!;
        var budget = new AwarenessBudget(_limits.AwarenessPerSecond, time.GetTimestamp());
        Context.Items[key] = budget;
        return budget;
    }

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

/// <summary>
/// A token bucket of awareness messages: it holds at most one second's worth and refills continuously at
/// <paramref name="perSecond"/>. It counts messages only and never looks at them.
/// </summary>
public sealed class AwarenessBudget(int perSecond, long startTimestamp)
{
    private double _tokens = perSecond;
    private long _last = startTimestamp;
    private readonly Lock _gate = new();

    public bool TryTake(TimeProvider time)
    {
        lock (_gate)
        {
            var now = time.GetTimestamp();
            _tokens = Math.Min(perSecond, _tokens + (double)(now - _last) / time.TimestampFrequency * perSecond);
            _last = now;
            if (_tokens < 1) return false;
            _tokens -= 1;
            return true;
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
        services.AddSingleton<RelayAccessSignal>();
        services.AddSingleton<IRelayAccessEvents>(sp => sp.GetRequiredService<RelayAccessSignal>());
        services.AddHostedService<RelayAccessWorker>();
        return services;
    }
}
