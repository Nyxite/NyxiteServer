using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Server.Realtime;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>A relay client over the real hub (05 §5.3), recording every callback it receives.</summary>
public sealed class RelayPeer(HubConnection connection) : IAsyncDisposable
{
    public List<EncryptedUpdate> Updates { get; } = [];
    public List<byte[]> Awareness { get; } = [];
    public List<PresenceDto[]> Presence { get; } = [];
    public List<(long CrdtSeq, long VersionSeq)> Snapshots { get; } = [];
    public List<string> Errors { get; } = [];
    public HubConnection Connection => connection;

    /// <summary>Set when the server closed the connection.</summary>
    public bool Closed { get; private set; }

    /// <param name="path">The hub path: the account relay, or a guest's <c>/share/{token}/ws</c>.</param>
    /// <param name="handler">Wraps the test server's handler, for a test that records every request the client sends.</param>
    /// <param name="upgrade">Sees the URL of the WebSocket upgrade.</param>
    public static async Task<RelayPeer> ConnectAsync(NyxiteApp app, string? token, bool webSockets = false, string path = RelayHub.Path,
        Func<HttpMessageHandler, HttpMessageHandler>? handler = null, Action<Uri>? upgrade = null)
    {
        var connection = new HubConnectionBuilder()
            .WithUrl("http://localhost" + path, o =>
            {
                o.HttpMessageHandlerFactory = _ => handler is null ? app.Server.CreateHandler() : handler(app.Server.CreateHandler());
                o.Transports = webSockets
                    ? Microsoft.AspNetCore.Http.Connections.HttpTransportType.WebSockets
                    : Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                // The upgrade carries the credential as access_token in the URL, as a browser has to send it.
                o.WebSocketFactory = async (context, ct) =>
                {
                    var uri = token is null ? context.Uri : new Uri(context.Uri + "&access_token=" + Uri.EscapeDataString(token));
                    upgrade?.Invoke(uri);
                    return await app.Server.CreateWebSocketClient().ConnectAsync(uri, ct);
                };
                if (token is not null) o.AccessTokenProvider = () => Task.FromResult<string?>(token);
            })
            .AddMessagePackProtocol()
            .Build();
        var peer = new RelayPeer(connection);
        connection.On<string, EncryptedUpdate[]>("OnUpdates", (_, updates) => { lock (peer.Updates) peer.Updates.AddRange(updates); });
        connection.On<string, EncryptedUpdate>("OnUpdate", (_, update) => { lock (peer.Updates) peer.Updates.Add(update); });
        connection.On<string, byte[]>("OnAwareness", (_, bytes) => { lock (peer.Awareness) peer.Awareness.Add(bytes); });
        connection.On<string, PresenceDto[]>("OnPresence", (_, roster) => { lock (peer.Presence) peer.Presence.Add(roster); });
        connection.On<string, long, long>("OnSnapshot", (_, crdtSeq, versionSeq) => { lock (peer.Snapshots) peer.Snapshots.Add((crdtSeq, versionSeq)); });
        connection.On<string, string, string>("OnError", (_, code, _) => { lock (peer.Errors) peer.Errors.Add(code); });
        connection.Closed += _ =>
        {
            peer.Closed = true;
            return Task.CompletedTask;
        };
        await connection.StartAsync();
        return peer;
    }

    public static async Task UntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++) await Task.Delay(25);
        Assert.True(condition(), "The relay did not deliver in time.");
    }

    public ValueTask DisposeAsync() => connection.DisposeAsync();
}
