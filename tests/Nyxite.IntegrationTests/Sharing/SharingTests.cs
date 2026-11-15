using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Nyxite.Application.Structure;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Server.Realtime;

namespace Nyxite.IntegrationTests.Sharing;

/// <summary>Every log line any provider would write, so a test can prove that no secret or content is in the log.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Lines { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner.Lines.Enqueue($"{category}: {formatter(state, exception)} {exception}");
    }
}

/// <summary>Records every request a client sends: method, URL, headers and body, as the network capture of the test method.</summary>
public sealed class RecordingHandler(HttpMessageHandler inner, ConcurrentQueue<string> requests) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        var headers = string.Join(";", request.Headers.Select(h => h.Key + "=" + string.Join(",", h.Value)));
        requests.Enqueue($"{request.Method} {request.RequestUri} {headers} {body}");
        return await base.SendAsync(request, ct);
    }
}

/// <summary>
/// Phase 2.2 server: account shares with wrapped keys and the subtree batch (P2.2-TC-3), link shares with a hashed
/// token, the guest bootstrap and the guest relay (P2.2-TC-1, TC-2), share abuse limits (P2.2-TC-5), the share audit,
/// and the "nothing leaks" inspection of the database, the blob store, the log and every request a guest sends.
/// </summary>
public sealed class SharingTests(PostgresFixture pg)
{
    private const string Origin = "https://nyxite.test";

    private sealed record Member(StructureDriver S, string Token, Guid Id, byte[] Seed, AuthDriver Auth);

    private static NyxiteApp App(string connectionString, CapturingLoggerProvider? logs = null, IDictionary<string, string?>? overrides = null) =>
        new(connectionString, overrides: overrides ?? new Dictionary<string, string?> { ["Relay:AccessRecheckInterval"] = "01:00:00" },
            configureServices: services =>
            {
                if (logs is not null) services.AddSingleton<ILoggerProvider>(logs);
            });

    /// <summary>A full account on an active device whose directory key is a real X-Wing key, so wraps to it open.</summary>
    private static async Task<Member> MemberAsync(NyxiteApp app, string displayName)
    {
        var auth = new AuthDriver(app);
        var keys = new KeyDriver(auth);
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var userId = await keys.UserIdAsync(token);
        var device = await keys.RegisterAsync(token);
        var seed = RandomNumberGenerator.GetBytes(XWing.SeedSize);
        var identity = new KeyDriver.Identity(Guid.CreateVersion7(), 1, HybridSigningKey.Generate(), XWing.PublicKeyFromSeed(seed));
        Assert.Equal(HttpStatusCode.OK, (await keys.PublishAsync(token, userId, identity)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await keys.ActivateAsync(token, userId, device, identity)).StatusCode);
        await Sql.ExecAsync(app.ConnectionString, "UPDATE users SET display_name = @name WHERE id = @id", ("name", displayName), ("id", userId));
        return new Member(new StructureDriver(auth.Client().WithBearer(token), seed), token, userId, seed, auth);
    }

    /// <summary>What the sharer's client does first: fetch the grantee's public key from the directory.</summary>
    private static async Task<byte[]> DirectoryKeyAsync(Member caller, Guid userId)
    {
        var directory = await (await caller.S.GetAsync($"/keys/directory?userId={userId}")).JsonAsync();
        return Base64UrlCodec.Decode(directory.GetProperty("keys")[0].GetProperty("kemPub").GetString()!);
    }

    private static object Wrap(StructureDriver.Sealed s, Guid memberId, byte[] publicKey) => new
    {
        keyId = s.KeyId, memberId, ciphertext = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, s.Id, s.KeyId, s.Key)), generation = 1,
        algId = CryptoSuite.HpkeAlgId,
    };

    private static object Grant(StructureDriver.Sealed s, Guid memberId, byte[] publicKey, bool folder = false) => new
    {
        fileId = folder ? (Guid?)null : s.Id, folderId = folder ? s.Id : (Guid?)null, keyId = s.KeyId, memberId,
        wrappedKey = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, s.Id, s.KeyId, s.Key)), algId = CryptoSuite.HpkeAlgId,
    };

    private static byte[] Seal(StructureDriver.Sealed file, string text, ObjectKind kind = ObjectKind.Crdt) =>
        NyxcFrame.Seal(file.Key, file.KeyId, file.Id, kind, Encoding.UTF8.GetBytes(text));

    private static string Open(byte[] key, Guid keyId, Guid fileId, byte[] frame, ObjectKind kind = ObjectKind.Crdt) =>
        Encoding.UTF8.GetString(NyxcFrame.Open(key, frame, NyxcFrame.BuildAad(keyId, fileId, kind)));

    private static async Task<HttpResponseMessage> SubmitAsync(StructureDriver s, StructureDriver.Sealed file, byte[] key, string text)
    {
        var frame = NyxcFrame.Seal(key, file.KeyId, file.Id, ObjectKind.Crdt, Encoding.UTF8.GetBytes(text));
        return await s.PostAsync($"/files/{file.Id}/crdt/log",
            new { updates = new[] { new { clientUpdateId = Guid.CreateVersion7(), keyId = file.KeyId, updateEnc = Base64UrlCodec.Encode(frame) } } }, null);
    }

    private static async Task PutSnapshotAsync(StructureDriver s, StructureDriver.Sealed file, long crdtSeq, string text)
    {
        var put = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/snapshot")
        {
            Content = new ByteArrayContent(Seal(file, text, ObjectKind.Snapshot)) { Headers = { ContentType = new("application/octet-stream") } },
        };
        put.Headers.Add("Nyxite-Content-Hash", Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(text))));
        put.Headers.Add("Nyxite-Key-Id", file.KeyId.ToString());
        put.Headers.Add("Nyxite-Snapshot-Seq", crdtSeq.ToString());
        Assert.Equal(HttpStatusCode.Created, (await s.Client.SendAsync(put)).StatusCode);
    }

    private static async Task<Guid> LinkShareAsync(Member owner, StructureDriver.Sealed file, string token, string permission, string? expiresAt = null)
    {
        var response = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "link", permission, linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(token)), expiresAt,
        });
        Assert.True(response.StatusCode == HttpStatusCode.Created, await response.Content.ReadAsStringAsync());
        return (await response.JsonAsync()).GetProperty("id").GetGuid();
    }

    private static async Task<int> RecheckAsync(NyxiteApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RelayAccessCheck>().RunAsync(CancellationToken.None);
    }

    private static HttpClient Anonymous(NyxiteApp app, ConcurrentQueue<string> requests) =>
        new(new RecordingHandler(app.Server.CreateHandler(), requests)) { BaseAddress = app.Server.BaseAddress };

    private static async Task<JsonElement> GuestBootstrapAsync(HttpClient guest, string url) =>
        await (await guest.GetAsync(ShareLink.RequestPath(url))).JsonAsync();

    private static async Task<string> TicketAsync(HttpClient guest, string token, string guestToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"/share/{token}/socket-ticket");
        request.Headers.Authorization = new("Bearer", guestToken);
        var response = await guest.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.JsonAsync()).GetProperty("ticket").GetString()!;
    }

    private static Task<RelayPeer> GuestPeerAsync(NyxiteApp app, string token, string ticket, ConcurrentQueue<string>? requests = null) =>
        RelayPeer.ConnectAsync(app, ticket, webSockets: true, path: $"/share/{token}/ws",
            handler: requests is null ? null : inner => new RecordingHandler(inner, requests), upgrade: uri => requests?.Enqueue("UPGRADE " + uri));

    /// <summary>
    /// The "nothing leaks" inspection (method-api-automated): no row of any table, no file of the blob store and no log
    /// line contains any of <paramref name="secrets"/>, as text or as the hex Postgres renders bytea in.
    /// </summary>
    private static async Task AssertNothingLeaksAsync(NyxiteApp app, CapturingLoggerProvider logs, params byte[][] secrets)
    {
        var needles = secrets.SelectMany(s => new[] { Encoding.UTF8.GetString(s), Convert.ToHexStringLower(s), Base64UrlCodec.Encode(s), Convert.ToBase64String(s) })
            .Where(n => n.Length >= 8).Distinct().ToList();
        var tables = await Sql.ListAsync<string>(app.ConnectionString, "SELECT tablename::text FROM pg_tables WHERE schemaname = 'public'");
        Assert.Contains("shares", tables);
        foreach (var table in tables)
        {
            foreach (var row in await Sql.ListAsync<string>(app.ConnectionString, $"SELECT row_to_json(t)::text FROM \"{table}\" t"))
            foreach (var needle in needles)
                Assert.False(row.Contains(needle, StringComparison.OrdinalIgnoreCase), $"{table} holds a secret: {row}");
        }

        foreach (var path in Directory.Exists(app.BlobRoot) ? Directory.EnumerateFiles(app.BlobRoot, "*", SearchOption.AllDirectories) : [])
        {
            var bytes = await File.ReadAllBytesAsync(path);
            foreach (var secret in secrets) Assert.True(bytes.AsSpan().IndexOf(secret) < 0, $"The blob {path} holds a secret.");
        }

        Assert.NotEmpty(logs.Lines);
        foreach (var line in logs.Lines)
        foreach (var needle in needles)
            Assert.False(line.Contains(needle, StringComparison.Ordinal), $"The log holds a secret: {line}");
    }

    // ---------------------------------------------------------------- account shares (P2.2-TC-3)

    /// <summary>
    /// P2.2-TC-3, server side: U1 shares a folder with U2. The server only ever holds opaque wraps; U2's client unwraps
    /// every key of the subtree with its own seed, reads and writes; the file outside the folder stays unreachable; the
    /// revocation ends reach at fetch, join, submit and in the open room at once.
    /// </summary>
    [Fact]
    public async Task Account_share_of_a_folder_unwraps_off_server_for_the_whole_subtree_and_ends_at_revocation()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = App(await pg.CreateDatabaseAsync(), logs);
        var owner = await MemberAsync(app, "Ada");
        var grantee = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("Quarterly plans");
        var folder = await owner.S.FolderAsync(project, "Shared plans");
        var sub = await owner.S.FolderAsync(project, "Draft plans", folder);
        var alpha = await owner.S.FileAsync(project, "alpha-plan.md", folder);
        var beta = await owner.S.FileAsync(project, "beta-plan.md", sub);
        var sketch = await owner.S.FileAsync(project, "sketch-plan.ink", folder, "ink");
        var hidden = await owner.S.FileAsync(project, "private-plan.md");
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, alpha, alpha.Key, "alpha secret paragraph")).StatusCode);

        // The sharer's client takes the grantee's public key from the directory and wraps locally.
        var publicKey = await DirectoryKeyAsync(owner, grantee.Id);
        Assert.Equal(XWing.PublicKeyFromSeed(grantee.Seed), publicKey);
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType = "folder", targetId = folder.Id, kind = "user_grant", granteeId = grantee.Id, permission = "write",
            wrappedKeys = new[] { Wrap(folder, grantee.Id, publicKey) },
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var shareId = (await created.JsonAsync()).GetProperty("id").GetGuid();
        // One live account share per target and grantee.
        var again = await owner.S.PostAsync("/shares", new
        {
            targetType = "folder", targetId = folder.Id, kind = "user_grant", granteeId = grantee.Id, permission = "read",
            wrappedKeys = new[] { Wrap(folder, grantee.Id, publicKey) },
        });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        // The subtree fan-out: every folder and file key. Each entry is judged on its own.
        object[] grants =
        [
            Grant(sub, grantee.Id, publicKey, folder: true), Grant(alpha, grantee.Id, publicKey), Grant(beta, grantee.Id, publicKey),
            Grant(sketch, grantee.Id, publicKey), Grant(hidden, grantee.Id, publicKey),
            new { fileId = alpha.Id, folderId = sub.Id, keyId = alpha.KeyId, memberId = grantee.Id, wrappedKey = Base64UrlCodec.Encode(new byte[10]) },
        ];
        var batch = await owner.S.PostAsync("/files/keys:batch", new { grants }, null);
        Assert.Equal(HttpStatusCode.OK, batch.StatusCode);
        var results = (await batch.JsonAsync()).GetProperty("results").EnumerateArray().ToList();
        Assert.Equal(["applied", "applied", "applied", "applied", "rejected", "rejected"], results.Select(r => r.GetProperty("status").GetString()));
        Assert.Equal("not_shared", results[4].GetProperty("error").GetString());
        Assert.Equal("validation_failed", results[5].GetProperty("error").GetString());
        // Idempotent: a replay applies again and adds no row.
        const string granteeRows = "SELECT count(*) FROM (SELECT id FROM file_keys WHERE member_id = @g UNION ALL SELECT id FROM structure_keys WHERE member_id = @g) k";
        var rows = await Sql.ScalarAsync<long>(app.ConnectionString, granteeRows, ("g", grantee.Id));
        Assert.Equal(5, rows);
        var replay = (await (await owner.S.PostAsync("/files/keys:batch", new { grants = grants[..4] }, null)).JsonAsync()).GetProperty("results");
        Assert.All(replay.EnumerateArray(), r => Assert.Equal("applied", r.GetProperty("status").GetString()));
        Assert.Equal(rows, await Sql.ScalarAsync<long>(app.ConnectionString, granteeRows, ("g", grantee.Id)));

        // The server holds the wraps byte for byte as sent, for the grantee only, and cannot open them.
        var stored = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT wrapped_key FROM structure_keys WHERE folder_id = @f AND member_id = @g",
            ("f", folder.Id), ("g", grantee.Id));
        Assert.Equal(folder.Key, ObjectKeyWrap.Open(grantee.Seed, folder.Id, folder.KeyId, stored!));
        Assert.ThrowsAny<CryptographicException>(() => ObjectKeyWrap.Open(owner.Seed, folder.Id, folder.KeyId, stored!));

        // The grantee finds the share, walks the subtree and opens every name with keys only its client can unwrap.
        var incoming = (await (await grantee.S.GetAsync("/shares")).JsonAsync()).GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(shareId, Assert.Single(incoming).GetProperty("id").GetGuid());
        Assert.Equal("Shared plans", await grantee.S.ReadNameAsync("folders", folder.Id));
        Assert.Equal(["Draft plans", "Shared plans"], (await grantee.S.ItemsAsync($"/projects/{project.Id}/folders")).Select(grantee.S.NameOf).Order());
        Assert.Equal(["alpha-plan.md", "beta-plan.md", "sketch-plan.ink"], (await grantee.S.ItemsAsync($"/projects/{project.Id}/files")).Select(grantee.S.NameOf).Order());
        Assert.Equal(["beta-plan.md"], (await grantee.S.ItemsAsync($"/folders/{sub.Id}/files")).Select(grantee.S.NameOf));
        Assert.Equal(HttpStatusCode.NotFound, (await grantee.S.GetAsync($"/files/{hidden.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await grantee.S.GetAsync($"/projects/{project.Id}")).StatusCode);
        var lookup = (await (await grantee.S.PostAsync("/keys/lookup", new { fileIds = new[] { alpha.Id, hidden.Id } }, null)).JsonAsync()).GetProperty("items");
        Assert.Equal(alpha.Id, Assert.Single(lookup.EnumerateArray()).GetProperty("id").GetGuid());

        // Content: the grantee decrypts the log with the key it unwrapped, and writes, since the share is a write share.
        var wrapped = (await (await grantee.S.GetAsync($"/files/{alpha.Id}/keys")).JsonAsync()).GetProperty("items")[0];
        var alphaKey = ObjectKeyWrap.Open(grantee.Seed, alpha.Id, alpha.KeyId, Base64UrlCodec.Decode(wrapped.GetProperty("ciphertext").GetString()!));
        var log = (await (await grantee.S.GetAsync($"/files/{alpha.Id}/crdt/log?since=0")).JsonAsync()).GetProperty("items");
        Assert.Equal("alpha secret paragraph", Open(alphaKey, alpha.KeyId, alpha.Id, Base64UrlCodec.Decode(log[0].GetProperty("updateEnc").GetString()!)));
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(grantee.S, alpha, alphaKey, "grace adds a secret line")).StatusCode);
        Assert.Equal(grantee.Id, await Sql.ScalarAsync<Guid>(app.ConnectionString, "SELECT author_id FROM crdt_updates WHERE seq = 2"));

        // Structure and sharing stay with the owner.
        Assert.Equal(HttpStatusCode.Forbidden, (await grantee.S.PatchAsync($"/folders/{folder.Id}", new { nameEnc = StructureDriver.Name(folder, "mine") })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await grantee.S.DeleteAsync($"/files/{alpha.Id}")).StatusCode);
        var reshare = await grantee.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = alpha.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(ShareLink.NewToken())),
        });
        Assert.Equal("acl_denied", await reshare.ProblemCodeAsync());
        Assert.Equal(HttpStatusCode.Forbidden, (await grantee.S.GetAsync($"/shares?targetType=folder&targetId={folder.Id}")).StatusCode);

        // Revocation is instant at every checkpoint: fetch, join, submit and the open room.
        await using var peer = await RelayPeer.ConnectAsync(app, grantee.Token);
        await peer.Connection.InvokeAsync("JoinDocument", alpha.Id.ToString(), 0L);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await grantee.S.GetAsync($"/files/{alpha.Id}/crdt/log?since=0")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await grantee.S.GetAsync($"/folders/{folder.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SubmitAsync(grantee.S, alpha, alphaKey, "too late")).StatusCode);
        var submit = await Assert.ThrowsAsync<HubException>(() =>
            peer.Connection.InvokeAsync<long>("SubmitUpdate", alpha.Id.ToString(), new EncryptedUpdate(0, Seal(alpha, "late"), alpha.KeyId.ToString())));
        Assert.Contains("not_found", submit.Message);
        Assert.Equal(1, await RecheckAsync(app));
        await RelayPeer.UntilAsync(() => peer.Errors.Contains("not_found"));
        Assert.Empty((await (await grantee.S.GetAsync("/shares")).JsonAsync()).GetProperty("items").EnumerateArray());

        await AssertNothingLeaksAsync(app, logs, alpha.Key, beta.Key, folder.Key, sub.Key, grantee.Seed,
            "alpha secret paragraph"u8.ToArray(), "grace adds a secret line"u8.ToArray(), "Shared plans"u8.ToArray(), "alpha-plan.md"u8.ToArray());
    }

    /// <summary>A grantee removes its own share (DL-3): the object stays live for its owner, and a read share never writes.</summary>
    [Fact]
    public async Task A_read_grantee_cannot_write_and_can_remove_its_own_share()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var reader = await MemberAsync(app, "Rita");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var publicKey = await DirectoryKeyAsync(owner, reader.Id);
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = reader.Id, permission = "read",
            wrappedKeys = new[] { Wrap(file, reader.Id, publicKey) },
        });
        var shareId = (await created.JsonAsync()).GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.OK, (await reader.S.GetAsync($"/files/{file.Id}")).StatusCode);
        Assert.Equal("acl_denied", await (await SubmitAsync(reader.S, file, file.Key, "x")).ProblemCodeAsync());
        await using var peer = await RelayPeer.ConnectAsync(app, reader.Token);
        await peer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        var denied = await Assert.ThrowsAsync<HubException>(() =>
            peer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(), new EncryptedUpdate(0, Seal(file, "x"), file.KeyId.ToString())));
        Assert.Contains("acl_denied", denied.Message);

        // A grantee may not change the share, but may drop it.
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.S.PatchAsync($"/shares/{shareId}", new { permission = "write" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await reader.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await reader.S.GetAsync($"/files/{file.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.S.GetAsync($"/files/{file.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
    }

    /// <summary>Share creation rejects what would be no valid share: an own grantee, a missing current key, a link to a folder.</summary>
    [Fact]
    public async Task Share_creation_validates_targets_grantees_keys_and_link_hashes()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var other = await MemberAsync(app, "Bob");
        var project = await owner.S.ProjectAsync("p");
        var folder = await owner.S.FolderAsync(project, "f");
        var file = await owner.S.FileAsync(project, "n.md", folder);
        var publicKey = await DirectoryKeyAsync(owner, other.Id);

        async Task<string> Code(object body) => await (await owner.S.PostAsync("/shares", body)).ProblemCodeAsync();
        Assert.Equal("validation_failed", await Code(new { targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = owner.Id, permission = "read", wrappedKeys = new[] { Wrap(file, owner.Id, publicKey) } }));
        Assert.Equal("validation_failed", await Code(new { targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = other.Id, permission = "read" }));
        Assert.Equal("validation_failed", await Code(new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = other.Id, permission = "read",
            wrappedKeys = new[] { new { keyId = Guid.CreateVersion7(), memberId = other.Id, ciphertext = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, file.Id, file.KeyId, file.Key)), generation = 1 } },
        }));
        Assert.Equal("not_found", await Code(new { targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = Guid.CreateVersion7(), permission = "read", wrappedKeys = new[] { Wrap(file, other.Id, publicKey) } }));
        Assert.Equal("validation_failed", await Code(new { targetType = "folder", targetId = folder.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(new byte[32]) }));
        Assert.Equal("validation_failed", await Code(new { targetType = "file", targetId = file.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(new byte[16]) }));
        Assert.Equal("validation_failed", await Code(new { targetType = "file", targetId = file.Id, kind = "link", permission = "admin", linkTokenHash = Base64UrlCodec.Encode(new byte[32]) }));
        Assert.Equal("validation_failed", await Code(new { targetType = "file", targetId = file.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(new byte[32]), expiresAt = app.Clock.Now.AddMinutes(-1) }));
        Assert.Equal("not_found", await Code(new { targetType = "file", targetId = Guid.CreateVersion7(), kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(new byte[32]) }));
        var token = ShareLink.NewToken();
        await LinkShareAsync(owner, file, token, "read");
        Assert.Equal("conflict", await Code(new { targetType = "file", targetId = file.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(ShareLink.TokenHash(token)) }));
        // Another account's object does not exist for the caller.
        var foreign = await (await other.S.PostAsync("/shares", new { targetType = "file", targetId = file.Id, kind = "link", permission = "read", linkTokenHash = Base64UrlCodec.Encode(new byte[32]) })).ProblemCodeAsync();
        Assert.Equal("not_found", foreign);
        // The owner lists the target's shares; a share never shows its token hash.
        var listed = await (await owner.S.GetAsync($"/shares?targetType=file&targetId={file.Id}")).JsonAsync();
        var share = Assert.Single(listed.GetProperty("items").EnumerateArray());
        Assert.False(share.TryGetProperty("linkTokenHash", out _));
    }

    // ---------------------------------------------------------------- link shares and guests (P2.2-TC-1, TC-2)

    /// <summary>
    /// P2.2-TC-1, server side: a guest opens a write link with no account. Its key comes from the URL fragment, which no
    /// request carries; it gets a guest token, a single-use socket ticket and the relay, reads the encrypted history,
    /// edits with <c>author_id = null</c>, and appears in the roster as a guest. The token is stored only hashed.
    /// </summary>
    [Fact]
    public async Task Guest_with_a_write_link_joins_the_relay_and_edits_with_a_fragment_key_that_no_request_carries()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = App(await pg.CreateDatabaseAsync(), logs);
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "guest-visible-name.md");
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, file, file.Key, "first owner sentence")).StatusCode);
        await PutSnapshotAsync(owner.S, file, 1, "snapshot of the owner text");
        Assert.Equal(HttpStatusCode.OK, (await SubmitAsync(owner.S, file, file.Key, "second owner sentence")).StatusCode);

        var token = ShareLink.NewToken();
        var url = ShareLink.Url(Origin, token, file.Key);
        var shareId = await LinkShareAsync(owner, file, token, "write");
        Assert.Equal(ShareLink.TokenHash(token), await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT link_token_hash FROM shares WHERE id = @id", ("id", shareId)));

        // The guest's client parses the link locally and sends only the path.
        Assert.True(ShareLink.TryParse(url, out var parsedToken, out var fragmentKey));
        var requests = new ConcurrentQueue<string>();
        var guest = Anonymous(app, requests);
        var boot = await GuestBootstrapAsync(guest, url);
        Assert.Equal("write", boot.GetProperty("permission").GetString());
        var shared = boot.GetProperty("file");
        Assert.Equal(file.Id, shared.GetProperty("id").GetGuid());
        Assert.Equal(file.KeyId, shared.GetProperty("keyId").GetGuid());
        Assert.Equal("guest-visible-name.md",
            Open(fragmentKey, file.KeyId, file.Id, Base64UrlCodec.Decode(shared.GetProperty("nameEnc").GetString()!), ObjectKind.Name));
        var guestToken = boot.GetProperty("guestToken").GetString()!;

        // Ciphertext with the guest token: the head snapshot, which the fragment key opens.
        var blob = new HttpRequestMessage(HttpMethod.Get, $"/share/{parsedToken}/blob");
        blob.Headers.Authorization = new("Bearer", guestToken);
        var head = await guest.SendAsync(blob);
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal("1", head.Headers.GetValues("Nyxite-Snapshot-Seq").Single());
        Assert.Equal("snapshot of the owner text", Open(fragmentKey, file.KeyId, file.Id, await head.Content.ReadAsByteArrayAsync(), ObjectKind.Snapshot));

        // The relay: an account and a guest in one room.
        await using var laptop = await RelayPeer.ConnectAsync(app, owner.Token);
        await laptop.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        var ticket = await TicketAsync(guest, parsedToken, guestToken);
        await using var browser = await GuestPeerAsync(app, parsedToken, ticket, requests);
        await browser.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 1L);
        await RelayPeer.UntilAsync(() => browser.Updates.Count == 1 && laptop.Presence.LastOrDefault()?.Length == 2);
        Assert.Equal("second owner sentence", Open(fragmentKey, file.KeyId, file.Id, browser.Updates[0].Ciphertext));
        Assert.Equal([PresenceDto.User, PresenceDto.Guest], laptop.Presence[^1].Select(p => p.Kind));
        Assert.Null(laptop.Presence[^1][1].UserId);

        var frame = NyxcFrame.Seal(fragmentKey, file.KeyId, file.Id, ObjectKind.Crdt, "guest secret edit"u8);
        var seq = await browser.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(), new EncryptedUpdate(0, frame, file.KeyId.ToString()));
        Assert.Equal(3, seq);
        await RelayPeer.UntilAsync(() => laptop.Updates.Any(u => u.Seq == 3));
        Assert.Equal("guest secret edit", Open(file.Key, file.KeyId, file.Id, laptop.Updates.Single(u => u.Seq == 3).Ciphertext));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates WHERE seq = 3 AND author_id IS NULL"));
        Assert.Equal(2L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates WHERE author_id = @o", ("o", owner.Id)));

        // A ticket opens one connection; a guest token works on its own link only and nowhere else.
        await Assert.ThrowsAnyAsync<Exception>(() => GuestPeerAsync(app, parsedToken, ticket));
        var otherFile = await owner.S.FileAsync(project, "other.md");
        var otherToken = ShareLink.NewToken();
        await LinkShareAsync(owner, otherFile, otherToken, "write");
        var foreign = new HttpRequestMessage(HttpMethod.Get, $"/share/{otherToken}/blob");
        foreign.Headers.Authorization = new("Bearer", guestToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await guest.SendAsync(foreign)).StatusCode);
        var api = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/files/{file.Id}");
        api.Headers.Authorization = new("Bearer", guestToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await guest.SendAsync(api)).StatusCode);
        await Assert.ThrowsAnyAsync<Exception>(() => RelayPeer.ConnectAsync(app, guestToken));
        var asUser = new HttpRequestMessage(HttpMethod.Get, $"/share/{parsedToken}/blob");
        asUser.Headers.Authorization = new("Bearer", owner.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await guest.SendAsync(asUser)).StatusCode);

        // A guest joins only its own file.
        var other = await Assert.ThrowsAsync<HubException>(() => browser.Connection.InvokeAsync("JoinDocument", otherFile.Id.ToString(), 0L));
        Assert.Contains("not_found", other.Message);

        // The network capture: the fragment and the file key are in no request the guest sent.
        Assert.Contains(requests, r => r.StartsWith("UPGRADE ", StringComparison.Ordinal));
        string[] fragmentForms = ["#", "k=" + Base64UrlCodec.Encode(fragmentKey), Base64UrlCodec.Encode(fragmentKey), Convert.ToHexStringLower(fragmentKey)];
        foreach (var request in requests)
        foreach (var form in fragmentForms)
            Assert.DoesNotContain(form, request);

        // Link access is audited as a guest, with the share, never the token or a key.
        var audit = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT action || ' ' || actor_kind || ' ' || detail::text FROM audit_log WHERE target_id = @s ORDER BY id", ("s", shareId));
        Assert.Contains(audit, a => a.StartsWith("share.link_access guest", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.StartsWith("share.create user", StringComparison.Ordinal));

        await AssertNothingLeaksAsync(app, logs, Encoding.ASCII.GetBytes(token), file.Key, "guest secret edit"u8.ToArray(),
            "first owner sentence"u8.ToArray(), "guest-visible-name.md"u8.ToArray());
    }

    /// <summary>
    /// P2.2-TC-2, server side: a read link receives updates and awareness, its <c>SubmitUpdate</c> is refused with
    /// <c>OnError(acl_denied)</c>, and its permission follows the share, so a change to write takes effect at once.
    /// </summary>
    [Fact]
    public async Task Read_only_link_receives_updates_and_awareness_but_cannot_submit()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var token = ShareLink.NewToken();
        var shareId = await LinkShareAsync(owner, file, token, "read");
        var guest = Anonymous(app, new ConcurrentQueue<string>());
        var boot = await GuestBootstrapAsync(guest, ShareLink.Url(Origin, token, file.Key));
        Assert.Equal("read", boot.GetProperty("permission").GetString());
        var guestToken = boot.GetProperty("guestToken").GetString()!;

        await using var laptop = await RelayPeer.ConnectAsync(app, owner.Token);
        await laptop.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);
        await using var viewer = await GuestPeerAsync(app, token, await TicketAsync(guest, token, guestToken));
        await viewer.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        await laptop.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(), new EncryptedUpdate(0, Seal(file, "owner types"), file.KeyId.ToString()));
        await RelayPeer.UntilAsync(() => viewer.Updates.Count == 1);
        var cursor = NyxcFrame.Seal(file.Key, file.KeyId, file.Id, ObjectKind.Awareness, "{\"cursor\":1}"u8);
        await laptop.Connection.InvokeAsync("SubmitAwareness", file.Id.ToString(), cursor);
        await RelayPeer.UntilAsync(() => viewer.Awareness.Count == 1);
        await viewer.Connection.InvokeAsync("SubmitAwareness", file.Id.ToString(), cursor);
        await RelayPeer.UntilAsync(() => laptop.Awareness.Count == 1);

        var denied = await Assert.ThrowsAsync<HubException>(() =>
            viewer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(), new EncryptedUpdate(0, Seal(file, "guest tries"), file.KeyId.ToString())));
        Assert.Contains("acl_denied", denied.Message);
        await RelayPeer.UntilAsync(() => viewer.Errors.Contains("acl_denied"));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM crdt_updates"));

        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/shares/{shareId}", new { permission = "write" })).StatusCode);
        Assert.Equal(2, await viewer.Connection.InvokeAsync<long>("SubmitUpdate", file.Id.ToString(), new EncryptedUpdate(0, Seal(file, "now allowed"), file.KeyId.ToString())));
    }

    /// <summary>
    /// The link lifecycle (04 §4.8, 13 §13.6a): a token never issued is <c>404</c>, an issued one that was revoked or has
    /// expired is <c>410</c> on every public endpoint, and a guest already in a room is closed by the next re-check.
    /// </summary>
    [Fact]
    public async Task Unknown_links_are_404_and_revoked_or_expired_links_are_410_everywhere()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var guest = Anonymous(app, new ConcurrentQueue<string>());

        Assert.Equal("not_found", await (await guest.GetAsync($"/share/{ShareLink.NewToken()}")).ProblemCodeAsync());
        Assert.Equal("not_found", await (await guest.GetAsync("/share/short")).ProblemCodeAsync());
        Assert.Equal("not_found", await (await guest.PostAsync($"/share/{ShareLink.NewToken()}/session", null)).ProblemCodeAsync());

        var token = ShareLink.NewToken();
        var shareId = await LinkShareAsync(owner, file, token, "write");
        var guestToken = (await GuestBootstrapAsync(guest, ShareLink.Url(Origin, token, file.Key))).GetProperty("guestToken").GetString()!;
        var renewed = await (await guest.PostAsync($"/share/{token}/session", null)).JsonAsync();
        Assert.Equal(app.Clock.Now.AddMinutes(15), renewed.GetProperty("expiresAt").GetDateTimeOffset());
        await using var browser = await GuestPeerAsync(app, token, await TicketAsync(guest, token, guestToken));
        await browser.Connection.InvokeAsync("JoinDocument", file.Id.ToString(), 0L);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
        Assert.Equal("share_revoked", await (await guest.GetAsync($"/share/{token}")).ProblemCodeAsync());
        Assert.Equal("share_revoked", await (await guest.PostAsync($"/share/{token}/session", null)).ProblemCodeAsync());
        var ticket = new HttpRequestMessage(HttpMethod.Post, $"/share/{token}/socket-ticket");
        ticket.Headers.Authorization = new("Bearer", guestToken);
        Assert.Equal("share_revoked", await (await guest.SendAsync(ticket)).ProblemCodeAsync());
        Assert.Equal(1, await RecheckAsync(app));
        await RelayPeer.UntilAsync(() => browser.Errors.Contains("share_revoked") && browser.Closed);

        // A shared file in Trash is gone for its guests.
        var trashed = await owner.S.FileAsync(project, "trashed.md");
        var live = ShareLink.NewToken();
        await LinkShareAsync(owner, trashed, live, "read");
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/files/{trashed.Id}")).StatusCode);
        Assert.Equal("not_found", await (await guest.GetAsync($"/share/{live}")).ProblemCodeAsync());

        var expiring = ShareLink.NewToken();
        await LinkShareAsync(owner, file, expiring, "read", app.Clock.Now.AddHours(1).ToString("O"));
        Assert.Equal(HttpStatusCode.OK, (await guest.GetAsync($"/share/{expiring}")).StatusCode);
        app.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal("link_expired", await (await guest.GetAsync($"/share/{expiring}")).ProblemCodeAsync());
        Assert.Equal("link_expired", await (await guest.PostAsync($"/share/{expiring}/session", null)).ProblemCodeAsync());
    }

    /// <summary>A purge takes the shares of what it purges with it, so no grant or link hash outlives its object (09 §9.2).</summary>
    [Fact]
    public async Task Purging_a_shared_file_removes_its_shares()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var grantee = await MemberAsync(app, "Grace");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        await LinkShareAsync(owner, file, ShareLink.NewToken(), "read");
        var publicKey = await DirectoryKeyAsync(owner, grantee.Id);
        Assert.Equal(HttpStatusCode.Created, (await owner.S.PostAsync("/shares", new
        {
            targetType = "project", targetId = project.Id, kind = "user_grant", granteeId = grantee.Id, permission = "read",
            wrappedKeys = new[] { Wrap(project, grantee.Id, publicKey) },
        })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/projects/{project.Id}")).StatusCode);
        app.Clock.Advance(TimeSpan.FromDays(61));
        await using (var scope = app.Services.CreateAsyncScope())
            Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<TrashPurger>().RunAsync(CancellationToken.None));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM shares"));
    }

    // ---------------------------------------------------------------- abuse limits (P2.2-TC-5)

    /// <summary>P2.2-TC-5, server side: the three share-abuse buckets answer <c>429</c> with <c>Retry-After</c> at their 13 §13.5 values.</summary>
    [Fact]
    public async Task Share_creation_link_access_and_directory_lookups_are_rate_limited()
    {
        await using var app = App(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?>
        {
            ["RateLimiting:Shares:PermitLimit"] = "30",
            ["RateLimiting:ShareAccess:PermitLimit"] = "30",
            ["RateLimiting:Directory:PermitLimit"] = "60",
        });
        var owner = await MemberAsync(app, "Ada");
        var guest = Anonymous(app, new ConcurrentQueue<string>());

        async Task AssertLimitedAsync(int permits, Func<Task<HttpResponseMessage>> call)
        {
            for (var i = 0; i < permits; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, (await call()).StatusCode);
            var limited = await call();
            Assert.Equal("rate_limited", await limited.ProblemCodeAsync());
            Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single()) > 0);
        }

        await AssertLimitedAsync(30, () => owner.S.PostAsync("/shares", new { targetType = "file", targetId = Guid.CreateVersion7(), kind = "link", permission = "read" }));
        await AssertLimitedAsync(30, () => guest.GetAsync($"/share/{ShareLink.NewToken()}"));
        Assert.Equal(HttpStatusCode.TooManyRequests, (await guest.PostAsync($"/share/{ShareLink.NewToken()}/session", null)).StatusCode);
        await AssertLimitedAsync(60, () => owner.S.GetAsync($"/keys/directory?userId={owner.Id}"));
    }

    // ---------------------------------------------------------------- audit and contract

    /// <summary>Share changes are audited with target and actor, never a key, a token or its hash (09 §9.7).</summary>
    [Fact]
    public async Task Share_create_update_and_revoke_are_audited_without_keys_or_token_hashes()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Ada");
        var project = await owner.S.ProjectAsync("p");
        var file = await owner.S.FileAsync(project, "note.md");
        var token = ShareLink.NewToken();
        var shareId = await LinkShareAsync(owner, file, token, "read");
        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/shares/{shareId}", new { permission = "write", expiresAt = app.Clock.Now.AddDays(1) })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.S.DeleteAsync($"/shares/{shareId}")).StatusCode);

        var events = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT action || '|' || actor_kind || '|' || coalesce(actor_id::text, '') || '|' || detail::text FROM audit_log WHERE target_id = @s ORDER BY id", ("s", shareId));
        Assert.Equal(["share.create", "share.update", "share.revoke"], events.Select(e => e.Split('|')[0]));
        Assert.All(events, e => Assert.Equal(owner.Id.ToString(), e.Split('|')[2]));
        var hash = ShareLink.TokenHash(token);
        Assert.All(events, e =>
        {
            Assert.DoesNotContain(token, e);
            Assert.DoesNotContain(Base64UrlCodec.Encode(hash), e);
            Assert.DoesNotContain(Convert.ToHexStringLower(hash), e);
        });
    }

    /// <summary>P2.2-CORE-1 build gate on the server: every request and response of <c>sharing.json</c> is what the contract documents.</summary>
    [Fact]
    public void Sharing_fixtures_match_the_openapi_contract()
    {
        var v = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Resources", "vectors", "sharing.json"))).RootElement;
        var drift = new List<string>();
        foreach (var request in v.GetProperty("requests").EnumerateArray())
        {
            var path = request.GetProperty("path").GetString()!.Split('?')[0];
            if (path.EndsWith("/ws", StringComparison.Ordinal)) continue;
            var operation = OpenApiContract.Operation(request.GetProperty("method").GetString()!, path);
            if (operation is null)
            {
                drift.Add($"{request.GetProperty("name")}: no operation");
                continue;
            }

            if (request.GetProperty("body").ValueKind != JsonValueKind.Null)
                drift.AddRange(OpenApiContract.CheckRequestBody(operation, request.GetProperty("body")).Select(e => $"{request.GetProperty("name")}: {e}"));
        }

        foreach (var response in v.GetProperty("responses").EnumerateArray())
        {
            var operation = OpenApiContract.Operation(response.GetProperty("method").GetString()!, response.GetProperty("path").GetString()!)!;
            var status = response.GetProperty("status").GetInt32();
            var body = response.GetProperty("body");
            var (media, bytes) = body.ValueKind == JsonValueKind.Null
                ? (null, Array.Empty<byte>())
                : (status >= 400 ? "application/problem+json" : "application/json", Encoding.UTF8.GetBytes(body.GetRawText()));
            drift.AddRange(OpenApiContract.CheckResponse(operation, status, media, bytes).Select(e => $"{response.GetProperty("name")}: {e}"));
        }

        Assert.True(drift.Count == 0, string.Join("\n", drift));
    }

    /// <summary>The schema keeps only a hash of a link token and opaque wrapped keys: no column could hold a token or a usable key.</summary>
    [Fact]
    public async Task Schema_stores_link_tokens_hashed_and_keys_wrapped_only()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        _ = app.CreateClient();
        var columns = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT table_name || '.' || column_name || ':' || data_type FROM information_schema.columns WHERE table_name IN ('shares','file_keys','structure_keys')");
        Assert.Contains("shares.link_token_hash:bytea", columns);
        Assert.DoesNotContain(columns, c => c.StartsWith("shares.", StringComparison.Ordinal) && c.Contains("token") && !c.StartsWith("shares.link_token_hash", StringComparison.Ordinal));
        var names = columns.Select(c => c.Split('.')[1]).ToList();
        Assert.DoesNotContain(names, c => c.Contains("fragment") || c.Contains("dek") || c.Contains("kek") || c.Contains("plain") || c.StartsWith("token"));
        Assert.Equal(["file_keys.wrapped_key:bytea", "structure_keys.wrapped_key:bytea"],
            columns.Where(c => c.Contains("key:") && !c.Contains("_id:")).Order());
        var check = await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_shares_kind_fields'");
        Assert.Contains("octet_length(link_token_hash) = 32", check);
    }
}
