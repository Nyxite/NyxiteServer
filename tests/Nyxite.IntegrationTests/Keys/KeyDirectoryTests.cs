using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Keys;

/// <summary>Public-key directory and its KT leaves (server 04 <c>/keys</c>, 17 §17.3, §17.6).</summary>
public sealed class KeyDirectoryTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth, KeyDriver Keys)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        return (app, auth, new KeyDriver(auth));
    }

    [Fact]
    public async Task First_publish_appends_the_byte_exact_leaf_and_is_served_by_id_and_email()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var userId = await keys.UserIdAsync(token);
        var id = KeyDriver.NewIdentity();

        var published = await keys.PublishAsync(token, userId, id);
        Assert.Equal(HttpStatusCode.OK, published.StatusCode);
        var dto = await published.JsonAsync();
        Assert.Equal(0, dto.GetProperty("ktLeafIndex").GetInt64());
        Assert.False(dto.GetProperty("revoked").GetBoolean());

        var leaf = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT leaf_data FROM kt_leaves WHERE leaf_index = 0");
        var hash = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT leaf_hash FROM kt_leaves WHERE leaf_index = 0");
        var loggedMs = dto.GetProperty("loggedAt").GetDateTimeOffset().ToUnixTimeMilliseconds();
        var message = DirectoryEntry.SignedMessage(DirectoryEntryType.UserKeyPublish, userId, id.KeyId, 1, CryptoSuite.DirectoryAlgId, id.KemPub, id.Signing.PublicKey);
        var selfSig = Base64UrlCodec.Decode(dto.GetProperty("selfSig").GetString()!);
        Assert.Equal(DirectoryEntry.LeafData(message, loggedMs, selfSig), leaf);
        Assert.Equal(SHA256.HashData([0x00, .. leaf!]), hash);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT tree_size FROM kt_state"));

        var other = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(other.Tokens.AccessToken);
        var byId = await (await client.GetAsync($"/api/v1/keys/directory?userId={userId}")).JsonAsync();
        var byEmail = await (await client.GetAsync($"/api/v1/keys/directory?email={Uri.EscapeDataString(account.Email.ToUpperInvariant())}")).JsonAsync();
        Assert.Equal(userId, byId.GetProperty("userId").GetGuid());
        Assert.Equal(id.KeyId, byEmail.GetProperty("keys")[0].GetProperty("keyId").GetGuid());
        Assert.Equal(Base64UrlCodec.Encode(id.KemPub), byId.GetProperty("keys")[0].GetProperty("kemPub").GetString());
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'key.publish'"));
    }

    [Fact]
    public async Task Malformed_or_unsigned_keys_are_rejected_and_nothing_is_logged()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        var userId = await keys.UserIdAsync(account.Tokens.AccessToken);
        var id = KeyDriver.NewIdentity();
        var foreign = HybridSigningKey.Generate().Sign("x"u8);

        foreach (var body in new[]
                 {
                     KeyDriver.PublishBody(userId, id, selfSig: foreign),
                     KeyDriver.PublishBody(userId, id, algId: "X25519+Ed25519"),
                     KeyDriver.PublishBody(Guid.NewGuid(), id), // signed for another subject
                 })
        {
            var response = await client.PutAsJsonAsync("/api/v1/keys", body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("validation_failed", await response.ProblemCodeAsync());
        }

        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM kt_leaves"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM user_keys"));
    }

    [Fact]
    public async Task Generation_must_follow_and_a_keyId_is_write_once()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var userId = await keys.UserIdAsync(token);

        var skipped = await keys.PublishAsync(token, userId, KeyDriver.NewIdentity(generation: 2));
        Assert.Equal(HttpStatusCode.Conflict, skipped.StatusCode);

        var id = KeyDriver.NewIdentity();
        Assert.Equal(HttpStatusCode.OK, (await keys.PublishAsync(token, userId, id)).StatusCode);
        var again = await keys.PublishAsync(token, userId, id);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(0, (await again.JsonAsync()).GetProperty("ktLeafIndex").GetInt64());

        var changed = id with { KemPub = KeyDriver.DevicePubkey() };
        Assert.Equal(HttpStatusCode.Conflict, (await keys.PublishAsync(token, userId, changed)).StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM kt_leaves"));
    }

    [Fact]
    public async Task Rotation_needs_an_active_device_and_logs_the_revocation_first()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var (account, userId, first, _) = await keys.AccountWithActiveDeviceAsync();
        var next = KeyDriver.NewIdentity(generation: 2);

        // A fresh login with password and TOTP, but without a device, cannot replace the owner's key.
        var thief = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var denied = await keys.PublishAsync(thief.AccessToken, userId, next);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal("device_not_active", await denied.ProblemCodeAsync());

        var rotated = await keys.PublishAsync(account.Tokens.AccessToken, userId, next);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.Equal(2, (await rotated.JsonAsync()).GetProperty("ktLeafIndex").GetInt64());
        Assert.Equal([(short)1, (short)2, (short)1],
            await Sql.ListAsync<short>(app.ConnectionString, "SELECT entry_type FROM kt_leaves ORDER BY leaf_index"));
        Assert.Equal(first.KeyId, await Sql.ScalarAsync<Guid>(app.ConnectionString, "SELECT key_id FROM kt_leaves WHERE leaf_index = 1"));

        var dir = await (await auth.Client().WithBearer(account.Tokens.AccessToken).GetAsync($"/api/v1/keys/directory?userId={userId}")).JsonAsync();
        var listed = dir.GetProperty("keys").EnumerateArray().Select(k => (k.GetProperty("generation").GetInt32(), k.GetProperty("revoked").GetBoolean())).ToList();
        Assert.Equal([(1, true), (2, false)], listed);
        Assert.Equal(1, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'key.rotate'"));
    }

    [Fact]
    public async Task Directory_lookup_hides_existence_and_needs_a_full_session()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        var noKeys = await keys.UserIdAsync(account.Tokens.AccessToken);

        foreach (var query in new[] { $"userId={Guid.NewGuid()}", $"userId={noKeys}", "email=nobody%40example.org", "email=not-an-email" })
        {
            var response = await client.GetAsync($"/api/v1/keys/directory?{query}");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await response.ProblemCodeAsync());
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync($"/api/v1/keys/directory?userId={noKeys}&email=a%40b.org")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/keys/directory")).StatusCode);

        var limited = await auth.RegisterAsync("limited-dir@example.org");
        var forbidden = await auth.Client().WithBearer(limited.AccessToken).GetAsync($"/api/v1/keys/directory?userId={noKeys}");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Equal("2fa_required", await forbidden.ProblemCodeAsync());
    }

    [Fact]
    public async Task Directory_lookups_are_rate_limited_per_user()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?>
        {
            ["RateLimiting:Directory:PermitLimit"] = "60",
        });
        var auth = new AuthDriver(app);
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        for (var i = 0; i < 60; i++)
            Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/v1/keys/directory?userId={Guid.NewGuid()}")).StatusCode);
        var limited = await client.GetAsync($"/api/v1/keys/directory?userId={Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.Contains("Retry-After"));

        // Another user has an own bucket.
        var other = await auth.RegisterWithTotpAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await auth.Client().WithBearer(other.Tokens.AccessToken).GetAsync($"/api/v1/keys/directory?userId={Guid.NewGuid()}")).StatusCode);
    }
}
