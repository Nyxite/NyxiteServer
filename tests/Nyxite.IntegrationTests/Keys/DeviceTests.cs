using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Keys;

/// <summary>Device enrollment: registration, pairing-code approval, single-use fetch, self-activation, revocation (server 04, 08 §8.3).</summary>
public sealed class DeviceTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth, KeyDriver Keys)> StartAsync(IDictionary<string, string?>? overrides = null)
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: overrides);
        var auth = new AuthDriver(app);
        return (app, auth, new KeyDriver(auth));
    }

    [Fact]
    public async Task Registration_returns_a_pending_device_bound_to_the_session()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var device = await keys.RegisterAsync(account.Tokens.AccessToken);

        Assert.Matches("^[0-9]{8}$", device.PairingCode);
        Assert.Equal(Base64UrlCodec.Encode(SHA256.HashData(device.Pubkey)), device.Fingerprint);
        var stored = await Sql.ScalarAsync<byte[]>(app.ConnectionString, "SELECT pairing_code_hash FROM devices WHERE id = @id", ("id", device.DeviceId));
        Assert.Equal(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(device.PairingCode)), stored);
        Assert.Equal(device.DeviceId, await Sql.ScalarAsync<Guid>(app.ConnectionString,
            "SELECT device_id FROM sessions WHERE device_id IS NOT NULL"));

        var listed = await (await auth.Client().WithBearer(account.Tokens.AccessToken).GetAsync("/api/v1/devices")).JsonAsync();
        var item = Assert.Single(listed.GetProperty("items").EnumerateArray());
        Assert.Equal("pending", item.GetProperty("status").GetString());
        Assert.Equal(device.Fingerprint, item.GetProperty("pubkeyFingerprint").GetString());

        var second = await keys.RegisterRawAsync(account.Tokens.AccessToken,
            new { label = "again", pubkey = Base64UrlCodec.Encode(KeyDriver.DevicePubkey()) }, Guid.NewGuid().ToString());
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Registration_is_idempotent_per_key_and_requires_one()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var body = new { label = "phone", pubkey = Base64UrlCodec.Encode(KeyDriver.DevicePubkey()) };

        Assert.Equal(HttpStatusCode.BadRequest, (await keys.RegisterRawAsync(token, body, null)).StatusCode);
        var first = await keys.RegisterRawAsync(token, body, "key-0001-abcdef");
        var replay = await keys.RegisterRawAsync(token, body, "key-0001-abcdef");
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, replay.StatusCode);
        Assert.Equal(await first.Content.ReadAsStringAsync(), await replay.Content.ReadAsStringAsync());
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM devices"));

        var different = await keys.RegisterRawAsync(token, body with { label = "other" }, "key-0001-abcdef");
        Assert.Equal(HttpStatusCode.Conflict, different.StatusCode);
        Assert.Equal("idempotency_conflict", await different.ProblemCodeAsync());

        Assert.Equal(HttpStatusCode.BadRequest,
            (await keys.RegisterRawAsync(token, new { label = "x", pubkey = Base64UrlCodec.Encode(new byte[32]) }, "key-0002-abcdef")).StatusCode);
    }

    /// <summary>P0.1-TC-5: approve from device A, B fetches the sealed bundle once and becomes active.</summary>
    [Fact]
    public async Task Approved_device_fetches_its_sealed_bundle_exactly_once()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var (account, _, _, deviceA) = await keys.AccountWithActiveDeviceAsync();
        var sessionB = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var deviceB = await keys.RegisterAsync(sessionB.AccessToken, "phone");

        var fromA = auth.Client().WithBearer(account.Tokens.AccessToken);
        var seen = await (await fromA.GetAsync($"/api/v1/devices/{deviceB.DeviceId}")).JsonAsync();
        Assert.Equal(deviceB.Fingerprint, seen.GetProperty("pubkeyFingerprint").GetString());

        Assert.Equal(HttpStatusCode.NotFound, (await auth.Client().WithBearer(sessionB.AccessToken).GetAsync("/api/v1/devices/me/enrollment")).StatusCode);
        var sealedBundle = RandomNumberGenerator.GetBytes(3000);
        Assert.Equal(HttpStatusCode.NoContent, (await keys.ApproveAsync(account.Tokens.AccessToken, deviceB.DeviceId, deviceB.PairingCode, sealedBundle)).StatusCode);

        var fetch = await auth.Client().WithBearer(sessionB.AccessToken).GetAsync("/api/v1/devices/me/enrollment");
        Assert.Equal(HttpStatusCode.OK, fetch.StatusCode);
        Assert.Equal(Base64UrlCodec.Encode(sealedBundle), (await fetch.JsonAsync()).GetProperty("wrappedIdentityKey").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await auth.Client().WithBearer(sessionB.AccessToken).GetAsync("/api/v1/devices/me/enrollment")).StatusCode);

        Assert.Equal("active", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT status FROM devices WHERE id = @id", ("id", deviceB.DeviceId)));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM devices WHERE pending_key_blob IS NOT NULL OR pairing_code_hash IS NOT NULL AND status = 'active'"));
        Assert.NotEqual(deviceA.DeviceId, deviceB.DeviceId);
    }

    [Fact]
    public async Task Wrong_codes_store_nothing_and_void_the_code_at_the_cap()
    {
        var (app, auth, keys) = await StartAsync(new Dictionary<string, string?> { ["Auth:PairingCodeMaxAttempts"] = "3" });
        await using var _ = app;
        var (account, _, _, _) = await keys.AccountWithActiveDeviceAsync();
        var sessionB = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var deviceB = await keys.RegisterAsync(sessionB.AccessToken);
        var wrong = ((int.Parse(deviceB.PairingCode) + 1) % 100_000_000).ToString("D8");

        for (var i = 0; i < 3; i++)
        {
            var response = await keys.ApproveAsync(account.Tokens.AccessToken, deviceB.DeviceId, wrong);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("pairing_code_invalid", await response.ProblemCodeAsync());
        }

        // The right code no longer helps once the cap is reached.
        var expired = await keys.ApproveAsync(account.Tokens.AccessToken, deviceB.DeviceId, deviceB.PairingCode);
        Assert.Equal(HttpStatusCode.Gone, expired.StatusCode);
        Assert.Equal("pairing_expired", await expired.ProblemCodeAsync());
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM devices WHERE pending_key_blob IS NOT NULL"));
    }

    [Fact]
    public async Task An_expired_code_is_refused_and_approval_needs_an_active_device()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var (account, _, _, _) = await keys.AccountWithActiveDeviceAsync();
        var sessionB = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var deviceB = await keys.RegisterAsync(sessionB.AccessToken);

        // A session without an active device cannot approve, even with the right code.
        var sessionC = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var notActive = await keys.ApproveAsync(sessionC.AccessToken, deviceB.DeviceId, deviceB.PairingCode);
        Assert.Equal(HttpStatusCode.Forbidden, notActive.StatusCode);
        Assert.Equal("device_not_active", await notActive.ProblemCodeAsync());

        app.Clock.Advance(TimeSpan.FromMinutes(11));
        // The 5-minute access token of A has expired as well, so A refreshes first.
        var refreshed = await auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = account.Tokens.RefreshToken });
        var tokenA = AuthDriver.TokensOf(await refreshed.JsonAsync()).AccessToken;
        var expired = await keys.ApproveAsync(tokenA, deviceB.DeviceId, deviceB.PairingCode);
        Assert.Equal(HttpStatusCode.Gone, expired.StatusCode);
        Assert.Equal("pairing_expired", await expired.ProblemCodeAsync());

        Assert.Equal(HttpStatusCode.NotFound, (await keys.ApproveAsync(tokenA, Guid.NewGuid(), deviceB.PairingCode)).StatusCode);
    }

    [Fact]
    public async Task Self_activation_needs_a_signature_by_the_live_identity_key()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var userId = await keys.UserIdAsync(token);
        var device = await keys.RegisterAsync(token);
        var identity = KeyDriver.NewIdentity();

        // No key is published yet.
        Assert.Equal(HttpStatusCode.BadRequest, (await keys.ActivateAsync(token, userId, device, identity)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await keys.PublishAsync(token, userId, identity)).StatusCode);

        var forged = await keys.ActivateAsync(token, userId, device, identity, signer: HybridSigningKey.Generate());
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.Equal("validation_failed", await forged.ProblemCodeAsync());

        // Another session cannot activate a device it is not bound to.
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);
        Assert.Equal(HttpStatusCode.NotFound, (await keys.ActivateAsync(other.AccessToken, userId, device, identity)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await keys.ActivateAsync(token, userId, device, identity)).StatusCode);
        Assert.Equal("active", await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT status FROM devices WHERE id = @id", ("id", device.DeviceId)));
        Assert.Equal(HttpStatusCode.NotFound, (await keys.ActivateAsync(token, userId, device, identity)).StatusCode);
    }

    [Fact]
    public async Task Revoking_a_device_revokes_its_sessions_and_hides_foreign_devices()
    {
        var (app, auth, keys) = await StartAsync();
        await using var _ = app;
        var (account, _, _, _) = await keys.AccountWithActiveDeviceAsync();
        var sessionB = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var deviceB = await keys.RegisterAsync(sessionB.AccessToken);

        var stranger = await auth.RegisterWithTotpAsync();
        var foreign = auth.Client().WithBearer(stranger.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.NotFound, (await foreign.GetAsync($"/api/v1/devices/{deviceB.DeviceId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await foreign.DeleteAsync($"/api/v1/devices/{deviceB.DeviceId}")).StatusCode);

        var owner = auth.Client().WithBearer(account.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/api/v1/devices/{deviceB.DeviceId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/api/v1/devices/{deviceB.DeviceId}")).StatusCode);
        var refresh = await auth.Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = sessionB.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
        Assert.Equal("device_revoked", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT revoke_reason FROM sessions WHERE device_id = @id", ("id", deviceB.DeviceId)));

        var dto = await (await owner.GetAsync($"/api/v1/devices/{deviceB.DeviceId}")).JsonAsync();
        Assert.Equal("revoked", dto.GetProperty("status").GetString());
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'device.revoke'"));
    }

    [Fact]
    public async Task Device_registration_is_rate_limited_per_user()
    {
        var (app, auth, keys) = await StartAsync(new Dictionary<string, string?> { ["RateLimiting:DeviceEnrollment:PermitLimit"] = "5" });
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var body = new { label = "x", pubkey = Base64UrlCodec.Encode(KeyDriver.DevicePubkey()) };
        for (var i = 0; i < 5; i++) await keys.RegisterRawAsync(account.Tokens.AccessToken, body, $"rate-limit-{i:D4}");
        var limited = await keys.RegisterRawAsync(account.Tokens.AccessToken, body, "rate-limit-9999");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("rate_limited", await limited.ProblemCodeAsync());
    }
}
