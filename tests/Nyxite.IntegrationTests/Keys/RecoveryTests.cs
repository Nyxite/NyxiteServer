using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Keys;

/// <summary>The server-opaque recovery blob (server 04 <c>/recovery</c>, 07 §7.8).</summary>
public sealed class RecoveryTests(PostgresFixture pg)
{
    [Fact]
    public async Task Blob_round_trips_and_replacing_it_needs_an_active_device()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var keys = new KeyDriver(auth);
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/recovery")).StatusCode);
        var body = KeyDriver.RecoveryBody();
        Assert.Equal(HttpStatusCode.NoContent, (await client.PutAsJsonAsync("/api/v1/recovery", body)).StatusCode);

        var got = await (await client.GetAsync("/api/v1/recovery")).Content.ReadAsStringAsync();
        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(body, System.Text.Json.JsonSerializerOptions.Web), got);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'recovery.use'"));

        var denied = await client.PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody(version: 2));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal("device_not_active", await denied.ProblemCodeAsync());

        var device = await keys.RegisterAsync(account.Tokens.AccessToken);
        var userId = await keys.UserIdAsync(account.Tokens.AccessToken);
        var identity = KeyDriver.NewIdentity();
        await keys.PublishAsync(account.Tokens.AccessToken, userId, identity);
        await keys.ActivateAsync(account.Tokens.AccessToken, userId, device, identity);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody(version: 2))).StatusCode);
        Assert.Equal(2, await Sql.ScalarAsync<int>(app.ConnectionString, "SELECT version FROM recovery_blobs"));
    }

    [Fact]
    public async Task First_blob_needs_an_active_device_once_one_exists_and_malformed_blobs_are_rejected()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var keys = new KeyDriver(auth);
        var (account, _, _, _) = await keys.AccountWithActiveDeviceAsync();

        var thief = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var denied = await auth.Client().WithBearer(thief.AccessToken).PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody());
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var owner = auth.Client().WithBearer(account.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.BadRequest, (await owner.PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody(saltSize: 8))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await owner.PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody(version: 0))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.PutAsJsonAsync("/api/v1/recovery", KeyDriver.RecoveryBody())).StatusCode);
    }
}
