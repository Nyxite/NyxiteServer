using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nyxite.Application.Licensing;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Http;

/// <summary>P0.1-TC-10: the server boots with no, a valid and a tampered license token, and <c>GET /me</c> reports the result.</summary>
public sealed class LicenseTests(PostgresFixture pg)
{
    private static readonly HybridSigningKey Vendor = HybridSigningKey.FromSeeds(
        Enumerable.Repeat((byte)3, 32).ToArray(), Enumerable.Repeat((byte)4, 32).ToArray());

    private async Task<(string State, string[] Flags)> CapabilitiesAsync(string? token)
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync(), clock,
            new Dictionary<string, string?> { [Entitlement.TokenKey] = token },
            services =>
            {
                services.RemoveAll<LicenseKeys>();
                services.AddSingleton(new LicenseKeys([Vendor.PublicKey]));
            });
        var auth = new AuthDriver(app);
        var account = await auth.RegisterWithTotpAsync();
        var me = await auth.Client().WithBearer(account.Tokens.AccessToken).GetAsync("/api/v1/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var capabilities = (await me.JsonAsync()).GetProperty("capabilities");
        return (capabilities.GetProperty("licenseState").GetString()!,
            capabilities.GetProperty("enterpriseFlags").EnumerateArray().Select(f => f.GetString()!).ToArray());
    }

    private static string Token() => LicenseEnvelope.Sign(new LicensePayload(2, Guid.NewGuid(), "operator@example.org", "commercial",
        "offline", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), DateTimeOffset.UtcNow.AddDays(365).ToUnixTimeSeconds()), Vendor);

    [Fact]
    public async Task Without_a_token_the_instance_is_community()
    {
        var (state, flags) = await CapabilitiesAsync(null);

        Assert.Equal("community", state);
        Assert.Empty(flags);
    }

    [Fact]
    public async Task A_valid_token_is_verified_offline_and_reports_the_enterprise_flags()
    {
        var (state, flags) = await CapabilitiesAsync(Token());

        Assert.Equal("in_lease", state);
        Assert.Equal(EnterpriseFlags.All, flags);
    }

    [Fact]
    public async Task A_tampered_token_still_boots_in_community_mode()
    {
        var token = Token();
        var (state, flags) = await CapabilitiesAsync(token[..20] + (token[20] == 'A' ? 'B' : 'A') + token[21..]);

        Assert.Equal("community", state);
        Assert.Empty(flags);
    }
}
