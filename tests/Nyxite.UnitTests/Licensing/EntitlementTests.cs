using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NetArchTest.Rules;
using Nyxite.Application.Licensing;
using Nyxite.Crypto;
using Nyxite.UnitTests.Auth;

namespace Nyxite.UnitTests.Licensing;

/// <summary>P0.1-SRV-6 / P0.1-TC-10: offline license verification, the community default and the degrade timeline (16).</summary>
public sealed class EntitlementTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    private static readonly HybridSigningKey Vendor = HybridSigningKey.FromSeeds(
        Enumerable.Repeat((byte)7, 32).ToArray(), Enumerable.Repeat((byte)8, 32).ToArray());
    private static readonly Guid Instance = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805b");

    private static string Offline(DateTimeOffset expires) => LicenseEnvelope.Sign(
        new LicensePayload(2, Instance, "operator@example.org", "commercial", "offline", Now.ToUnixTimeSeconds(), expires.ToUnixTimeSeconds()), Vendor);

    private static (Entitlement Entitlement, ManualTimeProvider Clock) Create(string? token, LicenseKeys? keys = null)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [Entitlement.TokenKey] = token }).Build();
        var clock = new ManualTimeProvider(Now);
        return (new Entitlement(configuration, keys ?? new LicenseKeys([Vendor.PublicKey]), clock, NullLogger<Entitlement>.Instance), clock);
    }

    [Fact]
    public void No_token_is_community_with_every_flag_off()
    {
        var (entitlement, _) = Create(null);

        Assert.Equal(LicenseState.Community, entitlement.State);
        Assert.Empty(entitlement.Flags);
        Assert.All(EnterpriseFlags.All, flag => Assert.False(entitlement.Has(flag)));
    }

    [Fact]
    public void A_valid_offline_token_enables_every_enterprise_flag()
    {
        var (entitlement, _) = Create(Offline(Now.AddDays(365)));

        Assert.Equal(LicenseState.InLease, entitlement.State);
        Assert.Equal(EnterpriseFlags.All, entitlement.Flags);
        Assert.True(entitlement.Has(EnterpriseFlags.Sso));
    }

    [Fact]
    public void A_tampered_token_a_garbage_token_and_an_unknown_signer_are_community()
    {
        var token = Offline(Now.AddDays(365));
        var tampered = token[..10] + (token[10] == 'A' ? 'B' : 'A') + token[11..];

        Assert.Equal(LicenseState.Community, Create(tampered).Entitlement.State);
        Assert.Equal(LicenseState.Community, Create("not a token").Entitlement.State);
        Assert.Equal(LicenseState.Community, Create(token, LicenseKeys.Embedded).Entitlement.State);
    }

    [Fact]
    public void The_shipped_key_slots_are_empty_so_no_token_can_verify_yet()
    {
        Assert.Empty(LicenseKeys.Embedded.Slots);
    }

    [Fact]
    public void An_online_token_without_a_lease_stays_community()
    {
        var online = LicenseEnvelope.Sign(
            new LicensePayload(2, Instance, "operator@example.org", "commercial", "online", Now.ToUnixTimeSeconds(), null), Vendor);

        var (entitlement, _) = Create(online);

        Assert.Equal(LicenseState.Community, entitlement.State);
        Assert.Empty(entitlement.Flags);
    }

    [Fact]
    public void A_lapsed_offline_token_degrades_then_locks_read_only_without_a_restart()
    {
        var (entitlement, clock) = Create(Offline(Now.AddDays(10)));
        Assert.Equal(LicenseState.InLease, entitlement.State);

        clock.Now = Now.AddDays(10);
        Assert.Equal(LicenseState.Degraded, entitlement.State);
        Assert.Empty(entitlement.Flags);

        clock.Now = Now.AddDays(40);
        Assert.Equal(LicenseState.Readonly, entitlement.State);
        Assert.Empty(entitlement.Flags);
    }

    /// <summary>Boot never depends on the license server: the entitlement code cannot make a network call at all.</summary>
    [Fact]
    public void Licensing_has_no_network_dependency()
    {
        var result = Types.InAssembly(typeof(Entitlement).Assembly).That().ResideInNamespace("Nyxite.Application.Licensing")
            .ShouldNot().HaveDependencyOnAny("System.Net.Http", "System.Net.Sockets").GetResult();

        Assert.True(result.IsSuccessful);
    }
}
