using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Nyxite.Crypto;

namespace Nyxite.Application.Licensing;

/// <summary>The license state of an instance as clients see it in <c>GET /me</c> (16 §16.6).</summary>
public enum LicenseState { Community, InLease, Degraded, Readonly }

/// <summary>The enterprise feature flags of 16 §16.5. Community mode has none of them.</summary>
public static class EnterpriseFlags
{
    public const string Sso = "ent.sso";
    public const string ReaderGroups = "ent.reader_groups";
    public const string AdminOverrides = "ent.admin_overrides";
    public const string AuditExport = "ent.audit_export";
    public const string LargeGroups = "ent.large_groups";

    public static readonly IReadOnlyList<string> All = [Sso, ReaderGroups, AdminOverrides, AuditExport, LargeGroups];
}

/// <summary>
/// The one seam every enterprise feature asks (16 §16.5). A flag is on only while a verified license entitles the
/// instance to it; whenever that cannot be determined the answer is community, so a gate can never fail open.
/// </summary>
public interface IEntitlement
{
    LicenseState State { get; }
    IReadOnlyList<string> Flags { get; }
    bool Has(string flag);
}

/// <summary>
/// The license public keys a token is verified against: two rotation slots, each a hybrid Ed25519 + ML-DSA-65 public
/// key (16 §16.2). The slots are empty until the vendor-side <c>NyxiteLicense</c> signing key exists (Phase 4.2), so
/// until then no token verifies and every build runs in community mode. Embedding development keys instead was
/// rejected, because a release that shipped them would accept licenses anyone can mint.
/// </summary>
public sealed class LicenseKeys(IReadOnlyList<byte[]> slots)
{
    public const int SlotCount = 2;

    public static readonly LicenseKeys Embedded = new([]);

    public IReadOnlyList<byte[]> Slots { get; } = slots.Count <= SlotCount
        ? slots
        : throw new ArgumentException($"At most {SlotCount} license key slots.", nameof(slots));
}

/// <summary>
/// Offline entitlement (16 §16.3): verifies <c>NYXITE_LICENSE_TOKEN</c> once at startup against the embedded keys, with
/// no network call, and never blocks boot. No token, a bad signature or a malformed token all mean community mode.
/// The state is recomputed from the clock on every read, so an offline token lapses without a restart.
/// </summary>
public sealed class Entitlement : IEntitlement
{
    /// <summary>Configuration key of the token (deploy, 14). Read without the <c>NYXITE__</c> prefix.</summary>
    public const string TokenKey = "NYXITE_LICENSE_TOKEN";

    /// <summary>Days from a lapsed entitlement to degrade, and from degrade to the read-only lockout (16 §16.6).</summary>
    public static readonly TimeSpan GraceWindow = TimeSpan.FromDays(30);

    private readonly TimeProvider _time;
    private readonly LicensePayload? _token;

    public Entitlement(IConfiguration configuration, LicenseKeys keys, TimeProvider time, ILogger<Entitlement> logger)
    {
        _time = time;
        var raw = configuration[TokenKey] ?? configuration["License:Token"];
        if (string.IsNullOrWhiteSpace(raw))
        {
            logger.LogInformation("No license token is configured: community mode.");
            return;
        }

        if (!LicenseEnvelope.TryVerifyToken(raw.Trim(), keys.Slots, out var payload))
        {
            logger.LogWarning("license_invalid: the configured license token does not verify. Running in community mode.");
            return;
        }

        _token = payload;
        if (payload.Mode == LicensePayload.OnlineMode)
        {
            // An online token is entitled by its lease only, and the check-in client that fetches leases arrives in
            // Phase 4.2. Without a lease the entitlement is indeterminate, which means community (16 §16.5).
            logger.LogInformation("license_awaiting_lease: the online license token of instance {InstanceId} is authentic, " +
                                  "but no lease is available yet. Running in community mode.", payload.InstanceId);
        }
        else
        {
            logger.LogInformation("license_valid: offline license of instance {InstanceId}, tier {Tier}.", payload.InstanceId, payload.Tier);
        }
    }

    public LicenseState State
    {
        get
        {
            if (_token?.EntitlementExp is not { } exp) return LicenseState.Community;
            var lapsed = _time.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(exp);
            if (lapsed < TimeSpan.Zero) return LicenseState.InLease;
            return lapsed < GraceWindow ? LicenseState.Degraded : LicenseState.Readonly;
        }
    }

    public IReadOnlyList<string> Flags => State == LicenseState.InLease ? EnterpriseFlags.All : [];

    public bool Has(string flag) => Flags.Contains(flag);

    public static string Name(LicenseState state) => state switch
    {
        LicenseState.Community => "community",
        LicenseState.InLease => "in_lease",
        LicenseState.Degraded => "degraded",
        LicenseState.Readonly => "readonly",
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };
}
