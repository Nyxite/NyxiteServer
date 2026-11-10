using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nyxite.Crypto;

/// <summary>Payload of a license token (license 01 §1.2). Times are Unix seconds.</summary>
public sealed record LicensePayload(
    int V, Guid InstanceId, string Email, string Tier, string Mode, long IssuedAt, long? EntitlementExp)
{
    public const int Version = 2;
    public const string OnlineMode = "online";
    public const string OfflineMode = "offline";
}

/// <summary>Payload of an entitlement lease (license 01 §1.5). Times are Unix seconds.</summary>
public sealed record LeasePayload(Guid InstanceId, string Tier, long LeaseExp, bool Revoked);

/// <summary>
/// The signed envelope of the licensing plane (license 01 §1.2, §1.5), used by both the license token and the
/// entitlement lease: <c>base64url(payload JSON) "." base64url(sig)</c>, where <c>sig</c> is the hybrid
/// Ed25519 + ML-DSA-65 dual signature over the payload bytes exactly as transmitted, so no JSON canonicalization is
/// involved. An envelope is authentic if both signature halves verify under any one of the given public keys.
/// </summary>
public static class LicenseEnvelope
{
    /// <summary>Upper bound of a whole envelope; a real one is about 5 KiB, most of it the ML-DSA signature.</summary>
    public const int MaxLength = 16 * 1024;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static bool TryVerifyToken(string? envelope, IReadOnlyList<byte[]> publicKeys, out LicensePayload payload)
    {
        payload = null!;
        if (!TryVerify(envelope, publicKeys, out var bytes) || !TryParse(bytes, out LicensePayload? parsed)) return false;
        if (parsed.V != LicensePayload.Version || parsed.InstanceId == Guid.Empty || string.IsNullOrEmpty(parsed.Tier)) return false;
        // An offline token carries its own expiry, an online one never does (license 01 §1.2).
        var wellFormed = parsed.Mode switch
        {
            LicensePayload.OnlineMode => parsed.EntitlementExp is null,
            LicensePayload.OfflineMode => parsed.EntitlementExp is not null,
            _ => false,
        };
        if (!wellFormed) return false;
        payload = parsed;
        return true;
    }

    public static bool TryVerifyLease(string? envelope, IReadOnlyList<byte[]> publicKeys, out LeasePayload payload)
    {
        payload = null!;
        if (!TryVerify(envelope, publicKeys, out var bytes) || !TryParse(bytes, out LeasePayload? parsed)) return false;
        if (parsed.InstanceId == Guid.Empty || string.IsNullOrEmpty(parsed.Tier) || parsed.LeaseExp <= 0) return false;
        payload = parsed;
        return true;
    }

    /// <summary>Checks the envelope shape and the dual signature and returns the raw payload bytes.</summary>
    public static bool TryVerify(string? envelope, IReadOnlyList<byte[]> publicKeys, out byte[] payload)
    {
        payload = [];
        if (envelope is null || envelope.Length > MaxLength) return false;
        var dot = envelope.IndexOf('.');
        if (dot <= 0 || dot != envelope.LastIndexOf('.')) return false;
        if (!Base64UrlCodec.TryDecode(envelope[..dot], out var bytes) || !Base64UrlCodec.TryDecode(envelope[(dot + 1)..], out var signature))
            return false;

        // Every slot is tried without an early exit, so timing does not tell which rotation slot signed.
        var authentic = false;
        foreach (var key in publicKeys) authentic |= HybridSignature.Verify(key, bytes, signature);
        if (!authentic) return false;
        payload = bytes;
        return true;
    }

    /// <summary>Vendor-side signing, used by <c>NyxiteLicense</c> and by tests and vector generation. The server never signs.</summary>
    public static string Sign<T>(T payload, HybridSigningKey key)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Json);
        return Base64UrlCodec.Encode(bytes) + "." + Base64UrlCodec.Encode(key.Sign(bytes));
    }

    private static bool TryParse<T>(byte[] bytes, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? value) where T : class
    {
        try
        {
            value = JsonSerializer.Deserialize<T>(bytes, Json);
            return value is not null;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
