using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Auth;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>A stored or fresh response of an idempotent create: status and the JSON body.</summary>
public sealed record IdempotentResponse(int Status, string Json);

/// <summary>
/// The <c>Idempotency-Key</c> replay store (03 §3.2 <c>idempotency_keys</c>, 04 §4.1). A key is scoped to
/// <c>(user, endpoint)</c>. A replay with the same request returns the stored response, the same key with a different
/// request answers <c>409 idempotency_conflict</c>. The row joins the caller's unit of work, so it commits together with
/// the create it records.
/// </summary>
public sealed class IdempotencyStore(NyxiteDbContext db, TimeProvider time, IOptions<AuthOptions> options)
{
    public static string? ValidKey(string? key) => key is { Length: >= 8 and <= 128 } && key.All(c => c is >= '!' and <= '~') ? key : null;

    public static byte[] Hash(object request) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(request, JsonSerializerOptions.Web));

    /// <summary>The stored response for this key, null when there is none (an expired one is dropped).</summary>
    public async Task<IdempotentResponse?> FindAsync(Guid userId, string endpoint, string key, byte[] requestHash, CancellationToken ct)
    {
        var row = await db.IdempotencyKeys.SingleOrDefaultAsync(k => k.UserId == userId && k.Endpoint == endpoint && k.Key == key, ct);
        if (row is null) return null;
        if (row.ExpiresAt <= time.GetUtcNow())
        {
            db.IdempotencyKeys.Remove(row);
            return null;
        }

        if (!CryptographicOperations.FixedTimeEquals(row.RequestHash, requestHash)) throw AuthException.IdempotencyConflict();
        return new IdempotentResponse(row.StatusCode, Encoding.UTF8.GetString(row.ResponseBody));
    }

    public IdempotentResponse Add(Guid userId, string endpoint, string key, byte[] requestHash, int status, object body)
    {
        var json = JsonSerializer.Serialize(body, JsonSerializerOptions.Web);
        var now = time.GetUtcNow();
        db.IdempotencyKeys.Add(new IdempotencyKeyEntity
        {
            UserId = userId,
            Endpoint = endpoint,
            Key = key,
            RequestHash = requestHash,
            StatusCode = status,
            ResponseBody = Encoding.UTF8.GetBytes(json),
            CreatedAt = now,
            ExpiresAt = now + options.Value.IdempotencyLifetime,
        });
        return new IdempotentResponse(status, json);
    }
}
