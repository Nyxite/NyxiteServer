using Nyxite.Contracts.Keys;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Crypto;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>
/// The server-opaque recovery blob (server 04 <c>/recovery</c>, 03 <c>recovery_blobs</c>, 07 §7.8): AES-256-GCM under an
/// Argon2id key from the recovery phrase. The server checks only the frame shape and bounds, it cannot open the blob.
/// </summary>
public sealed class RecoveryService(NyxiteDbContext db, DeviceGuard guard, AuditWriter audit, TimeProvider time)
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int SaltSize = 16;
    public const int MaxCiphertextSize = 64 * 1024;

    private sealed record StoredKdf(string Alg, int M, int T, int P, string Salt);

    public async Task<RecoveryBlobDto> GetAsync(ClaimsPrincipal principal, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        var row = await db.RecoveryBlobs.AsNoTracking().SingleOrDefaultAsync(r => r.UserId == userId, ct) ?? throw AuthException.NotFound();
        var kdf = JsonSerializer.Deserialize<StoredKdf>(row.KdfParams, JsonSerializerOptions.Web)!;
        var blob = row.Blob;
        audit.Add("recovery.use", userId, request, targetType: "user", targetId: userId);
        await db.SaveChangesAsync(ct);
        return new RecoveryBlobDto(row.Version, new KdfParamsDto(kdf.Alg, kdf.M, kdf.T, kdf.P, kdf.Salt),
            Base64UrlCodec.Encode(blob.AsSpan(..NonceSize)), Base64UrlCodec.Encode(blob.AsSpan(NonceSize..^TagSize)), Base64UrlCodec.Encode(blob.AsSpan(^TagSize..)));
    }

    /// <summary>
    /// Stores or replaces the blob. Replacing needs an active device, and so does a first blob once the account has an active
    /// device, so a stolen password and second factor cannot swap the owner's recovery path.
    /// </summary>
    public async Task PutAsync(ClaimsPrincipal principal, RecoveryBlobDto body, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        var kdf = body.Kdf;
        if (body.Version < 1 || kdf is null || kdf.Alg != "argon2id"
            || kdf.M is < 8 or > 4 * 1024 * 1024 || kdf.T is < 1 or > 100 || kdf.P is < 1 or > 255
            || !Base64UrlCodec.TryDecode(kdf.Salt, out var salt) || salt.Length != SaltSize
            || !Base64UrlCodec.TryDecode(body.Nonce, out var nonce) || nonce.Length != NonceSize
            || !Base64UrlCodec.TryDecode(body.Tag, out var tag) || tag.Length != TagSize
            || !Base64UrlCodec.TryDecode(body.Ciphertext, out var ciphertext) || ciphertext.Length is 0 or > MaxCiphertextSize)
            throw AuthException.Validation("The recovery blob is malformed.");

        var row = await db.RecoveryBlobs.SingleOrDefaultAsync(r => r.UserId == userId, ct);
        if (row is not null || await guard.HasActiveDeviceAsync(userId, ct)) await guard.RequireActiveDeviceAsync(principal, ct);

        var kdfJson = JsonSerializer.Serialize(new StoredKdf(kdf.Alg, kdf.M, kdf.T, kdf.P, Base64UrlCodec.Encode(salt)), JsonSerializerOptions.Web);
        byte[] blob = [.. nonce, .. ciphertext, .. tag];
        if (row is null)
        {
            db.RecoveryBlobs.Add(new RecoveryBlobEntity { UserId = userId, Version = body.Version, Blob = blob, KdfParams = kdfJson, UpdatedAt = time.GetUtcNow() });
        }
        else
        {
            row.Version = body.Version;
            row.Blob = blob;
            row.KdfParams = kdfJson;
            row.UpdatedAt = time.GetUtcNow();
        }

        audit.Add("recovery.set", userId, request, targetType: "user", targetId: userId, detail: new { version = body.Version, replaced = row is not null });
        await db.SaveChangesAsync(ct);
    }
}
