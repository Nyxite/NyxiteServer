using Nyxite.Contracts.Keys;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Crypto;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>
/// The public-key directory (server 04 <c>/keys</c>, 03 <c>user_keys</c>). Every publish and every revoke appends its KT
/// leaf in the same transaction (17 §17.6), so no key is ever in the directory without its leaf.
/// </summary>
public sealed class KeyDirectoryService(NyxiteDbContext db, KeyTransparencyLog log, DeviceGuard devices, AuditWriter audit, TimeProvider time)
{
    /// <summary>
    /// A user's keys, live and revoked. An unknown user, an unverified account and a user without keys all answer the same
    /// <c>404</c>, so the lookup tells no more than a share attempt would.
    /// </summary>
    public async Task<DirectoryDto> LookupAsync(Guid? userId, string? email, CancellationToken ct)
    {
        if (userId is null == email is null) throw AuthException.Validation("Pass exactly one of userId and email.");
        UserEntity? user;
        if (userId is { } id)
        {
            user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct);
        }
        else
        {
            var normalized = NativeAuthService.NormalizeEmail(email) ?? throw AuthException.NotFound();
            user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Email == normalized, ct);
        }

        if (user is null || user.EmailVerifiedAt is null) throw AuthException.NotFound();
        var keys = await db.UserKeys.AsNoTracking().Where(k => k.UserId == user.Id).OrderBy(k => k.Generation).ToListAsync(ct);
        if (keys.Count == 0) throw AuthException.NotFound();
        var leaves = await PublishLeavesAsync(user.Id, ct);
        return new DirectoryDto(user.Id, keys.Select(k => ToDto(k, leaves[k.KeyId])).ToList());
    }

    /// <summary>
    /// Publishes the caller's identity keys (first publish) or rotates them (any later one). <c>generation</c> must be the
    /// highest so far + 1. A rotation revokes the previous live key and needs an active device. Re-sending an already
    /// published key unchanged returns it again.
    /// </summary>
    public async Task<DirectoryKeyDto> PublishAsync(ClaimsPrincipal principal, PublishKeyRequest body, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        if (body.AlgId != CryptoSuite.DirectoryAlgId) throw AuthException.Validation("Unsupported algId.");
        if (body.KeyId == Guid.Empty || body.Generation < 1) throw AuthException.Validation("keyId and generation are required.");
        if (!Base64UrlCodec.TryDecode(body.KemPub, out var kemPub) || kemPub.Length != CryptoSuite.HybridKemPublicKeySize
            || !Base64UrlCodec.TryDecode(body.SigPub, out var sigPub) || sigPub.Length != CryptoSuite.HybridSignaturePublicKeySize
            || !Base64UrlCodec.TryDecode(body.SelfSig, out var selfSig))
            throw AuthException.Validation("kemPub, sigPub or selfSig is malformed.");
        var message = DirectoryEntry.SignedMessage(DirectoryEntryType.UserKeyPublish, userId, body.KeyId, (uint)body.Generation, body.AlgId, kemPub, sigPub);
        if (!HybridSignature.Verify(sigPub, message, selfSig)) throw AuthException.Validation("selfSig does not verify.");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // Serializes publishes of one user, so two rotations cannot both pass the generation check.
        await db.Database.ExecuteSqlAsync($"SELECT 1 FROM users WHERE id = {userId} FOR UPDATE", ct);
        var keys = await db.UserKeys.Where(k => k.UserId == userId).ToListAsync(ct);

        if (keys.SingleOrDefault(k => k.KeyId == body.KeyId) is { } existing)
        {
            var same = existing.Generation == body.Generation && existing.AlgId == body.AlgId && existing.PublicX25519.AsSpan().SequenceEqual(kemPub)
                       && existing.PublicEd25519.AsSpan().SequenceEqual(sigPub) && existing.SelfSig.AsSpan().SequenceEqual(selfSig);
            if (!same) throw AuthException.Conflict("This keyId is already published with other values.");
            var leaves = await PublishLeavesAsync(userId, ct);
            return ToDto(existing, leaves[existing.KeyId]);
        }

        var highest = keys.Count == 0 ? 0 : keys.Max(k => k.Generation);
        if (body.Generation != highest + 1) throw AuthException.Conflict($"generation must be {highest + 1}.");
        var rotation = keys.Count > 0;
        // The first publish happens before any device can be active: the identity key is what activates it.
        if (rotation) await devices.RequireActiveDeviceAsync(principal, ct);

        var now = time.GetUtcNow();
        foreach (var live in keys.Where(k => k.RevokedAt is null))
        {
            live.RevokedAt = now;
            await log.AppendAsync(DirectoryEntryType.UserKeyRevoke, userId, live.KeyId, (uint)live.Generation, live.AlgId,
                live.PublicX25519, live.PublicEd25519, live.SelfSig, ct);
        }

        var appended = await log.AppendAsync(DirectoryEntryType.UserKeyPublish, userId, body.KeyId, (uint)body.Generation, body.AlgId,
            kemPub, sigPub, selfSig, ct);
        var key = new UserKeyEntity
        {
            UserId = userId,
            KeyId = body.KeyId,
            PublicX25519 = kemPub,
            PublicEd25519 = sigPub,
            AlgId = body.AlgId,
            Generation = body.Generation,
            SelfSig = selfSig,
            CreatedAt = now,
        };
        db.UserKeys.Add(key);
        audit.Add(rotation ? "key.rotate" : "key.publish", userId, request, targetType: "user_key", targetId: body.KeyId,
            detail: new { generation = body.Generation, ktLeafIndex = appended.LeafIndex });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return ToDto(key, appended);
    }

    /// <summary>The publish leaf of each of the user's keys; it carries the <c>loggedAt</c> and index clients verify.</summary>
    private async Task<Dictionary<Guid, KeyTransparencyLog.Appended>> PublishLeavesAsync(Guid userId, CancellationToken ct)
    {
        var publish = (short)DirectoryEntryType.UserKeyPublish;
        var leaves = await db.KtLeaves.AsNoTracking()
            .Where(l => l.SubjectId == userId && l.EntryType == publish)
            .Select(l => new { l.KeyId, l.LeafIndex, l.LoggedAt })
            .ToListAsync(ct);
        return leaves.ToDictionary(l => l.KeyId, l => new KeyTransparencyLog.Appended(l.LeafIndex, l.LoggedAt));
    }

    private static DirectoryKeyDto ToDto(UserKeyEntity k, KeyTransparencyLog.Appended leaf) => new(k.KeyId, k.Generation, k.AlgId,
        Base64UrlCodec.Encode(k.PublicX25519), Base64UrlCodec.Encode(k.PublicEd25519), Base64UrlCodec.Encode(k.SelfSig),
        leaf.LoggedAt, leaf.LeafIndex, k.RevokedAt is not null);
}
