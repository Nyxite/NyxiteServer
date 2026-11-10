using Nyxite.Contracts.Keys;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>
/// Device enrollment (server 04 <c>/devices</c>, 08 §8.3). A device is registered <c>pending</c> and bound to the calling
/// session, then becomes <c>active</c> either by fetching the identity bundle another active device sealed to it after the
/// server verified the pairing code, or by signing its own enrollment with the identity key (first device, recovery).
/// </summary>
public sealed class DeviceService(
    NyxiteDbContext db, DeviceGuard guard, IdempotencyStore idempotency, AuditWriter audit,
    TimeProvider time, IOptions<AuthOptions> options)
{
    public const string RegisterEndpoint = "POST /devices";

    /// <summary>Upper bound of a sealed identity bundle; the hybrid bundle is a few KiB.</summary>
    public const int MaxWrappedKeySize = 64 * 1024;

    private readonly AuthOptions _options = options.Value;

    public async Task<IReadOnlyList<DeviceDto>> ListAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        var rows = await db.Devices.AsNoTracking().Where(d => d.UserId == userId).OrderBy(d => d.EnrolledAt).ToListAsync(ct);
        return rows.Select(ToDto).ToList();
    }

    public async Task<DeviceDto> GetAsync(ClaimsPrincipal principal, Guid id, CancellationToken ct)
    {
        var userId = principal.UserId();
        var row = await db.Devices.AsNoTracking().SingleOrDefaultAsync(d => d.Id == id && d.UserId == userId, ct);
        return row is null ? throw AuthException.NotFound() : ToDto(row);
    }

    public async Task<IdempotentResponse> RegisterAsync(ClaimsPrincipal principal, RegisterDeviceRequest body, string? idempotencyKey,
        RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        var key = IdempotencyStore.ValidKey(idempotencyKey) ?? throw AuthException.Validation("A valid Idempotency-Key header is required.");
        var hash = IdempotencyStore.Hash(body);
        if (await idempotency.FindAsync(userId, RegisterEndpoint, key, hash, ct) is { } replay) return replay;

        var label = body.Label?.Trim();
        if (label is null || label.Length > 100) throw AuthException.Validation("label is required and at most 100 characters.");
        if (!Base64UrlCodec.TryDecode(body.Pubkey, out var pubkey) || pubkey.Length != CryptoSuite.HybridKemPublicKeySize)
            throw AuthException.Validation("pubkey must be a hybrid X25519 + ML-KEM-768 public key.");
        if (_options.PairingCodeDigits is < 6 or > 8) throw new InvalidOperationException("Auth:PairingCodeDigits must be 6 to 8.");

        var session = await guard.SessionAsync(principal, ct);
        if (session.DeviceId is { } bound
            && await db.Devices.AnyAsync(d => d.Id == bound && d.Status != DeviceStatus.Revoked, ct))
            throw AuthException.Conflict("This session is already bound to a device.");

        var now = time.GetUtcNow();
        var code = PairingCode(_options.PairingCodeDigits);
        var device = new DeviceEntity
        {
            Id = Guid.CreateVersion7(now),
            UserId = userId,
            Label = label.Length == 0 ? null : label,
            Pubkey = pubkey,
            Status = DeviceStatus.Pending,
            PairingCodeHash = HashCode(code),
            PairingExpiresAt = now + _options.PairingCodeLifetime,
            EnrolledAt = now,
        };
        db.Devices.Add(device);
        session.DeviceId = device.Id;
        audit.Add("device.enroll", userId, request, targetType: "device", targetId: device.Id, detail: new { step = "register" });

        var fingerprint = Base64UrlCodec.Encode(SHA256.HashData(pubkey));
        var response = new RegisteredDeviceDto(device.Id, "pending", code, new QrPayloadDto(device.Id, code, fingerprint));
        var stored = idempotency.Add(userId, RegisterEndpoint, key, hash, 201, response);
        await db.SaveChangesAsync(ct);
        return stored;
    }

    /// <summary>
    /// Stores the identity bundle an active device sealed to a pending one, after verifying the pairing code: constant-time
    /// hash compare, unexpired, under the attempt cap. The device row is locked so parallel guesses count one by one.
    /// </summary>
    public async Task ApproveAsync(ClaimsPrincipal principal, Guid id, ApproveDeviceRequest body, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        await guard.RequireActiveDeviceAsync(principal, ct);
        if (body.PairingCode is not { Length: >= 6 and <= 8 } code || !code.All(char.IsAsciiDigit))
            throw AuthException.Validation("pairingCode must be 6 to 8 digits.");
        if (!Base64UrlCodec.TryDecode(body.WrappedIdentityKey, out var wrapped) || wrapped.Length is 0 or > MaxWrappedKeySize)
            throw AuthException.Validation("wrappedIdentityKey is malformed.");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var pending = DbValue.Of(DeviceStatus.Pending);
        var device = (await db.Devices
            .FromSql($"SELECT * FROM devices WHERE id = {id} AND user_id = {userId} AND status = {pending} FOR UPDATE")
            .ToListAsync(ct)).SingleOrDefault() ?? throw AuthException.NotFound();

        var now = time.GetUtcNow();
        if (device.PairingCodeHash is null || device.PairingExpiresAt is not { } expires || expires <= now
            || device.PairingAttempts >= _options.PairingCodeMaxAttempts)
        {
            ClearPairing(device);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            throw AuthException.PairingExpired();
        }

        if (!CryptographicOperations.FixedTimeEquals(HashCode(code), device.PairingCodeHash))
        {
            device.PairingAttempts++;
            if (device.PairingAttempts >= _options.PairingCodeMaxAttempts) ClearPairing(device);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            throw AuthException.PairingCodeInvalid();
        }

        device.PendingKeyBlob = wrapped;
        ClearPairing(device);
        audit.Add("device.enroll", userId, request, targetType: "device", targetId: device.Id, detail: new { step = "approve" });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>The single-use fetch: one statement clears the sealed bundle and activates the device, so it is served once.</summary>
    public async Task<EnrollmentDto> FetchEnrollmentAsync(ClaimsPrincipal principal, RequestInfo request, CancellationToken ct)
    {
        var session = await guard.SessionAsync(principal, ct);
        if (session.DeviceId is not { } deviceId) throw AuthException.NotFound();
        var active = DbValue.Of(DeviceStatus.Active);
        var pending = DbValue.Of(DeviceStatus.Pending);
        // One transaction: the bundle is only cleared when its audit row commits too.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var blob = (await db.Database.SqlQuery<byte[]>($"""
                WITH prev AS (SELECT id, pending_key_blob FROM devices
                             WHERE id = {deviceId} AND user_id = {session.UserId} AND status = {pending} AND pending_key_blob IS NOT NULL
                             FOR UPDATE)
                UPDATE devices d SET status = {active}, pending_key_blob = NULL
                FROM prev WHERE d.id = prev.id
                RETURNING prev.pending_key_blob AS "Value"
                """).ToListAsync(ct)).SingleOrDefault() ?? throw AuthException.NotFound();
        audit.Add("device.enroll", session.UserId, request, targetType: "device", targetId: deviceId, detail: new { step = "fetch" });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return new EnrollmentDto(Base64UrlCodec.Encode(blob));
    }

    /// <summary>
    /// Activates the caller's own pending device on a signature by the user's live directory key, which only a holder of the
    /// identity private key can produce (first device after its first publish, recovery-phrase restore).
    /// </summary>
    public async Task ActivateAsync(ClaimsPrincipal principal, Guid id, ActivateDeviceRequest body, RequestInfo request, CancellationToken ct)
    {
        var device = await guard.BoundDeviceAsync(principal, ct);
        if (device is null || device.Id != id || device.Status != DeviceStatus.Pending) throw AuthException.NotFound();
        if (!Base64UrlCodec.TryDecode(body.Sig, out var sig)) throw AuthException.Validation("sig is malformed.");
        var key = await db.UserKeys.AsNoTracking()
            .SingleOrDefaultAsync(k => k.UserId == device.UserId && k.KeyId == body.KeyId && k.RevokedAt == null, ct);
        if (key is null) throw AuthException.Validation("keyId is not a live directory key of this account.");
        var message = DeviceActivation.SignedMessage(device.UserId, device.Id, key.KeyId, device.Pubkey);
        if (!HybridSignature.Verify(key.PublicEd25519, message, sig)) throw AuthException.Validation("sig does not verify.");

        device.Status = DeviceStatus.Active;
        device.PendingKeyBlob = null;
        ClearPairing(device);
        audit.Add("device.enroll", device.UserId, request, targetType: "device", targetId: device.Id, detail: new { step = "activate" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Revokes one of the caller's devices and every session bound to it. Revoking an already revoked device is a no-op.</summary>
    public async Task RevokeAsync(ClaimsPrincipal principal, Guid id, RequestInfo request, CancellationToken ct)
    {
        var userId = principal.UserId();
        var device = await db.Devices.SingleOrDefaultAsync(d => d.Id == id && d.UserId == userId, ct) ?? throw AuthException.NotFound();
        if (device.Status == DeviceStatus.Revoked) return;

        var now = time.GetUtcNow();
        device.Status = DeviceStatus.Revoked;
        device.RevokedAt = now;
        device.PendingKeyBlob = null;
        ClearPairing(device);
        audit.Add("device.revoke", userId, request, targetType: "device", targetId: id);
        // One transaction: a revoked device never keeps live sessions.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.SaveChangesAsync(ct);
        await db.Sessions.Where(s => s.DeviceId == id && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now).SetProperty(x => x.RevokeReason, RevokeReason.DeviceRevoked), ct);
        await tx.CommitAsync(ct);
    }

    private static void ClearPairing(DeviceEntity device)
    {
        device.PairingCodeHash = null;
        device.PairingExpiresAt = null;
    }

    private static string PairingCode(int digits)
    {
        var max = (int)Math.Pow(10, digits);
        return RandomNumberGenerator.GetInt32(max).ToString(new string('0', digits), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] HashCode(string code) => SHA256.HashData(Encoding.ASCII.GetBytes(code));

    private static DeviceDto ToDto(DeviceEntity d) => new(d.Id, d.Label, DbValue.Of(d.Status),
        Base64UrlCodec.Encode(SHA256.HashData(d.Pubkey)), d.EnrolledAt, d.RevokedAt);
}
