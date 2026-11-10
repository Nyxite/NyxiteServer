using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Auth;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>
/// Resolves the device bound to the caller's session (<c>sessions.device_id</c>, set by <c>POST /devices</c>) and enforces
/// that key-management writes come from an active device (server 04, 08 §8.3).
/// </summary>
public sealed class DeviceGuard(NyxiteDbContext db)
{
    public async Task<SessionEntity> SessionAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var userId = principal.UserId();
        var sid = principal.SessionIdOf();
        return await db.Sessions.SingleOrDefaultAsync(s => s.Id == sid && s.UserId == userId && s.RevokedAt == null, ct)
               ?? throw AuthException.Unauthenticated();
    }

    /// <summary>The caller's own device, or null when the session is not bound to one.</summary>
    public async Task<DeviceEntity?> BoundDeviceAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var session = await SessionAsync(principal, ct);
        return session.DeviceId is { } id ? await db.Devices.SingleOrDefaultAsync(d => d.Id == id && d.UserId == session.UserId, ct) : null;
    }

    public async Task<DeviceEntity> RequireActiveDeviceAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var device = await BoundDeviceAsync(principal, ct);
        return device is { Status: DeviceStatus.Active } ? device : throw AuthException.DeviceNotActive();
    }

    public Task<bool> HasActiveDeviceAsync(Guid userId, CancellationToken ct) =>
        db.Devices.AnyAsync(d => d.UserId == userId && d.Status == DeviceStatus.Active, ct);
}
