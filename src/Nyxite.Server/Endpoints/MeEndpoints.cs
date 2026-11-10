using Microsoft.EntityFrameworkCore;
using Nyxite.Application.Auth;
using Nyxite.Contracts.Auth;
using Nyxite.Application.Licensing;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;

namespace Nyxite.Server.Endpoints;

/// <summary><c>GET /api/v1/me</c>. The capabilities carry the license state and the active <c>ent.*</c> flags (16 §16.5).</summary>
public static class MeEndpoints
{
    public static RouteGroupBuilder MapMeEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/me", async (HttpContext http, NyxiteDbContext db, IEntitlement entitlement, Nyxite.Application.Content.ContentService content, CancellationToken ct) =>
        {
            var id = http.User.UserId();
            var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct) ?? throw AuthException.Unauthenticated();
            return Results.Ok(new MeDto(user.Id, user.Email, user.DisplayName, DbValue.Of(user.Role), DbValue.Of(user.Status),
                user.StorageQuotaBytes, await content.UsageBytesAsync(id, ct), new CapabilitiesDto(false, [.. entitlement.Flags], Entitlement.Name(entitlement.State))));
        }).RequireAuthorization();
        return api;
    }
}
