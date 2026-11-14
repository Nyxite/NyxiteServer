using Nyxite.Application.Sync;
using Nyxite.Contracts.Sync;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>
/// Manifest and delta sync over structure and opaque content pointers (server 04 "sync", 06 §6.3). There is no search
/// endpoint: clients search locally over what they decrypt (11).
/// </summary>
public static class SyncEndpoints
{
    public static RouteGroupBuilder MapSyncEndpoints(this RouteGroupBuilder api)
    {
        var sync = api.MapGroup("/sync").RequireAuthorization();

        sync.MapGet("/manifest", async (Guid projectId, string? cursor, int? limit, bool? keys, SyncService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ManifestAsync(http.User, projectId, cursor, limit, keys ?? true, ct)));

        sync.MapPost("/changes", async (ChangesRequest body, SyncService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ChangesAsync(http.User, body, http.Info(), ct)));

        return api;
    }
}
