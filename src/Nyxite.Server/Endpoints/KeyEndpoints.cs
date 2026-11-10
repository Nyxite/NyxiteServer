using Nyxite.Contracts.Keys;
using Nyxite.Application.Keys;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>Public-key directory, device enrollment and the recovery blob (server 04 "Keys, devices, recovery", 08 §8.3).</summary>
public static class KeyEndpoints
{
    public const string IdempotencyHeader = "Idempotency-Key";

    public static RouteGroupBuilder MapKeyEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/keys/directory", async (Guid? userId, string? email, KeyDirectoryService directory, CancellationToken ct) =>
                Results.Ok(await directory.LookupAsync(userId, email, ct)))
            .RequireAuthorization().RequireRateLimiting(RateLimiting.Directory);

        api.MapPut("/keys", async (PublishKeyRequest body, KeyDirectoryService directory, HttpContext http, CancellationToken ct) =>
            Results.Ok(await directory.PublishAsync(http.User, body, http.Info(), ct))).RequireAuthorization();

        var devices = api.MapGroup("/devices").RequireAuthorization();

        // The collection routes sit on api itself: on the group, "" would map as "/devices/".
        api.MapGet("/devices", async (DeviceService service, HttpContext http, CancellationToken ct) =>
            Results.Ok(new { items = await service.ListAsync(http.User, ct) })).RequireAuthorization();

        api.MapPost("/devices", async (RegisterDeviceRequest body, DeviceService service, HttpContext http, CancellationToken ct) =>
        {
            var key = http.Request.Headers.TryGetValue(IdempotencyHeader, out var v) ? v.ToString() : null;
            var response = await service.RegisterAsync(http.User, body, key, http.Info(), ct);
            return Results.Text(response.Json, "application/json", System.Text.Encoding.UTF8, response.Status);
        }).RequireAuthorization().RequireRateLimiting(RateLimiting.DeviceEnrollment);

        devices.MapGet("/me/enrollment", async (DeviceService service, HttpContext http, CancellationToken ct) =>
            Results.Ok(await service.FetchEnrollmentAsync(http.User, http.Info(), ct)));

        devices.MapGet("/{id:guid}", async (Guid id, DeviceService service, HttpContext http, CancellationToken ct) =>
            Results.Ok(await service.GetAsync(http.User, id, ct)));

        devices.MapDelete("/{id:guid}", async (Guid id, DeviceService service, HttpContext http, CancellationToken ct) =>
        {
            await service.RevokeAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        });

        devices.MapPost("/{id:guid}/approve", async (Guid id, ApproveDeviceRequest body, DeviceService service, HttpContext http, CancellationToken ct) =>
        {
            await service.ApproveAsync(http.User, id, body, http.Info(), ct);
            return Results.NoContent();
        });

        devices.MapPost("/{id:guid}/activate", async (Guid id, ActivateDeviceRequest body, DeviceService service, HttpContext http, CancellationToken ct) =>
        {
            await service.ActivateAsync(http.User, id, body, http.Info(), ct);
            return Results.NoContent();
        });

        api.MapGet("/recovery", async (RecoveryService recovery, HttpContext http, CancellationToken ct) =>
            Results.Ok(await recovery.GetAsync(http.User, http.Info(), ct))).RequireAuthorization();

        api.MapPut("/recovery", async (RecoveryBlobDto body, RecoveryService recovery, HttpContext http, CancellationToken ct) =>
        {
            await recovery.PutAsync(http.User, body, http.Info(), ct);
            return Results.NoContent();
        }).RequireAuthorization();

        return api;
    }
}
