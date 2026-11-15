using Nyxite.Application.Content;
using Nyxite.Application.Sharing;
using Nyxite.Contracts.Content;
using Nyxite.Contracts.Sharing;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>Account and link shares and the wrapped keys members get with them (server 04 "shares", "file keys", 09).</summary>
public static class ShareEndpoints
{
    public static RouteGroupBuilder MapShareEndpoints(this RouteGroupBuilder api)
    {
        // The collection routes sit on api itself: on a group, "" would map with a trailing slash.
        api.MapGet("/shares", async (string? targetType, Guid? targetId, string? cursor, int? limit, ShareService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListAsync(http.User, targetType, targetId, cursor, limit, ct))).RequireAuthorization();

        api.MapPost("/shares", async (CreateShareRequest body, ShareService s, HttpContext http, CancellationToken ct) =>
        {
            var key = http.Request.Headers.TryGetValue(KeyEndpoints.IdempotencyHeader, out var v) ? v.ToString() : null;
            var response = await s.CreateAsync(http.User, body, key, http.Info(), ct);
            return Results.Text(response.Json, "application/json", System.Text.Encoding.UTF8, response.Status);
        }).RequireAuthorization().RequireRateLimiting(RateLimiting.Shares);

        var shares = api.MapGroup("/shares").RequireAuthorization();
        shares.MapPatch("/{id:guid}", async (Guid id, UpdateShareRequest body, ShareService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.UpdateAsync(http.User, id, body, http.Info(), ct)));
        shares.MapDelete("/{id:guid}", async (Guid id, ShareService s, HttpContext http, CancellationToken ct) =>
        {
            await s.RevokeAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        });

        var files = api.MapGroup("/files").RequireAuthorization();
        files.MapPost("/{id:guid}/keys", async (Guid id, UploadFileKeysRequest body, KeyGrantService keys, HttpContext http, CancellationToken ct) =>
        {
            await keys.UploadAsync(http.User, id, body, ct);
            return Results.NoContent();
        });
        files.MapPost("/{id:guid}/keys/rotate", async (Guid id, RotateFileKeyRequest body, KeyRotationService rotation, HttpContext http, CancellationToken ct) =>
        {
            var key = http.Request.Headers.TryGetValue(KeyEndpoints.IdempotencyHeader, out var v) ? v.ToString() : null;
            await rotation.CommitAsync(http.User, id, body, key, http.Info(), ct);
            return Results.NoContent();
        });
        files.MapPost("/keys:batch", async (BatchGrantRequest body, KeyGrantService keys, HttpContext http, CancellationToken ct) =>
            Results.Ok(await keys.BatchAsync(http.User, body, ct)));

        return api;
    }
}

/// <summary>
/// The public, token-scoped link-share surface outside <c>/api/v1</c> (04 §4.8). The link token in the path is the
/// credential of the bootstrap and of the guest-token renewal; the ciphertext and the socket ticket need the guest
/// token, which must belong to the same link. The decryption key is the URL fragment and is never sent here. Every
/// request under <see cref="Prefix"/> counts against the per-IP <c>share-access</c> bucket before authentication
/// (<see cref="RateLimiting.UseNyxitePreAuthenticationRateLimiting"/>), so a rejected guest token counts as well.
/// </summary>
public static class PublicShareEndpoints
{
    public const string Prefix = "/share";

    public static IEndpointRouteBuilder MapPublicShareEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(Prefix + "/{token}", async (string token, GuestShareService guests, HttpContext http, CancellationToken ct) =>
            Results.Ok(await guests.BootstrapAsync(token, http.Info(), ct)));

        app.MapPost(Prefix + "/{token}/session", async (string token, GuestShareService guests, HttpContext http, CancellationToken ct) =>
            Results.Ok(await guests.SessionAsync(token, http.Info(), ct)));

        app.MapGet(Prefix + "/{token}/blob", async (GuestShareService guests, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            var shareId = http.User.GuestShareIdOrThrow();
            var share = await guests.LiveShareAsync(shareId, ct);
            var read = await content.ReadHeadAsync(http.User, share.FileId!.Value, http.Request.Headers.IfNoneMatch.ToString() is { Length: > 0 } tag ? tag : null, ct);
            await guests.RecordBlobAccessAsync(shareId, http.Info(), ct);
            if (read is null) return Results.StatusCode(StatusCodes.Status304NotModified);
            if (read.Version.CrdtSeq is { } crdtSeq)
                http.Response.Headers[ContentEndpoints.SnapshotSeqHeader] = crdtSeq.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return ContentEndpoints.Stream(http, read);
        }).RequireAuthorization(AuthSetup.Guest);

        app.MapPost(Prefix + "/{token}/socket-ticket", async (GuestShareService guests, HttpContext http, CancellationToken ct) =>
            Results.Ok(await guests.IssueTicketAsync(http.User.GuestShareIdOrThrow(), ct)))
            .RequireAuthorization(AuthSetup.Guest);

        return app;
    }

    private static Guid GuestShareIdOrThrow(this System.Security.Claims.ClaimsPrincipal user) =>
        Nyxite.Application.Auth.AuthClaims.GuestShareId(user) ?? throw Nyxite.Application.Auth.AuthException.Unauthenticated();
}
