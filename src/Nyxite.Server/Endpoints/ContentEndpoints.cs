using Microsoft.AspNetCore.Http.Features;
using Nyxite.Application.Auth;
using Nyxite.Application.Content;
using Nyxite.Application.Keys;
using Nyxite.Contracts.Content;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>File content as ciphertext: blobs, versions, the encrypted update log and snapshots (server 04 "content", "versions").</summary>
public static class ContentEndpoints
{
    public const string ContentHashHeader = "Nyxite-Content-Hash";
    public const string KeyIdHeader = "Nyxite-Key-Id";
    public const string SnapshotSeqHeader = "Nyxite-Snapshot-Seq";
    public const string LayoutHeader = "Nyxite-Blob-Layout";

    public static RouteGroupBuilder MapContentEndpoints(this RouteGroupBuilder api)
    {
        var files = api.MapGroup("/files").RequireAuthorization();

        files.MapGet("/{id:guid}/blob", async (Guid id, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            var read = await content.ReadHeadAsync(http.User, id, http.Request.Headers.IfNoneMatch.ToString() is { Length: > 0 } tag ? tag : null, ct);
            return read is null ? Results.StatusCode(StatusCodes.Status304NotModified) : Stream(http, read);
        });

        files.MapPut("/{id:guid}/blob", async (Guid id, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            if (!long.TryParse(http.Request.Headers.IfMatch.ToString().Trim('"'), out var parentSeq) || parentSeq < 0)
                throw AuthException.Validation("If-Match must be the version seq the upload is based on, 0 for the first.");
            var body = await ReadBodyAsync(http, content.MaxInlineBlobBytes, ct);
            var result = await content.PutBlobAsync(http.User, id, parentSeq, http.Request.Headers[ContentHashHeader], KeyId(http), body, ct);
            return result.Winner is null
                ? Results.Json(result.Version, statusCode: StatusCodes.Status201Created)
                : Results.Json(new
                {
                    type = "urn:nyxite:problem:conflict",
                    title = "Another write came first. The upload is kept as a version that is not the head.",
                    status = 409,
                    code = "conflict",
                    winner = result.Winner,
                    sibling = result.Version,
                }, contentType: Problems.ContentType, statusCode: StatusCodes.Status409Conflict);
        });

        files.MapGet("/{id:guid}/versions", async (Guid id, string? cursor, int? limit, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            var (items, next) = await content.ListVersionsAsync(http.User, id, cursor, limit, ct);
            return Results.Ok(new { items, nextCursor = next });
        });

        files.MapGet("/{id:guid}/versions/{seq:long}", async (Guid id, long seq, ContentService content, HttpContext http, CancellationToken ct) =>
            Results.Ok(await content.GetVersionAsync(http.User, id, seq, ct)));

        files.MapGet("/{id:guid}/versions/{seq:long}/blob", async (Guid id, long seq, ContentService content, HttpContext http, CancellationToken ct) =>
            Stream(http, await content.ReadVersionAsync(http.User, id, seq, ct)));

        files.MapPost("/{id:guid}/restore", async (Guid id, RestoreRequest body, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            if (IdempotencyStore.ValidKey(http.Request.Headers[KeyEndpoints.IdempotencyHeader]) is null)
                throw AuthException.Validation("A valid Idempotency-Key header is required.");
            await content.RecordRestoreAsync(http.User, id, body, http.Info(), ct);
            return Results.NoContent();
        });

        files.MapGet("/{id:guid}/crdt/log", async (Guid id, long since, int? limit, ContentService content, HttpContext http, CancellationToken ct) =>
            Results.Ok(await content.ReadUpdatesAsync(http.User, id, since, limit, ct)));

        files.MapPost("/{id:guid}/crdt/log", async (Guid id, SubmitUpdatesRequest body, ContentService content, HttpContext http, CancellationToken ct) =>
            Results.Ok(await content.SubmitUpdatesAsync(http.User, id, body.Updates ?? [], ct)));

        files.MapGet("/{id:guid}/snapshot", async (Guid id, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            var read = await content.ReadSnapshotAsync(http.User, id, ct);
            http.Response.Headers[SnapshotSeqHeader] = (read.Version.CrdtSeq ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Stream(http, read);
        });

        files.MapPut("/{id:guid}/snapshot", async (Guid id, ContentService content, HttpContext http, CancellationToken ct) =>
        {
            if (!long.TryParse(http.Request.Headers[SnapshotSeqHeader], out var crdtSeq))
                throw AuthException.Validation("Nyxite-Snapshot-Seq must be the seq of the last update the snapshot contains.");
            var body = await ReadBodyAsync(http, content.MaxInlineBlobBytes, ct);
            var version = await content.PutSnapshotAsync(http.User, id, crdtSeq, http.Request.Headers[ContentHashHeader], KeyId(http), body, ct);
            return Results.Json(version, statusCode: StatusCodes.Status201Created);
        });

        return api;
    }

    private static Guid KeyId(HttpContext http) =>
        Guid.TryParse(http.Request.Headers[KeyIdHeader], out var id) ? id : throw AuthException.Validation("Nyxite-Key-Id must be a UUID.");

    private static IResult Stream(HttpContext http, BlobRead read)
    {
        http.Response.Headers[LayoutHeader] = read.Version.Layout;
        http.Response.Headers.ETag = $"\"{read.Version.ContentHash}\"";
        http.Response.Headers[KeyIdHeader] = read.Version.KeyId.ToString();
        return Results.Stream(read.Content, "application/octet-stream");
    }

    /// <summary>
    /// Reads an upload of at most <paramref name="max"/> bytes into memory. The server's general body limit is lifted
    /// for this request and replaced by this one, so a larger upload stops after <paramref name="max"/> bytes.
    /// </summary>
    private static async Task<ReadOnlyMemory<byte>> ReadBodyAsync(HttpContext http, long max, CancellationToken ct)
    {
        if (http.Request.ContentLength > max) throw ContentService.PayloadTooLarge("The upload is larger than the inline limit.");
        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = max;
        using var buffer = new MemoryStream(http.Request.ContentLength is { } length ? (int)length : 0);
        var chunk = new byte[81920];
        int read;
        while ((read = await http.Request.Body.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > max) throw ContentService.PayloadTooLarge("The upload is larger than the inline limit.");
            buffer.Write(chunk, 0, read);
        }

        return buffer.GetBuffer().AsMemory(0, (int)buffer.Length);
    }
}
