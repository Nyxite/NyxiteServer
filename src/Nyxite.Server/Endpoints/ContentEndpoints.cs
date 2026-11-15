using Nyxite.BlobStore;
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

        files.MapPut("/{id:guid}/blob", async (Guid id, ContentService content, IBlobStore blobs, HttpContext http, CancellationToken ct) =>
        {
            if (!long.TryParse(http.Request.Headers.IfMatch.ToString().Trim('"'), out var parentSeq) || parentSeq < 0)
                throw AuthException.Validation("If-Match must be the version seq the upload is based on, 0 for the first.");
            using var body = await StageBodyAsync(http, blobs, content.MaxInlineBlobBytes, ct);
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
            await content.RecordRestoreAsync(http.User, id, body, http.Request.Headers[KeyEndpoints.IdempotencyHeader], http.Info(), ct);
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

        files.MapPut("/{id:guid}/snapshot", async (Guid id, ContentService content, IBlobStore blobs, HttpContext http, CancellationToken ct) =>
        {
            if (!long.TryParse(http.Request.Headers[SnapshotSeqHeader], out var crdtSeq))
                throw AuthException.Validation("Nyxite-Snapshot-Seq must be the seq of the last update the snapshot contains.");
            using var body = await StageBodyAsync(http, blobs, content.MaxInlineBlobBytes, ct);
            var version = await content.PutSnapshotAsync(http.User, id, crdtSeq, http.Request.Headers[ContentHashHeader], KeyId(http), body, ct);
            return Results.Json(version, statusCode: StatusCodes.Status201Created);
        });

        // The head of a key rotation, staged under the new key before the commit names it (09 §9.6).
        files.MapPut("/{id:guid}/keys/rotate/head", async (Guid id, ContentService content, IBlobStore blobs, HttpContext http, CancellationToken ct) =>
        {
            long? crdtSeq = http.Request.Headers.ContainsKey(SnapshotSeqHeader)
                ? long.TryParse(http.Request.Headers[SnapshotSeqHeader], out var seq) ? seq : throw AuthException.Validation("Nyxite-Snapshot-Seq must be a number.")
                : null;
            var ifMatch = http.Request.Headers.IfMatch.ToString().Trim('"');
            long? parentSeq = ifMatch.Length == 0 ? null
                : long.TryParse(ifMatch, out var parent) && parent >= 0 ? parent : throw AuthException.Validation("If-Match must be the version seq the head is based on.");
            using var body = await StageBodyAsync(http, blobs, content.MaxInlineBlobBytes, ct);
            await content.StageRotationHeadAsync(http.User, id, KeyId(http), http.Request.Headers[ContentHashHeader], crdtSeq, parentSeq, body, ct);
            return Results.NoContent();
        });

        return api;
    }

    private static Guid KeyId(HttpContext http) =>
        Guid.TryParse(http.Request.Headers[KeyIdHeader], out var id) ? id : throw AuthException.Validation("Nyxite-Key-Id must be a UUID.");

    internal static IResult Stream(HttpContext http, BlobRead read)
    {
        http.Response.Headers[LayoutHeader] = read.Version.Layout;
        http.Response.Headers.ETag = $"\"{read.Version.ContentHash}\"";
        http.Response.Headers[KeyIdHeader] = read.Version.KeyId.ToString();
        return Results.Stream(read.Content, "application/octet-stream");
    }

    /// <summary>
    /// Streams an upload of at most <paramref name="max"/> bytes to the blob store's staging area, so a large upload
    /// never sits in memory. The server's general body limit is lifted for this request and replaced by this one, so a
    /// larger upload stops after <paramref name="max"/> bytes.
    /// </summary>
    private static async Task<StagedBlob> StageBodyAsync(HttpContext http, IBlobStore blobs, long max, CancellationToken ct)
    {
        if (http.Request.ContentLength > max) throw ContentService.PayloadTooLarge("The upload is larger than the inline limit.");
        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = max;
        try
        {
            return await blobs.StageAsync(http.Request.Body, max, ct);
        }
        catch (BlobTooLargeException)
        {
            throw ContentService.PayloadTooLarge("The upload is larger than the inline limit.");
        }
    }
}
