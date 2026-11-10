using Nyxite.Application.Keys;
using Nyxite.Application.Structure;
using Nyxite.Contracts.Structure;
using Nyxite.Server.Http;

namespace Nyxite.Server.Endpoints;

/// <summary>Projects, folders and files with encrypted names, and the caller's wrapped keys for them (server 04 "structure").</summary>
public static class StructureEndpoints
{
    public static RouteGroupBuilder MapStructureEndpoints(this RouteGroupBuilder api)
    {
        // The collection routes sit on api itself: on a group, "" would map with a trailing slash.
        api.MapGet("/projects", async (string? cursor, int? limit, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListProjectsAsync(http.User, cursor, limit, keys ?? true, ct))).RequireAuthorization();
        api.MapPost("/projects", async (CreateProjectRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Created(await s.CreateProjectAsync(http.User, body, Key(http), ct))).RequireAuthorization();

        var projects = api.MapGroup("/projects").RequireAuthorization();
        projects.MapGet("/{id:guid}", async (Guid id, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.GetProjectAsync(http.User, id, keys ?? true, ct)));
        projects.MapPatch("/{id:guid}", async (Guid id, UpdateProjectRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.UpdateProjectAsync(http.User, id, body, ct)));
        projects.MapDelete("/{id:guid}", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
        {
            await s.DeleteProjectAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        });
        projects.MapGet("/{id:guid}/folders", async (Guid id, string? cursor, int? limit, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListFoldersAsync(http.User, id, cursor, limit, keys ?? true, ct)));
        projects.MapGet("/{id:guid}/files", async (Guid id, string? cursor, int? limit, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListFilesAsync(http.User, id, null, cursor, limit, keys ?? true, ct)));
        projects.MapGet("/{id:guid}/keys", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ProjectKeysAsync(http.User, id, ct)));

        api.MapPost("/folders", async (CreateFolderRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Created(await s.CreateFolderAsync(http.User, body, Key(http), ct))).RequireAuthorization();

        var folders = api.MapGroup("/folders").RequireAuthorization();
        folders.MapGet("/{id:guid}", async (Guid id, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.GetFolderAsync(http.User, id, keys ?? true, ct)));
        folders.MapPatch("/{id:guid}", async (Guid id, UpdateFolderRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.UpdateFolderAsync(http.User, id, body, ct)));
        folders.MapDelete("/{id:guid}", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
        {
            await s.DeleteFolderAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        });
        folders.MapGet("/{id:guid}/files", async (Guid id, string? cursor, int? limit, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListFilesAsync(http.User, null, id, cursor, limit, keys ?? true, ct)));
        folders.MapGet("/{id:guid}/keys", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.FolderKeysAsync(http.User, id, ct)));

        api.MapPost("/files", async (CreateFileRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Created(await s.CreateFileAsync(http.User, body, Key(http), ct))).RequireAuthorization();

        var files = api.MapGroup("/files").RequireAuthorization();
        files.MapGet("/{id:guid}", async (Guid id, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.GetFileAsync(http.User, id, keys ?? true, ct)));
        files.MapPatch("/{id:guid}", async (Guid id, UpdateFileRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.UpdateFileAsync(http.User, id, body, ct)));
        files.MapDelete("/{id:guid}", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
        {
            await s.DeleteFileAsync(http.User, id, http.Info(), ct);
            return Results.NoContent();
        });
        files.MapGet("/{id:guid}/keys", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.FileKeysAsync(http.User, id, ct)));

        // ---- keys of many objects
        api.MapPost("/keys/lookup", async (KeyLookupRequest body, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.LookupKeysAsync(http.User, body, ct))).RequireAuthorization();

        // ---- trash
        api.MapGet("/trash", async (string? cursor, int? limit, bool? keys, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.ListTrashAsync(http.User, cursor, limit, keys ?? true, ct))).RequireAuthorization();
        var trash = api.MapGroup("/trash").RequireAuthorization();
        trash.MapPost("/projects/{id:guid}/restore", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.RestoreProjectAsync(http.User, id, http.Info(), ct)));
        trash.MapPost("/folders/{id:guid}/restore", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.RestoreFolderAsync(http.User, id, http.Info(), ct)));
        trash.MapPost("/files/{id:guid}/restore", async (Guid id, StructureService s, HttpContext http, CancellationToken ct) =>
            Results.Ok(await s.RestoreFileAsync(http.User, id, http.Info(), ct)));

        return api;
    }

    private static string? Key(HttpContext http) =>
        http.Request.Headers.TryGetValue(KeyEndpoints.IdempotencyHeader, out var v) ? v.ToString() : null;

    private static IResult Created(IdempotentResponse response) =>
        Results.Text(response.Json, "application/json", System.Text.Encoding.UTF8, response.Status);
}
