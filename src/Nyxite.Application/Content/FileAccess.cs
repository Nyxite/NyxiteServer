using Microsoft.EntityFrameworkCore;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Content;

/// <summary>What the server ACL lets a principal do with a file (09 §9.5). Decryption is a separate, client-side question.</summary>
public enum FileAccessLevel
{
    /// <summary>No reach: the caller gets <c>404</c>, as for an id that does not exist.</summary>
    None,
    Read,
    Write,
}

/// <summary>
/// The server ACL of file content (09 §9.1, first layer): every content read and write, the relay join and submit, and
/// the relay's periodic re-check ask here, so a revoked reach ends at every checkpoint at once.
/// </summary>
public interface IFileAccess
{
    /// <summary>The effective level of <paramref name="userId"/> on a live <paramref name="file"/>: the maximum over all its paths.</summary>
    Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct);
}

/// <summary>
/// Ownership as the only path to a file, until shares add direct and inherited grants (Phase 2.2). The project must be
/// live as well, so a project in Trash cuts off its files.
/// </summary>
public sealed class OwnerFileAccess(NyxiteDbContext db) : IFileAccess
{
    public async Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct) =>
        await db.Projects.AnyAsync(p => p.Id == file.ProjectId && p.OwnerId == userId && p.DeletedAt == null, ct)
            ? FileAccessLevel.Write
            : FileAccessLevel.None;
}
