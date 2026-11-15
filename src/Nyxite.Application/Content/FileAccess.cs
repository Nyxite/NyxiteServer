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

    /// <summary>The level of a link guest on a live <paramref name="file"/>: its link share's permission while the share is live.</summary>
    Task<FileAccessLevel> GuestLevelAsync(Guid shareId, FileEntity file, CancellationToken ct);
}

/// <summary>Ownership of the project and account shares on the project, a folder above the file or the file (09 §9.5).</summary>
public sealed class ShareFileAccess(Sharing.ShareAccess access) : IFileAccess
{
    public Task<FileAccessLevel> LevelAsync(Guid userId, FileEntity file, CancellationToken ct) => access.FileLevelAsync(userId, file, ct);

    public Task<FileAccessLevel> GuestLevelAsync(Guid shareId, FileEntity file, CancellationToken ct) => access.GuestLevelAsync(shareId, file, ct);
}
