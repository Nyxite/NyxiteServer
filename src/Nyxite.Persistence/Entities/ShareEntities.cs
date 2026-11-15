namespace Nyxite.Persistence.Entities;

/// <summary>
/// <c>shares</c> (03 §3.3, 09 §9.2): one ACL grant on one file, folder or project. An account share names its grantee,
/// whose wrapped keys live in <c>file_keys</c> and <c>structure_keys</c>. A link share holds only the SHA-256 of its
/// token; the file key rides the URL fragment and never reaches the server.
/// </summary>
public sealed class ShareEntity
{
    public const string UserGrant = "user_grant";
    public const string Link = "link";
    public const string Read = "read";
    public const string Write = "write";

    public Guid Id { get; set; }
    public Guid? FileId { get; set; }
    public Guid? FolderId { get; set; }
    public Guid? ProjectId { get; set; }
    public required string Kind { get; set; }
    public Guid? GranteeId { get; set; }

    /// <summary>SHA-256 of the ASCII link token; set for a link share only. The token itself is never stored.</summary>
    public byte[]? LinkTokenHash { get; set; }
    public required string Permission { get; set; }
    public Guid CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
