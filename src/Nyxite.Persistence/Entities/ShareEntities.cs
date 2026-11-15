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

    /// <summary>The unique index that makes a link token name exactly one share.</summary>
    public const string LinkIndex = "uq_shares_link";

    /// <summary>The partial unique index that allows one unrevoked account share per target and grantee.</summary>
    public const string LiveGrantIndex = "uq_shares_live_grant";

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

    /// <summary>
    /// A link kept through a key rotation (09 §9.6): the generation its fragment key belongs to. Null while the link
    /// follows the file. A frozen link serves only what that key opens: <see cref="FrozenVersionSeq"/>, the name and the
    /// metadata as they were sealed before the rotation, read only, and no relay room.
    /// </summary>
    public int? FrozenGeneration { get; set; }

    /// <summary>The head version at the rotation that froze the link; null when the file had no head.</summary>
    public long? FrozenVersionSeq { get; set; }

    /// <summary>The file's <c>name_enc</c> sealed with the frozen generation's key, as it was before the rotation.</summary>
    public byte[]? FrozenNameEnc { get; set; }

    /// <summary>The file's <c>metadata_enc</c> sealed with the frozen generation's key, as it was before the rotation.</summary>
    public byte[]? FrozenMetadataEnc { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
