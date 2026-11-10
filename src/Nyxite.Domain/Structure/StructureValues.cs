namespace Nyxite.Domain.Structure;

/// <summary>
/// <c>files.content_type</c> (02 §2.3). Server-visible, because it selects the sync channel and the client decoder, and
/// fixed at creation.
/// </summary>
public static class ContentTypes
{
    public const string Markdown = "markdown";
    public const string Plaintext = "plaintext";
    public const string SourceCode = "sourcecode";
    public const string Ink = "ink";
    public const string Office = "office";
    public const string Image = "image";
    public const string Binary = "binary";

    public static readonly IReadOnlySet<string> All = new HashSet<string> { Markdown, Plaintext, SourceCode, Ink, Office, Image, Binary };

    /// <summary>The text types ride the CRDT relay and therefore carry a <c>crdt_doc_id</c>.</summary>
    public static bool IsCrdt(string contentType) => contentType is Markdown or Plaintext or SourceCode;
}

/// <summary><c>sync_policy</c> (02 §2.4). Exactly two server values; offline pinning is client-local.</summary>
public static class SyncPolicies
{
    public const string ServerDefault = "server-default";
    public const string Excluded = "excluded";

    public static bool IsValid(string value) => value is ServerDefault or Excluded;
}

/// <summary>Folder invariants that need no database (02 §2.2.4).</summary>
public static class FolderRules
{
    /// <summary>
    /// True when moving <paramref name="folderId"/> under a parent with the given ancestor chain (the parent itself
    /// first) would make the folder its own ancestor.
    /// </summary>
    public static bool WouldCycle(Guid folderId, IEnumerable<Guid> newParentAndItsAncestors) => newParentAndItsAncestors.Contains(folderId);
}
