namespace Nyxite.Application.Content;

/// <summary>
/// The relay members a change of access may concern: the connections of some accounts, of some link shares' guests, or
/// every connection in the rooms of some files. A member matches when any of the three names it. It carries ids only.
/// </summary>
public sealed record RelayAccessScope(IReadOnlySet<Guid> Users, IReadOnlySet<Guid> Shares, IReadOnlySet<Guid> Files)
{
    public static RelayAccessScope ForUser(Guid userId) => new(new HashSet<Guid> { userId }, Empty, Empty);

    public static RelayAccessScope ForShare(Guid shareId) => new(Empty, new HashSet<Guid> { shareId }, Empty);

    public static RelayAccessScope ForFiles(IEnumerable<Guid> fileIds) => new(Empty, Empty, fileIds.ToHashSet());

    public bool IsEmpty => Users.Count == 0 && Shares.Count == 0 && Files.Count == 0;

    public bool Matches(Guid fileId, Guid? userId, Guid? shareId) =>
        Files.Contains(fileId) || (userId is { } u && Users.Contains(u)) || (shareId is { } s && Shares.Contains(s));

    /// <summary>One scope that matches every member any of <paramref name="scopes"/> matches.</summary>
    public static RelayAccessScope Merge(IEnumerable<RelayAccessScope> scopes)
    {
        var list = scopes.ToList();
        return new RelayAccessScope(list.SelectMany(s => s.Users).ToHashSet(), list.SelectMany(s => s.Shares).ToHashSet(),
            list.SelectMany(s => s.Files).ToHashSet());
    }

    private static readonly IReadOnlySet<Guid> Empty = new HashSet<Guid>();
}

/// <summary>
/// Tells the relay that access changed after the change committed, so the affected room members are judged again at
/// once instead of at the next periodic re-check (05 §5.4, 09 §9.6): a revoked or changed share, a move to Trash. It
/// only queues; the relay runs a targeted pass of its re-check, and the periodic pass stays the backstop for what no
/// event covers, such as a share that expires on its own.
/// </summary>
public interface IRelayAccessEvents
{
    void AccessChanged(RelayAccessScope scope);
}
