namespace Nyxite.Application.Content;

/// <summary>Configuration sections <c>Limits</c> and <c>Relay</c> (<c>NYXITE__Limits__*</c>, <c>NYXITE__Relay__*</c>, 14) for file content.</summary>
public sealed class ContentOptions
{
    /// <summary>Largest ciphertext of one inline blob or snapshot upload (04 §4.7).</summary>
    public long MaxInlineBlobBytes { get; set; } = 100L * 1024 * 1024;

    /// <summary>Largest ciphertext of one CRDT update. A bigger change is sent as a snapshot.</summary>
    public int MaxCrdtUpdateBytes { get; set; } = 1024 * 1024;

    /// <summary>Largest encrypted awareness message the relay forwards.</summary>
    public int MaxAwarenessBytes { get; set; } = 64 * 1024;
}

public sealed class RelayOptions
{
    public const string Section = "Relay";

    /// <summary>Updates younger than this are never pruned, also when a snapshot covers them (05 §5.6).</summary>
    public int SafetyTailDays { get; set; } = 7;

    /// <summary>This many of a document's newest updates are never pruned, also when a snapshot covers them (05 §5.6).</summary>
    public int SafetyTailUpdates { get; set; } = 1000;

    /// <summary>
    /// How often the relay checks again that every connection in a room still has reach and a live session (05 §5.4,
    /// 09 §9.6). Join and submit check on every call; this bounds how long a revoked reader keeps receiving.
    /// </summary>
    public TimeSpan AccessRecheckInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Awareness messages one connection may send per second, over all its rooms, as a token bucket that holds one
    /// second's worth (05 §5.7, 13 §13.5). Clients coalesce awareness to 20 to 30 Hz per document, so twice that leaves
    /// room for two active documents and timer jitter. A message beyond it is refused with <c>rate_limited</c>.
    /// </summary>
    public int AwarenessPerSecond { get; set; } = 60;

    /// <summary>Connections one room holds at most, accounts and guests together; one more join answers <c>room_full</c>.</summary>
    public int MaxConnectionsPerRoom { get; set; } = 100;

    /// <summary>Rooms one connection is in at most; one more join answers <c>too_many_rooms</c>.</summary>
    public int MaxRoomsPerConnection { get; set; } = 50;
}
