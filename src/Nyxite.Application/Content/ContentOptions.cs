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
}
