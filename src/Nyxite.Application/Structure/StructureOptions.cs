namespace Nyxite.Application.Structure;

/// <summary>Configuration section <c>Limits</c> (<c>NYXITE__Limits__*</c>, 14): size caps of opaque structure fields.</summary>
public sealed class StructureOptions
{
    public const string Section = "Limits";

    /// <summary>Largest accepted <c>nameEnc</c>, frame overhead included. A 255 character name is about 1 KiB sealed.</summary>
    public int NameEncMaxBytes { get; set; } = 2048;

    /// <summary>Largest accepted <c>metadataEnc</c>, frame overhead included.</summary>
    public int MetadataEncMaxBytes { get; set; } = 64 * 1024;
}
