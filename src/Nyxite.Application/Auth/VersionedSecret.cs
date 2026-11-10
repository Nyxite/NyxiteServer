namespace Nyxite.Application.Auth;

/// <summary>
/// A rotatable server secret with numbered versions, configured as <c>{version}:{base64 key}</c> entries separated by
/// <c>;</c> (14). The highest version is current; older versions stay valid for verification during a rollover.
/// </summary>
public sealed class VersionedSecret
{
    public const int MinimumKeyBytes = 32;

    private readonly SortedDictionary<int, byte[]> _keys;

    private VersionedSecret(SortedDictionary<int, byte[]> keys) => _keys = keys;

    public int CurrentVersion => _keys.Keys.Last();
    public byte[] Current => _keys[CurrentVersion];
    public IReadOnlyCollection<int> Versions => _keys.Keys;

    public bool TryGet(int version, out byte[] key) => _keys.TryGetValue(version, out key!);

    public static VersionedSecret Parse(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException($"{name} is not configured.");
        var keys = new SortedDictionary<int, byte[]>();
        foreach (var entry in value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var colon = entry.IndexOf(':');
            if (colon <= 0 || !int.TryParse(entry.AsSpan(0, colon), out var version) || version < 1)
                throw new InvalidOperationException($"{name}: each entry must be '<version>:<base64 key>' with version >= 1.");
            byte[] key;
            try { key = Convert.FromBase64String(entry[(colon + 1)..]); }
            catch (FormatException) { throw new InvalidOperationException($"{name}: version {version} is not valid base64."); }
            if (key.Length < MinimumKeyBytes)
                throw new InvalidOperationException($"{name}: version {version} must be at least {MinimumKeyBytes} bytes.");
            if (!keys.TryAdd(version, key)) throw new InvalidOperationException($"{name}: version {version} appears twice.");
        }

        if (keys.Count == 0) throw new InvalidOperationException($"{name} is not configured.");
        return new VersionedSecret(keys);
    }
}
