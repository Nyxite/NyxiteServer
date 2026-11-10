namespace Nyxite.BlobStore;

/// <summary>
/// A content address (03 §3.4): the client-computed BLAKE3-256 of the plaintext. The server cannot check it against
/// the ciphertext it names and treats it as an opaque, write-once name.
/// </summary>
public readonly record struct BlobAddress
{
    public const int Size = 32;

    private readonly string _hex;

    private BlobAddress(string hex) => _hex = hex;

    /// <summary>64 lower-case hex characters.</summary>
    public string Hex => _hex ?? throw new InvalidOperationException("The address is not set.");

    public static BlobAddress From(ReadOnlySpan<byte> hash) =>
        hash.Length == Size ? new BlobAddress(Convert.ToHexStringLower(hash)) : throw new ArgumentException($"A blob address is {Size} bytes.", nameof(hash));

    public override string ToString() => Hex;
}

/// <summary>Where a stored blob is and how large its ciphertext is.</summary>
public sealed record BlobRef(BlobAddress Address, long Size);

/// <summary>The bytes offered as a blob are not an NYXC frame.</summary>
public sealed class BlobFormatException(string message) : Exception(message);

/// <summary>The ciphertext store (03 §3.4). It holds NYXC frames only and never a key.</summary>
public interface IBlobStore
{
    /// <summary>
    /// Stores a frame under its address. Addresses are write-once: when one is taken, the stored blob stays and its
    /// reference is returned. Throws <see cref="BlobFormatException"/> for anything that is not an NYXC frame.
    /// </summary>
    Task<BlobRef> PutAsync(ReadOnlyMemory<byte> ciphertext, BlobAddress address, CancellationToken ct);

    /// <summary>The stored ciphertext. Throws <see cref="FileNotFoundException"/> when the address holds nothing.</summary>
    Task<Stream> OpenReadAsync(BlobRef reference, CancellationToken ct);

    Task<bool> ExistsAsync(BlobAddress address, CancellationToken ct);

    /// <summary>Garbage collection only. Deleting an absent blob is not an error.</summary>
    Task DeleteAsync(BlobRef reference, CancellationToken ct);

    /// <summary>Proves the store accepts writes, for startup and readiness (14 §14.4, §14.5). Throws when it does not.</summary>
    Task ProbeAsync(CancellationToken ct);
}
