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

    /// <summary>Reads the lower-case hex form back, as it appears in a file name or a <c>blob_ref</c> column.</summary>
    public static bool TryParseHex(string? hex, out BlobAddress address)
    {
        address = default;
        if (hex is not { Length: Size * 2 } || !hex.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f')) return false;
        address = new BlobAddress(hex);
        return true;
    }

    public override string ToString() => Hex;
}

/// <summary>Where a stored blob is and how large its ciphertext is.</summary>
public sealed record BlobRef(BlobAddress Address, long Size);

/// <summary>The bytes offered as a blob are not an NYXC frame.</summary>
public sealed class BlobFormatException(string message) : Exception(message);

/// <summary>The bytes offered as a blob are larger than the caller allowed.</summary>
public sealed class BlobTooLargeException(long limit) : Exception($"The blob is larger than {limit} bytes.")
{
    public long Limit { get; } = limit;
}

/// <summary>
/// An upload that is fully received but has no address yet (03 §3.4). Receiving and naming are separate steps, so a
/// large upload streams to the store's volume while no database lock is held, and the caller checks it (size, frame
/// header, quota) before <see cref="IBlobStore.CommitAsync"/> names it. Disposing drops whatever was not committed.
/// </summary>
public abstract class StagedBlob : IDisposable
{
    /// <summary>Ciphertext length in bytes.</summary>
    public required long Length { get; init; }

    /// <summary>The first bytes of the upload, up to <see cref="Nyxite.Crypto.NyxcFrame.Overhead"/>, for the header check.</summary>
    public required ReadOnlyMemory<byte> Head { get; init; }

    public abstract void Dispose();
}

/// <summary>A blob the store holds, as the garbage collector sees it.</summary>
public sealed record StoredBlob(BlobAddress Address, long Size, DateTimeOffset LastWrittenAt);

/// <summary>The ciphertext store (03 §3.4). It holds NYXC frames only and never a key.</summary>
public interface IBlobStore
{
    /// <summary>
    /// Receives an upload into the store's staging area without naming it. Throws <see cref="BlobTooLargeException"/>
    /// once more than <paramref name="maxBytes"/> arrive, so an oversized upload is cut off instead of stored.
    /// </summary>
    Task<StagedBlob> StageAsync(Stream source, long maxBytes, CancellationToken ct);

    /// <summary>
    /// Gives a staged upload its address. Addresses are write-once: when one is taken, the stored blob stays and its
    /// reference is returned, and its write time is renewed, because it is being referenced again. Throws
    /// <see cref="BlobFormatException"/> for anything that is not an NYXC frame.
    /// </summary>
    Task<BlobRef> CommitAsync(StagedBlob staged, BlobAddress address, CancellationToken ct);

    /// <summary>Stage and commit in one call, for small payloads already in memory.</summary>
    async Task<BlobRef> PutAsync(ReadOnlyMemory<byte> ciphertext, BlobAddress address, CancellationToken ct)
    {
        using var staged = await StageAsync(new MemoryStream(ciphertext.ToArray(), writable: false), long.MaxValue, ct);
        return await CommitAsync(staged, address, ct);
    }

    /// <summary>The stored ciphertext. Throws <see cref="FileNotFoundException"/> when the address holds nothing.</summary>
    Task<Stream> OpenReadAsync(BlobRef reference, CancellationToken ct);

    Task<bool> ExistsAsync(BlobAddress address, CancellationToken ct);

    /// <summary>Every stored blob, in no particular order. Garbage collection only.</summary>
    IAsyncEnumerable<StoredBlob> ListAsync(CancellationToken ct);

    /// <summary>Garbage collection only. Deleting an absent blob is not an error.</summary>
    Task DeleteAsync(BlobAddress address, CancellationToken ct);

    /// <summary>
    /// Deletes staging leftovers older than <paramref name="olderThan"/>, which only a crash during an upload leaves
    /// behind. Returns how many it removed.
    /// </summary>
    Task<int> DeleteStaleStagingAsync(TimeSpan olderThan, CancellationToken ct);

    /// <summary>Proves the store accepts writes, for startup and readiness (14 §14.4, §14.5). Throws when it does not.</summary>
    Task ProbeAsync(CancellationToken ct);
}
