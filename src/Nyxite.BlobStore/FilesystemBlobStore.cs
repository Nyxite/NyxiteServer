using System.Runtime.InteropServices;
using Nyxite.Crypto;

namespace Nyxite.BlobStore;

/// <summary>
/// <see cref="IBlobStore"/> on a directory (03 §3.4), laid out as <c>&lt;aa&gt;/&lt;bb&gt;/&lt;full-hash&gt;</c> so no directory
/// grows without bound. A blob is written to <c>.tmp</c> on the same volume and then linked to its final name, which
/// is atomic and never replaces an existing blob, so a reader sees a whole blob or none.
/// </summary>
public sealed class FilesystemBlobStore : IBlobStore
{
    private const string TempDirectory = ".tmp";

    private readonly string _root;
    private readonly string _temp;

    public FilesystemBlobStore(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath)) throw new ArgumentException("The blob root path is not set.", nameof(rootPath));
        _root = Path.GetFullPath(rootPath);
        _temp = Path.Combine(_root, TempDirectory);
        Directory.CreateDirectory(_temp);
    }

    public async Task<BlobRef> PutAsync(ReadOnlyMemory<byte> ciphertext, BlobAddress address, CancellationToken ct)
    {
        if (!NyxcFrame.TryParseHeader(ciphertext.Span, out _)) throw new BlobFormatException("A blob must be an NYXC frame.");

        var final = PathOf(address);
        if (File.Exists(final)) return new BlobRef(address, new FileInfo(final).Length);

        Directory.CreateDirectory(Path.GetDirectoryName(final)!);
        var temp = Path.Combine(_temp, Guid.NewGuid().ToString("N"));
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                await stream.WriteAsync(ciphertext, ct);
                // On disk before it gets its name: after a crash the address holds a whole blob or nothing.
                stream.Flush(flushToDisk: true);
            }

            // Another writer may take the address first. Write-once: its blob stays, and this one is dropped.
            PublishIfAbsent(temp, final);
        }
        finally
        {
            File.Delete(temp);
        }

        return new BlobRef(address, new FileInfo(final).Length);
    }

    /// <summary>
    /// Gives the finished temp file its final name unless that name exists, as one atomic step. On Unix this is a hard
    /// link, which fails when the name is taken. <c>File.Move</c> without overwrite is not used there, because it checks
    /// and renames in two steps and a second writer can slip in between and replace the first one's blob.
    /// </summary>
    private static void PublishIfAbsent(string temp, string final)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                File.Move(temp, final, overwrite: false);
            }
            catch (IOException) when (File.Exists(final))
            {
            }

            return;
        }

        const int AlreadyExists = 17;
        if (link(temp, final) != 0 && Marshal.GetLastPInvokeError() is var error and not AlreadyExists)
            throw new IOException($"Storing a blob failed (errno {error}).");
    }

    [DllImport("libc", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int link([MarshalAs(UnmanagedType.LPUTF8Str)] string oldPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);

    public Task<Stream> OpenReadAsync(BlobRef reference, CancellationToken ct) =>
        Task.FromResult<Stream>(new FileStream(PathOf(reference.Address), FileMode.Open, FileAccess.Read, FileShare.Read, 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan));

    public Task<bool> ExistsAsync(BlobAddress address, CancellationToken ct) => Task.FromResult(File.Exists(PathOf(address)));

    public Task DeleteAsync(BlobRef reference, CancellationToken ct)
    {
        File.Delete(PathOf(reference.Address));
        return Task.CompletedTask;
    }

    public async Task ProbeAsync(CancellationToken ct)
    {
        var probe = Path.Combine(_temp, "probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            await File.WriteAllBytesAsync(probe, [0], ct);
        }
        finally
        {
            File.Delete(probe);
        }
    }

    private string PathOf(BlobAddress address)
    {
        var hex = address.Hex;
        return Path.Combine(_root, hex[..2], hex[2..4], hex);
    }
}
