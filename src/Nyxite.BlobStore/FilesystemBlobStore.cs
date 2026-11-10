using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Nyxite.Crypto;

namespace Nyxite.BlobStore;

/// <summary>
/// <see cref="IBlobStore"/> on a directory (03 §3.4), laid out as <c>&lt;aa&gt;/&lt;bb&gt;/&lt;full-hash&gt;</c> so no directory
/// grows without bound. An upload is streamed to <c>.tmp</c> on the same volume and then linked to its final name,
/// which is atomic and never replaces an existing blob, so a reader sees a whole blob or none.
/// </summary>
public sealed class FilesystemBlobStore : IBlobStore
{
    private const string TempDirectory = ".tmp";
    private const int BufferSize = 81920;

    private readonly string _root;
    private readonly string _temp;

    public FilesystemBlobStore(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath)) throw new ArgumentException("The blob root path is not set.", nameof(rootPath));
        _root = Path.GetFullPath(rootPath);
        _temp = Path.Combine(_root, TempDirectory);
        Directory.CreateDirectory(_temp);
    }

    private sealed class TempFile : StagedBlob
    {
        public required string Path { get; init; }

        public override void Dispose() => File.Delete(Path);
    }

    public async Task<StagedBlob> StageAsync(Stream source, long maxBytes, CancellationToken ct)
    {
        var temp = Path.Combine(_temp, Guid.NewGuid().ToString("N"));
        var head = new byte[NyxcFrame.Overhead];
        var headLength = 0;
        long length = 0;
        try
        {
            await using (var target = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferSize, FileOptions.Asynchronous))
            {
                var buffer = new byte[BufferSize];
                int read;
                while ((read = await source.ReadAsync(buffer, ct)) > 0)
                {
                    length += read;
                    if (length > maxBytes) throw new BlobTooLargeException(maxBytes);
                    var take = Math.Min(read, head.Length - headLength);
                    buffer.AsSpan(0, take).CopyTo(head.AsSpan(headLength));
                    headLength += take;
                    await target.WriteAsync(buffer.AsMemory(0, read), ct);
                }

                // On disk before it can get a name: after a crash an address holds a whole blob or nothing.
                target.Flush(flushToDisk: true);
            }

            return new TempFile { Path = temp, Length = length, Head = head.AsMemory(0, headLength) };
        }
        catch
        {
            File.Delete(temp);
            throw;
        }
    }

    public Task<BlobRef> CommitAsync(StagedBlob staged, BlobAddress address, CancellationToken ct)
    {
        if (staged is not TempFile temp) throw new ArgumentException("The upload was staged by another store.", nameof(staged));
        if (staged.Length < NyxcFrame.Overhead || !NyxcFrame.TryParseHeader(staged.Head.Span, out _))
            throw new BlobFormatException("A blob must be an NYXC frame.");

        var final = PathOf(address);
        Directory.CreateDirectory(Path.GetDirectoryName(final)!);
        // Another writer may take the address first. Write-once: its blob stays, and this one is dropped. Its write
        // time is renewed, so the garbage collector's age check sees that it is wanted again.
        if (!PublishIfAbsent(temp.Path, final)) File.SetLastWriteTimeUtc(final, DateTime.UtcNow);
        return Task.FromResult(new BlobRef(address, new FileInfo(final).Length));
    }

    /// <summary>
    /// Gives the finished temp file its final name unless that name exists, as one atomic step, and says whether it
    /// did. On Unix this is a hard link, which fails when the name is taken. <c>File.Move</c> without overwrite is not
    /// used there, because it checks and renames in two steps and a second writer can slip in between and replace the
    /// first one's blob. The temp file itself is removed when the staged upload is disposed.
    /// </summary>
    private static bool PublishIfAbsent(string temp, string final)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                File.Copy(temp, final, overwrite: false);
                return true;
            }
            catch (IOException) when (File.Exists(final))
            {
                return false;
            }
        }

        const int AlreadyExists = 17;
        if (link(temp, final) == 0) return true;
        var error = Marshal.GetLastPInvokeError();
        return error == AlreadyExists ? false : throw new IOException($"Storing a blob failed (errno {error}).");
    }

    [DllImport("libc", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int link([MarshalAs(UnmanagedType.LPUTF8Str)] string oldPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string newPath);

    public Task<Stream> OpenReadAsync(BlobRef reference, CancellationToken ct) =>
        Task.FromResult<Stream>(new FileStream(PathOf(reference.Address), FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan));

    public Task<bool> ExistsAsync(BlobAddress address, CancellationToken ct) => Task.FromResult(File.Exists(PathOf(address)));

    public async IAsyncEnumerable<StoredBlob> ListAsync([EnumeratorCancellation] CancellationToken ct)
    {
        foreach (var first in Directory.EnumerateDirectories(_root))
        {
            if (Path.GetFileName(first) == TempDirectory) continue;
            foreach (var path in Directory.EnumerateFiles(first, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                if (!BlobAddress.TryParseHex(Path.GetFileName(path), out var address)) continue;
                var info = new FileInfo(path);
                if (!info.Exists) continue;
                yield return new StoredBlob(address, info.Length, info.LastWriteTimeUtc);
            }

            await Task.Yield();
        }
    }

    public Task DeleteAsync(BlobAddress address, CancellationToken ct)
    {
        File.Delete(PathOf(address));
        return Task.CompletedTask;
    }

    public Task<int> DeleteStaleStagingAsync(TimeSpan olderThan, CancellationToken ct)
    {
        var cutoff = DateTime.UtcNow - olderThan;
        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(_temp))
        {
            if (File.GetLastWriteTimeUtc(path) >= cutoff) continue;
            File.Delete(path);
            removed++;
        }

        return Task.FromResult(removed);
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
