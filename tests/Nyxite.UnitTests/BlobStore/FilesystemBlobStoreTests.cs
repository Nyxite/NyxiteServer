using System.Security.Cryptography;
using Nyxite.BlobStore;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.BlobStore;

/// <summary>The filesystem ciphertext store (03 §3.4): sharded, content-addressed, write-once, frames only.</summary>
public sealed class FilesystemBlobStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "nyxite-blobtest-" + Guid.NewGuid().ToString("N"));
    private readonly FilesystemBlobStore _store;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public FilesystemBlobStoreTests() => _store = new FilesystemBlobStore(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static byte[] Frame(string text) =>
        NyxcFrame.Seal(RandomNumberGenerator.GetBytes(32), Guid.CreateVersion7(), Guid.CreateVersion7(), ObjectKind.Blob, System.Text.Encoding.UTF8.GetBytes(text));

    private static BlobAddress Address(string text) => BlobAddress.From(Blake3.Hash(System.Text.Encoding.UTF8.GetBytes(text)));

    [Fact]
    public async Task A_blob_round_trips_and_lies_under_its_sharded_address()
    {
        var frame = Frame("hello");
        var address = Address("hello");

        var reference = await _store.PutAsync(frame, address, Ct);

        Assert.Equal(frame.Length, reference.Size);
        Assert.True(await _store.ExistsAsync(address, Ct));
        Assert.True(File.Exists(Path.Combine(_root, address.Hex[..2], address.Hex[2..4], address.Hex)));
        await using var stream = await _store.OpenReadAsync(reference, Ct);
        using var copy = new MemoryStream();
        await stream.CopyToAsync(copy, Ct);
        Assert.Equal(frame, copy.ToArray());
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, ".tmp")));
    }

    [Fact]
    public async Task An_address_is_write_once()
    {
        var address = Address("same plaintext");
        var first = Frame("same plaintext");
        await _store.PutAsync(first, address, Ct);

        var second = await _store.PutAsync(Frame("same plaintext, sealed again and longer"), address, Ct);

        Assert.Equal(first.Length, second.Size);
        Assert.Equal(first, await File.ReadAllBytesAsync(Path.Combine(_root, address.Hex[..2], address.Hex[2..4], address.Hex), Ct));
    }

    [Fact]
    public async Task Concurrent_writers_of_one_address_leave_one_whole_blob()
    {
        var address = Address("race");
        var frames = Enumerable.Range(0, 16).Select(i => Frame("race " + new string('x', i))).ToArray();

        var references = await Task.WhenAll(frames.Select(f => Task.Run(() => _store.PutAsync(f, address, Ct))));

        var stored = await File.ReadAllBytesAsync(Path.Combine(_root, address.Hex[..2], address.Hex[2..4], address.Hex), Ct);
        Assert.Contains(frames, f => f.SequenceEqual(stored));
        Assert.All(references, r => Assert.Equal(stored.Length, r.Size));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(_root, ".tmp")));
    }

    [Fact]
    public async Task Anything_that_is_not_a_frame_is_refused()
    {
        var address = Address("plain");

        await Assert.ThrowsAsync<BlobFormatException>(() => _store.PutAsync("plaintext, not a frame, but long enough to be one"u8.ToArray(), address, Ct));
        await Assert.ThrowsAsync<BlobFormatException>(() => _store.PutAsync(new byte[10], address, Ct));

        Assert.False(await _store.ExistsAsync(address, Ct));
    }

    [Fact]
    public async Task Delete_removes_a_blob_and_tolerates_a_missing_one()
    {
        var address = Address("gone");
        var reference = await _store.PutAsync(Frame("gone"), address, Ct);

        await _store.DeleteAsync(reference, Ct);
        await _store.DeleteAsync(reference, Ct);

        Assert.False(await _store.ExistsAsync(address, Ct));
        await Assert.ThrowsAsync<FileNotFoundException>(() => _store.OpenReadAsync(reference, Ct));
    }

    [Fact]
    public async Task Probe_passes_on_a_writable_root_and_leaves_nothing_behind()
    {
        await _store.ProbeAsync(Ct);

        Assert.Empty(Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void An_address_is_32_bytes_and_a_root_path_is_required()
    {
        Assert.Throws<ArgumentException>(() => BlobAddress.From(new byte[31]));
        Assert.Throws<ArgumentException>(() => new FilesystemBlobStore(" "));
        Assert.Equal(64, BlobAddress.From(new byte[32]).Hex.Length);
    }
}
