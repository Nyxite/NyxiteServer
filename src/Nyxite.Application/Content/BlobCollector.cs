using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Application.Maintenance;
using Nyxite.BlobStore;
using Nyxite.Persistence;

namespace Nyxite.Application.Content;

/// <summary>
/// Blob garbage collection (10 §10.6, 03 §3.4): deletes stored ciphertext that no <c>file_versions</c> row references.
/// It works on references only and never reads content. Two sources of such blobs exist: the versions a purge removed,
/// and uploads whose blob was named while their transaction then failed.
/// </summary>
/// <remarks>
/// A writer can reference an existing blob again, because equal content in the same file and key has the same address.
/// Writer and collector therefore serialise on a transaction-scoped Postgres advisory lock per address: the writer
/// holds it from naming the blob until its version row is committed, and the collector checks for references and
/// deletes while holding it. Without it, a collector could see no reference, a writer could then reuse the blob and
/// commit, and the collector would delete bytes a version points to.
/// </remarks>
public sealed class BlobCollector(NyxiteDbContext db, IBlobStore blobs, TimeProvider time, IOptions<RetentionOptions> options,
    ILogger<BlobCollector> logger)
{
    /// <summary>Distinguishes these locks from any other advisory lock (the two-int form has its own key space per class).</summary>
    private const int LockClass = 0x4E59_4243; // "NYBC"

    /// <summary>Takes the address lock inside the caller's transaction; it ends with the transaction.</summary>
    public static async Task LockAddressAsync(NyxiteDbContext db, BlobAddress address, CancellationToken ct)
    {
        var key = LockKey(address);
        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({LockClass}, {key})", ct);
    }

    /// <summary>Deletes the blob at <paramref name="address"/> when nothing references it. Returns whether it did.</summary>
    public async Task<bool> CollectAsync(BlobAddress address, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var key = LockKey(address);
        // Skip instead of wait: a writer holding the lock is about to reference the blob.
        var locked = await db.Database.SqlQuery<bool>($"SELECT pg_try_advisory_xact_lock({LockClass}, {key}) AS \"Value\"").SingleAsync(ct);
        if (!locked) return false;
        var hex = address.Hex;
        if (await db.FileVersions.AnyAsync(v => v.BlobRef == hex, ct)) return false;
        await blobs.DeleteAsync(address, ct);
        await tx.CommitAsync(ct);
        return true;
    }

    /// <summary>
    /// Sweeps the whole store for unreferenced blobs older than <c>Retention:OrphanBlobAgeHours</c>, and drops staging
    /// leftovers of that age. The age keeps the sweep away from uploads still in flight; correctness against writers
    /// rests on the address lock, not on the age.
    /// </summary>
    public async Task<int> SweepAsync(CancellationToken ct)
    {
        var age = TimeSpan.FromHours(options.Value.OrphanBlobAgeHours);
        var cutoff = time.GetUtcNow() - age;
        var removed = await blobs.DeleteStaleStagingAsync(age, ct);
        var candidates = new List<BlobAddress>();
        await foreach (var blob in blobs.ListAsync(ct))
        {
            if (blob.LastWrittenAt < cutoff) candidates.Add(blob.Address);
            if (candidates.Count < 500) continue;
            removed += await CollectUnreferencedAsync(candidates, ct);
            candidates.Clear();
        }

        removed += await CollectUnreferencedAsync(candidates, ct);
        if (removed > 0) logger.LogInformation("Blob collection removed {Count} unreferenced blobs and staging files.", removed);
        return removed;
    }

    private async Task<int> CollectUnreferencedAsync(List<BlobAddress> candidates, CancellationToken ct)
    {
        if (candidates.Count == 0) return 0;
        // One query narrows the batch; each survivor is then checked again under its lock.
        var hexes = candidates.Select(a => a.Hex).ToList();
        var referenced = (await db.FileVersions.Where(v => hexes.Contains(v.BlobRef)).Select(v => v.BlobRef).Distinct().ToListAsync(ct)).ToHashSet();
        var removed = 0;
        foreach (var address in candidates.Where(a => !referenced.Contains(a.Hex)))
        {
            if (await CollectAsync(address, ct)) removed++;
        }

        return removed;
    }

    private static int LockKey(BlobAddress address) => Convert.ToInt32(address.Hex[..8], 16);
}
