using Microsoft.EntityFrameworkCore;
using Nyxite.Crypto;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Keys;

/// <summary>
/// Appends directory key events to <c>kt_leaves</c> (17 §17.6). Only the leaves exist before Phase 4.3; nodes, signed
/// checkpoints and proofs are computed from them later. Callers must hold an open transaction, which this joins: the
/// <c>kt_state</c> row lock serializes appends so <c>leaf_index</c> stays gapless, and the directory change commits or
/// rolls back with its leaf.
/// </summary>
public sealed class KeyTransparencyLog(NyxiteDbContext db, TimeProvider time)
{
    public sealed record Appended(long LeafIndex, DateTimeOffset LoggedAt);

    public async Task<Appended> AppendAsync(DirectoryEntryType type, Guid subjectId, Guid keyId, uint generation, string algId,
        byte[] kemPub, byte[] sigPub, byte[] selfSig, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("A KT append needs the caller's transaction.");
        var size = await db.Database.SqlQuery<long>($"SELECT tree_size AS \"Value\" FROM kt_state WHERE id FOR UPDATE").SingleAsync(ct);

        // logged_at is hashed at millisecond precision, so the stored timestamp is truncated to match it exactly.
        var ms = time.GetUtcNow().ToUnixTimeMilliseconds();
        var loggedAt = DateTimeOffset.FromUnixTimeMilliseconds(ms);
        var message = DirectoryEntry.SignedMessage(type, subjectId, keyId, generation, algId, kemPub, sigPub);
        var leaf = DirectoryEntry.LeafData(message, ms, selfSig);
        db.KtLeaves.Add(new KtLeafEntity
        {
            LeafIndex = size,
            EntryType = (short)type,
            SubjectId = subjectId,
            KeyId = keyId,
            LeafData = leaf,
            LeafHash = DirectoryEntry.LeafHash(leaf),
            LoggedAt = loggedAt,
        });
        await db.Database.ExecuteSqlAsync($"UPDATE kt_state SET tree_size = tree_size + 1 WHERE id", ct);
        return new Appended(size, loggedAt);
    }
}
