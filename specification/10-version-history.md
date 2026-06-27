# 10 — Version History

> **E2EE.** History is a chain of **encrypted, content-addressed snapshots** the server stores but cannot read. **Diffs and restore logic run client-side.** Concrete mechanics are **[P]**.

## 10.1 Model

- Every file has an append-only history of immutable **encrypted** versions (`file_versions`, [03](03-data-model.md)): each a content-addressed ciphertext snapshot of the file at a point in time.
- Head is `files.current_version_id`; history is `file_versions` ordered by `seq DESC`.
- History is **full**; retention/purge is an explicit admin/GC action ([§10.6](#106-retention--garbage-collection)).

## 10.2 How versions are produced

| Content | Snapshot trigger | Produced by |
|---------|------------------|-------------|
| Text (CRDT) | Compaction of the encrypted update log into an encrypted snapshot ([05 §5.6](05-realtime-collaboration.md)) | **Client** (server can't read the log) |
| Ink / binary | Every accepted `PUT /files/{id}/blob` (LWW losers retained) | Client uploads ciphertext |
| Restore | Restore writes a new head ([§10.5](#105-restore)) | Client |

The server records `content_hash` (client-computed), `blob_ref`, `size_cipher`, `key_id`, `author_id` (null for guests). It stores no plaintext size and no diff summary.

## 10.3 Deduplication

- Snapshots are content-addressed by **plaintext BLAKE3** ([07 §7.5](07-encryption.md)); re-saving unchanged content resolves to the existing address. Within a file (same file key), identical plaintext → identical ciphertext → physical dedup. Cross-file dedup is not available under per-file client-held keys (and isn't a goal).
- A `file_versions` row may still be recorded for the timeline even when bytes dedup, so events are visible while the heavy blob is stored once.

## 10.4 Diffs (client-side)

- **There is no server diff endpoint.** A client fetches two encrypted snapshots, decrypts them locally, and computes the diff ([04](04-rest-api.md)).
- Text: client-side line/word or CRDT-structural diff. Ink/binary: client-side metadata-level diff. **[P]**
- This is the only option under E2EE — the server can't read either version.

## 10.5 Restore

- `POST /files/{id}/restore` body = `{ "seq": n }` **only** — **no ciphertext upload in the restore call**. The new head arrives via the **normal write path**:
  - Text: the client produces a CRDT update transforming the current doc to the restored content (so collaborators converge), encrypts it, submits **via the relay**, then snapshots.
  - Ink/binary: the client uploads the restored bytes as ciphertext via **`PUT /files/{id}/blob`** = new head version.
- The restore endpoint **records the restore** (audit), linking the new head to the source `seq`. Prior versions are untouched (non-destructive).

## 10.6 Retention & garbage collection

- **Default:** keep full history.
- **GC:** background job removes blobs whose **last referencing version** is purged (no live `file_versions`/`crdt_updates`/head reference across **any** file). Operates purely on references — no content needed.
- **Purge** (admin/retention) hard-deletes versions + now-unreferenced blobs; audited ([12](12-administration.md)).

## 10.7 Guarantees

- **No destructive overwrite:** LWW losers are retained as versions ([06 §6.9](06-sync.md)).
- **Encrypted history:** every snapshot is ciphertext; a DB/blob backup without a member's key yields nothing.
- **All files** get history (E2EE is universal now — there is no special non-private class to exclude).
