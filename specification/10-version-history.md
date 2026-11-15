# 10 — Version History

> **E2EE.** History is a chain of **encrypted, content-addressed snapshots** the server stores but cannot read. **Diffs and restore logic run client-side.** Concrete mechanics are **[P]**.

## 10.1 Model

- Every file has an append-only history of immutable **encrypted** versions (`file_versions`, [03](03-data-model.md)): each a content-addressed ciphertext snapshot of the file at a point in time.
- Head is `files.current_version_id`; history is `file_versions` ordered by `seq DESC`.
- History is **full**; retention/purge is an explicit admin/GC action ([§10.6](#106-retention--garbage-collection)).
- Who sees it **[P]**: every account with read reach on the file lists and fetches its versions, a read-only grantee included, because the history is content the grantee can already decrypt. Link guests get the head only, because a guest token is never accepted under `/api/v1` ([04 §4.8](04-rest-api.md)).
  A version sealed with an older key generation stays listed for a member who never had that generation, who sees the record but cannot open it ([09 §9.6](09-sharing-and-acl.md)).
  Read access sees and diffs the history, write access restores, and link guests get no history (confirmed by the user on 2026-11-15).
- Parent of a version [P]: every version records `parent_seq`, the version its upload was based on: the `If-Match` of a blob, the head a snapshot or a rotation's head replaced, `0` for none ([03](03-data-model.md)).
  A version whose parent was not the head when it arrived lost last-write-wins and is a kept sibling ([06 §6.5](06-sync.md)).
  A client replays the list in `seq` order, keeping the head: a version whose `parentSeq` equals the head becomes the head, any other is a kept loser.
  The record is the signal, so every member, a grantee included, flags concurrent siblings from the history alone (decided by the user on 2026-11-15).
  Flagging from the change feed was rejected, because the feed stays owner-scoped until shared-tree sync exists, and the `409` sibling and a `seq` above the head reach only the writer of the losing upload.
  Versions written before the column was added take `seq - 1` as their parent, which is right for every version that won.

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
- The client checks every fetched version before it diffs **[P]**: it opens the frame with the wrap of the version's `keyId`, recomputes BLAKE3 over the plaintext and rejects the version if it differs from `contentHash`, which `GET …/versions/{seq}/blob` also sends as `ETag`.
  The server cannot make this check, because it never holds the plaintext ([07 §7.5](07-encryption.md)).
  P2.4-TC-1 pins it as an integration test that fetches, opens, verifies and diffs two versions as the owner and as a read-only grantee, and finds no diff route in the route table or in `openapi/v1.yaml`.

## 10.5 Restore

- `POST /files/{id}/restore` body = `{ "seq": n }` **only** — **no ciphertext upload in the restore call**. The new head arrives via the **normal write path**:
  - Text: the client produces a CRDT update transforming the current doc to the restored content (so collaborators converge), encrypts it, submits **via the relay**, then snapshots.
  - Ink/binary: the client uploads the restored bytes as ciphertext via **`PUT /files/{id}/blob`** = new head version.
- The restore endpoint **records the restore** (audit), linking the new head to the source `seq`. Prior versions are untouched (non-destructive).

> Restore as built in Phase 2.4 [P]:
> the call writes the audit event `version.restore` with the source `seq` and marks the file with `pending_restore_seq` and the recording account in `pending_restore_by` ([03](03-data-model.md)).
> It moves no content and changes no version, so it cannot destroy anything.
> 1. The restoring account's next version of the file takes the mark as `restored_from_seq` and clears it, whether the version comes from `PUT /files/{id}/snapshot` or `PUT /files/{id}/blob`.
>    A version another account writes in between neither takes nor clears the mark, because a collaborator's edit is no restore.
>    Linking the next head of anyone, which Phase 1.1 did, was rejected, because a concurrent collaborator's write would then show up in the history as the restore.
> 2. A restore upload that loses LWW is kept as a sibling version ([06 §6.5](06-sync.md)) and still takes the mark, because it holds the restored bytes.
>    A retry on top of the new head is then a plain write, and a client that wants that head marked as well records the restore again.
> 3. A second restore, by the same or another account, replaces a pending mark, and the audit keeps both events.
>    One mark per file was chosen over a list of pending restores, because the mark only labels the history and the audit is the record.
> 4. A mark that no version of the restoring account takes within `NYXITE__Limits__RestoreMarkLifetime` (default 10 minutes, [14](14-deployment-and-config.md)) lapses, stored as `pending_restore_at`.
>    The next version of any account then clears it without taking it, so a client that recorded a restore and never saved does not label a later unrelated write as a restore.
>    A time limit was chosen over a header that marks the next write as no restore, because it needs no change to the write paths and still covers a client that crashed after the record.
>    Ten minutes cover the decrypt, verify and upload of a large version, and an operator with slow clients raises it.
>
> Points 1 to 4 were confirmed by the user on 2026-11-15.
>
> The call requires `Idempotency-Key`, and a replay of the same request answers `204` again without a second event, because a client retrying after a lost answer must not double the audit.
> The idempotency record names the file and the seq, so the same key reused on another file is `409 idempotency_conflict` instead of a silent success that recorded nothing (V3 of the review of 2026-11-15).
> It needs write reach from a session on an active device, so a read-only grantee gets `403 acl_denied`, and a seq the file does not have is `404`.
> A file excluded from sync answers `409 excluded_content`, because the server takes no content for it and no new head could follow.
> The restored content is written with the file's current key like every other write, otherwise `412 key_generation_stale`, so a client restoring a version of an older generation opens it with that generation's wrap and seals it again ([09 §9.6](09-sharing-and-acl.md)).
> P2.4-TC-2 pins both write paths as integration tests: the binary path through `PUT /blob` and the text path through an update on the log followed by a snapshot, each with every earlier version row and its served bytes unchanged afterwards.

## 10.6 Retention & garbage collection

- **Default:** keep full history for a live file.
- **Deletion lifecycle:** when a file is deleted it runs the staged **Trash → grace → purge** timeline ([03 §3.3](03-data-model.md), DL-1–DL-5). A delete **never rewrites history**, and a Trash restore brings the history back intact. At the end of the timeline (~60 days) the file's **version-history snapshots are purged together with the file** — the scheduled purge job hard-deletes `file_versions`/`crdt_updates` for that file as part of the same operation (DL-2).
- **GC:** background job removes blobs whose **last referencing version** is purged (no live `file_versions`/`crdt_updates`/head reference across **any** file). Operates purely on references — no content needed.
  - **Implementation [P].** `TrashPurger` and `BlobCollector` run every `NYXITE__Retention__PurgeInterval` (default 6 h) in their own hosted service, apart from the hourly row cleanup, because the sweep reads every name in the blob store. The purge deletes each root older than Trash plus grace in its own transaction, together with what its delete took along (`deleted_root_id`), the wrapped keys of those objects, their `file_versions` and `crdt_updates`, and audits one `trash.purged` event with the counts. It then deletes the blobs of the purged versions directly, which is safe because a storage address is scoped to its file and key ([§10.3](#103-deduplication)), so no other file can reference them.
  - **Sweep.** The second source of unreferenced blobs is an upload whose blob got its name while its transaction then failed. The sweep lists the store and deletes blobs no `file_versions` row references once they are older than `NYXITE__Retention__OrphanBlobAgeHours` (default 24), and staging files of that age, which only a crash during an upload leaves. A blob that a write references again has its write time renewed.
  - **Writer and collector serialise on a Postgres advisory lock per storage address** (transaction-scoped, two-key form with its own class). A writer holds it from naming the blob until its version row is committed. The collector takes it with `pg_try_advisory_xact_lock`, skips the blob when a writer holds it, and checks for references and deletes while holding it. Without the lock, a collector could find no reference, a writer could then reuse the same address by dedup and commit, and the collector would delete bytes a version points to. The age alone was rejected for this, because a slow request can outlive any age.
- **Purge** (staged-deletion timer or admin/retention action) hard-deletes versions + now-unreferenced blobs; audited ([12](12-administration.md)).

## 10.7 Guarantees

- **No destructive overwrite:** LWW losers are retained as versions ([06 §6.9](06-sync.md)).
- **Encrypted history:** every snapshot is ciphertext; a DB/blob backup without a member's key yields nothing.
- **All files** get history (E2EE is universal now — there is no special non-private class to exclude).
