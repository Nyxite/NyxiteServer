# 06 — Sync Engine

> **E2EE.** The server syncs **ciphertext + structure**, never plaintext. It moves bytes, sequences encrypted updates, and tracks versions/policies; clients encrypt/decrypt and merge. Mechanics below are **[P]**.

## 6.1 Responsibilities

Reconcile each client's local state with the server for all readable files, honoring per-file policy and the right model per content type — all over ciphertext:

| Content | Model | Channel (ciphertext) |
|---------|-------|----------------------|
| markdown, plaintext, sourcecode | **CRDT (client-merged)** | Encrypted relay ([05](05-realtime-collaboration.md)) + REST encrypted-log fallback |
| ink | **LWW** | Encrypted blob upload/download |
| office, image, binary | **LWW** | Encrypted blob upload/download |

CRDT-vs-LWW assignment is **decided ([OD-4] resolved)**.

## 6.2 Per-file policy enforcement (**[OD-3] resolved**)

| Policy | Server storage | Sync behavior |
|--------|----------------|---------------|
| `server-default` | Ciphertext stored & relayed | Two-way sync of ciphertext |
| `excluded` | **Nothing stored** | Uploads rejected (`409 excluded_content`); server tolerates content-absent files |

The server model has exactly **two** values. **Offline pinning is purely client-local** — a device cache directive the zero-knowledge server never sees; the former `pinned-local` value is **removed** from the server model. Transitions: `excluded → server-default` triggers an **initial ciphertext upload** from the owning device; `server-default → excluded` schedules server content purge. The `sync_policy` column is authoritative.

**Purge of excluded content (decided 2026-11-14).** A switch to `excluded` sets `files.excluded_at`, a switch back clears it. Content stored before the switch (every version with its ciphertext and the update log) is purged by the storage job once `excluded_at` is older than Trash window plus grace window, about 60 days by default, the same timeline as a delete ([10 §10.6](10-version-history.md)). The file row stays, with no head. The window lets a mistaken switch be undone without loss. An immediate purge was rejected, because one wrong tap would destroy the server history for good, and keeping the content until the file is deleted was rejected, because the server would hold ciphertext the user asked it not to hold. Version numbers are counters and are never reused, so an upload after a switch back starts at `If-Match: 0` and gets the next number. The purge is audited as `content.excluded_purged`.

## 6.3 Reconciliation protocol **[P]**

Two tiers: a full **manifest** to (re)establish state, and a cursor-based **delta** for everything after. Both are scoped to **one project**, so a client syncs only what it opened and a cursor never spans projects. Binary values are **base64url without padding**; ids are UUID strings; timestamps RFC 3339 UTC.

### 6.3.1 Manifest reconcile (`GET /sync/manifest?projectId=&cursor=&limit=`)

Paginated with the standard envelope ([04 §4.1](04-rest-api.md)), default `limit` 500, max 1000. `keys=false` leaves `wrappedKey` out of the items, like on every structure read (ST-4).

```jsonc
{
  "projectId": "uuid",
  "syncCursor": "opaque",            // delta cursor positioned at the moment page 1 was produced
  "items": [ {
    "fileId": "uuid",
    "folderId": "uuid|null",          // null = project root
    "contentType": "markdown|plaintext|sourcecode|ink|office|image|binary",
    "syncPolicy": "server-default|excluded",
    "currentVersionSeq": 42,          // null when no version exists yet (excluded, or never uploaded)
    "contentHash": "base64url|null",  // opaque BLAKE3 address of the head
    "layout": "single|chunked",
    "sizeCipher": 1234,
    "keyId": "uuid",
    "keyGeneration": 3,
    "crdtHeadSeq": 1810,              // text types only: highest crdt_updates seq; null otherwise
    "crdtDocId": "uuid|null",         // text types only
    "wrappedKey": WrappedKey,         // the file key wrapped to the caller; absent with keys=false (ST-4)
    "updatedAt": "…", "deletedAt": "…|null"
  } ],
  "nextCursor": "opaque|null"         // manifest page cursor (not the delta cursor)
}
```

All structural/opaque, no names, no content. The client diffs locally to decide pull/push/delete and to drive its **local search index** ([11](11-search.md)). After the last page it continues with `POST /sync/changes` from `syncCursor`; changes that happened while paging are delivered again by the delta, which is harmless because every server change is an idempotent upsert.

### 6.3.2 Delta sync (`POST /sync/changes`)

```jsonc
// request
{ "projectId": "uuid", "since": "opaque|null", "limit": 500, "keys": true,
  "localChanges": [ LocalChange … ] }       // at most 200
// response
{ "results": [ LocalChangeResult … ],     // one per localChanges entry, same order
  "serverChanges": [ ServerChange … ],
  "nextCursor": "opaque", "hasMore": false }
```

**`localChanges` carries structure only.** A client batches its offline **structure** edits (create, rename, move, policy change, delete of projects/folders/files) here, so a device that was offline for a week replays them in one round-trip. **Content never travels in `localChanges`**: blobs go through `PUT /files/{id}/blob` or the chunked path, CRDT updates through the relay or `POST /files/{id}/crdt/log`, rotations through `POST /files/{id}/keys/rotate` ([04](04-rest-api.md)). Those endpoints already carry the LWW, generation-guard and idempotency rules, and duplicating them in a batch would create a second, divergent write path.

```jsonc
LocalChange = {
  "clientChangeId": "uuid",                 // per-item idempotency key, stored like Idempotency-Key (24 h)
  "kind": "structure|delete",
  "ref": StructureRef | DeleteRef }

StructureRef = {
  "entity": "project|folder|file", "id": "uuid", "op": "create|update",  // project: update only
  "parentFolderId": "uuid|null",            // folder/file; null = project root
  "contentType": "…",                       // file create only; immutable afterwards
  "crdtDocId": "uuid",                      // file create only; text types only
  "nameEnc": "base64url", "metadataEnc": "base64url",
  "syncPolicy": "server-default|excluded|null", // null only for a folder: follow the parent (ST-3)
  "ownerWrappedKey": WrappedKey }           // create only, required there (ST-1); fields absent on update = unchanged
DeleteRef = { "entity": "project|folder|file", "id": "uuid" }

LocalChangeResult = {
  "clientChangeId": "uuid",
  "status": "applied|rejected",
  "error": "problem code|null" }            // e.g. validation_failed (move cycle), not_found, acl_denied
```

**Frozen for Phase 1.1 [P].** A create in `localChanges` carries exactly what the matching `POST /folders` or `POST /files` requires, and the server applies it through the same code path: the client-allocated id (ST-2, a taken id is `rejected` with `conflict`), the object's own key wrapped to the caller (ST-1) and, for a text file, its `crdtDocId`. A project is never created here, because the batch is scoped to a project that must already exist, so a new project goes through `POST /projects` first. The replay of an offline Trash restore is not part of the batch either, because restore has its own rules (ST-5) and is rare enough to wait for the network.

Items are applied **in order**, each in its own transaction, so one rejected item does not block the rest. Concurrent structure edits are **last-write-wins per field by server-received time**; structure carries no history, and a lost rename is visible and cheap to redo, so a conflict protocol would cost more than it saves. A replayed `clientChangeId` returns the stored result without re-applying.

```jsonc
ServerChange = { "seq": 9001, "at": "…", "kind": "structure|blob|crdt|delete|keyrotate", "ref": … }
```

| `kind` | `ref` | Client action |
|---|---|---|
| `structure` | `{ entity, id, parentFolderId, contentType?, crdtDocId?, nameEnc, metadataEnc, syncPolicy?, wrappedKey?, rotationPending?, updatedAt }`, the **full** current row. `wrappedKey` is absent with `keys: false`. `rotationPending` (files only) is true while a revocation by the owner waits for its key rotation ([09 §9.6](09-sharing-and-acl.md)) | Upsert, decrypt `nameEnc`. A Trash restore arrives as this upsert. `rotationPending: true` queues the rotation task |
| `blob` | `{ fileId, seq, contentHash, layout, sizeCipher, keyId, isHead, parentSeq, url }`, `url` = `/api/v1/files/{id}/versions/{seq}/blob` | Mark pending pull; fetch eagerly or on demand. `isHead=false` = an LWW losing sibling ([§6.5](#65-ink--binary-sync-lww-encrypted)), `parentSeq` the version it was based on ([10 §10.1](10-version-history.md)) |
| `crdt` | `{ fileId, fromSeq, toSeq }` | Fetch `GET /files/{id}/crdt/log?since=<local>` unless the relay already delivered them. Consecutive updates to one file are **coalesced** into one change |
| `delete` | `{ entity, id, deletedAt, reason: "deleted|purged|access_revoked" }` | Propagate soft delete; on `purged` or `access_revoked` drop local ciphertext and plaintext cache |
| `keyrotate` | `{ fileId, keyId, generation }` | Refetch the wrapped key for the new generation |

- **Cursor.** `nextCursor` is **opaque base64url**: monotonic, resumable, tied to `change_log.seq` ([03](03-data-model.md)); clients must not parse it. `hasMore=true` means call again immediately with `nextCursor`. `since: null` is only valid right after a manifest; otherwise the client sends the cursor it stored.
- **Expired cursor.** The change log is pruned after `NYXITE__Retention__ChangeLogDays`. A cursor older than that gets **`410 cursor_expired`**, and the client falls back to a full manifest reconcile. Nothing is lost, because the manifest is authoritative.
- **ACL filtering.** The server returns only changes to items the caller can currently reach. Losing reach produces exactly one `delete` with `reason: "access_revoked"`; gaining reach (a new share) produces `structure` upserts for the newly visible items.
- **Shared conformance fixture.** These shapes are part of `P1.1-CORE-2`; the JSON schemas live in the OpenAPI document ([04 §4.1](04-rest-api.md)). The integration suite checks every response the server sends against that document, so the server cannot drift from the frozen shapes unnoticed.
- **Trash and purge in the delta.** A move to Trash produces `delete` with `reason: "deleted"`, a restore the `structure` upsert of every row it brings back, and the purge at the end of the grace window `delete` with `reason: "purged"` ([10 §10.6](10-version-history.md)).
- **Points pinned during Phase 1.2 (2026-11-14).**
  - **One entry per affected row.** A folder delete or purge records a `delete` for the folder and for every folder and file it took along, the mirror of the restore, which records an upsert per row. A restored folder or project is recorded before its subtree, so a client never meets a row whose parent it does not know yet. A single entry for the root was rejected, because a client would have to rebuild the subtree from its own possibly stale copy.
  - **A project in Trash has no feed.** Manifest and delta of a deleted project answer `404`, like any unreachable object, so the project delete itself is the last entry its devices can miss. A client that gets `404` drops the project, and a restore makes it reachable again with upserts of everything that came back. A purged project takes its `change_log` rows with it.
  - **Snapshots are announced as `blob` changes** with `isHead: true`, so a text file's new head reaches devices the same way an LWW head does. Every `crdt` entry covers one submit, and consecutive entries of one file are coalesced within one response.
  - **The cursor is the feed position plus the moment it was handed out.** An expired cursor is one whose moment is older than `NYXITE__Retention__ChangeLogDays`, because every row after its position was written after that moment and may now be pruned. Every response hands out a fresh moment, also when nothing is new, so a device that keeps syncing an idle project never expires. A pruned-up-to marker was rejected, because it would expire the cursor of every idle project once other projects' rows were pruned past it. `since: null` reads from the start of the retained feed and is meant only right after a manifest.
  - **No change is skipped by a reader.** Feed numbers come from an identity column and are handed out at insert, so a later transaction can commit first. Writers therefore hold a shared, transaction-scoped advisory lock on the project from recording until commit, and a reader takes it exclusively while it reads, so no write of the project is in flight then and every later one gets a higher number. Writers do not wait for each other. A gapless counter per project was rejected, because it would serialise every write of a project, the busy relay included.
  - **An outbox item commits together with its result.** Each item runs in its own transaction with its idempotency record, so a crash cannot leave an item applied without a result to replay. Rejected items are stored as well, so a replay answers what the first attempt answered, except `idempotency_conflict`, which is the client's mistake and not stored. Device and account status are checked once per batch, so a blocked account gets one `403` instead of a stored rejection per item.

### 6.3.3 Per-file sync state machine

Every client keeps the same per-file state set, so a badge means the same on every device (desktop and Android 08 §8.8, web 08 §8.9): `Synced`, `PendingPush`, `PendingPull`, `Downloading`, `Uploading`, `Conflicted`, `Rotating`, `Excluded`, `Error(code)`. The state lives only on the client, because it describes the relation between one device's copy and the server. The server's part is the signals that move a file between states.

| Server signal | Transition |
| --- | --- |
| `blob` change with `isHead: true` and a `contentHash` other than the local one, or `crdt` change past the local cursor | `Synced` to `PendingPull` |
| Download or log catch-up finished | `Downloading` to `Synced` |
| `PUT /files/{id}/blob` answered `201` with the version as head | `Uploading` to `Synced` |
| `PUT /files/{id}/blob` answered `409 conflict` with the winner, the upload kept as a sibling | `Uploading` to `Conflicted` |
| `412 key_generation_stale`, or a `keyrotate` change | to `Rotating`, back once the new wrapped key is fetched |
| `409 excluded_content`, or `syncPolicy: "excluded"` in a `structure` change | to `Excluded` |
| `413 payload_too_large`, `404`, or another problem code | to `Error(code)` |

`Rotating` is part of the set although the Phase 1.1 step text omits it, because a key rotation blocks writes like no other state does and the clients already list it.

## 6.4 Text sync (CRDT, encrypted)

- Live: encrypted relay ([05](05-realtime-collaboration.md)).
- Offline/catch-up: client pulls encrypted updates (`GET /files/{id}/crdt/log?since=`) and the latest **encrypted snapshot**, decrypts, reconstructs its Yrs state vector **locally**, merges, and pushes its own encrypted updates. Convergence is client-side and order-independent.
- The server persists encrypted updates and relies on **clients** to produce encrypted snapshots ([05 §5.6](05-realtime-collaboration.md), [10](10-version-history.md)).

## 6.5 Ink & binary sync (LWW, encrypted)

- The client sends the **parent version `seq`** it edited from on every binary/ink write — `If-Match: <seq>` header or body `parentSeq`.
- On `PUT /files/{id}/blob` (ciphertext):
  - **head `== parentSeq`** → accept ciphertext as a new content-addressed blob, advance head, record a `file_versions` row.
  - **head `!= parentSeq`** → `409 conflict` returning the current **winning** version metadata; the rejected bytes are **retained as a sibling losing version row** (not head) and surfaced in history for manual resolution.
- **True-concurrent tie-break = last-write-wins by server-received timestamp.**
- The server does **not** read encrypted version-vectors; conflict **detection is purely head-`seq` based**. Its role is storage + ordering, not semantic merge.
- Download is **on-demand**: metadata syncs eagerly; ciphertext is pulled on open or when the client pins it locally.

## 6.6 Deletes
Soft deletes propagate via manifest/delta (`deleted_at`) so devices converge. `excluded` files that never reached the server need no round-trip to delete.

## 6.7 Encryption boundary
**All content is encrypted on the client before it reaches the server**, and decrypted on the client after fetch ([07](07-encryption.md)). The server's transport is TLS; its storage is ciphertext. There is no server-side encrypt/decrypt step — unlike the previous at-rest model.

## 6.8 On-demand download & caching
- Clients hold structure/manifests for all readable files but fetch ciphertext lazily.
- Client-local **pinning** proactively fetches + keeps plaintext offline (and indexed) on that device — a purely client-side setting the server never sees.
- Conditional fetch by content-hash (`If-None-Match`) avoids re-downloading unchanged ciphertext. **[P]**

## 6.9 Conflict philosophy
- **Text:** no conflicts — CRDT merge on clients.
- **Ink/binary:** LWW head, but **history retains every version**, so an LWW "loss" is recoverable — satisfying the full-history guarantee under E2EE.
