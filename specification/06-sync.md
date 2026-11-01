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

## 6.3 Reconciliation protocol **[P]**

Two tiers: a full **manifest** to (re)establish state, and a cursor-based **delta** for everything after. Both are scoped to **one project**, so a client syncs only what it opened and a cursor never spans projects. Binary values are **base64url without padding**; ids are UUID strings; timestamps RFC 3339 UTC.

### 6.3.1 Manifest reconcile (`GET /sync/manifest?projectId=&cursor=&limit=`)

Paginated with the standard envelope ([04 §4.1](04-rest-api.md)), default `limit` 500, max 1000.

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
    "updatedAt": "…", "deletedAt": "…|null"
  } ],
  "nextCursor": "opaque|null"         // manifest page cursor (not the delta cursor)
}
```

All structural/opaque, no names, no content. The client diffs locally to decide pull/push/delete and to drive its **local search index** ([11](11-search.md)). After the last page it continues with `POST /sync/changes` from `syncCursor`; changes that happened while paging are delivered again by the delta, which is harmless because every server change is an idempotent upsert.

### 6.3.2 Delta sync (`POST /sync/changes`)

```jsonc
// request
{ "projectId": "uuid", "since": "opaque|null", "limit": 500,
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
  "entity": "project|folder|file", "id": "uuid", "op": "create|update",
  "parentFolderId": "uuid|null",            // folder/file; null = project root
  "contentType": "…",                       // file create only; immutable afterwards
  "nameEnc": "base64url", "metadataEnc": "base64url",
  "syncPolicy": "server-default|excluded" } // fields absent on update = unchanged
DeleteRef = { "entity": "project|folder|file", "id": "uuid" }

LocalChangeResult = {
  "clientChangeId": "uuid",
  "status": "applied|rejected",
  "error": "problem code|null" }            // e.g. validation_failed (move cycle), not_found, acl_denied
```

Items are applied **in order**, each in its own transaction, so one rejected item does not block the rest. Concurrent structure edits are **last-write-wins per field by server-received time**; structure carries no history, and a lost rename is visible and cheap to redo, so a conflict protocol would cost more than it saves. A replayed `clientChangeId` returns the stored result without re-applying.

```jsonc
ServerChange = { "seq": 9001, "at": "…", "kind": "structure|blob|crdt|delete|keyrotate", "ref": … }
```

| `kind` | `ref` | Client action |
|---|---|---|
| `structure` | `{ entity, id, parentFolderId, contentType?, nameEnc, metadataEnc, syncPolicy?, updatedAt }`, the **full** current row | Upsert, decrypt `nameEnc` |
| `blob` | `{ fileId, seq, contentHash, layout, sizeCipher, keyId, isHead, url }`, `url` = `/api/v1/files/{id}/versions/{seq}/blob` | Mark pending pull; fetch eagerly or on demand. `isHead=false` = an LWW losing sibling ([§6.5](#65-ink--binary-sync-lww-encrypted)) |
| `crdt` | `{ fileId, fromSeq, toSeq }` | Fetch `GET /files/{id}/crdt/log?since=<local>` unless the relay already delivered them. Consecutive updates to one file are **coalesced** into one change |
| `delete` | `{ entity, id, deletedAt, reason: "deleted|purged|access_revoked" }` | Propagate soft delete; on `purged` or `access_revoked` drop local ciphertext and plaintext cache |
| `keyrotate` | `{ fileId, keyId, generation }` | Refetch the wrapped key for the new generation |

- **Cursor.** `nextCursor` is **opaque base64url**: monotonic, resumable, tied to `change_log.seq` ([03](03-data-model.md)); clients must not parse it. `hasMore=true` means call again immediately with `nextCursor`. `since: null` is only valid right after a manifest; otherwise the client sends the cursor it stored.
- **Expired cursor.** The change log is pruned after `NYXITE__Retention__ChangeLogDays`. A cursor older than that gets **`410 cursor_expired`**, and the client falls back to a full manifest reconcile. Nothing is lost, because the manifest is authoritative.
- **ACL filtering.** The server returns only changes to items the caller can currently reach. Losing reach produces exactly one `delete` with `reason: "access_revoked"`; gaining reach (a new share) produces `structure` upserts for the newly visible items.
- **Shared conformance fixture.** These shapes are part of `P1.1-CORE-2`; the JSON schemas live in the OpenAPI document ([04 §4.1](04-rest-api.md)).

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
