# 06 — Sync Engine

> **E2EE.** The server syncs **ciphertext + structure**, never plaintext. It moves bytes, sequences encrypted updates, and tracks versions/policies; clients encrypt/decrypt and merge. Mechanics below are **[P]**.

## 6.1 Responsibilities

Reconcile each client's local state with the server for all readable files, honoring per-file policy and the right model per content type — all over ciphertext:

| Content | Model | Channel (ciphertext) |
|---------|-------|----------------------|
| markdown, plaintext, sourcecode | **CRDT (client-merged)** | Encrypted relay ([05](05-realtime-collaboration.md)) + REST encrypted-log fallback |
| ink | **LWW / version-vector** | Encrypted blob upload/download |
| office, image, binary | **LWW / version-vector** | Encrypted blob upload/download |

CRDT-vs-LWW assignment is **[OD-4]**.

## 6.2 Per-file policy enforcement **[OD-3]**

| Policy | Server storage | Sync behavior |
|--------|----------------|---------------|
| `server-default` | Ciphertext stored & relayed | Two-way sync of ciphertext |
| `pinned-local` | Ciphertext stored & relayed | Same server-side; client keeps plaintext offline |
| `excluded` | **Nothing stored** | Uploads rejected (`409 excluded_content`); server tolerates content-absent files |

Transitions: `excluded → synced` triggers an **initial ciphertext upload** from the owning device; `synced → excluded` schedules server content purge. The `sync_policy` column is authoritative.

## 6.3 Reconciliation protocol **[P]**

### 6.3.1 Manifest reconcile (`GET /sync/manifest`)
Per project: `{ fileId, contentType, syncPolicy, currentVersionSeq, contentHash, keyGeneration, updatedAt, deletedAt }`. All structural/opaque — no names, no content. The client diffs locally to decide pull/push/delete, and to drive its **local search index** ([11](11-search.md)).

### 6.3.2 Delta sync (`POST /sync/changes`)
Cursor-based incremental exchange of **structure changes + ciphertext refs**:
```jsonc
{ "since": "cursor", "projectId": "uuid",
  "localChanges": [ { "fileId": "...", "kind": "structure|blob|crdt|delete|keyrotate", "ref": "..." } ] }
// → { "serverChanges": [ ... ], "nextCursor": "cursor" }
```
Text content changes are referenced (actual exchange on the encrypted relay); blob changes carry a ciphertext `blob_ref` to pull; `keyrotate` signals a new `keyGeneration` so clients refetch their wrapped key.

## 6.4 Text sync (CRDT, encrypted)

- Live: encrypted relay ([05](05-realtime-collaboration.md)).
- Offline/catch-up: client pulls encrypted updates (`GET /files/{id}/crdt/log?since=`) and the latest **encrypted snapshot**, decrypts, reconstructs its Yrs state vector **locally**, merges, and pushes its own encrypted updates. Convergence is client-side and order-independent.
- The server persists encrypted updates and relies on **clients** to produce encrypted snapshots ([05 §5.6](05-realtime-collaboration.md), [10](10-version-history.md)).

## 6.5 Ink & binary sync (LWW / version-vector, encrypted)

- Each device advances its version-vector entry locally (kept in `metadata_enc`, [03](03-data-model.md)).
- On `PUT /files/{id}/blob` (ciphertext), the server compares the **client-supplied** vector summary it's allowed to see, or simply accepts and lets clients resolve **[P]**:
  - Strictly newer → accept ciphertext as new content-addressed blob, advance head, record a `file_versions` row.
  - Concurrent → **last-write-wins** by server-received time **[P]**; the losing ciphertext is **retained as a version** (no data loss), and `409 conflict` returns the winning version for client reconciliation.
- Download is **on-demand**: metadata syncs eagerly; ciphertext is pulled on open or for `pinned-local`.

> Because the server can't read content, conflict *detection* for ink leans on small, possibly-encrypted version-vector hints managed by clients; the server's role is storage + ordering, not semantic merge.

## 6.6 Deletes
Soft deletes propagate via manifest/delta (`deleted_at`) so devices converge. `excluded` files that never reached the server need no round-trip to delete.

## 6.7 Encryption boundary
**All content is encrypted on the client before it reaches the server**, and decrypted on the client after fetch ([07](07-encryption.md)). The server's transport is TLS; its storage is ciphertext. There is no server-side encrypt/decrypt step — unlike the previous at-rest model.

## 6.8 On-demand download & caching
- Clients hold structure/manifests for all readable files but fetch ciphertext lazily.
- `pinned-local` proactively fetches + keeps plaintext offline (and indexed) on that device.
- Conditional fetch by content-hash (`If-None-Match`) avoids re-downloading unchanged ciphertext. **[P]**

## 6.9 Conflict philosophy
- **Text:** no conflicts — CRDT merge on clients.
- **Ink/binary:** LWW head, but **history retains every version**, so an LWW "loss" is recoverable — satisfying the full-history guarantee under E2EE.
