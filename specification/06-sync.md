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

### 6.3.1 Manifest reconcile (`GET /sync/manifest`)
Per project: `{ fileId, contentType, syncPolicy, currentVersionSeq, contentHash, keyGeneration, updatedAt, deletedAt }`. All structural/opaque — no names, no content. The client diffs locally to decide pull/push/delete, and to drive its **local search index** ([11](11-search.md)).

### 6.3.2 Delta sync (`POST /sync/changes`)
Cursor-based incremental exchange of **structure changes + ciphertext refs**:
```jsonc
{ "since": "cursor", "projectId": "uuid",
  "localChanges": [ { "fileId": "...", "kind": "structure|blob|crdt|delete|keyrotate", "ref": "..." } ] }
// → { "serverChanges": [ ... ], "nextCursor": "cursor" }
```
Text content changes are referenced (actual exchange on the encrypted relay); blob changes carry a ciphertext `blob_ref` to pull; `keyrotate` signals a new `keyGeneration` so clients refetch their wrapped key. The `nextCursor` is an **opaque base64url** token — monotonic, resumable, tied to the global change-log seq; clients must not parse it.

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
