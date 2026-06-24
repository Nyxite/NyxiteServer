# 02 — Domain Model

> **E2EE.** Content and **names** are client-encrypted; the server holds structure, ACLs, sizes, timestamps, public keys, and wrapped keys ([07 §7.7](07-encryption.md)). All identifiers and rules below are **[P]** concretizations of master spec §3. Persistence form in [03-data-model.md](03-data-model.md).

## 2.1 Entity overview

```
User ──owns──┐    User ──has──► IdentityKeypair (public on server) ──► Device(s) ──► RecoveryBlob
             ▼
          Project ──contains──► Folder ──contains──► File ──has──► FileVersion (encrypted snapshots)
                                   │ (nestable)         │
                                   └────────────────────┤
                                                        ├─ FileKey wraps (one per member; server stores only wrapped)
                                                        ├─ CRDT update log (encrypted, server-relayed)
                                                        ├─ SyncPolicy (per file)
                                                        └─ Share / ACL entries
```

## 2.2 Entities

### 2.2.1 User
Thin projection of a Keycloak subject (no credentials). Account identity (`display_name`, `email`) is server-visible — needed for sharing-by-account and presence — and is **not** file content.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUIDv7 | |
| `keycloak_sub` | string | OIDC `sub`; unique |
| `display_name`, `email` | string | Account identity (from Keycloak) |
| `role` | `user` \| `admin` | |
| `settings_enc` | bytea | **Client-encrypted** user settings |
| timestamps | timestamptz | |

### 2.2.2 IdentityKeypair / Device / RecoveryBlob (E2EE additions)
- **IdentityKeypair** — per user: X25519 (wrapping) + Ed25519 (signing). **Public** keys published to the server directory (`user_keys`); private keys never leave devices.
- **Device** — a user's enrolled device with its own key; enrollment grants access to the identity private key (device-approval or recovery-key unwrap).
- **RecoveryBlob** — the identity private key wrapped by the user's **recovery key**, stored server-opaque; the only recovery path ([07 §7.8](07-encryption.md)).

### 2.2.3 Project / 2.2.4 Folder
As master spec, with **encrypted names** (`name_enc`) and encrypted metadata. The server keeps the structure graph (parent IDs) for sync/ACL. Folder invariant: parent chain stays within the same project and is acyclic (enforced in Domain).

### 2.2.5 File
| Field | Type | Notes |
|-------|------|-------|
| `id` | UUIDv7 | |
| `project_id`, `folder_id`, `owner_id` | UUID | structure (folder nullable = project root) |
| `name_enc` | bytea | **encrypted** name |
| `content_type` | enum (§2.3) | server-visible (selects client decoder); immutable after creation **[P]** |
| `sync_policy` | enum (§2.4) | default `server-default` |
| `current_version_id` | UUID, nullable | head of history |
| `crdt_doc_id` | UUID, nullable | text types only |
| `key_generation` | int | current file-key rotation generation ([09 §9.6](09-sharing-and-acl.md)) |
| `metadata_enc` | bytea, nullable | **encrypted** per-file metadata |
| timestamps + `deleted_at` | timestamptz | soft delete |

> The previous `zk` opt-in column is **gone** — E2EE is the default for every file.

### 2.2.6 FileKey (wraps)
Not one row — a set of **wrapped** file keys ([03 `file_keys`](03-data-model.md)): one per authorized member, each the per-file AES-256-GCM key wrapped to that member's public key (HPKE), plus a generation marker for rotation. The server stores only wrapped copies and cannot open them.

### 2.2.7 FileVersion (history)
Immutable, **encrypted**, content-addressed snapshot ([10](10-version-history.md)). Fields: `seq`, `content_hash` (client-computed BLAKE3 of plaintext), `blob_ref` (ciphertext), `size_cipher`, `key_id`, `author_id` (null for guests), `created_at`. No plaintext size or server-side diff summary.

### 2.2.8 FileContent (logical)
- **Text:** encrypted Yrs update log (`crdt_doc_id`) relayed by the server + client-produced encrypted snapshots.
- **Ink / binary:** encrypted blob; LWW/version-vector metadata held **encrypted** in `metadata_enc` (the version-vector itself can be small and client-managed; the server need not read it). **[P]**

### 2.2.9 Share / ACL — see [09](09-sharing-and-acl.md). 2.2.10 AuditEntry — see [12](12-administration.md).

## 2.3 Content types

| `content_type` | Phase | Sync model | Editor |
|----------------|-------|-----------|--------|
| `markdown` | 1 | CRDT (client-merged) | Markdown |
| `plaintext` | 1 | CRDT (client-merged) | Plain text |
| `ink` | 3 | LWW / version-vector | Vector strokes |
| `office` | 5 | LWW / version-vector | — |
| `sourcecode` | 5 | CRDT (client-merged) | Code |
| `image` | 5 | LWW / version-vector | — |

`content_type` is fixed at creation **[P]**; the CRDT-vs-LWW assignment is **[OD-4]**. `content_type` is one of the few content-adjacent facts the server sees, because it must route the right sync channel and tell the client which decoder to use.

## 2.4 Sync policy (per file) **[OD-3]**

| Value | Meaning | Server behavior |
|-------|---------|-----------------|
| `server-default` | Synced through the server (as ciphertext) | Stored/relayed encrypted |
| `pinned-local` | Kept offline on the device **and** synced | Same server storage; "pin" is a client cache directive |
| `excluded` | Device-only, never uploaded | Server **never receives** content; tolerates content-absent files |

Semantics are **[OD-3]**. Note: even `server-default` content is opaque to the server under E2EE — "synced through the server" means *relayed as ciphertext*, not *readable*.

## 2.5 Identifiers and naming

- **Primary keys:** UUIDv7 (confirmed).
- **Content addresses:** client-computed BLAKE3 of plaintext, opaque to the server.
- **Names:** Unicode, **encrypted at rest on the server**; the server can't sort/dedupe by name. Uniqueness within a parent is not enforced **[P]**; clients disambiguate by id (and decrypt names locally).

## 2.6 Lifecycle and soft delete

- Projects/folders/files use **soft delete** (`deleted_at`) so clients converge on deletions; history (encrypted) is preserved **[P]**.
- A hard-delete/purge path exists for admin/GC (removes blobs whose last referencing version is purged); purges are audited.
- Deleting a folder soft-deletes its subtree as one audited event with the affected count (count is structural, not content).

## 2.7 Multi-content-type sync split (summary)

Text rides the **encrypted** CRDT relay; ink/binary use LWW/version-vector with on-demand **encrypted** blob download ([06](06-sync.md), [OD-4]). One `File` abstraction carries both shapes. The server moves bytes and sequences updates; it never reads them.
