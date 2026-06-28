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
A **native, server-owned account** (not a thin IdP projection). The server holds the credentials needed for native auth — an Argon2id **password verifier**, a **TOTP secret**, and any **WebAuthn/passkey credentials** ([08](08-authentication.md)) — none of which is content-derivable. Account identity (`display_name`, `email`) is server-visible — needed for sharing-by-account and presence — and is **not** file content. An external IdP subject is recorded **only** for enterprise-linked accounts.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUIDv7 | |
| `display_name`, `email` | string | Account identity |
| `password_verifier` | bytea? | Argon2id verifier; **nullable** for passkey-only or enterprise-linked accounts |
| `totp_secret_enc` | bytea? | Enrolled TOTP secret (encrypted at rest); required alongside a password |
| `external_idp` | string? | Enterprise IdP name (e.g. `keycloak`); **null** for native accounts |
| `external_idp_sub` | string? | OIDC `sub` from the enterprise IdP; **null** for native accounts |
| `role` | `user` \| `admin` | Lives on the native account; an enterprise IdP may map a claim to it |
| `settings_enc` | bytea | **Client-encrypted** user settings |
| timestamps | timestamptz | |

WebAuthn/passkey credentials are a separate per-user collection (**WebAuthnCredential**: `credential_id`, `public_key`, `sign_count`, …) — see [03 §3.2](03-data-model.md).

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

> **`current_version_id` vs `currentVersionSeq` (mapping):** the DB persists `files.current_version_id` (uuid FK to `file_versions.id`); the API/wire exposes `currentVersionSeq` = that row's `file_versions.seq`. The server resolves uuid → seq on read ([03](03-data-model.md), [04](04-rest-api.md)).

### 2.2.6 FileKey (wraps)
Not one row — a set of **wrapped** file keys ([03 `file_keys`](03-data-model.md)): one per authorized member, each the per-file AES-256-GCM key wrapped to that member's public key (HPKE), plus a generation marker for rotation. The server stores only wrapped copies and cannot open them.

> **`key_id` vs `generation` (clarification):** `key_id` (uuid) identifies a specific file-key; `generation` (int) is a monotonic counter incremented on each rotation. They are **1:1** — each generation has exactly one `key_id`. `key_id` is the stable reference embedded in encrypted frames / `crdt_updates` / `file_versions`; `generation` is the ordering/staleness basis for `412 key_generation_stale` ([04](04-rest-api.md), [09 §9.6](09-sharing-and-acl.md)).

### 2.2.7 FileVersion (history)
Immutable, **encrypted**, content-addressed snapshot ([10](10-version-history.md)). Fields: `seq`, `content_hash` (client-computed BLAKE3 of plaintext), `blob_ref` (ciphertext), `size_cipher`, `key_id`, `author_id` (null for guests), `created_at`. No plaintext size or server-side diff summary.

### 2.2.8 FileContent (logical)
- **Text:** encrypted Yrs update log (`crdt_doc_id`) relayed by the server + client-produced encrypted snapshots.
- **Ink / binary:** encrypted blob; **LWW** by head sequence. Conflict detection is purely head-`seq` based (the client sends the parent version `seq` on write); the server does **not** read encrypted metadata ([06 §6.5](06-sync.md)). **[P]**

### 2.2.9 Share / ACL — see [09](09-sharing-and-acl.md). 2.2.10 AuditEntry — see [12](12-administration.md).

## 2.3 Content types

| `content_type` | Phase | Sync model | Editor |
|----------------|-------|-----------|--------|
| `markdown` | 1 | CRDT (client-merged) | Markdown |
| `plaintext` | 1 | CRDT (client-merged) | Plain text |
| `ink` | 3 | LWW | Vector strokes |
| `office` | 5 | LWW | — |
| `sourcecode` | 5 | CRDT (client-merged) | Code |
| `image` | 5 | LWW | — |

`content_type` is fixed at creation **[P]**; the CRDT-vs-LWW assignment is **decided ([OD-4] resolved)**. `content_type` is one of the few content-adjacent facts the server sees, because it must route the right sync channel and tell the client which decoder to use.

## 2.4 Sync policy (per file) (**[OD-3] resolved**)

| Value | Meaning | Server behavior |
|-------|---------|-----------------|
| `server-default` | Synced through the server (as ciphertext) | Stored/relayed encrypted |
| `excluded` | Device-only, never uploaded | Server **never receives** content; tolerates content-absent files |

The server model has exactly **two** values. **Offline pinning is purely client-local** — a device cache directive the zero-knowledge server never sees; the former `pinned-local` value is **removed** from the server model. Note: even `server-default` content is opaque to the server under E2EE — "synced through the server" means *relayed as ciphertext*, not *readable*.

## 2.5 Identifiers and naming

- **Primary keys:** UUIDv7 (confirmed).
- **Content addresses:** client-computed BLAKE3 of plaintext, opaque to the server.
- **Names:** Unicode, **encrypted at rest on the server**; the server can't sort/dedupe by name. Uniqueness within a parent is not enforced **[P]**; clients disambiguate by id (and decrypt names locally).

## 2.6 Lifecycle and soft delete

- Projects/folders/files use **soft delete** (`deleted_at`) so clients converge on deletions; history (encrypted) is preserved **[P]**.
- A hard-delete/purge path exists for admin/GC (removes blobs whose last referencing version is purged); purges are audited.
- Deleting a folder soft-deletes its subtree as one audited event with the affected count (count is structural, not content).

## 2.7 Multi-content-type sync split (summary)

Text rides the **encrypted** CRDT relay; ink/binary use **LWW** with on-demand **encrypted** blob download ([06](06-sync.md), [OD-4] resolved). One `File` abstraction carries both shapes. The server moves bytes and sequences updates; it never reads them.
