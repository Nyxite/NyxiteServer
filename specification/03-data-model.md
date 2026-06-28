# 03 — Data Model (PostgreSQL + Blob Store)

> **E2EE model ([07](07-encryption.md)).** The server stores **only ciphertext, wrapped keys, structure, ACLs, and timestamps**. Names/titles are encrypted; there is **no server-side search index** and **no server-readable content**. All schema below is **[P]**. Types are PostgreSQL 17; managed by EF Core migrations in `Nyxite.Persistence`.

## 3.1 Conventions

- Primary keys: `uuid` (UUIDv7, app-generated).
- Timestamps: `timestamptz`, UTC.
- Soft delete: nullable `deleted_at`; partial indexes filter `WHERE deleted_at IS NULL`.
- Ciphertext / wrapped keys / hashes: `bytea`.
- Encrypted display names: `bytea` (`*_name_enc`) — the server never holds the plaintext name.
- FKs `ON DELETE RESTRICT` (deletion is soft or via explicit purge), except audit/append tables.

## 3.2 Identity & keys (new under E2EE)

### users
```sql
CREATE TABLE users (
  id            uuid PRIMARY KEY,
  keycloak_sub  text NOT NULL UNIQUE,
  display_name  text NOT NULL,            -- account identity (from Keycloak), NOT file content
  email         text NOT NULL,
  role          text NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  settings_enc  bytea,                     -- client-encrypted user settings (server-opaque)
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
```
> `display_name`/`email` are account identity from Keycloak (needed for sharing-by-account and presence), not file content. User *settings* are client-encrypted.

### user_keys  (public-key directory)
```sql
CREATE TABLE user_keys (
  user_id        uuid NOT NULL REFERENCES users(id),
  key_id         uuid NOT NULL,
  public_x25519  bytea NOT NULL,           -- for HPKE wrapping to this user
  public_ed25519 bytea NOT NULL,           -- for signature verification
  generation     int  NOT NULL DEFAULT 1,  -- bumped on identity rotation
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  PRIMARY KEY (user_id, key_id)
);
```
Only **public** keys live here. Private keys never reach the server.

### devices  (per-device enrollment)
```sql
CREATE TABLE devices (
  id               uuid PRIMARY KEY,
  user_id          uuid NOT NULL REFERENCES users(id),
  label            text,
  pubkey           bytea NOT NULL,            -- device public key (enrollment/approval)
  status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','active','revoked')),
  pending_key_blob bytea,                     -- HPKE-seal of the identity bundle to this device's pubkey;
                                              --   set on approval, DELETED after the single-use enrollment fetch
  enrolled_at      timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz
);
```
> A device is created `pending`; an existing device approves it by sealing the identity bundle to its `pubkey` (HPKE) into `pending_key_blob`. The new device fetches it once (single-use), then the server clears `pending_key_blob` and the device becomes `active` ([04](04-rest-api.md), [08 §8.3](08-authentication.md)).

### recovery_blobs  (client-encrypted recovery blob — server-opaque)
```sql
CREATE TABLE recovery_blobs (
  user_id     uuid PRIMARY KEY REFERENCES users(id),
  version     int  NOT NULL DEFAULT 1,      -- bound into the AEAD AAD (userId ‖ version)
  blob        bytea NOT NULL,              -- AES-256-GCM frame: nonce(12B) ‖ ciphertext ‖ tag(16B);
                                           --   plaintext = identity bundle (X25519 priv ‖ Ed25519 priv)
  kdf_params  jsonb NOT NULL,              -- non-secret: { alg:"argon2id", m, t, p, salt(16B) }
  updated_at  timestamptz NOT NULL DEFAULT now()
);
```
The blob is **AES-256-GCM** under a 256-bit key derived from the user's recovery phrase via **Argon2id** (not HPKE — the recovery key is symmetric). The server stores but **cannot open** this ([07 §7.8](07-encryption.md)). No server/admin escrow.

## 3.3 Domain tables

### projects
```sql
CREATE TABLE projects (
  id          uuid PRIMARY KEY,
  owner_id    uuid NOT NULL REFERENCES users(id),
  name_enc    bytea NOT NULL,              -- encrypted project name
  metadata_enc bytea,                       -- encrypted free-form metadata
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);
CREATE INDEX ix_projects_owner ON projects(owner_id) WHERE deleted_at IS NULL;
```

### folders
```sql
CREATE TABLE folders (
  id               uuid PRIMARY KEY,
  project_id       uuid NOT NULL REFERENCES projects(id),
  parent_folder_id uuid REFERENCES folders(id),
  name_enc         bytea NOT NULL,          -- encrypted folder name
  metadata_enc     bytea,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz
);
CREATE INDEX ix_folders_project ON folders(project_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_folders_parent  ON folders(parent_folder_id) WHERE deleted_at IS NULL;
```
> The server keeps the **structure graph** (parent IDs) to route sync and evaluate ACLs ([07 §7.7](07-encryption.md)); names are encrypted.

### files
```sql
CREATE TABLE files (
  id                 uuid PRIMARY KEY,
  project_id         uuid NOT NULL REFERENCES projects(id),
  folder_id          uuid REFERENCES folders(id),
  owner_id           uuid NOT NULL REFERENCES users(id),
  name_enc           bytea NOT NULL,        -- encrypted file name
  content_type       text NOT NULL CHECK (content_type IN
                       ('markdown','plaintext','ink','office','sourcecode','image','binary')),  -- 'binary' = generic LWW attachment ([06 §6.1](06-sync.md)); adding it needs an EF Core migration
  sync_policy        text NOT NULL DEFAULT 'server-default'
                       CHECK (sync_policy IN ('server-default','excluded')),  -- pinned-local is client-local only, never a server value
  current_version_id uuid,                   -- FK added after file_versions; API exposes file_versions.seq as currentVersionSeq
  crdt_doc_id        uuid,                    -- text types only (client-allocated UUIDv7 at creation)
  key_generation     int NOT NULL DEFAULT 1,  -- current file-key rotation generation
  metadata_enc       bytea,                    -- encrypted per-file metadata
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);
CREATE INDEX ix_files_project ON files(project_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_files_folder  ON files(folder_id)  WHERE deleted_at IS NULL;
CREATE INDEX ix_files_owner   ON files(owner_id)   WHERE deleted_at IS NULL;
```
> `content_type` and sizes stay visible (needed to route sync and pick the client decoder); everything content-bearing is encrypted. The former `zk` hook is gone — **E2EE is the default**, not an opt-in.

### shares  (ACL — see [09](09-sharing-and-acl.md))
> Defined **before** `file_keys`, which references `shares(id)`.
```sql
CREATE TABLE shares (
  id              uuid PRIMARY KEY,
  file_id         uuid REFERENCES files(id),
  folder_id       uuid REFERENCES folders(id),
  project_id      uuid REFERENCES projects(id),
  kind            text NOT NULL CHECK (kind IN ('user_grant','link')),
  grantee_id      uuid REFERENCES users(id),
  link_token_hash bytea,                    -- hash of the link token; KEY is in the URL fragment, never here
  permission      text NOT NULL CHECK (permission IN ('read','write')),
  created_by      uuid NOT NULL REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  revoked_at      timestamptz,
  CHECK (num_nonnulls(file_id, folder_id, project_id) = 1)
);
CREATE INDEX ix_shares_target_file   ON shares(file_id)   WHERE revoked_at IS NULL;
CREATE INDEX ix_shares_target_folder ON shares(folder_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_shares_link          ON shares(link_token_hash) WHERE kind='link' AND revoked_at IS NULL;
```
> For a **user_grant**, the file key is wrapped to the grantee's public key in `file_keys`. For a **link**, the key rides the URL fragment ([09](09-sharing-and-acl.md)); the server stores only the token hash.

### file_keys  (wrapped file keys — one row per authorized member or link-share grant)
```sql
CREATE TABLE file_keys (
  id           uuid PRIMARY KEY,             -- surrogate key (UUIDv7)
  file_id      uuid NOT NULL REFERENCES files(id),
  member_id    uuid REFERENCES users(id),   -- set for account grants; null for link/guest shares
  share_id     uuid REFERENCES shares(id),  -- set for link/guest grants; null for account grants
  key_id       uuid NOT NULL,                -- which file-key (1:1 with generation)
  wrapped_key  bytea NOT NULL,               -- FK wrapped to member's public key (HPKE)
  generation   int  NOT NULL DEFAULT 1,      -- rotation generation; 1:1 with key_id
  created_at   timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz,
  -- exactly one of a member grant or a link-share grant
  CHECK ((member_id IS NOT NULL) <> (share_id IS NOT NULL))
);
-- partial unique indexes replace the old composite PK (which broke on nullable member_id)
CREATE UNIQUE INDEX uq_file_keys_member ON file_keys(file_id, key_id, member_id) WHERE member_id IS NOT NULL;
CREATE UNIQUE INDEX uq_file_keys_share  ON file_keys(file_id, key_id, share_id)  WHERE share_id IS NOT NULL;
```
> **The server holds only *wrapped* file keys** — it cannot unwrap them. Link-share keys are not stored at all when carried in the URL fragment ([09](09-sharing-and-acl.md)); a `share_id` row is used only if a link key is server-relayed wrapped to an ephemeral share keypair.
> **`key_id` vs `generation`:** `key_id` (uuid) names a specific file-key; `generation` (int) is a monotonic rotation counter — **1:1** with `key_id`. `key_id` is the stable reference embedded in frames / `crdt_updates` / `file_versions`; `generation` drives staleness (`412 key_generation_stale`).

### file_versions  (history — encrypted snapshots)
```sql
CREATE TABLE file_versions (
  id           uuid PRIMARY KEY,
  file_id      uuid NOT NULL REFERENCES files(id),
  seq          bigint NOT NULL,
  content_hash bytea NOT NULL,             -- client-computed BLAKE3 of plaintext (opaque address)
  blob_ref     text  NOT NULL,             -- ciphertext address in blob store
  size_cipher  bigint NOT NULL,
  key_id       uuid NOT NULL,              -- file-key generation used
  author_id    uuid REFERENCES users(id), -- null for guests
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (file_id, seq)
);
CREATE INDEX ix_versions_file ON file_versions(file_id, seq DESC);
ALTER TABLE files ADD CONSTRAINT fk_files_current_version
  FOREIGN KEY (current_version_id) REFERENCES file_versions(id);
```
> No `size_plain` and no `summary`: the server can't measure plaintext or summarize a diff (diffs are client-side, [10](10-version-history.md)).

### crdt_updates  (encrypted, server-opaque relay log)
```sql
CREATE TABLE crdt_updates (
  id          bigserial PRIMARY KEY,
  crdt_doc_id uuid NOT NULL,
  seq         bigint NOT NULL,
  update_enc  bytea NOT NULL,             -- ENCRYPTED Yrs update (server cannot read)
  key_id      uuid NOT NULL,
  author_id   uuid,                        -- null for guests
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (crdt_doc_id, seq)
);
CREATE INDEX ix_crdt_updates_doc ON crdt_updates(crdt_doc_id, seq);
```
> The server **stores and relays** encrypted updates; it does **not** apply or merge them ([05](05-realtime-collaboration.md)). Compaction into encrypted snapshots is **client-driven**.

### audit_log  (security events only — no content)
```sql
CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id    uuid,
  actor_kind  text NOT NULL,              -- 'user','admin','guest','system'
  action      text NOT NULL,              -- 'auth.login','share.create','key.rotate',...
  target_type text,
  target_id   uuid,
  detail      jsonb NOT NULL DEFAULT '{}',-- structural/security metadata only, never content
  ip          inet,
  user_agent  text
);
CREATE INDEX ix_audit_time   ON audit_log(occurred_at DESC);
CREATE INDEX ix_audit_actor  ON audit_log(actor_id);
CREATE INDEX ix_audit_action ON audit_log(action);
```

> **Removed vs the previous model:** the `search_index` table and Postgres FTS are **gone** — search is client-side ([11](11-search.md)). The `file_keys.wrapped_dek`/KEK columns are replaced by member-wrapped keys; there is **no server KEK**.

## 3.3a Removed/changed summary

| Was (encryption-at-rest) | Now (E2EE) |
|--------------------------|------------|
| `search_index` + GIN FTS | **removed** (client-side search) |
| `file_keys.wrapped_dek` wrapped by **server KEK** | `file_keys.wrapped_key` wrapped by **member public key** |
| Plaintext `name` columns | `*_name_enc` ciphertext |
| `crdt_updates.update_blob` server-readable | `update_enc` server-opaque; server relays, never merges |
| `file_versions.size_plain`, `summary` | removed (no server-readable plaintext/diffs) |
| `files.zk` opt-in hook | removed — **E2EE is the default** |

## 3.4 Blob store layout

Content-addressed store behind `IBlobStore` (unchanged interface). Stores **ciphertext only**.

- **Address:** client-computed BLAKE3 of plaintext; the server treats it as opaque and enforces write-once.
- **Layout (filesystem):** sharded by hash prefix `blobs/<aa>/<bb>/<full-hash>`. **[P]**
- **Stored content:** AES-256-GCM framed ciphertext ([07 §7.4](07-encryption.md)) for blobs, snapshots, and large CRDT updates.
- **GC:** removes blobs with no live `file_versions`/`crdt_updates` reference ([10](10-version-history.md)).

```csharp
public interface IBlobStore
{
    Task<BlobRef> PutAsync(ReadOnlyMemory<byte> ciphertext, BlobAddress address, CancellationToken ct);
    Task<Stream>  OpenReadAsync(BlobRef reference, CancellationToken ct);  // returns ciphertext
    Task<bool>    ExistsAsync(BlobAddress address, CancellationToken ct);
    Task          DeleteAsync(BlobRef reference, CancellationToken ct);    // GC only
}
```

## 3.5 Migrations & integrity

- EF Core migrations are the schema authority.
- The server validates structure, ACLs, and write-once addressing — but **cannot** validate plaintext or content-hash correctness ([07 §7.5](07-encryption.md)); clients are trusted to address and encrypt honestly.
- Deletes are soft; the only hard delete is admin/GC purge, which is audited.
