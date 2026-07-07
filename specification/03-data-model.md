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
  id                uuid PRIMARY KEY,
  email             text NOT NULL UNIQUE,
  display_name      text NOT NULL,            -- account identity, NOT file content
  password_verifier bytea,                    -- Argon2id (m=64MiB,t=3,p=1) over HMAC-SHA256(password, pepper); NULL for passkey-only / enterprise accounts
  password_pepper_version int,                -- which PASSWORD_PEPPER version this verifier used; drives lazy re-pepper at next login (§08); NULL when no verifier
  totp_secret_enc   bytea,                    -- enrolled TOTP secret, encrypted at rest; required alongside a password
  external_idp      text,                     -- enterprise IdP name (e.g. 'keycloak'); NULL for native accounts
  external_idp_sub  text,                     -- OIDC `sub` from the enterprise IdP; NULL for native accounts
  role              text NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),  -- bootstrap flag only; fine-grained access is RBAC (§3.2a)
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),  -- 'blocked' = download-only (§12.6)
  storage_quota_bytes bigint,                 -- per-user storage limit (ciphertext bytes); NULL = unlimited (§12.6)
  settings_enc      bytea,                    -- client-encrypted user settings (server-opaque)
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (external_idp, external_idp_sub)     -- enterprise-linked identity, when present
);
```
> Native, server-owned account ([08](08-authentication.md)): `password_verifier` is an **Argon2id hash over an HMAC-SHA256(password, pepper) pre-hash** (the password never feeds content-key derivation; the **pepper** is a server secret held outside Postgres — [14](14-deployment-and-config.md)), `password_pepper_version` records the pepper version so rotation can **re-pepper lazily at next login**, `totp_secret_enc` the required second factor; passkeys live in `webauthn_credentials`. `external_idp`/`external_idp_sub` are populated **only** for enterprise OIDC-linked accounts. `display_name`/`email` are account identity (needed for sharing-by-account and presence), not file content. User *settings* are client-encrypted. `status='blocked'` and `storage_quota_bytes` are admin-set and **server-enforced** ([12 §12.6](12-administration.md)) — both operate on metadata/sizes only, never content.

### Access control — roles, permissions, groups (admin RBAC) — §3.2a

System-defined **permissions** (one per feature/capability, code-owned by stable key — not a mutable table) are bundled into **roles**, granted to users via **groups**. A user's effective permissions are the union of their groups' roles. See [12 §12.1](12-administration.md).

```sql
CREATE TABLE roles (
  id          uuid PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  is_builtin  boolean NOT NULL DEFAULT false,   -- preset roles cannot be deleted
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE role_permissions (              -- permission_key is a system constant, validated against the catalog in code
  role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_key text NOT NULL,
  scope          jsonb,                       -- target-aware constraint (AD-1): NULL = instance-wide; else e.g. {"groups":[...]} / {"excludeRoles":["admin"]} (§12.6)
  PRIMARY KEY (role_id, permission_key)
);
CREATE TABLE groups (
  id          uuid PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE group_roles (
  group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role_id  uuid NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
  PRIMARY KEY (group_id, role_id)
);
CREATE TABLE group_members (
  group_id  uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   uuid NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
```
> These are **access-control** groups (membership + roles, metadata only, **no keys**). The **enterprise/family file-sharing groups** (per-visibility encryption, group-key layer) **build directly on this model** — same `groups`/`group_members` rows as the membership primitive, extended with public-key columns and grant/wrap storage in §3.2b. They do **not** introduce a parallel membership concept.

### Enterprise/family file-sharing groups — group-key layer — §3.2b

A **group-key layer** inserted into the envelope hierarchy (`personal key → group key → DEK → file`, [07 §7.2a](07-encryption.md)) so a file readable by a whole group is stored **once** and adding a reader is **one blob (O(1))**. The **membership** stays the §3.2a `groups`/`group_members` rows; this subsection adds only the **public key material, per-member grants, DEK-to-group wraps, and reader-group attachments**. The server holds **only opaque wrapped blobs, membership rows, and public keys** — never a group private key, content key, or plaintext name ([13 §13.6b](13-security.md)). Build steps P4.4-SRV-1..4.

A file-sharing group **extends** the existing `groups` table with public material + scoping + the size override; plain RBAC groups leave these `NULL`.
```sql
ALTER TABLE groups
  ADD COLUMN group_pubkey   bytea,                 -- hybrid X25519 + ML-KEM-768 public half (HPKE target); private half NEVER on server
  ADD COLUMN ed25519_pubkey bytea,                 -- hybrid Ed25519 + ML-DSA-65 group signing public key (verify group-authored writes)
  ADD COLUMN scope_kind     text CHECK (scope_kind IN ('project','time_period')),  -- G-4 scope granularity
  ADD COLUMN max_members    int;                   -- per-group size override (G-5); NULL → instance default group_max_members (§12.7)
-- group_pubkey/ed25519_pubkey are set together iff the group is key-bearing (a file-sharing group).
```
> `group_pubkey` is published in the key directory as just another HPKE target — **no new primitive** ([07 §7.3](07-encryption.md)). `max_members` is a **metadata-only** count cap, enforced by membership-row count at enrollment ([12 §12.7](12-administration.md)).

**Per-member group-key grant — `group_key_grants` (append-only).** The group private key HPKE-wrapped **once per member** under that member's personal public key, per scope/generation.
```sql
CREATE TABLE group_key_grants (
  id                    uuid PRIMARY KEY,          -- surrogate (UUIDv7)
  group_id              uuid NOT NULL REFERENCES groups(id),
  member_id             uuid NOT NULL REFERENCES users(id),
  scope_id              uuid NOT NULL,             -- project/time-period scope this key covers (G-4)
  wrapped_group_privkey bytea NOT NULL,            -- hybrid group privkey bundle (X25519+ML-KEM-768 ‖ Ed25519+ML-DSA-65), HPKE-wrapped to member pubkey — OPAQUE
  generation            int  NOT NULL DEFAULT 1,   -- rotation generation per (group, scope)
  alg_id                text NOT NULL,             -- wrap-suite id; v1 pins the hybrid PQC suite (crypto-agility)
  created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_group_grants_group  ON group_key_grants(group_id, scope_id, generation);
CREATE INDEX ix_group_grants_member ON group_key_grants(member_id);
```
> **Append-only** (no `deleted_at`, no UPDATE): rotation **bumps `generation` and appends**, never mutates, giving an auditable "who could read what when" history. A **soft removal** deletes the departing member's live grant row; a **rotate/full** removal appends a new-generation grant for the remaining members ([09 §9.9](09-sharing-and-acl.md)). Stored as **opaque bytes** — no key columns; the server cannot open a grant. Enrollment appends **one** row and is gated on a **transparency-verified** member public key ([09 §9.9](09-sharing-and-acl.md), P4.4-SRV-2). `alg_id` carries the wrap suite (v1 pins the **hybrid PQC** suite) so any later primitive change re-wraps small keys without touching content ([07 §7.3](07-encryption.md), [15 §15.3](15-roadmap-and-versioning.md)).

**DEK-to-group wraps** reuse the existing `file_keys` store with a **group** principal (per scope/generation), alongside the per-member/link rows:
```sql
ALTER TABLE file_keys
  ADD COLUMN group_id uuid REFERENCES groups(id),  -- set for a DEK-to-group wrap; null for member/link grants
  ADD COLUMN scope_id uuid;                         -- the group scope (G-4) this wrap belongs to; null for non-group rows
-- The old two-way CHECK becomes three-way: exactly one principal — member, link-share, or group.
ALTER TABLE file_keys DROP CONSTRAINT IF EXISTS file_keys_check;
ALTER TABLE file_keys ADD CONSTRAINT ck_file_keys_principal
  CHECK (num_nonnulls(member_id, share_id, group_id) = 1);
CREATE UNIQUE INDEX uq_file_keys_group ON file_keys(file_id, key_id, group_id) WHERE group_id IS NOT NULL;
```
> A group-principal row wraps the file's **DEK to the group public key** (HPKE) instead of a member's — the same `wrapped_key`/`key_id`/`generation` columns, still **opaque**. This is what makes the enterprise "manager reads all" path work: a worker wraps a DEK to **own key + the managers-group pubkey** with no membership in that group ([09 §9.9](09-sharing-and-acl.md)).

**Reader-group attachment** — an **opaque** per-project/folder structure field naming the group whose public key new files are auto-wrapped to (client-enforced cascade; the server only stores/serves the opaque bytes):
```sql
ALTER TABLE projects ADD COLUMN reader_group_attachment bytea;  -- opaque client-set auto-wrap policy; server never interprets
ALTER TABLE folders  ADD COLUMN reader_group_attachment bytea;  -- inherit/specific-group/none resolved client-side ([09 §9.9](09-sharing-and-acl.md))
```
> The reader-group attachment rides the **existing per-project/folder/file cascade** (same inheritance as sync policy [06](06-sync.md)); the server stores it as **opaque structure metadata** and never learns which group it names.

### webauthn_credentials  (passkey / WebAuthn public credentials)
```sql
CREATE TABLE webauthn_credentials (
  id             uuid PRIMARY KEY,
  user_id        uuid NOT NULL REFERENCES users(id),
  credential_id  bytea NOT NULL UNIQUE,       -- WebAuthn credential ID
  public_key     bytea NOT NULL,              -- COSE public key (PUBLIC material only)
  sign_count     bigint NOT NULL DEFAULT 0,   -- signature counter (clone-detection)
  label          text,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_webauthn_user ON webauthn_credentials(user_id);
```
> Only **public** credential material is stored; a passkey is phishing-resistant and sufficient on its own ([08 §8.1](08-authentication.md)). Nothing here is content-derivable.

### user_keys  (public-key directory)
```sql
CREATE TABLE user_keys (
  user_id        uuid NOT NULL REFERENCES users(id),
  key_id         uuid NOT NULL,
  public_x25519  bytea NOT NULL,           -- hybrid KEM public key (X25519 ‖ ML-KEM-768) for HPKE wrapping to this user
  public_ed25519 bytea NOT NULL,           -- hybrid signing public key (Ed25519 ‖ ML-DSA-65) for signature verification
  alg_id         text NOT NULL,            -- suite id pinning the hybrid primitives (e.g. 'X25519MLKEM768' + Ed25519ML-DSA65) — crypto-agility ([07 §7.3](07-encryption.md))
  generation     int  NOT NULL DEFAULT 1,  -- bumped on identity rotation
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  PRIMARY KEY (user_id, key_id)
);
```
Only **public** keys live here — each a **hybrid classical + post-quantum** public key ([07 §7.3](07-encryption.md)). Private keys never reach the server.

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
                                           --   plaintext = hybrid identity bundle (X25519+ML-KEM-768 priv ‖ Ed25519+ML-DSA-65 priv)
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
