# 03 — Data Model (PostgreSQL + Blob Store)

> **E2EE model ([07](07-encryption.md)).** The server stores **only ciphertext, wrapped keys, structure, ACLs, and timestamps**. Names/titles are encrypted; there is **no server-side search index** and **no server-readable content**. All schema below is **[P]**. Types are PostgreSQL 17; managed by EF Core migrations in `Nyxite.Persistence`.

## 3.1 Conventions

- Primary keys: `uuid` (UUIDv7, app-generated).
- Timestamps: `timestamptz`, UTC.
- Soft delete: nullable `deleted_at`; partial indexes filter `WHERE deleted_at IS NULL`. `deleted_at` is the single timestamp that drives the **staged deletion lifecycle** (Trash → grace → purge, cluster DL-1–DL-5) — see the deletion-lifecycle note under §3.3.
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
  ADD COLUMN max_members    int,                   -- per-group size override (G-5); NULL → instance default group_max_members (§12.7)
  ADD COLUMN group_key_id   uuid,                  -- id of the generation-1 group key (logged in the KT log, 17 §17.3)
  ADD COLUMN self_sig       bytea;                 -- hybrid self-signature of the group public keys by ed25519_pubkey (17 §17.3)
-- group_pubkey/ed25519_pubkey/group_key_id/self_sig are set together iff the group is key-bearing (a file-sharing group).

CREATE TABLE group_scope_keys (                    -- public keys minted by a scope-scoped rotation (09 §9.9)
  group_id       uuid NOT NULL REFERENCES groups(id),
  scope_id       uuid NOT NULL,
  generation     int  NOT NULL,                    -- >= 2; generation 1 of every scope is the groups.group_pubkey key
  key_id         uuid NOT NULL UNIQUE,
  group_pubkey   bytea NOT NULL,                   -- hybrid X25519 + ML-KEM-768 public half
  sig_pubkey     bytea NOT NULL,                   -- hybrid Ed25519 + ML-DSA-65 public half
  alg_id         text NOT NULL,
  self_sig       bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, scope_id, generation)
);
```
> **Current group key of a scope** = the highest-generation `group_scope_keys` row for `(group_id, scope_id)`, or the `groups` base key if the scope was never rotated. A rotation that only re-wrapped the old private key would give no forward secrecy, so every rotation mints a **new keypair** and its public half must be published here, both so other members (and "manager reads all" workers) wrap new DEKs to it and so it enters the key-transparency log (`entry_type 3`, [17](17-key-transparency.md)). Append-only, like the grants.
> `group_pubkey` is published in the key directory as just another HPKE target — **no new primitive** ([07 §7.3](07-encryption.md)). `max_members` is a **metadata-only** count cap, enforced by membership-row count at enrollment ([12 §12.7](12-administration.md)).

**Per-member group-key grant — `group_key_grants` (append-only).** The group private key HPKE-wrapped **once per member** under that member's personal public key, per scope/generation.
```sql
CREATE TABLE group_key_grants (
  id                    uuid PRIMARY KEY,          -- surrogate (UUIDv7)
  group_id              uuid NOT NULL REFERENCES groups(id),
  member_id             uuid NOT NULL REFERENCES users(id),
  scope_id              uuid NOT NULL,             -- project/time-period scope this key covers (G-4); opaque, the server only groups by it and never interprets it
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
  self_sig       bytea NOT NULL,           -- hybrid directory self-signature by public_ed25519 over the entry (09 §9.3, 17 §17.3)
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  PRIMARY KEY (user_id, key_id)
);
```
Only **public** keys live here — each a **hybrid classical + post-quantum** public key ([07 §7.3](07-encryption.md)). Private keys never reach the server.

> **Key-transparency log.** Every `user_keys` insert/revoke and every group public key is appended, in the same transaction, to the KT log. Its tables (`kt_leaves`, `kt_nodes`, `kt_checkpoints`, `kt_state`) are specified with the log in [17 §17.6](17-key-transparency.md), so the byte-exact format and the storage stay in one place.

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
  pairing_code_hash  bytea,                   -- SHA-256 of the 6–8 digit pairingCode; NULL once approved or expired
  pairing_expires_at timestamptz,             -- now() + NYXITE__Auth__PairingCodeLifetime at POST /devices
  pairing_attempts   int NOT NULL DEFAULT 0,  -- failed code entries; at NYXITE__Auth__PairingCodeMaxAttempts the code is void
  enrolled_at      timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz
);
```
> A device is created `pending`; an existing device approves it by sealing the identity bundle to its `pubkey` (HPKE) into `pending_key_blob`. The new device fetches it once (single-use), then the server clears `pending_key_blob` and the device becomes `active` ([04](04-rest-api.md), [08 §8.3](08-authentication.md)).
>
> **Pairing code storage.** The `pairingCode` belongs to exactly one pending device and dies with it, so it lives on the `devices` row instead of in [`ephemeral_tokens`](#ephemeral_tokens--single-use-short-lived-tokens). A 6–8 digit code has at most ~27 bits of entropy, so its hash is reversible by brute force; it is protected by its **short lifetime** and the **attempt cap**, not by the hash — the hash only keeps it out of plain sight in a dump. The server **verifies the code on `POST /devices/{id}/approve`** ([04](04-rest-api.md)) and rejects the approval otherwise. On approval or expiry `pairing_code_hash` and `pairing_expires_at` are set to NULL.

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

### sessions  (one row per signed-in client — refresh-token family)
```sql
CREATE TABLE sessions (
  id              uuid PRIMARY KEY,            -- the `sid` claim carried in every access token of this session
  user_id         uuid NOT NULL REFERENCES users(id),
  device_id       uuid REFERENCES devices(id), -- NULL until the device is enrolled; login precedes enrollment (08 §8.3)
  client_kind     text NOT NULL
                    CHECK (client_kind IN ('desktop','android','web','admin')),
  auth_method     text NOT NULL
                    CHECK (auth_method IN ('password_totp','passkey','oidc')),
  mfa_verified_at timestamptz NOT NULL,        -- last second factor on this session; drives `403 2fa_required` step-up (08 §8.2)
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),  -- bumped on refresh; idle timeout is measured from here
  expires_at      timestamptz NOT NULL,        -- absolute lifetime; refresh never extends it
  last_ip         inet,                        -- for the admin sessions list only; overwritten, no history kept here
  user_agent      text,
  revoked_at      timestamptz,
  revoke_reason   text
                    CHECK (revoke_reason IN ('logout','admin','device_revoked','user_blocked',
                                             'credential_change','reuse_detected'))
);
CREATE INDEX ix_sessions_user_active ON sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_sessions_device      ON sessions(device_id) WHERE revoked_at IS NULL;
```
> A session is the server-side anchor for **revocation**: `/auth/logout`, admin force-logout (`DELETE /admin/users/{id}/sessions/{sid}`, [12](12-administration.md)), device revocation, blocking a user and a password/TOTP/passkey change all set `revoked_at` + `revoke_reason`, which kills every refresh token of the session at once. Access tokens stay **stateless** ([08 §8.7](08-authentication.md)); a revoked session therefore loses access within one access-token lifetime (~5 min) — the server does **not** look up `sessions` on every request, because that would make every call a DB round-trip for a 5-minute gain. Holds no key material and nothing content-derived.

### refresh_tokens  (rotate-on-use chain within a session)
```sql
CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY,
  session_id  uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  parent_id   uuid REFERENCES refresh_tokens(id) ON DELETE CASCADE,  -- the token this one replaced; NULL = issued at login
  token_hash  bytea NOT NULL UNIQUE,         -- SHA-256 of the opaque 256-bit random token; the raw token is never stored
  issued_at   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,          -- idle lifetime; capped at sessions.expires_at
  used_at     timestamptz                    -- set when exchanged at /auth/refresh; a used token is never valid again
);
CREATE UNIQUE INDEX ux_refresh_parent ON refresh_tokens(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX ix_refresh_session ON refresh_tokens(session_id);
```
- **Opaque, hashed.** The refresh token is a random 256-bit value, not a signed token, so it is only valid while its row exists and is unused — revocation is a row update, not a deny-list. Only its **SHA-256** is stored, so a database leak yields no usable refresh token; a slow hash (Argon2id) is unnecessary because the input is 256 bits of randomness, not a guessable password.
- **Rotation.** `POST /auth/refresh` looks the token up by hash, requires `used_at IS NULL`, `expires_at > now()` and the parent session not revoked/expired, then — in **one transaction** — sets `used_at`, inserts the child with `parent_id` = the old row, and bumps `sessions.last_seen_at`. The **unique index on `parent_id`** makes a double-spend race fail at the database: two concurrent refreshes of the same token cannot both create a child.
- **Reuse detection.** Presenting a token whose `used_at` is already set means it was copied; the server revokes the whole session (`revoke_reason = 'reuse_detected'`), audits `auth.refresh_reuse` ([12](12-administration.md)) and returns `401`. This is the OAuth 2.0 Security BCP rotation pattern, chosen over a fixed long-lived refresh token because a stolen token is then usable at most until its legitimate owner refreshes next.
- **Lifetimes** are configuration, not constants: `NYXITE__Auth__RefreshTokenIdleLifetime` and `NYXITE__Auth__SessionAbsoluteLifetime` ([14](14-deployment-and-config.md)); an admin security-policy session timeout ([12](12-administration.md)) may only shorten them.
- **Cleanup.** The ops job that already sweeps expired shares also deletes sessions revoked or expired longer than `NYXITE__Retention__SessionRetentionDays` ago; `ON DELETE CASCADE` takes their refresh-token chain with them, because a dead chain has no value and keeping it only keeps credential hashes around. The audit trail of the session lives in `audit_log`, not here.

### ephemeral_tokens  (single-use short-lived tokens)
```sql
CREATE TABLE ephemeral_tokens (
  token_hash  bytea PRIMARY KEY,             -- SHA-256 of the opaque 256-bit random token; the raw token is never stored
  kind        text NOT NULL
                CHECK (kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff')),
  user_id     uuid REFERENCES users(id),     -- NULL only for 'oidc_state' (no user is known before the IdP answers)
  session_id  uuid REFERENCES sessions(id) ON DELETE CASCADE,  -- socket_ticket: the session it was minted from; NULL for 'mfa'
  attempts    int NOT NULL DEFAULT 0,        -- 'mfa': failed TOTP codes; at NYXITE__Auth__MfaMaxAttempts the token is void
  detail      jsonb,                         -- 'oidc_state' only: { nonce, codeVerifier, redirectUri, client }
  issued_at   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz                    -- set by the consuming request; a used token is never valid again
);
ALTER TABLE ephemeral_tokens ADD CONSTRAINT ck_ephemeral_user
  CHECK (user_id IS NOT NULL OR kind = 'oidc_state');
CREATE INDEX ix_ephemeral_expires ON ephemeral_tokens(expires_at);
```
- **What lives here.** The interim `mfaToken` between `POST /auth/login` and `POST /auth/login/totp` (lifetime `NYXITE__Auth__MfaTokenLifetime`); the relay **socket ticket** minted from a user bearer (single-use, **60 s**, [08 §8.4](08-authentication.md)); the **password-reset** token of `/auth/password/forgot` (30 min); the **invite** token sent to an admin-imported user (7 days, [12 §12.2](12-administration.md)); and the enterprise OIDC `oidc_state` (10 min, its `state`/`nonce`/PKCE verifier kept in a `detail jsonb` column) and `oidc_handoff` (60 s) values ([08 §8.1](08-authentication.md)). Lifetimes are config keys `NYXITE__Auth__Lifetimes__<Kind>` ([14](14-deployment-and-config.md)). Both must be **single-use**, which a stateless signed token cannot enforce, so they need server state.
- **Consume = one statement.** `UPDATE ephemeral_tokens SET used_at = now() WHERE token_hash = $1 AND kind = $2 AND used_at IS NULL AND expires_at > now() RETURNING …` — exactly one request can win, with no read-then-write race, and it works unchanged when several server nodes share the database.
- **Why Postgres, not in-memory or Redis.** In-memory state is lost on restart and is invisible to a second node, so a ticket minted on node A would fail on node B. Redis would work but would turn an **optional** component (today only the multi-node relay backplane, [14](14-deployment-and-config.md)) into a **required** part of the default stack. The row volume is tiny (one row per login attempt and per socket connect, gone within minutes), so Postgres carries it without cost. Access goes through an `IEphemeralTokenStore` interface, so a Redis implementation can be added later for large multi-node deployments without a schema change.
- **Cleanup.** The ops job deletes rows past `expires_at`; nothing here is kept for audit, because login and relay events are already in `audit_log`.

### Guest share-session token — stateless, not stored

The 15-minute guest **share-session token** ([08 §8.2](08-authentication.md), [09 §9.6](09-sharing-and-acl.md)) has **no table**. It is a token signed with the server's token-signing key, carrying the `share_id`, the link permission (read/write) and `exp`. It need not be single-use, so the main reason for server state is absent, and every **renewal** re-checks the `shares` row, which already gives the specified "revoked within one renewal cycle". Not storing it also means the server keeps **no per-guest record** beyond the `auth.guest_session` audit event, which is the privacy-preferring choice.

### idempotency_keys  (replay store for `Idempotency-Key`)
```sql
CREATE TABLE idempotency_keys (
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint      text NOT NULL,               -- route template, e.g. 'POST /projects', not the concrete URL
  key           text NOT NULL,               -- client-supplied Idempotency-Key header value
  request_hash  bytea NOT NULL,              -- SHA-256 of the canonical request body; detects same key + different body
  status_code   int NOT NULL,
  response_body bytea NOT NULL,              -- the original response (IDs, timestamps, ciphertext refs — nothing the server could read anyway)
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,        -- created_at + 24 h (04 §4.1)
  PRIMARY KEY (user_id, endpoint, key)
);
CREATE INDEX ix_idempotency_expires ON idempotency_keys(expires_at);
```
- Implements the rule in [04 §4.1](04-rest-api.md) / [01 §1.5](01-architecture.md): scope `(user, endpoint)`, **24 h**, replay returns the stored status + body, same key with a different `request_hash` → `409 idempotency_conflict`.
- **Same transaction as the create.** The row is inserted in the **same transaction** that performs the create, just before commit. A concurrent duplicate request blocks on the primary key until the first commits, then hits the unique violation and returns the stored response. This needs no "in progress" state and no extra error code, and a failed create leaves no row, so the client can safely retry.
- **Cleanup.** The ops job deletes rows past `expires_at`.

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

> **Deletion lifecycle — staged retention (DL-1–DL-5).** A delete never hard-deletes immediately: setting `deleted_at` starts a fixed, timestamp-driven **three-stage timeline** the server runs over opaque blobs (it stores only `deleted_at`, learns no content, and cannot distinguish stages beyond timestamps — DL-2):
> - **Trash** — for the configured trash window (default **30 days**, [14 §14.3](14-deployment-and-config.md)): the row is hidden from live queries (partial indexes) but **client-visible in a Trash view** with one-click restore (clears `deleted_at`). Restore brings back version history intact.
> - **Grace** — for the configured grace window past Trash (default **30 days**): the row leaves the normal client UI entirely; ciphertext + wrapped keys are still retained, restorable **only by an explicit admin action** (DL-4).
> - **Purge** — at the end (~**60 days** total): a scheduled job hard-deletes the metadata row, ciphertext, wrapped keys, and the file's version-history snapshots **together** ([10 §10.6](10-version-history.md)); irreversible. **Every** delete runs the full timeline — there is **no early/permanent-now purge** (DL-5).
>
> Both windows are an **instance-wide admin default with a per-user override** (same mechanism as the storage quota / `group_max_members`, [14 §14.3](14-deployment-and-config.md), [12 §12.7](12-administration.md)). **Scope (DL-3):** a share-**recipient's** delete removes only their own `shares` row (their reference), leaving the file live for everyone else; the file **owner's** delete sets `files.deleted_at` and runs the timeline **globally** for all members.

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
  layout       text NOT NULL DEFAULT 'single' CHECK (layout IN ('single','chunked')),  -- 'chunked': blob_ref is the chunk manifest (07 §7.4a)
  author_id    uuid REFERENCES users(id), -- null for guests
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (file_id, seq)
);
CREATE INDEX ix_versions_file ON file_versions(file_id, seq DESC);
ALTER TABLE files ADD CONSTRAINT fk_files_current_version
  FOREIGN KEY (current_version_id) REFERENCES file_versions(id);
```
> No `size_plain` and no `summary`: the server can't measure plaintext or summarize a diff (diffs are client-side, [10](10-version-history.md)).

### file_chunks / file_version_chunks  (chunked large files, Phase 5.1)
```sql
CREATE TABLE file_chunks (                 -- one row per uploaded chunk ciphertext (07 §7.4a)
  file_id      uuid  NOT NULL REFERENCES files(id),
  address      bytea NOT NULL,             -- client-computed chunk address (32 B), opaque to the server
  blob_ref     text  NOT NULL,             -- ciphertext location in the blob store
  size_cipher  bigint NOT NULL,            -- counted against the uploader's quota from upload time
  uploaded_by  uuid REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, address)
);
CREATE TABLE file_version_chunks (         -- ordered chunk list of a chunked version
  version_id   uuid NOT NULL REFERENCES file_versions(id),
  chunk_index  int  NOT NULL,
  file_id      uuid NOT NULL,
  address      bytea NOT NULL,
  PRIMARY KEY (version_id, chunk_index),
  FOREIGN KEY (file_id, address) REFERENCES file_chunks(file_id, address)
);
```
> Chunks are scoped **per file** (primary key `(file_id, address)`), so an existence check never answers across files. The server sees the **chunk count** of a version, which reveals the size in 4 MiB steps; `size_cipher` already reveals the size, so nothing new leaks. A chunk not referenced by any `file_version_chunks` row is **pending**; the blob GC ([§3.4](#34-blob-store-layout)) deletes pending chunks older than `NYXITE__Limits__PendingChunkTtlHours` and every chunk whose versions were all purged.

### change_log  (delta-sync feed, 06 §6.3.2)
```sql
CREATE TABLE change_log (
  seq         bigserial PRIMARY KEY,         -- the position behind the opaque sync cursor
  project_id  uuid NOT NULL REFERENCES projects(id),
  kind        text NOT NULL CHECK (kind IN ('structure','blob','crdt','delete','keyrotate')),
  entity      text NOT NULL CHECK (entity IN ('project','folder','file')),
  entity_id   uuid NOT NULL,
  ref         jsonb NOT NULL,                 -- the ServerChange ref, opaque/structural fields only
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_change_log_project ON change_log(project_id, seq);
```
> Written in the **same transaction** as the change it describes, so the feed can never miss or invent a write. ACL filtering happens at read time, not here. `ref` holds only what `ServerChange` exposes (ids, sequence numbers, opaque `nameEnc`/hashes), never content. Pruned after `NYXITE__Retention__ChangeLogDays`; an older cursor gets `410 cursor_expired` ([06 §6.3.2](06-sync.md)). `bigserial` may leave gaps after a rollback; cursors only require monotonicity, not gaplessness.

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
- **GC:** removes blobs with no live `file_versions`/`crdt_updates`/`file_version_chunks` reference, and pending chunks past their TTL ([10](10-version-history.md), [§3.3](#file_chunks--file_version_chunks--chunked-large-files-phase-51)).

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
