# 12 — Administration (server-owned API & audit)

> **E2EE.** Admins manage the instance and users and see **structure, usage, and audit** — but **cannot read content at all**. There is **no break-glass**, because the server holds no key to break into. This is stronger than the master spec's "audited break-glass." Concrete APIs are **[P]**.

> **The operator dashboard is a separate component.** The admin **UI/product surface** has been extracted out of the server into its own repo — **`NyxiteAdmin`** (a Next.js + shadcn/ui app; see [features/admin.md](https://github.com/Nyxite/Nyxite/blob/main/features/admin.md) and the `admin` repo `specification/`). This section specifies the **server-owned data + enforcement plane** the dashboard consumes: the `/admin/**` API, audit-log storage/append + signed-export generation, `admin`-role auth, device-revoke enforcement, and the operational jobs. The server no longer renders any admin UI itself.

## 12.1 Admin model — RBAC (permissions, roles, groups)

- Access control is **role/group-based**, not a single flag. **Permissions are system-defined** (one per feature/capability, code-enforced by stable key); **roles** bundle permissions (built-in presets plus operator-created custom roles); **groups** carry roles, and a user's effective permissions are the **union of their groups' roles**. Backing tables `roles`, `role_permissions`, `groups`, `group_roles`, `group_members` are in [03 §3.2a](03-data-model.md). A bootstrap super-admin exists from install; the legacy coarse `users.role` remains only as that bootstrap flag. With the enterprise IdP enabled, a Keycloak claim may map onto a role ([08](08-authentication.md)).
- Admin visibility: account list, **structure by opaque ID** (names are encrypted), storage usage, version/key-generation counts, audit log.
- Admin **cannot** decrypt names or content. No content-read policy and no break-glass exist ([08 §8.5](08-authentication.md)).

## 12.2 Admin API (`/api/v1/admin/**`) **[P]**

> These endpoints are the contract the **`NyxiteAdmin`** dashboard calls; the server serves them, the dashboard renders them.

### Users & instance
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/users` | List users (identity + usage + **status** + **quota**) |
| `GET` | `/admin/users/{id}` | Usage, counts, devices, key generations, group/role membership |
| `PATCH` | `/admin/users/{id}` | Role/group, **storage quota**, limits, **status** (block/unblock) |
| `POST` | `/admin/users/bulk` | **Bulk edit** — apply changes to many users in one request |
| `POST` | `/admin/users/import` · `GET /admin/users/export` | CSV import/export; SCIM (`/scim/v2/**`) drives IdP lifecycle |
| `GET` | `/admin/instance` | Status: storage, DB, blob store, relay, key directory health |
| `GET` | `/admin/instance/config` | Effective **non-secret** configuration |

### Roles, permissions & groups
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/permissions` | System-defined permission catalog (read-only) |
| `GET/POST/PATCH/DELETE` | `/admin/roles[/{id}]` | Role presets + custom roles (composed from permissions) |
| `GET/POST/PATCH/DELETE` | `/admin/groups[/{id}]` | Create/edit groups; assign roles |
| `POST/DELETE` | `/admin/groups/{id}/members` | Add/remove members (bulk-capable) |

### Structure, sessions (no content, no names)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/projects` | All projects: owners, sizes, structure by **opaque ID** — names are ciphertext |
| `GET` | `/admin/files` | File records: ids, content-type, sizes, versions — **no names, no content** |
| `GET` | `/admin/users/{id}/sessions` · `DELETE …/{sid}` | List / revoke active sessions (force-logout) |

> There are **no** `/admin/breakglass`, content-read, or content-search endpoints — removed entirely. The capability cannot exist under E2EE.

### Keys & devices (operational, public material only)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/keys/health` | Key-directory consistency, orphaned wrapped keys, rotation backlog (public/opaque only) |
| `POST` | `/admin/users/{id}/devices/{deviceId}/revoke` | Administratively revoke a device (cannot read its keys) |

### Audit
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/audit?from=&to=&actor=&action=&target=` | Query the audit log |
| `GET` | `/admin/audit/export` | Export a signed audit bundle (see below) **[P]** |
| `GET/PUT` | `/admin/audit/stream` | Configure **SIEM streaming** (syslog/webhook) + retention |

> **Signed audit bundle format [P]:** `NDJSON` of audit rows + a `manifest.json` `{ from, to, count, chainHead, alg:"ed25519", signature }`. The rows form a **rolling hash chain** (each row hashes the previous), and the manifest carries a **detached Ed25519 signature** over the final `chainHead` using a server **audit-signing key**. A verifier replays the chain and checks the signature to prove the export is complete and untampered.

## 12.3 Audit log

Append-only `audit_log` ([03](03-data-model.md)), distinct from app logs. Covers **auth events, device/key lifecycle, shares created/revoked, key rotations, admin actions, and purges** — **never content or keys** (there is no content to log).

Recorded `action` values (non-exhaustive) **[P]**:

| Category | Examples |
|----------|----------|
| Auth | `auth.login`, `auth.2fa_challenge`, `auth.guest_session` |
| Keys/devices | `device.enroll`, `device.revoke`, `key.publish`, `key.rotate`, `recovery.use` |
| Sharing | `share.create`, `share.update`, `share.revoke`, `share.link_access` |
| Admin | `admin.user_update`, `admin.user_block`, `admin.user_unblock`, `admin.quota_set`, `admin.bulk_update`, `admin.role_change`, `admin.group_change`, `admin.session_revoke`, `admin.config_view`, `admin.device_revoke` |
| Content lifecycle (structural) | `file.delete`, `file.restore`, `version.purge`, `blob.gc` |

Each entry: `occurred_at`, `actor_id`/`actor_kind`, `action`, `target_type`/`target_id`, structural `detail`, `ip`, `user_agent`.

### Integrity & retention
- App DB role has **no UPDATE/DELETE** on `audit_log` (append-only by grant). **[P]**
- Optional tamper-evidence: hash-chained entries / periodic signed checkpoints. **[P]**
- Operator-configured retention; rotation/export via the admin API; expiry purge is itself audited.

## 12.4 Configuration surface

- Admin endpoints expose **effective non-secret** config only — never the native token-signing key, the enterprise Keycloak client secret, or any keys. (There is no server content KEK to expose.)
- Per-user/per-file settings (sync policy, etc.) are surfaced via user-facing endpoints ([04 `/me/settings`](04-rest-api.md)) and are **client-encrypted**.

## 12.5 Operational admin

- Health/readiness ([14](14-deployment-and-config.md)).
- Triggerable maintenance: GC/purge runs, key-directory consistency checks, share-expiry sweeps — all audited. **No** reindex (no server index) and **no** content operations.

## 12.6 Enforcement (server-side)

The dashboard sets these; the **server enforces** them — none require reading content.

- **Storage quota.** `users.storage_quota_bytes` ([03](03-data-model.md)); the server tracks **ciphertext** bytes per user and **rejects uploads that would exceed the quota** (`413`/`507`) at the blob/upload path ([04](04-rest-api.md), [06](06-sync.md)). Names/content stay opaque; only sizes are counted.
- **Account status / block.** `users.status ∈ {active, blocked}` ([03](03-data-model.md)). `blocked` = **download-only**: the server denies all writes (create/edit/upload/share/CRDT relay) and **refuses web-client sessions**, while still serving **ciphertext download** to the desktop/Android/API path so the user can keep local copies. Enforced at the ACL/authorization layer ([09](09-sharing-and-acl.md)); reversible; every transition audited.
- **Existence-hiding on `/admin/**`.** Admin resources addressed by id (`/admin/users/{id}`, `/admin/projects`, `/admin/files`, etc.) return **`404`** when the caller lacks reach — indistinguishable from a non-existent id — rather than `403`; `403` is used only for capability/collection denials that expose no id (e.g. a non-admin hitting `GET /admin/users`) or when the caller already has read reach. See [13 §13.6a](13-security.md).
- **RBAC — per-permission guards, target-aware (AD-1).** Each protected operation is guarded **once** by the single permission key it requires (policy-based authorization, e.g. `[RequirePermission("users.block")]`); the operation→permission mapping ships **in code with the feature**, while the DB stores only role→permission (with scope) and group assignments ([03 §3.2a](03-data-model.md)). At request time the caller's effective grants resolve `token → user → group_members → group_roles → role_permissions` (union, cached per request). The guard passes when the caller holds the required key **and the target satisfies the grant's `scope`** — a `scope` (jsonb) constrains valid targets, e.g. `{ "groups": [...] }` (delegated admin over specific groups) or `{ "excludeRoles": ["admin"] }` (cannot act on other admins); a **null scope is instance-wide** (super-admin). **Roles are never checked directly** — custom roles only recombine system-defined permission keys, so they introduce **no new check site**; on role create/update the server validates every `permission_key` against the system catalog (`GET /admin/permissions`). **Response on failure follows existence-hiding (§13.6a):** no reach to the target → `404`; caller can see the target but scope/permission forbids the action → `403`. The dashboard's UI gating is **advisory only** — the server re-checks every mutation.
- **Security policy.** MFA/passkey mandate, password policy, session timeout, and IP allowlist/geofencing are enforced at auth/session issuance ([08](08-authentication.md)); anomaly signals (mass-download, impossible-travel, brute-force) are computed from audit metadata only.
