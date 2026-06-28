# 12 — Administration

> **E2EE.** Admins manage the instance and users and see **structure, usage, and audit** — but **cannot read content at all**. There is **no break-glass**, because the server holds no key to break into. This is stronger than the master spec's "audited break-glass." Concrete APIs are **[P]**.

## 12.1 Admin model

- The `admin` role lives on the native account (`users.role`); with the enterprise IdP enabled, a Keycloak claim may be mapped onto it ([08](08-authentication.md)).
- Admin visibility: account list, **structure by opaque ID** (names are encrypted), storage usage, version/key-generation counts, audit log.
- Admin **cannot** decrypt names or content. No content-read policy and no break-glass exist ([08 §8.5](08-authentication.md)).

## 12.2 Admin API (`/api/v1/admin/**`) **[P]**

### Users & instance
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/users` | List users (account identity + usage) |
| `GET` | `/admin/users/{id}` | Storage usage, counts, device list, key generations |
| `PATCH` | `/admin/users/{id}` | Role/limit adjustments (on the native account; an enterprise IdP may constrain role mapping) |
| `GET` | `/admin/instance` | Status: storage, DB, blob store, relay, key directory health |
| `GET` | `/admin/instance/config` | Effective **non-secret** configuration |

### Structure (no content, no names)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/projects` | All projects: owners, sizes, structure by **opaque ID** — names are ciphertext |
| `GET` | `/admin/files` | File records: ids, content-type, sizes, versions — **no names, no content** |

> There are **no** `/admin/breakglass` endpoints — removed entirely. The capability cannot exist under E2EE.

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

> **Signed audit bundle format [P]:** `NDJSON` of audit rows + a `manifest.json` `{ from, to, count, chainHead, alg:"ed25519", signature }`. The rows form a **rolling hash chain** (each row hashes the previous), and the manifest carries a **detached Ed25519 signature** over the final `chainHead` using a server **audit-signing key**. A verifier replays the chain and checks the signature to prove the export is complete and untampered.

## 12.3 Audit log

Append-only `audit_log` ([03](03-data-model.md)), distinct from app logs. Covers **auth events, device/key lifecycle, shares created/revoked, key rotations, admin actions, and purges** — **never content or keys** (there is no content to log).

Recorded `action` values (non-exhaustive) **[P]**:

| Category | Examples |
|----------|----------|
| Auth | `auth.login`, `auth.2fa_challenge`, `auth.guest_session` |
| Keys/devices | `device.enroll`, `device.revoke`, `key.publish`, `key.rotate`, `recovery.use` |
| Sharing | `share.create`, `share.update`, `share.revoke`, `share.link_access` |
| Admin | `admin.user_update`, `admin.config_view`, `admin.device_revoke` |
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
