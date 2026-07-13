# 13 — Security

> **Privacy-first / E2EE.** The strongest control is structural: the server holds **no content keys**, so compromise of the server, database, blob store, or operator yields **no readable content**. Account auth is **native** (peppered-Argon2id password verifiers + required TOTP, or passkeys) and holds **no content-derivable secrets**. Every **asymmetric** E2EE seam is **hybrid classical + post-quantum** (X25519 + ML-KEM-768 wraps, Ed25519 + ML-DSA-65 signatures, NIST level 3) from v1.0.0, closing **harvest-now-decrypt-later** on the indefinitely-stored ciphertext ([07 §7.3](07-encryption.md)). Concrete controls below are **[P]**.

## 13.1 What the server can and cannot see

| Server **can** see | Server **cannot** see |
|--------------------|------------------------|
| Object IDs + structure graph (folder/project containment) | File/folder/project **names** (encrypted) |
| `content_type`, ciphertext sizes, timestamps | Any **content** (markdown, text, ink, attachments) |
| ACL grants, wrapped-key blobs (opaque) | Any **content key** (only wrapped copies it can't open) |
| CRDT update sizes/ordering (opaque) | CRDT update **contents** |
| Public keys; account identity (name/email); peppered-Argon2id password verifiers, passkey public credentials | Private keys, recovery keys, fragment keys; the login password (seen only transiently at login); the **password pepper** (held outside the DB) |

This table is the heart of the security model — design changes must preserve the right-hand column.

## 13.2 Security model summary

| Control | Mechanism | Section |
|---------|-----------|---------|
| Content confidentiality | **E2EE**; per-file client-held keys; server zero-knowledge | [07](07-encryption.md) |
| Transport security | TLS everywhere (Cloudflare → nginx → Kestrel) | [14](14-deployment-and-config.md) |
| Account auth | **Native**: password (Argon2id over a peppered HMAC pre-hash) + required TOTP, or passkeys (WebAuthn); enterprise Keycloak/OIDC optional | [08](08-authentication.md) |
| Decryption auth | Device/identity keys + wrapped/fragment file keys | [07](07-encryption.md), [09](09-sharing-and-acl.md) |
| Access control | Server ACL (reach) + crypto (decrypt) | [09](09-sharing-and-acl.md) |
| Admin firewall | Structure/usage/audit only; **no break-glass** | [12](12-administration.md) |
| Auditability | Append-only audit log (no content) | [12](12-administration.md) |
| Abuse resistance | Rate limiting; hashed link tokens; high-entropy fragment keys | §13.4, [09](09-sharing-and-acl.md) |

## 13.3 Transport & TLS

- **TLS everywhere.** Public users via **Cloudflare** (Universal SSL); origin presents **Cloudflare Origin CA** certs over **WireGuard** (INFRASTRUCTURE.md). `nyxite.app` is **HSTS-preloaded**; the Origin CA root must be installed on admin devices hitting the origin directly.
- Admin/origin-direct access is gated behind WireGuard; internal DNS via bind9 over the VPN.
- (TLS protects traffic; E2EE protects content even if TLS or the server is breached.)

## 13.4 Tokens, keys & secrets

- **Short-lived tokens** for relay upgrades and any presigned ciphertext URLs. Concrete lifetimes **[P]**: access token **~5 min**; relay **socket ticket** single-use, **60s** TTL; guest **share-session token 15 min**, renewable while the share is valid ([08 §8.2](08-authentication.md)).
- Server-held secrets are the **native-auth token-signing key**, the **account-password pepper** (`PASSWORD_PEPPER`), and **DB credentials** — and, **only when the enterprise profile is enabled**, the **Keycloak client secret**. There is **no content KEK** to guard. Injected via env/mounted secrets with tight permissions, never in DB or admin config ([14](14-deployment-and-config.md)). Holding the **pepper outside Postgres** is deliberate: a **DB-only leak** (dump/backup theft without the app-secret store) yields **verifiers an attacker cannot brute-force**, since the HMAC pre-hash key is missing.
- Link tokens ≥128-bit, stored hashed; **fragment keys** ≥256-bit, never sent to the server ([09](09-sharing-and-acl.md)).
- **User recovery keys** are the critical user-held secret; losing one (with all devices) is unrecoverable by design ([07 §7.8](07-encryption.md)).

## 13.5 Rate limiting

Limits on **authentication, key-directory lookups, device enrollment, share creation, and link access** (master spec §15 + E2EE additions). Concrete buckets **[P]**:

Concrete starting values (tunable):

| Surface | Limit (tunable) |
|---------|------------------|
| Auth / login | **10/min/IP** |
| `GET /keys/directory` | **60/min/user** (limits social-graph probing) |
| `POST /devices` enrollment | strict per-user |
| `POST /shares` | **30/min/user** |
| `/share/{token}*` guest access | **30/min/IP** |
| Blob upload | **60/min/user** |
| General API | **600/min/user** |

`429 rate_limited` + `Retry-After`.

## 13.6 Input & content safety

- Structure/ACL DTOs validated at the edge; domain invariants enforced. **Content is opaque** — the server cannot and does not inspect plaintext ([04](04-rest-api.md)).
- Ciphertext upload size/type limits; `excluded` uploads rejected.
- CRDT updates are relayed without server validation of contents; a malformed update simply fails to apply on clients (low risk in a trusted single-tenant system).
- Served ciphertext carries safe content-type/disposition headers; the guest client is the only unauthenticated surface and is token-scoped, with the key supplied by the URL fragment ([04 §4.8](04-rest-api.md)).

## 13.6a Existence-hiding responses (no resource enumeration)

Authorization failures on a resource must not reveal that the resource exists. **Prefer `404` over `403` for anything addressed by an id or token.**

- **`404 not_found`** — an authenticated caller with **no reach** to a resource (files, projects, folders, users, **admin resources**, share URLs) gets the **same response as for a non-existent id**: identical `code`/body and, as far as practical, indistinguishable timing. An attacker cannot tell "exists but I'm not authorized" from "nothing there"; only the **correct token + real access** returns `200`.
- **`403 acl_denied` is still allowed**, but **only** where existence is not a secret to the caller — they **already have read reach** and merely lack the specific action (e.g. a read-only collaborator writing; a `blocked` account writing its own file), or a **capability/collection** denial that exposes no id (e.g. a non-admin calling `GET /admin/users`).
- **`401`** (no valid auth) is uniform across all ids and leaks nothing.
- Share tokens: a never-issued/unauthorized token → `404`; a genuinely-issued but dead token → `410` `share_revoked`/`link_expired` (presenting it already proves the holder knew it existed).
- Applies uniformly to the `/admin/**` surface ([12](12-administration.md)) and all content/ACL endpoints ([04 §4.4](04-rest-api.md), [09 §9.5](09-sharing-and-acl.md)). Avoid timing/error-shape side channels that re-introduce the distinction.

## 13.6b Group zero-knowledge invariant (enterprise/family groups)

The group-key layer ([07 §7.2a](07-encryption.md), [09 §9.9](09-sharing-and-acl.md)) is designed to **preserve** the right-hand column of §13.1 — it must never weaken it.

- **Server holds only opaque group material.** For file-sharing groups the server stores **only**: opaque per-member grants (`group_key_grants`), DEK-to-group wraps (`file_keys` group-principal rows), membership rows, **opaque** reader-group attachments, and group **public keys**. It **never** holds a group private key, a content key, or a plaintext group name — and there is **no break-glass** ([12 §12.7](12-administration.md)). This holds even though a group key wraps *many* DEKs; every wrap already ships the **hybrid post-quantum suite** and the `alg_id` keeps it re-wrappable for any future primitive change without ever exposing a private key ([07 §7.3](07-encryption.md)).
- **Metadata-only enforcement.** The member-count limit (G-5) and enrollment gate are enforced by **membership-row count** and a **key-transparency inclusion proof** on the member's *public* key — reading no content and no key ([09 §9.9](09-sharing-and-acl.md), [12 §12.7](12-administration.md)).
- **Existence-hiding on group-by-id.** Any group addressed by id (`/groups/{id}`, `/groups/{id}/members`, `/groups/{id}/keys`, `/admin/groups/{id}`) returns **`404`** to a caller with no reach — indistinguishable from a non-existent id (§13.6a); a fetch-ACL failure on a group-key blob within the target-aware RBAC `scope` is treated the same. `403` only where the caller demonstrably already has reach.

## 13.7 Revocation

Two-layered: **instant server-ACL cutoff** + **client-driven key rotation** for forward secrecy ([09 §9.6](09-sharing-and-acl.md)). Content a removed member already downloaded can't be recalled — inherent to any system.

## 13.8 Threat notes & boundaries

| Threat | Mitigated by | Residual / boundary |
|--------|--------------|---------------------|
| DB/blob theft | **E2EE** — no content key on the server | None for content; structure/sizes/timestamps still leak metadata |
| Compromised/malicious server or operator | **E2EE** — server never holds keys | Metadata visible; server could withhold/relay-tamper (detectable via client signatures **[P]**) |
| Curious/rogue admin | No content path, no break-glass | Can see structure/usage/audit only |
| Stolen link | Hashed token + expiry + revocation + rate limits | A live link's fragment key decrypts until expiry/rotation |
| Confirmation-of-file | No convergent encryption | Narrower dedup accepted |
| Lost keys | Recovery key | Lose all devices **and** recovery key → permanent loss (by design) |
| Malicious client (bad updates) | Trusted single-tenant; client-side merge tolerates/ignores | No server-side validation possible |
| Key-directory MITM (wrong pubkey on share) | TLS + directory hybrid self-signature; **key-transparency log at Phase 4.3** (v1.0.0, G-3) | Single shares trust the directory (TLS + self-sig); the transparency **log** ships in v1.0.0 at 4.3 (required for groups), while client-facing safety-number **verification** stays optional Phase 6 [15](15-roadmap-and-versioning.md) |
| Substituted key at **group** enrollment (whole-corpus exposure) | **Key transparency inclusion proof required before wrapping** the group key (Phase 4.3, G-3) | Higher-value target than a single share, so groups **depend on** transparency, not directory trust alone [09 §9.9](09-sharing-and-acl.md) |
| Broken group key (one key wraps many DEKs) | Scoped keys bound the blast radius (G-4); `alg_id` keeps every wrap re-wrappable | Bounded to the affected scope; wraps ship hybrid PQC at v1 [15 §15.3](15-roadmap-and-versioning.md) |
| **Harvest-now, decrypt-later** (future quantum adversary records ciphertext + wrapped keys today) | **Hybrid X25519 + ML-KEM-768** wraps and **Ed25519 + ML-DSA-65** signatures at v1.0.0 — both classical and PQC halves must break ([07 §7.3](07-encryption.md)) | AES-256/BLAKE3/Argon2id only Grover-halved (safe at current sizes); residual is a break of **both** hybrid halves |
| **DB-only leak of password verifiers** (dump/backup without the app-secret store) | Verifiers are **Argon2id over HMAC-SHA256(password, pepper)** with the **pepper held outside Postgres** ([08 §8.1](08-authentication.md)) | Falls back to plain Argon2id strength only if the pepper store is *also* breached |

## 13.9 Hardening checklist (build-time) **[P]**

- HSTS, secure headers, strict CORS (known client origins only).
- Least-privilege DB roles (app role: no audit UPDATE/DELETE; migrations under a separate role).
- Signed CRDT updates / key-directory entries (**hybrid Ed25519 + ML-DSA-65**) to detect relay tampering and key swaps. **[P]**
- Secrets never logged; structured logs scrubbed.
- Dependency/container scanning in CI; pinned base images.
- Token-signing-key rotation runbook (and the enterprise Keycloak-secret rotation runbook when that profile is on) — no content KEK to rotate.
