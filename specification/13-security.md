# 13 — Security

> **Privacy-first / E2EE.** The strongest control is structural: the server holds **no content keys**, so compromise of the server, database, blob store, or operator yields **no readable content**. Account auth is **native** (Argon2id password verifiers + required TOTP, or passkeys) and holds **no content-derivable secrets**. Concrete controls below are **[P]**.

## 13.1 What the server can and cannot see

| Server **can** see | Server **cannot** see |
|--------------------|------------------------|
| Object IDs + structure graph (folder/project containment) | File/folder/project **names** (encrypted) |
| `content_type`, ciphertext sizes, timestamps | Any **content** (markdown, text, ink, attachments) |
| ACL grants, wrapped-key blobs (opaque) | Any **content key** (only wrapped copies it can't open) |
| CRDT update sizes/ordering (opaque) | CRDT update **contents** |
| Public keys; account identity (name/email); Argon2id password verifiers, passkey public credentials | Private keys, recovery keys, fragment keys; the login password (seen only transiently at login) |

This table is the heart of the security model — design changes must preserve the right-hand column.

## 13.2 Security model summary

| Control | Mechanism | Section |
|---------|-----------|---------|
| Content confidentiality | **E2EE**; per-file client-held keys; server zero-knowledge | [07](07-encryption.md) |
| Transport security | TLS everywhere (Cloudflare → nginx → Kestrel) | [14](14-deployment-and-config.md) |
| Account auth | **Native**: password (Argon2id) + required TOTP, or passkeys (WebAuthn); enterprise Keycloak/OIDC optional | [08](08-authentication.md) |
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
- Server-held secrets are the **native-auth token-signing key + DB credentials** — and, **only when the enterprise profile is enabled**, the **Keycloak client secret**. There is **no content KEK** to guard. Injected via env/mounted secrets with tight permissions, never in DB or admin config ([14](14-deployment-and-config.md)).
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
| Key-directory MITM (wrong pubkey on share) | TLS + (future) key transparency / verification | v1.0.0 trusts the directory; verification is a hardening item [15](15-roadmap-and-versioning.md) |

## 13.9 Hardening checklist (build-time) **[P]**

- HSTS, secure headers, strict CORS (known client origins only).
- Least-privilege DB roles (app role: no audit UPDATE/DELETE; migrations under a separate role).
- Signed CRDT updates / key-directory entries (Ed25519) to detect relay tampering and key swaps. **[P]**
- Secrets never logged; structured logs scrubbed.
- Dependency/container scanning in CI; pinned base images.
- Token-signing-key rotation runbook (and the enterprise Keycloak-secret rotation runbook when that profile is on) — no content KEK to rotate.
