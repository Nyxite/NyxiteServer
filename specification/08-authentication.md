# 08 — Authentication, Keys & Authorization

> **E2EE.** Login (Keycloak OIDC + TOTP) authenticates the *account*; a separate **device-key / identity-keypair** layer governs *decryption*. The two are deliberately distinct: authenticating does not hand the server any content key. Concrete flows are **[P]**.

## 8.1 Identity provider

- **Keycloak** is the sole IdP (OIDC): credentials, registration, password reset, and **TOTP 2FA**. The server is an OIDC resource server validating tokens; it stores no passwords, only a thin `users` projection keyed by `sub` ([02](02-domain-model.md)).
- **Account auth ≠ content access.** Unlike a passphrase-unlock design, Keycloak login yields an access token for the API but **no content key**. Content keys come from the user's **identity private key**, held on devices.

## 8.2 Token model **[P]**

- Authorization Code + PKCE per surface; access + refresh tokens from Keycloak.
- The server validates access tokens against Keycloak **JWKS** (`iss`, `aud`, `exp`, signature); consumes `sub`, name/email, and roles (`user`/`admin`).
- **Token lifetimes [P]:** OIDC access token **~5 min** (Keycloak-configured); relay **socket ticket** single-use, **60s** TTL; guest **share-session token 15 min**, renewable while the share is valid (revocation effective within one renewal cycle).
- **2FA signal** (`amr`/`acr`) may be required for sensitive **account/admin** actions → else `403 2fa_required`. (There is no content break-glass to gate — content is unreadable to the server regardless.)

## 8.3 Device & identity keys (the E2EE layer)

- On first sign-in a client **enrolls a device** and ensures the user has an **identity keypair** (X25519 + Ed25519). The **public** keys go to the server directory (`user_keys`); private keys stay on the device ([03](03-data-model.md), [07](07-encryption.md)).
- **Enrolling a device:** `POST /devices { label, pubkey }` → `{ deviceId, status:"pending", pairingCode, qrPayload }`. An enrolled device approves it via `POST /devices/{id}/approve { wrappedIdentityKey }` — the identity bundle **HPKE-sealed** to the pending device's `pubkey`, stored in `pending_key_blob`. The new device then calls `GET /devices/me/enrollment` to fetch `{ wrappedIdentityKey }` **once** (single-use; the server clears the blob and marks the device `active`). Alternatively the device recovers the identity private key via **recovery-phrase** unwrap ([07 §7.8](07-encryption.md)).
- **Recovery key** (user-held, shown once) derives an Argon2id key that unwraps the **AES-256-GCM** recovery blob (`recovery_blobs`); it is the **only** way back in if all devices are lost ([07 §7.8](07-encryption.md)). No server/admin escrow.

## 8.4 WebSocket / relay upgrade auth

- The relay socket ([05](05-realtime-collaboration.md)) authenticates the upgrade with a **short-lived token** — a user bearer, a **single-use socket ticket (60s TTL)** minted from it, or a guest **share-session token (15 min)** ([§8.2](#82-token-model-p)).
- The share token authorizes **relay access** only; the **decryption key** comes from the link's URL fragment ([09 §9.4](09-sharing-and-acl.md)), never the server.

## 8.5 Authorization model

Two independent gates:

1. **Server ACL** — can the principal reach the ciphertext / join the relay? (owner / grantee / link / admin-structure-only).
2. **Crypto** — can they *decrypt*? Requires the right wrapped or fragment file key. The server cannot influence this.

Resource-action policies **[P]**:

| Policy | Grants (server ACL) |
|--------|---------------------|
| `resource:read-ciphertext` | Owner, grantee (read/write), guest via link, **admin: no** |
| `resource:write` | Owner, grantee `write`, guest via write link |
| `resource:share` | Owner |
| `admin:*` | Admin role (structure/usage/audit only) |

> Note there is **no `resource:read-content`** — reading content is a purely client-side capability gated by key possession, not a server permission.

## 8.6 Admin distinction

`admin` (Keycloak role → `users.role`) manages instance/users and sees **structure/usage/audit**. Admins **cannot read content** — no key exists for them, and there is **no break-glass** ([12](12-administration.md)). This is stronger than the master spec's "audited break-glass": the capability simply does not exist.

## 8.7 Sessions & logout

- Stateless bearer auth; logout/refresh are Keycloak concerns. Device keys persist locally until the device is revoked.
- Guest relay sessions use a **15-minute** share-session token, renewable while the share is valid; revoking the share cuts off new sessions instantly and live ones within one renewal cycle ([09 §9.6](09-sharing-and-acl.md)).

## 8.8 Auditing

Auth events, device enrollment/revocation, key publication/rotation, recovery use, share issuance — all audited ([12](12-administration.md)); keys and content never logged.

## 8.9 Rate limiting

Auth-adjacent endpoints, key-directory lookups, device enrollment, and share/link access are rate-limited ([13](13-security.md)).
