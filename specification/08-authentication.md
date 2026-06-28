# 08 — Authentication, Keys & Authorization

> **E2EE.** Login (**Nyxite-native account auth** by default — password + required TOTP, or passkeys) authenticates the *account*; a separate **device-key / identity-keypair** layer governs *decryption*. The two are deliberately distinct: authenticating does not hand the server any content key. Native auth is the baseline; Keycloak/OIDC is a pluggable **enterprise** IdP. (Canonical model: [SPECIFICATION §10](https://github.com/Nyxite/Nyxite) / [OPEN-DECISIONS #9](https://github.com/Nyxite/Nyxite).) Concrete flows are **[P]**.

## 8.1 Identity model (native by default; pluggable IdP seam)

- **Nyxite-native, server-owned authentication is the default for all tiers.** The server keeps a real account store, not a thin IdP projection: per user a **password verifier** (Argon2id), an enrolled **TOTP secret**, and zero or more **WebAuthn/passkey credentials** ([02](02-domain-model.md), [03](03-data-model.md)).
- **Two co-equal primary methods** from day one:
  - **(a) Password + required TOTP** — the password is verified against an **Argon2id** hash (pinned params m=64 MiB, t=3, p=1 — [07](07-encryption.md)); a TOTP second factor is **mandatory**, not optional. The server sees the password only **transiently** over TLS at login and stores only the verifier, never the password.
  - **(b) Passkeys (WebAuthn)** — phishing-resistant public-key credentials, **sufficient on their own** (no separate TOTP needed). The server stores only the credential's **public** key + signature counter.
- **Load-bearing rule: the login password (or passkey) NEVER feeds any content-key derivation.** Account auth and content access are independent secrets — content keys come only from the identity / device / recovery-phrase path ([07 §7.8](07-encryption.md)). So an account/password compromise yields **no content**.
- **Property restatement:** "no passwords on the server" → **"no content-derivable secrets on the server."** Argon2id password verifiers and passkey public credentials unlock an **API token, never a key**.
- **Pluggable IdP seam — IdP-agnostic API.** Identity providers plug in behind **one internal token**; the rest of the API never sees which IdP authenticated the user. Native auth is one provider; **(enterprise) Keycloak-OIDC** is another. Both resolve to the **same server-issued token** ([§8.2](#82-token-model-p)).
- **Keycloak / OAuth-OIDC SSO is an enterprise-tier option** (optional `enterprise` deploy profile — [14](14-deployment-and-config.md)), **not the default and not load-bearing**. When enabled, the server validates the OIDC token, links/provisions a native `users` row via `external_idp`/`external_idp_sub`, and **mints its own internal token** so downstream code is unchanged.
- **Account recovery ≠ content recovery.** Forgot-password / email reset restores **login only**; content still requires the **recovery phrase** or an **enrolled device** ([07 §7.8](07-encryption.md)). Email/account compromise yields no content.

### Native auth endpoints **[P]**

All under `/api/v1/auth` (unauthenticated except where noted); they issue/refresh the server's own tokens ([04](04-rest-api.md)). When the `enterprise` profile is on, an additional `GET /auth/oidc/*` (authorize/callback) flow resolves to the same token.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/register` | Create a native account: `{ email, displayName, password }` → user row with an Argon2id verifier; TOTP enrollment is then required before first full login |
| `POST` | `/auth/login` | Password login: `{ email, password }` → `{ challenge: "totp_required", mfaToken }` (password-only never yields a full token; TOTP is mandatory) |
| `POST` | `/auth/login/totp` | Complete login: `{ mfaToken, totpCode }` → `{ accessToken, refreshToken }` |
| `POST` | `/auth/totp/enroll` | (auth'd) Begin TOTP enrollment → `{ secret, otpauthUri }`; secret stored only after verify |
| `POST` | `/auth/totp/verify` | (auth'd) Confirm enrollment `{ totpCode }` → activates the second factor |
| `POST` | `/auth/webauthn/register/options` | (auth'd) Begin passkey registration → WebAuthn creation options (challenge) |
| `POST` | `/auth/webauthn/register` | (auth'd) Finish registration: attestation response → stores a `webauthn_credentials` row |
| `POST` | `/auth/webauthn/assert/options` | Begin passkey login `{ email? }` → WebAuthn request options (challenge) |
| `POST` | `/auth/webauthn/assert` | Finish passkey login: assertion response → `{ accessToken, refreshToken }` (sufficient alone) |
| `POST` | `/auth/refresh` | Exchange a valid refresh token → a new `{ accessToken, refreshToken }` |
| `POST` | `/auth/logout` | Revoke the presented refresh token (and current session) |
| `POST` | `/auth/password/forgot` | Start email-based reset → emailed token (**restores login only**, never content) |
| `POST` | `/auth/password/reset` | Complete reset `{ resetToken, newPassword }` → new Argon2id verifier |

- **Account auth ≠ content access.** A successful login (any method) yields an access token for the API but **no content key**. Content keys come from the user's **identity private key**, held on devices ([§8.3](#83-device--identity-keys-the-e2ee-layer)).

## 8.2 Token model **[P]**

- **The Nyxite server issues its own access + refresh tokens.** Native auth and (enterprise) Keycloak-OIDC are **pluggable identity providers** that both resolve to **one internal token**; the rest of the API is IdP-agnostic and never sees which IdP was used.
- Tokens are signed with the server's own **token-signing key** ([14](14-deployment-and-config.md)); the server validates its own tokens against that key (no external JWKS dependency in the default profile). The token carries the internal subject (`users.id`), name/email, and role (`user`/`admin`).
- **Enterprise profile:** the OIDC login path uses Authorization Code + PKCE against Keycloak; the server validates that token against Keycloak **JWKS** (`iss`, `aud`, `exp`, signature), maps the external `sub` to a native `users` row, and then **issues its own internal token** — downstream is identical to native login.
- **Token lifetimes [P]:** access token **~5 min**; refresh token rotated on use; relay **socket ticket** single-use, **60s** TTL; guest **share-session token 15 min**, renewable while the share is valid (revocation effective within one renewal cycle).
- **2FA step-up** — sensitive **account/admin** actions require a recent second factor; if the step-up is missing the server returns **`403 2fa_required`**. (There is no content break-glass to gate — content is unreadable to the server regardless.)

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

The `admin` role lives on the native account (`users.role`); when the enterprise IdP is enabled, a Keycloak claim may be mapped onto it. An admin manages instance/users and sees **structure/usage/audit**. Admins **cannot read content** — no key exists for them, and there is **no break-glass** ([12](12-administration.md)). This is stronger than the master spec's "audited break-glass": the capability simply does not exist.

## 8.7 Sessions & logout

- Stateless bearer auth on the server's own access token; logout/refresh are handled by the native `/auth/refresh` and `/auth/logout` endpoints ([§8.1](#81-identity-model-native-by-default-pluggable-idp-seam)) — refresh tokens rotate on use and can be revoked. Device keys persist locally until the device is revoked.
- Guest relay sessions use a **15-minute** share-session token, renewable while the share is valid; revoking the share cuts off new sessions instantly and live ones within one renewal cycle ([09 §9.6](09-sharing-and-acl.md)).

## 8.8 Auditing

Auth events, device enrollment/revocation, key publication/rotation, recovery use, share issuance — all audited ([12](12-administration.md)); keys and content never logged.

## 8.9 Rate limiting

Auth-adjacent endpoints, key-directory lookups, device enrollment, and share/link access are rate-limited ([13](13-security.md)).
