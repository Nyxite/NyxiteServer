# 14 — Deployment & Configuration

> **E2EE.** The server stores ciphertext and holds **no content KEK** — the server-side secrets are the **native-auth token-signing key**, the account-password **pepper** (`PASSWORD_PEPPER`, held outside the DB — [08 §8.1](08-authentication.md)), and DB credentials (plus the Keycloak client secret **only** under the optional `enterprise` profile). There is **no server search service**. Deploy stack graduates to the `deploy` repo; this section is the server's deployment contract. Values are **[P]**.

## 14.1 Runtime packaging

- **Primary artifact = the Docker Compose stack** on **Hetzner ARM64** (nginx + Postgres + server + blob store). The earlier "single binary vs container" question is **resolved in favor of container/Compose** as the supported primary; a single self-contained binary is **not** a v1 target.
- **Docker image**, multi-arch incl. **linux/arm64** (Hetzner ARM64 VPS).
- Runs in the **Docker Compose** stack behind **nginx**.
- **Default services:** `nyxite-server`, `postgres`, blob store (filesystem volume now; MinIO later), `redis` (later, relay backplane). The **optional `enterprise` Compose profile** adds `keycloak` (the pluggable enterprise IdP — [08](08-authentication.md)). nginx reverse-proxies; Cloudflare fronts public traffic.

## 14.2 Dependencies

| Dependency | Required | Notes |
|------------|----------|-------|
| PostgreSQL 17 | yes | Structure, ACLs, wrapped keys, encrypted names, audit |
| Blob store volume / endpoint | yes | **Ciphertext** behind `IBlobStore` |
| Keycloak | enterprise only | Optional `enterprise` profile: OIDC issuer + JWKS reachable from the server. Native auth needs no external IdP. |
| Redis | optional | Multi-node relay backplane / presence |
| ~~Meilisearch~~ | **n/a** | No server-side search under E2EE |
| ~~KEK provider~~ | **n/a** | No server content KEK — keys live on clients |

## 14.3 Configuration model

- `IOptions` from environment + mounted secret files (12-factor). Precedence: secret file > env > default.
- Secrets never read from the DB or exposed via admin config ([12](12-administration.md), [13](13-security.md)).

### Configuration keys **[P]**

| Key (env) | Purpose |
|-----------|---------|
| `NYXITE__Database__ConnectionString` | PostgreSQL DSN |
| `NYXITE__BlobStore__Provider` | `filesystem` \| `s3` |
| `NYXITE__BlobStore__RootPath` | Filesystem blob root (content-addressed, sharded) |
| `NYXITE__BlobStore__S3__*` | Endpoint/bucket/credentials when `s3` |
| `NYXITE__Auth__TokenSigningKey` (secret) | **Native** token-signing key — signs/validates the server's own access + refresh tokens (always required) |
| `NYXITE__Auth__PasswordPepper` (secret; deploy secret `PASSWORD_PEPPER`) | **Versioned, rotatable** account-password **pepper** — the HMAC-SHA256 key applied as a pre-hash before Argon2id ([08 §8.1](08-authentication.md)). Held **outside Postgres** (alongside DB creds) so a **DB-only leak yields uncrackable verifiers**. Format `{version}:{key}` (or a versioned set); rotation adds a new version and **re-peppers lazily at each user's next login**. Account-auth only — **not** applied to the recovery-phrase KDF |
| `NYXITE__Auth__Audience` | Expected token audience |
| `NYXITE__Auth__Enterprise__Enabled` | `true` to enable the enterprise OIDC IdP (default `false` = native only) |
| `NYXITE__Auth__Enterprise__Authority` | Keycloak issuer URL (**enterprise profile only**) |
| `NYXITE__Auth__Enterprise__ClientId` / `ClientSecret` (secret) | OIDC client (**enterprise profile only**) |
| `NYXITE__Realtime__Backplane` | `none` \| `redis` |
| `NYXITE__Realtime__Redis` (secret) | Redis connection when enabled |
| `NYXITE__Limits__*` | Upload sizes, rate-limit buckets ([13](13-security.md)) |
| `NYXITE__Relay__PruneAfterSnapshotSeq` | How long to keep encrypted updates past a client snapshot ([05](05-realtime-collaboration.md)) |
| `NYXITE__Retention__*` | History/audit retention ([10](10-version-history.md), [12](12-administration.md)) |
| `NYXITE__Retention__TrashWindowDays` | Deletion-lifecycle **Trash** window — instance-wide default **30** ([03 §3.3](03-data-model.md), DL-1); per-user override stored in metadata, same mechanism as the storage quota |
| `NYXITE__Retention__GraceWindowDays` | Deletion-lifecycle **grace** window past Trash — instance-wide default **30** (admin/support-assisted restore only, DL-4); per-user override supported. Purge fires at Trash + grace (~60 days); **no early/permanent-now purge** (DL-5) |
| `NYXITE_LICENSE_TOKEN` | **Optional** per-instance license token — absent = community mode (free non-commercial). Verified **offline** against embedded license public keys; unlocks enterprise gates. Not a secret to protect (per-instance, non-sensitive). ([16](16-licensing-and-entitlement.md)) |
| `NYXITE__Support__Enabled` | **Capability flag** for the in-app bug-reporting relay ([§14.9](#149-support-relay), [04 §4.9](04-rest-api.md)). Default `false`; in v1 set `true` **only on the maintainer's official instance(s)** (SUP-9). When `false` the `/support/**` routes are absent and clients show no reporting surface |
| `NYXITE__Support__ServiceBaseUrl` | Base URL of the central vendor-side `NyxiteSupport` service the relay forwards `POST /reports` to (only used when `Support__Enabled`) |
| `NYXITE__Support__InstanceCredential` (secret) | Instance credential / fingerprint used to **authenticate this relay to `NyxiteSupport`** (analogous to the `NyxiteLicense /register` instance anchor) — proves the forwarded report comes from a recognized, enabled instance |

> **Removed vs prior model:** `NYXITE__Kek__*` (no server KEK) and `NYXITE__Search__*` (no server search).
> **No server crypto config:** AEAD/HPKE primitives are fixed in the wire format ([07 §7.3–7.4](07-encryption.md)); **Argon2id recovery params** (m/t/p/salt) are **client-chosen and persisted per blob** in `recovery_blobs.kdf_params` ([03](03-data-model.md)), not server configuration.

## 14.4 Startup & lifecycle

- **Migrations** run as a discrete deploy step (separate DB role), not at app startup in prod. **[P]**
- Boot validation: DB reachable + migrated, native **token-signing key** present, **password pepper** present (native-auth profile), blob store writable. The **Keycloak JWKS reachable** check applies **only under the `enterprise` profile** (native auth validates its own tokens with the signing key). (No KEK probe — there is none.) Fail fast otherwise.
- Background hosted services: blob GC, share-token/expiry sweeps, audit retention. **No** snapshotting/indexing (client-side).

## 14.5 Health & observability

| Endpoint | Purpose |
|----------|---------|
| `GET /health/live` | Liveness |
| `GET /health/ready` | Readiness (deps healthy) |
| `GET /metrics` | OpenTelemetry/Prometheus **[P]** |

Structured logs to stdout; security events → audit log; **never content** (none readable).

## 14.6 Networking & TLS

- Server listens plain HTTP **inside** the Compose network; **nginx terminates TLS** (Cloudflare Origin CA); Cloudflare fronts public traffic (INFRASTRUCTURE.md, [13](13-security.md)).
- Admin/origin-direct access over **WireGuard**; internal DNS via **bind9** over the VPN.
- Trust forwarded-proto/for headers only from known nginx/Cloudflare hops (correct client IP for rate limiting/audit). **[P]**

## 14.7 Backups & DR

- DB and blob backups hold **only ciphertext + wrapped keys + encrypted names** — useless without a member's private key. **No KEK exists** to back up or lose on the server side.
- The critical secret is each **user's recovery key**, held by users, not the operator. Server DR cannot recover content if users lose their keys — by design ([07 §7.8](07-encryption.md)).
- Restore drill: DB restore → blob restore → server boots → clients reconnect and decrypt with their own keys.

## 14.8 Environments **[P]**

- **dev/test:** Testcontainers for Postgres (and Keycloak only when exercising the `enterprise` profile); filesystem blob store; throwaway test client keypairs.
- **prod:** the Compose stack on the ARM64 VPS.

## 14.9 Support relay

> The in-app bug-reporting helpdesk (feature [`support.md`](https://github.com/Nyxite/Nyxite), OPEN-DECISIONS **SUP-1..SUP-9**). The server participates only as an **authenticating relay — it stores no ticket** (SUP-7). The helpdesk itself is the **central vendor-side `NyxiteSupport`** service (ASP.NET Core + PostgreSQL, its own operator UI); like `NyxiteLicense` it is **maintainer-run vendor infrastructure and is not part of the self-hosted stack** — it has **no Compose entry** and no operator deploys it (SUP-5).

- **`support.enabled` capability flag** (`NYXITE__Support__Enabled`, §14.3). Off by default; in v1 turned on **only on the maintainer's official instance(s)** (SUP-9). When off, the relay endpoints ([04 §4.9](04-rest-api.md)) are absent and clients advertise no reporting surface.
- **Relay target** — `NYXITE__Support__ServiceBaseUrl` points at the central `NyxiteSupport` service; the enabled server forwards authenticated reports there over TLS.
- **Relay credential** — `NYXITE__Support__InstanceCredential` (secret) authenticates this instance to `NyxiteSupport` and lets it attribute/rate-limit and reject junk by instance; the server also tags each forwarded report with the `instance_fingerprint` + an opaque `user_ref` (SUP-6/SUP-7).
- **Non-E2EE plane.** This is the project's one consensual exception to zero-knowledge (SUP-1); it is disjoint from the content plane and carries no content key — the server-side content secrets above (§14 header) are untouched.
