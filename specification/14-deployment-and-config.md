# 14 — Deployment & Configuration

> **E2EE.** The server stores ciphertext and holds **no content KEK** — the only server-side secrets are the Keycloak client secret and DB credentials. There is **no server search service**. Deploy stack graduates to the `deploy` repo; this section is the server's deployment contract. Values are **[P]**.

## 14.1 Runtime packaging

- **Primary artifact = the Docker Compose stack** on **Hetzner ARM64** (nginx + Keycloak + Postgres + server). The earlier "single binary vs container" question is **resolved in favor of container/Compose** as the supported primary; a single self-contained binary is **not** a v1 target.
- **Docker image**, multi-arch incl. **linux/arm64** (Hetzner ARM64 VPS).
- Runs in the **Docker Compose** stack behind **nginx**, alongside **Keycloak**.
- Services: `nyxite-server`, `postgres`, `keycloak`, blob store (filesystem volume now; MinIO later), `redis` (later, relay backplane). nginx reverse-proxies; Cloudflare fronts public traffic.

## 14.2 Dependencies

| Dependency | Required | Notes |
|------------|----------|-------|
| PostgreSQL 17 | yes | Structure, ACLs, wrapped keys, encrypted names, audit |
| Blob store volume / endpoint | yes | **Ciphertext** behind `IBlobStore` |
| Keycloak | yes | OIDC issuer + JWKS reachable from the server |
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
| `NYXITE__Auth__Authority` | Keycloak issuer URL |
| `NYXITE__Auth__Audience` | Expected token audience |
| `NYXITE__Auth__ClientId` / `ClientSecret` (secret) | OIDC client |
| `NYXITE__Realtime__Backplane` | `none` \| `redis` |
| `NYXITE__Realtime__Redis` (secret) | Redis connection when enabled |
| `NYXITE__Limits__*` | Upload sizes, rate-limit buckets ([13](13-security.md)) |
| `NYXITE__Relay__PruneAfterSnapshotSeq` | How long to keep encrypted updates past a client snapshot ([05](05-realtime-collaboration.md)) |
| `NYXITE__Retention__*` | History/audit retention ([10](10-version-history.md), [12](12-administration.md)) |

> **Removed vs prior model:** `NYXITE__Kek__*` (no server KEK) and `NYXITE__Search__*` (no server search).
> **No server crypto config:** AEAD/HPKE primitives are fixed in the wire format ([07 §7.3–7.4](07-encryption.md)); **Argon2id recovery params** (m/t/p/salt) are **client-chosen and persisted per blob** in `recovery_blobs.kdf_params` ([03](03-data-model.md)), not server configuration.

## 14.4 Startup & lifecycle

- **Migrations** run as a discrete deploy step (separate DB role), not at app startup in prod. **[P]**
- Boot validation: DB reachable + migrated, Keycloak JWKS reachable, blob store writable. (No KEK probe — there is none.) Fail fast otherwise.
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

- **dev/test:** Testcontainers for Postgres + Keycloak; filesystem blob store; throwaway test client keypairs.
- **prod:** the Compose stack on the ARM64 VPS.
