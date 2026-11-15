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
| `NYXITE__Database__ConnectionString` | PostgreSQL DSN of the server's login role, a member of `nyxite_app` ([03 §3.5](03-data-model.md)) |
| `NYXITE__Database__MigrationConnectionString` | PostgreSQL DSN of the migration role (table owner, `CREATEROLE`), read only by `nyxite-server migrate` |
| `NYXITE__BlobStore__Provider` | `filesystem` \| `s3`. Only `filesystem` is implemented; anything else stops the start |
| `NYXITE__BlobStore__RootPath` | Filesystem blob root (content-addressed, sharded). **Required**: the server refuses to start when it is unset or not writable |
| `NYXITE__Limits__MaxInlineBlobBytes` / `__MaxCrdtUpdateBytes` / `__MaxAwarenessBytes` | Largest ciphertext of one blob or snapshot upload, of one CRDT update, and of one relayed awareness message ([04 §4.3](04-rest-api.md), [05](05-realtime-collaboration.md)). Defaults **100 MiB** / **1 MiB** / **64 KiB** **[P]** |
| `NYXITE__Relay__SafetyTailDays` / `__SafetyTailUpdates` | Updates younger than this many days, and this many newest updates of a document, are never pruned, also when a snapshot covers them ([05 §5.6](05-realtime-collaboration.md)). Defaults **7** / **1000** **[P]** |
| `NYXITE__Relay__AccessRecheckInterval` | How often the relay checks again that every connection in a room still has reach and a live session ([05 §5.4](05-realtime-collaboration.md), [09 §9.6](09-sharing-and-acl.md)). It bounds how long a revoked reader keeps receiving, while join and submit are checked on every call. It must be positive, and the server refuses to start otherwise, because zero runs passes without pause and a negative value fails on every turn. Default **00:00:30** **[P]** |
| `NYXITE__Limits__NameEncMaxBytes` / `__MetadataEncMaxBytes` | Largest accepted `nameEnc` / `metadataEnc`, frame overhead included ([04 §4.3](04-rest-api.md)). Defaults **2048** / **65536** **[P]**. A 255 character name is about 1 KiB sealed |
| `NYXITE__BlobStore__S3__*` | Endpoint/bucket/credentials when `s3` |
| `NYXITE__Auth__TokenSigningKey` (secret) | **Native** token-signing key — signs/validates the server's own access + refresh tokens (always required). Format `{version}:{base64 key}` entries separated by `;`, at least 32 bytes each. The highest version signs and becomes the `kid`, older versions only validate, so a rollover keeps live tokens valid |
| `NYXITE__Auth__PasswordPepper` (secret; deploy secret `PASSWORD_PEPPER`) | **Versioned, rotatable** account-password **pepper** — the HMAC-SHA256 key applied as a pre-hash before Argon2id ([08 §8.1](08-authentication.md)). Held **outside Postgres** (alongside DB creds) so a **DB-only leak yields uncrackable verifiers**. Format `{version}:{key}` (or a versioned set); rotation adds a new version and **re-peppers lazily at each user's next login**. Account-auth only — **not** applied to the recovery-phrase KDF |
| `NYXITE__Auth__Audience` | Expected token audience |
| `NYXITE__Auth__Issuer` | `iss` of issued access tokens, the instance base URL ([08 §8.2](08-authentication.md)) |
| `NYXITE__Auth__AccessTokenLifetime` | Access-token lifetime. Default **5 min** **[P]** |
| `NYXITE__Auth__WebAuthn__RelyingPartyId` / `__RelyingPartyName` / `__Origins__<n>` | Passkey relying party: the RP ID (instance host), the name shown by authenticators (default `Nyxite`) and the allowed origins (web origin, `android:apk-key-hash:…`). Passkey endpoints answer `503` while the RP ID or the origins are unset, because a guessed RP ID would bind every credential to the wrong domain |
| `NYXITE__Auth__WebAuthnChallengeLifetime` / `__TotpEnrollLifetime` | Lifetimes of a passkey challenge and of a pending TOTP enrollment ([03 §3.2](03-data-model.md)). Defaults **5 min** / **10 min** **[P]** |
| `NYXITE__Auth__TotpIssuer` | Issuer shown in authenticator apps. Default `Nyxite` |
| `NYXITE__Auth__EmailCodeLifetime` | Lifetime of an emailed one-time code (email verification, email second factor, email step-up) ([08 §8.1](08-authentication.md)). Default **15 min** **[P]** |
| `NYXITE__Auth__UnverifiedAccountLifetime` / `__UnverifiedAccountSweepInterval` | How long an account may stay unverified before it is purged and its address is free again, and how often the background job looks. Defaults **24 h** / **1 h** **[P]** |
| `NYXITE__Auth__StepUpLifetime` | Lifetime of a single-use step-up token ([08 §8.2](08-authentication.md)). Default **5 min** **[P]** |
| `NYXITE__Auth__BackupCodeCount` | Backup codes per generated set. Default **10** **[P]** |
| `NYXITE__Auth__SecondFactorFailureLimit` / `__SecondFactorFailureWindow` | Wrong second-factor codes allowed per account within the window before `429 rate_limited` ([08 §8.1](08-authentication.md)). Defaults **10** / **15 min** **[P]** |
| `NYXITE__Auth__MaxConcurrentPasswordHashes` / `__PasswordHashQueueTimeout` | How many Argon2id derivations run at once, and how long a sign-in waits for a free slot before `429 rate_limited` ([13 §13.5](13-security.md)). Each derivation holds 64 MiB, so the cap bounds the memory sign-ins can take. Defaults **0** (one per CPU core) / **5 s** **[P]** |
| `NYXITE__Auth__PasswordResetEmailLimit` / `__PasswordResetEmailWindow` | Password-reset emails per account within the window, further requests are dropped silently ([13 §13.5](13-security.md)). Defaults **3** / **1 h** **[P]** |
| `NYXITE__RateLimiting__Auth__PermitLimit` / `__Window` | Fixed window of the per-IP auth bucket ([08 §8.9](08-authentication.md), [13 §13.5](13-security.md)). Defaults **10** / **1 min** **[P]** |
| `NYXITE__Email__Host` / `__Port` / `__EnableSsl` / `__Username` / `__Password` (secret) / `__From` | SMTP relay for account email (verification and one-time codes, never content). Submission with STARTTLS, default port **587**. `Host` and `From` are **required**: the server refuses to start without them, because no account can be verified, and so none can become usable, without mail |
| `NYXITE__Email__SendTimeout` / `__OutboxPollInterval` / `__OutboxMaxAttempts` | Outbox worker ([03 §3.2](03-data-model.md) `email_outbox`): time limit of one delivery attempt, how often the worker polls when nothing woke it, and attempts per mail before it is given up on. Defaults **30 s** / **5 s** / **5** **[P]** |
| `NYXITE__Retention__CleanupInterval` | How often the maintenance job deletes expired `ephemeral_tokens`, `idempotency_keys` and long-dead `sessions` ([03 §3.2](03-data-model.md)). Default **1 h** **[P]** |
| `NYXITE__Network__CorsOrigins__<n>` | Browser origins allowed to call the API ([13 §13.9](13-security.md)). Unset = same-origin only, which fits the default deployment where nginx serves the web client and the API under one host |
| `NYXITE__Metrics__Port` | Port of the separate `/metrics` listener ([§14.5](#145-health--observability)). Unset = metrics are off |
| `NYXITE__Network__KnownProxies__<n>` / `__KnownNetworks__<n>` | IP addresses / CIDR ranges of the nginx and Cloudflare hops whose `X-Forwarded-For` / `-Proto` are trusted ([§14.6](#146-networking--tls)). Unset = the headers are ignored and the socket peer is the client IP, and the server logs a warning at startup, because behind a proxy all clients then share one rate-limit bucket |
| `NYXITE__Auth__Lifetimes__PasswordReset` / `__Invite` / `__OidcState` / `__OidcHandoff` / `__SocketTicket` | Lifetimes of the single-use `ephemeral_tokens` kinds ([03 §3.2](03-data-model.md)). Defaults **30 min** / **7 days** / **10 min** / **60 s** / **60 s** **[P]** |
| `NYXITE__Auth__Enterprise__RedirectUris` | Allowlist of client redirect URIs for the OIDC flow, e.g. `nyxite://oidc`, the web origin ([08 §8.1](08-authentication.md)); anything else → `400` (**enterprise profile only**) |
| `NYXITE__Scim__Token` (secret) | Bearer token the enterprise IdP uses for `/scim/v2/**` ([12 §12.2](12-administration.md)); SCIM is disabled when unset (**enterprise profile only**) |
| `NYXITE__Auth__RefreshTokenIdleLifetime` | Idle lifetime of a refresh token — a session unused for longer must sign in again ([03 §3.2](03-data-model.md) `refresh_tokens`). Default **14 days** **[P]** |
| `NYXITE__Auth__SessionAbsoluteLifetime` | Absolute lifetime of a session regardless of use; refresh never extends it ([03 §3.2](03-data-model.md) `sessions`). Default **90 days** **[P]** |
| `NYXITE__Auth__MfaTokenLifetime` | Lifetime of the interim `mfaToken` between the password and TOTP step ([03 §3.2](03-data-model.md) `ephemeral_tokens`). Default **5 min** **[P]** |
| `NYXITE__Auth__MfaMaxAttempts` | Wrong TOTP codes allowed per `mfaToken` before it is void and the password step must be repeated. Default **5** **[P]** |
| `NYXITE__Auth__PairingCodeLifetime` | Lifetime of a pending device's `pairingCode` ([03 §3.2](03-data-model.md) `devices`). Default **10 min** **[P]** |
| `NYXITE__Auth__PairingCodeDigits` | Length of a pending device's `pairingCode`, 6 to 8. Default **8** **[P]**, the longest value the spec allows, because the code is typed only in the QR fallback and every digit multiplies the guessing work under the attempt cap |
| `NYXITE__RateLimiting__DeviceEnrollment__PermitLimit` / `__Window` | Per-user bucket of `POST /devices` ([13 §13.5](13-security.md)). Default **5 per hour** **[P]**, because a person enrolls a device rarely and every pending device holds a guessable pairing code |
| `NYXITE__RateLimiting__Directory__PermitLimit` / `__Window` | Per-user bucket of `GET /keys/directory`. Default **60 per minute** **[P]** ([13 §13.5](13-security.md)) |
| `NYXITE__Auth__PairingCodeMaxAttempts` | Wrong pairing-code entries allowed before the code is void; the low-entropy code is protected by this cap and its lifetime. Default **5** **[P]** |
| `NYXITE__Auth__Enterprise__Enabled` | `true` to enable the enterprise OIDC IdP (default `false` = native only) |
| `NYXITE__Auth__Enterprise__Authority` | Keycloak issuer URL (**enterprise profile only**) |
| `NYXITE__Auth__Enterprise__ClientId` / `ClientSecret` (secret) | OIDC client (**enterprise profile only**) |
| `NYXITE__KeyTransparency__SigningKey` (secret) | Hybrid Ed25519 + ML-DSA-65 **log signing key** of the key-transparency log ([17 §17.5](17-key-transparency.md)); held outside Postgres, used for nothing else. Required from Phase 4.3 |
| `NYXITE__KeyTransparency__Origin` | Log origin line, default `<public host>/nyxite-kt/v1` ([17 §17.5](17-key-transparency.md)) |
| `NYXITE__Limits__PendingChunkTtlHours` | Age after which an uploaded chunk that no committed version references is garbage-collected ([03](03-data-model.md) `file_chunks`). Default **24** **[P]** |
| `NYXITE__Limits__MaxChunksPerFile` | Upper bound of chunks per chunked version ([04 §4.3](04-rest-api.md)); 4 MiB each. Default **25600** (= 100 GiB) **[P]** |
| `NYXITE__Groups__DefaultMaxMembers` | Instance default `group_max_members` for file-sharing groups ([12 §12.7](12-administration.md)); per-group `max_members` overrides it. Default **16**, equal to the community-mode cap, so a community instance never needs an override **[P]** |
| `NYXITE__Realtime__Backplane` | `none` \| `redis` |
| `NYXITE__Realtime__Redis` (secret) | Redis connection when enabled |
| `NYXITE__Limits__*` | Upload sizes, rate-limit buckets ([13](13-security.md)) |
| `NYXITE__Relay__PruneAfterSnapshotSeq` | Not a setting. The name in the Phase 1.1 plan stands for the pruning rule, which is configured by `NYXITE__Relay__SafetyTailDays` and `__SafetyTailUpdates` above, because a snapshot seq alone cannot express the safety tail ([05 §5.6](05-realtime-collaboration.md)) |
| `NYXITE__Retention__*` | History/audit retention ([10](10-version-history.md), [12](12-administration.md)) |
| `NYXITE__Retention__SessionRetentionDays` | How long revoked/expired `sessions` rows (and their refresh-token chain) are kept before the ops job deletes them; the audit trail lives in `audit_log` independently. Default **30** **[P]** |
| `NYXITE__Retention__ChangeLogDays` | How long `change_log` rows are kept; an older sync cursor gets `410 cursor_expired` and the client re-runs the manifest ([06 §6.3.2](06-sync.md)). Default **90** **[P]**, long enough that a device offline for a quarter still resumes by delta |
| `NYXITE__Retention__TrashWindowDays` | Deletion-lifecycle **Trash** window — instance-wide default **30** ([03 §3.3](03-data-model.md), DL-1); per-user override stored in metadata, same mechanism as the storage quota. The per-user override is not built yet |
| `NYXITE__Retention__GraceWindowDays` | Deletion-lifecycle **grace** window past Trash — instance-wide default **30** (admin/support-assisted restore only, DL-4); per-user override supported. Purge fires at Trash + grace (~60 days); **no early/permanent-now purge** (DL-5). The per-user override is not built yet, the instance value applies to everyone |
| `NYXITE__Retention__PurgeInterval` / `__OrphanBlobAgeHours` | How often the purge and the blob sweep run, and how old an unreferenced blob or staging file must be before the sweep deletes it ([10 §10.6](10-version-history.md)). Defaults **6 h** / **24** **[P]** |
| `NYXITE_LICENSE_TOKEN` | **Optional** per-instance license token — absent = community mode (free non-commercial). Verified **offline** against embedded license public keys; unlocks enterprise gates. Not a secret to protect (per-instance, non-sensitive). ([16](16-licensing-and-entitlement.md)) |
| `NYXITE__Support__Enabled` | **Capability flag** for the in-app bug-reporting relay ([§14.9](#149-support-relay), [04 §4.9](04-rest-api.md)). Default `false`; in v1 set `true` **only on the maintainer's official instance(s)** (SUP-9). When `false` the `/support/**` routes are absent and clients show no reporting surface |
| `NYXITE__Support__ServiceBaseUrl` | Base URL of the central vendor-side `NyxiteSupport` service the relay forwards `POST /reports` to (only used when `Support__Enabled`) |
| `NYXITE__Support__InstanceCredential` (secret) | Instance credential / fingerprint used to **authenticate this relay to `NyxiteSupport`** (analogous to the `NyxiteLicense /register` instance anchor) — proves the forwarded report comes from a recognized, enabled instance |

> **Removed vs prior model:** `NYXITE__Kek__*` (no server KEK) and `NYXITE__Search__*` (no server search).
> **No server crypto config:** AEAD/HPKE primitives are fixed in the wire format ([07 §7.3–7.4](07-encryption.md)); **Argon2id recovery params** (m/t/p/salt) are **client-chosen and persisted per blob** in `recovery_blobs.kdf_params` ([03](03-data-model.md)), not server configuration.

## 14.4 Startup & lifecycle

- **Migrations** run as a discrete deploy step (separate DB role), not at app startup in prod. **[P]** The step is `nyxite-server migrate`: the server binary applies pending migrations with `NYXITE__Database__MigrationConnectionString` and exits (`0` on success, `2` when the connection string is missing). It ships in the same image as the server, so code and schema versions cannot diverge, and it needs none of the server's secrets. Until it has run, `/health/ready` answers `503`. A separate EF migrations bundle was rejected as a second artifact to build and version, and a generated SQL script because it needs `psql` in the deploy and a manual release step.
- Boot validation: DB reachable + migrated, native **token-signing key** present, **password pepper** present (native-auth profile), **mail relay** configured (`NYXITE__Email__Host` / `__From`), blob store writable, `NYXITE__Relay__AccessRecheckInterval` positive. The **Keycloak JWKS reachable** check applies **only under the `enterprise` profile** (native auth validates its own tokens with the signing key). (No KEK probe — there is none.) Fail fast otherwise.
- Background hosted services: blob GC, share-token/expiry sweeps, the email outbox worker, the unverified-account sweep and the cleanup of expired rows ([03 §3.2](03-data-model.md)). **No** snapshotting/indexing (client-side). Audit retention is not a hosted service but the scheduled CLI step `nyxite-server purge-audit` as the migration role, because the app role has no `DELETE` on `audit_log` ([12 §12.3](12-administration.md)).

## 14.5 Health & observability

| Endpoint | Purpose |
|----------|---------|
| `GET /health/live` | Liveness |
| `GET /health/ready` | Readiness (deps healthy): Postgres reachable with no pending migration, and the blob store writable. The IdP check of P0.1-SRV-5 joins when the enterprise sign-in exists. `503` otherwise, without error detail, because the endpoint is public |
| `GET /metrics` | Prometheus text format, on its own port `NYXITE__Metrics__Port` and off when unset |

- **Metrics on a separate port.** Metrics show usage patterns, so they must not be public. The listener carries nothing but `/metrics` and the reverse proxy only forwards the API port, so only monitoring inside the deployment network reaches it and no token has to be managed. Serving it on the API port behind a bearer token was rejected, because the endpoint would then be reachable from the internet.
- **What is exported.** Request count and duration by method, route template and status, plus the server's own counters: audit events by `action`, mails sent and failed, rows deleted by maintenance. No user id, email, IP or URL value is ever a label.
- **Exporter.** The text format is rendered in-house on .NET's `MeterListener`, because the OpenTelemetry Prometheus exporter is only published as a pre-release package. The instruments are standard .NET meters, so an OpenTelemetry exporter can be added later without touching them.
- **Logs.** One JSON object per line on stdout with the request's trace id, written by the JSON console logger that ships with .NET. It was chosen over Serilog, because it needs no extra package and stdout is all a container deployment collects. Every response carries the same id as `Nyxite-Request-Id`, so a client report can be matched to its log lines. Expected failures (a wrong code, a `401`, a validation error) are answers and are not logged as errors. Security events go to the audit log, and content is never logged, because none is readable.

## 14.6 Networking & TLS

- Server listens plain HTTP **inside** the Compose network; **nginx terminates TLS** (Cloudflare Origin CA); Cloudflare fronts public traffic (INFRASTRUCTURE.md, [13](13-security.md)).
- Admin/origin-direct access over **WireGuard**; internal DNS via **bind9** over the VPN.
- Trust forwarded-proto/for headers only from known nginx/Cloudflare hops (correct client IP for rate limiting/audit), configured by `NYXITE__Network__KnownProxies` / `__KnownNetworks` (§14.3). **[P]**

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
