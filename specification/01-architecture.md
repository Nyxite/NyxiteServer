# 01 — Architecture

> **Privacy-first / E2EE.** The server is a **blind relay/store**: it persists and forwards ciphertext, enforces ACLs and structure, and does **no** reading, merging, indexing, or processing of content ([00](00-overview.md), [07](07-encryption.md)).

## 1.1 Technology stack

| Concern | Choice | Source / status |
|---------|--------|-----------------|
| Language / runtime | C# / ASP.NET Core, async throughout | Master spec §2 |
| Target framework | **.NET 10 (LTS)** | Confirmed |
| Web framework | ASP.NET Core Minimal APIs + controllers hybrid | **[P]** |
| Real-time | SignalR (encrypted **relay**, no server merge) | Master spec §2.1; relay per privacy decision |
| ORM / data access | EF Core 10 (+ Npgsql); raw SQL for hot read paths | **[P]** |
| Metadata DB | PostgreSQL 17 (structure, ACLs, wrapped keys, **encrypted names**) | Master spec §2.2 |
| Blob store | Content-addressed filesystem behind `IBlobStore`; **ciphertext only**; S3-compatible later | Master spec §2.2 |
| CRDT | Yrs family; **client-side merge** (`ydotnet` on desktop). Server runs **no CRDT engine in the live path** | Privacy decision |
| Search | **Client-side** (no server index) | Privacy decision |
| Cache / backplane | Redis 7 (later; encrypted relay backplane + presence) | Master spec §2.2 |
| Auth | **Native** (password+TOTP / passkeys, server-issued tokens) + per-device key enrollment; enterprise Keycloak/OIDC pluggable | Master spec §2.1, §10 + E2EE |
| Crypto | AES-256-GCM, HPKE (X25519), Ed25519, BLAKE3, Argon2id | [07](07-encryption.md) **[P]** |
| Reverse proxy / packaging | nginx behind Cloudflare; Docker Compose on Hetzner ARM64 | INFRASTRUCTURE.md |

## 1.2 Solution and project layout **[P]**

```
Nyxite.sln
├── src/
│   ├── Nyxite.Server               # ASP.NET Core host: endpoints, relay hub, DI, middleware
│   ├── Nyxite.Application          # use-cases (structure CRUD, ACL, relay coordination, history index)
│   ├── Nyxite.Domain               # entities, ACL rules, sync-policy semantics  ── shared with desktop
│   ├── Nyxite.Contracts            # DTOs, request/response records, enums       ── shared with desktop
│   ├── Nyxite.Crypto               # HPKE wrap/unwrap, AEAD, content addressing, recovery blob (AES-GCM/Argon2id) ── shared
│   ├── Nyxite.Crdt                 # ydotnet glue, encrypted update encode/snapshot ── shared (CLIENT-side merge)
│   ├── Nyxite.Persistence          # EF Core DbContext, migrations, repositories
│   └── Nyxite.BlobStore            # IBlobStore + filesystem implementation (+ S3 later)
└── tests/
    ├── Nyxite.UnitTests
    ├── Nyxite.IntegrationTests     # Testcontainers: Postgres (Keycloak only for the enterprise profile)
    └── Nyxite.CrdtConformanceTests # Yrs wire-protocol conformance vs Yjs / android yrs/UniFFI
```

- **No `Nyxite.Search` project** — search is client-side.
- `Nyxite.Crypto` and `Nyxite.Crdt` are shared with desktop because the **desktop performs the same client-side encryption and merge** as the other clients. The **server** uses `Nyxite.Crypto` only for HPKE-opaque handling it can do without keys (none of which decrypts content) and does **not** merge CRDTs.
- Sharing boundary unchanged: shared projects must not depend on `Nyxite.Server`/`Nyxite.Persistence`/ASP.NET/EF.

## 1.3 Layered responsibilities

- **Nyxite.Server** — HTTP/WebSocket host: routing, the `RelayHub`, authn/authz middleware, rate limiting, validation of **structure/ACL** requests, OpenAPI, problem-details. Forwards ciphertext.
- **Nyxite.Application** — use-cases that touch only server-visible data: structure CRUD, ACL evaluation, relay sequencing/persistence, version bookkeeping, key-directory management. **Never** decrypts.
- **Nyxite.Domain** — entities, hierarchy invariants, ACL evaluation, sync-policy enum semantics. No I/O.
- **Nyxite.Persistence** — EF Core context, migrations, repositories.
- **Nyxite.Crypto / Nyxite.Crdt / Nyxite.BlobStore** — infrastructure seams; on the server side they handle only opaque ciphertext.

## 1.4 Runtime topology

```
                         Cloudflare (proxy, Universal SSL)
                                    │  HTTPS
                                    ▼
                                  nginx  ── TLS termination (Origin CA), routing
                ┌───────────────────┼───────────────────────────┐
                ▼                   ▼                           ▼
        Nyxite.Server         Keycloak (JVM)            (static client assets)
        ├─ REST API            OIDC (enterprise
        ├─ Native auth          profile only)
        │   (pw+TOTP/passkeys,
        │    server-issued tokens)
        ├─ RelayHub (encrypted)
        └─ background workers (GC, expiry, audit)
             │        │            │
             ▼        ▼            ▼
        PostgreSQL  Blob store   Redis (later: relay backplane + presence)
        (structure, (CIPHERTEXT
         ACLs,       only)
         wrapped
         keys,
         enc names)

   ✗ No KEK, no content keys, no search index on the server — keys live on CLIENTS.
```

### Scaling note
v1.0.0 is single-node. The relay's no-merge design makes horizontal scale-out (Redis backplane) cheaper than a server-authoritative model. Not a v1.0.0 requirement.

## 1.5 Cross-cutting concerns

| Concern | Approach |
|---------|----------|
| **AuthN** | The server's own access token (users; native auth by default, enterprise OIDC resolves to the same token) + per-device keys; short-lived share tokens (guests). [08](08-authentication.md) |
| **AuthZ** | Server ACL gates ciphertext/relay; crypto layer gates decryption. [09](09-sharing-and-acl.md) |
| **Validation** | Structure/ACL DTOs validated at the edge; **content is opaque** (server can't validate plaintext). |
| **Errors** | RFC 9457 `application/problem+json`. [04 §4.4](04-rest-api.md) |
| **Logging** | Structured logs (Serilog **[P]**), correlation IDs; security events → audit log; **never content** (there is none readable). |
| **Config** | `IOptions` from env + mounted secrets. [14](14-deployment-and-config.md) |
| **Telemetry** | OpenTelemetry **[P]**; health/readiness. |
| **Idempotency** | Content-addressed writes are idempotent; `Idempotency-Key` **required on POST creates** — the server stores `key → response` for 24h scoped to `(user, endpoint)`; a replay returns the original response/status; the same key with a different body → `409 idempotency_conflict` ([04](04-rest-api.md)). **[P]** |
| **Background work** | Blob GC, share-token/expiry sweeps, audit retention. **No** snapshotting/indexing (those are client-side). |

## 1.6 Request lifecycle (REST write of ciphertext)

1. nginx → Kestrel (TLS already terminated).
2. Rate-limiting middleware ([13](13-security.md)).
3. Bearer (the server's own access token) or share token → principal.
4. Routing → endpoint; structure/ACL DTO validation (content payloads passed through opaque).
5. Authorization: ACL policy for the target.
6. Application service: transaction → structure/ACL change and/or `IBlobStore.Put(ciphertext)` → commit.
7. Side effects: audit entry, relay notify. **No** reindex/merge.
8. Response; problem-details on failure.

## 1.7 Real-time lifecycle (relay)

1. Authenticated WebSocket upgrade (bearer or share token).
2. Join `file:{fileId}` relay group; ACL-checked.
3. Server returns encrypted updates after the client's cursor + pointer to the latest encrypted snapshot.
4. Client merges locally; submits **encrypted** updates; server persists + rebroadcasts without reading.
5. Encrypted awareness relayed ephemerally.
6. **Clients** snapshot to encrypted, content-addressed blobs (→ version history).

Details in [05](05-realtime-collaboration.md) and [06](06-sync.md).
