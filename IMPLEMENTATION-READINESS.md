# NyxiteServer — Implementation Readiness Assessment

**Question:** Can NyxiteServer be **fully implemented across all phases** using only (a) this component's `specification/` + `FEATURES.md` and (b) the shared `Nyxite` info repo (`docs/`, `features/`, `implementation/`)?

**Verdict: NO — not *fully*.**

The server specification is exceptionally detailed and internally consistent. The **required v1.0.0 band is buildable end-to-end for Phases 0.1, 0.2, 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 3.1, 4.1, 4.2, and 4.5** — every `-SRV-` step in those phases maps cleanly to a concrete chapter (schema, endpoints, DTOs, status codes, wire framing, crypto suite IDs, rate limits, config keys). However there are **2 hard blockers** (one of them in the required v1.0.0 band), **2 intentionally-deferred Phase-6 research tracks** whose design is by admission not written, and a handful of moderate/minor gaps. A developer could start today and get most of the way through v1.0.0, but would hit a wall at **Phase 4.3 (key transparency)** and could not build **Phase 5.1 (chunked upload)** or **Phase 6.x** without new design work.

The reason the count is low: the server repo's `specification/` (00–15) is a genuinely complete build spec for the core platform, and `docs/OPEN-DECISIONS.md` lists **zero** live-open decisions (#1–#12, AD-1–AD-5, G-1–G-5 all resolved). The gaps below are places where a **required capability is referenced but its concrete server-buildable design was never written into any spec** — typically because it depends on a cross-cutting `-CORE-` fixture step that itself says the format is still "to be defined." One gap (MG-2) is a different category: the design exists, but the **highest-leverage server-owned artifact — the frozen `/openapi/v1.json` wire contract every client validates against — has not been produced on disk yet**, and the sync payload shapes it depends on are still loose.

---

## HARD BLOCKERS

### HB-1 — Key transparency subsystem is entirely unspecified (REQUIRED for v1.0.0)
**Blocks:** Phase 4.3 step `P4.3-SRV-1`; cascades to Phase 4.4 step `P4.4-SRV-2` (group enrollment must "verify a key-transparency inclusion proof … before accepting the grant"). Groups (4.4) are a **v1.0.0 feature**, and 4.3 was deliberately **pulled into the required band** (decision G-3, re-sequencing note 2026-07-04). So this is not optional hardening — it is on the critical path to v1.0.0.

**What is missing.** The server must "serve verification data and an **append-only transparency log with inclusion (and consistency) proofs** over directory public keys" (`P4.3-SRV-1`), and the enrollment endpoint `POST /groups/{id}/members` must verify an inclusion proof for the member's directory key (`server 09 §9.9`, `P4.4-SRV-2`). But nothing in the server repo specifies **how**:
- **No dedicated chapter.** `specification/` runs 00–15; none covers key transparency. It appears only as passing references (`09 §9.9`, `13 §13.8`, `15 §15.2`).
- **No data model.** `03-data-model.md §3.2` has no tables for the log — no Merkle leaves, tree nodes, signed tree heads (STH)/checkpoints, or witness/consistency state.
- **No wire format.** The inclusion-proof and consistency-proof encodings are not defined. `P4.3-CORE-1` explicitly says the job is to *"Define … the transparency-log inclusion-proof format"* and ship vectors — i.e. it does not yet exist.
- **No endpoints.** `04-rest-api.md` has no `/keys/transparency`, no STH/checkpoint fetch, no inclusion-proof endpoint.
- **No algorithm details.** The tree hash function (BLAKE3-256? SHA-256?), the leaf serialization (what tuple is logged — `userId ‖ keyId ‖ pubkey ‖ generation`?), the log-signing key/model, gossip/witnessing, and — most importantly — the **exact verification procedure the server runs at group enrollment** are all unspecified.

**Doc-drift on this gap (resolved 2026-07-12):** `09 §9.3`, `13`, `15`, and `docs/OPEN-DECISIONS.md #8` previously described key transparency as a deferred Phase-6 item; they now consistently state that the transparency **log** is **required at Phase 4.3** (G-3) with only the client-facing safety-number **verification** left optional in Phase 6, and that the directory self-signature is the **hybrid Ed25519 + ML-DSA-65** suite. The remaining gap is the concrete transparency-log **design/schema** (still to be written into the server spec), not the sequencing.

**To resolve:** author a server `specification/` chapter (or an extension of 07/09) that pins: the transparency-log data model (leaves, internal nodes, STH/checkpoint table), the Merkle tree hash + leaf schema, the log-signing model, the REST endpoints (append/read/STH/inclusion/consistency), the inclusion/consistency-proof wire format (as a shared conformance vector — this is `P4.3-CORE-1`), and the server-side inclusion-proof verification algorithm consumed by `POST /groups/{id}/members`.

### HB-2 — Chunked / resumable ciphertext-upload contract is unspecified
**Blocks:** Phase 5.1 step `P5.1-SRV-1` ("add chunked/resumable ciphertext upload for large blobs"); reused by Phase 5.3 (`P5.3-SRV-1`). Phase 5 is **optional-in-v1.0.0**, so this is a lesser priority than HB-1 — but the phase cannot be built as-is.

**What is missing.** `04-rest-api.md §4.7` contains only a placeholder — *"Max ciphertext upload: 100 MB inline (larger → chunked, Phase 5)."* There is no:
- init / part-upload / complete endpoint set,
- part addressing / offset scheme, resume semantics, per-part idempotency,
- chunk-size definition, or reassembly-by-content-address protocol.

`P5.1-CORE-1` confirms the contract is not yet pinned: it is a task to *"pin the chunked/resumable ciphertext upload contract (part addressing, resume, idempotency)."*

**To resolve:** define the chunked-upload endpoints and contract (a tus-style or S3-multipart-style protocol) in `04`, plus the `P5.1-CORE-1` shared fixture. The required v1.0.0 band is unaffected — it only needs the fully-specified 100 MB inline `PUT /files/{id}/blob` path.

---

## INTENTIONALLY-DEFERRED RESEARCH TRACKS (block "full implementation," but by design)

These are Phase-6 optional hardening tracks whose design the plan itself treats as **go/no-go research**, not settled spec. They cannot be implemented from the current information, but that is acknowledged and deliberate — not a spec defect in the normal sense.

- **DR-1 — Metadata-graph hiding (Phase 6.2, `P6.2-SRV-1`).** `07 §7.7` explicitly calls hiding the structure graph "a larger, separate design" that is **not** taken; `P6.2-CORE-1` is *"Design how containment is hidden."* No opaque-parentage schema or ACL-reach-without-graph mechanism exists yet.
- **DR-2 — Leak-free searchable index (Phase 6.3, `P6.3-SRV-1`).** `11 §11.5` and `P6.3-CORE-1` frame this as an explicit **go/no-go leakage audit** that "may be declined." No scheme is specified.

---

## MODERATE GAPS (implementable with standard patterns, but unspecified — resolve before coding)

### MG-1 — Server-side session / refresh-token / idempotency persistence is absent from the data model
**Affects:** `P0.1-SRV-3` (refresh tokens), `/auth/logout`, `P4.2-SRV-1b` (`GET/DELETE /admin/users/{id}/sessions`), and the `Idempotency-Key` store.

The spec requires **revocable** refresh tokens (`08 §8.7`: "refresh tokens rotate on use and can be revoked"), a `/auth/logout` that "revoke[s] the presented refresh token / session," an admin **sessions list + force-logout**, and an idempotency store ("`key → response` for 24h scoped to `(user, endpoint)`", `01 §1.5` / `04 §4.1`). All of these require **server-side state**, but `03-data-model.md §3.2` defines **no `sessions`, `refresh_tokens`, or `idempotency_keys` table** (the schema lists users, RBAC tables, webauthn_credentials, user_keys, devices, recovery_blobs, structure, shares, file_keys, file_versions, crdt_updates, audit_log — and nothing else). Likewise the ephemeral `mfaToken` (interim password→TOTP token), device `pairingCode`, single-use 60 s **socket ticket**, and 15 min **guest share-session token** have no specified storage tier (Redis? DB? in-memory?). A senior dev can add standard tables/cache, but the persistence model is genuinely unspecified and should be pinned so migrations and revocation semantics are correct — **resolve this before writing the first migration.**

### MG-2 — Canonical OpenAPI wire contract does not exist yet; sync payload shapes still loose (cross-cutting, server-owned)
**Affects:** every client component (which validates against the frozen contract in CI) and the Phase 2.x sync steps (`P2.2-SRV-*`).

Two **server-owned** artifacts are still outstanding and are the single highest-leverage items to produce early:

- **The frozen `/openapi/v1.json` does not exist on disk.** This is the canonical machine-readable wire contract that every other Nyxite client validates against in CI. Until it is authored/generated and frozen, no client can pin against a stable server contract. The prose REST surface (`04`) is complete enough to *derive* it, so this is production work rather than missing design — but because it is server-owned and gates every downstream client, it should be the **first foundational deliverable**, not a late-phase cleanup.
- **The `GET /sync/manifest` and `POST /sync/changes` payload shapes are still loose.** `06` specifies the sync *flow*, but the concrete request/response payload schemas and the **per-kind ref formats** (`structure` / `blob` / `crdt` / `delete` / `keyrotate`) are not fully pinned. These must be nailed down before `/openapi/v1.json` can be frozen, and they are likewise server-owned.

Neither requires new cryptographic or protocol design — the inputs exist — but both are prerequisites for a stable, client-consumable contract and should be locked before broad client work begins.

---

## MINOR AMBIGUITIES (a competent dev resolves these in-flight)

- **MA-1 — Token format/algorithm not pinned.** `08 §8.2` says the server signs its own access/refresh tokens with a "token-signing key" (`NYXITE__Auth__TokenSigningKey`) but does not fix JWT vs opaque, or the algorithm (Ed25519 / HS256 / RS256). Choosable, but unstated.
- **MA-2 — SCIM + CSV import/export contracts.** `12 §12.2` references `POST /admin/users/import`, `GET /admin/users/export` (CSV) and SCIM `/scim/v2/**` with no schema. SCIM is RFC 7643/7644 (standard); CSV shape is trivial to define — but neither contract is in-repo.
- **MA-3 — Group default size value.** `12 §12.7` / `14` reference an instance-default `group_max_members` config but give no default number (trivial to pick).
- **MA-4 — Enterprise OIDC endpoints thin.** `GET /auth/oidc/authorize` + `/callback` (`08 §8.2`) are described at the "Auth Code + PKCE, validate against Keycloak JWKS" level only; adequate for a standard OIDC implementer, not fully detailed. Enterprise profile is optional.
- **MA-5 — Group `scope_id` semantics.** The G-4 project-vs-time-period granularity is a design-deferred sub-choice (`features/groups.md` open questions). **Server-side this is a non-issue** — the server stores `scope_kind` (enum `project|time_period`) + an opaque `scope_id` uuid and never interprets it; noted only for completeness.

---

## What IS fully specified and buildable (for the record)

To keep the "NO" honest: the following are pinned to genuine implementation depth and need no further decisions —

- **Data model** (`03`): every core table with columns, types, checks, partial indexes, FKs, and the `IBlobStore` interface.
- **REST surface** (`04`): routes, methods, representative DTOs, RFC 9457 error model with a full code table, pagination/idempotency/existence-hiding (`404` vs `403`) rules.
- **Crypto** (`07`): AES-256-GCM framing (`magic "NYXC" | 0x01 | key_id | nonce | ct | tag`, AAD construction, `object_kind` enum), hybrid HPKE KEM suite id `X25519MLKEM768` (X25519 + ML-KEM-768) / HKDF-SHA256 / AES-256-GCM, hybrid Ed25519 + ML-DSA-65 signatures / BLAKE3-256 / Argon2id params, recovery-blob format, content addressing.
- **Relay** (`05`): SignalR hub contract, MessagePack wire encoding, join/update/awareness flow, snapshot triggers + prune safety-tail (7 days OR 1000 updates).
- **Sync** (`06`, the flow — but see MG-2: the `/sync/manifest` + `/sync/changes` payload shapes and per-kind ref formats still need pinning), **sharing/ACL + rotation** (`09`, incl. `409`/`412` generation-guard), **version history** (`10`), **admin API + signed audit bundle + RBAC scope** (`12`), **security/rate-limits/existence-hiding** (`13`), **deploy/config keys** (`14`).
- **Auth** (`08`): native password+TOTP / passkey flows, endpoint list, token lifetimes (access ~5 min, socket ticket 60 s, guest session 15 min), two-gate authz model.

Phases 0.1 → 4.2 (server steps), plus 2.1–2.4, 3.1, 4.1, and 4.5, are implementable directly from the current documents; the block is concentrated at **4.3 (key transparency)**, cascading into **4.4 enrollment verification**, and at the optional **5.x / 6.x** bands.

---

## Gaps grouped by phase

| Phase | Gap | Severity |
|-------|-----|----------|
| Cross-cutting | Canonical `/openapi/v1.json` not authored on disk; `/sync/manifest` + `/sync/changes` payload shapes and per-kind ref formats loose (MG-2) — server-owned, highest-leverage | Moderate (high-leverage) |
| 0.1 | Session/refresh-token/idempotency persistence tables absent (MG-1); token format not pinned (MA-1) | Moderate / Minor |
| 0.2–2.4, 3.1, 4.1 | Sync payload shapes/ref formats need pinning (part of MG-2); otherwise fully specified | Moderate / — |
| 4.2 | SCIM/CSV import-export contracts (MA-2); admin sessions store (part of MG-1) | Minor / Moderate |
| **4.3** | **Key transparency log: no chapter, schema, proof format, endpoints, or verification algorithm (HB-1)** | **Hard blocker (required v1.0.0)** |
| 4.4 | Enrollment inclusion-proof verification depends on HB-1; group default size value (MA-3) | Hard blocker (inherits HB-1) / Minor |
| 4.5 | None | — |
| **5.1 / 5.3** | **Chunked/resumable upload contract unspecified (HB-2)** | **Hard blocker (optional-in-v1.0.0)** |
| 5.2 | None (`sourcecode` rides the existing CRDT path) | — |
| 6.2 / 6.3 | Designs intentionally deferred (DR-1, DR-2) | Deferred research |

---

## Top 6 most critical gaps

1. **Key transparency subsystem (HB-1)** — required for v1.0.0 (Phase 4.3, blocks 4.4 group enrollment); no data model, proof wire format, endpoints, or server verification algorithm anywhere in the server repo.
2. **Chunked/resumable ciphertext-upload contract (HB-2)** — Phase 5.1/5.3; only a one-line placeholder exists (`§4.7`).
3. **Canonical OpenAPI wire contract + sync payload shapes (MG-2)** — the frozen `/openapi/v1.json` that all clients validate against in CI does not exist on disk, and the `/sync/manifest` + `/sync/changes` payloads and per-kind ref formats are still loose; both are server-owned and the highest-leverage early deliverables (no new design required, but they gate all client work).
4. **Session / refresh-token / idempotency persistence (MG-1)** — revocable refresh, `/auth/logout`, admin sessions list, and the idempotency store all need server state, but no tables are in the data model; resolve before the first migration.
5. **Phase 6.2 / 6.3 designs (DR-1, DR-2)** — metadata-graph hiding and leak-free search are undesigned go/no-go research tracks; unbuildable as-is by admission.
6. **Minor contracts unspecified (MA-1/2/3)** — token signing algorithm/format, SCIM + CSV admin import-export, and the instance-default `group_max_members` value.
