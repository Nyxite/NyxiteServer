# 15 — Roadmap & Versioning

> **E2EE is the default from Phase 0**, not a deferred opt-in. The roadmap below is the build order within v1.0.0.

## 15.1 v1.0.0 definition

**v1.0.0 = the complete, end-to-end-encrypted server platform.** Phases are build order, not separate product versions. Because E2EE is foundational, the key/device/recovery subsystem ships in Phase 0; later phases never have to retrofit encryption.

## 15.2 Phase → server deliverables

### Phase 0 — Foundations
- Solution/project scaffold ([01](01-architecture.md)); `NyxiteDbContext` + initial migration ([03](03-data-model.md)).
- Keycloak OIDC + 2FA ([08](08-authentication.md)).
- **E2EE foundation: key directory (`user_keys`), device enrollment, client-encrypted recovery blob (`recovery_blobs`, AES-256-GCM under Argon2id)** ([07](07-encryption.md), [08](08-authentication.md)).
- `IBlobStore` filesystem impl (**ciphertext**); structure/metadata CRUD with **encrypted names** ([02](02-domain-model.md), [04](04-rest-api.md)); OpenAPI.
- Audit-log foundation; health/readiness.

### Phase 1 — Notes that sync (single user)
- Markdown + plaintext on the **encrypted CRDT relay** ([05](05-realtime-collaboration.md)); encrypted update log + **client** snapshots ([10](10-version-history.md)).
- Encrypted blob sync; **on-demand download** ([06](06-sync.md)).
- Sync policies `server-default`/`excluded` (**[OD-3] resolved**); offline pinning is client-local only.
- Sync manifests that drive **client-side search** ([11](11-search.md)) — no server index.

### Phase 2 — Collaboration & sharing
- Multi-client **encrypted relay**; rooms; encrypted awareness ([05](05-realtime-collaboration.md)).
- **Account shares** (HPKE-wrapped file keys) + **link/guest shares** (fragment keys) ([09](09-sharing-and-acl.md)).
- **Rotation-based revocation** (instant ACL cutoff + client key rotation).
- Version history of encrypted snapshots; **client-side** diffs/restore ([10](10-version-history.md)).

### Phase 3 — Handwriting
- Ink vector strokes as **encrypted** blobs ([02](02-domain-model.md), [07](07-encryption.md)).
- **LWW** ink sync ([06 §6.5](06-sync.md), **[OD-4] resolved**).

### Phase 4 — Admin & polish
- Admin APIs (structure/usage/audit, **no content, no break-glass**) ([12](12-administration.md)).
- Device/key admin (revocation, directory health); audit-log surfacing.
- Rich **client-encrypted** per-user/per-file config ([04](04-rest-api.md)).

### Phase 5 — Format expansion
- Office docs, source-code text types, images as **encrypted** blobs; any processing (thumbnails, extraction) is **client-side** ([11](11-search.md)).
- Chunked/resumable ciphertext upload for large binaries ([04 §4.7](04-rest-api.md)).

### Phase 6 — Advanced hardening (optional)
- **Key transparency / verification** (safety numbers) to defend the key directory ([09 §9.3](09-sharing-and-acl.md), [13](13-security.md)).
- Optional **metadata-graph hiding** (encrypt structure too) — a larger design beyond names ([07 §7.7](07-encryption.md)).
- Possible **zero-knowledge searchable index** (blind indexing) only if it leaks nothing ([11](11-search.md)).
- (E2EE itself is **not** here — it's the Phase-0 default.)

### Cross-cutting / later
- **Redis relay backplane** + multi-node ([01](01-architecture.md), [05 §5.10](05-realtime-collaboration.md)).
- **S3-compatible** blob store (MinIO) + cold offload ([14](14-deployment-and-config.md)).
- **Samsung Notes `.sdoc` migration** — its own roadmap item (master §16).

## 15.3 Versioning policy **[P]**

- **API:** URL-versioned (`/api/v1`); OpenAPI is the published contract.
- **Server releases:** SemVer; v1.0.0 is the first complete release; pre-1.0 tags track phases.
- **Schema:** forward-only EF Core migrations.
- **Crypto agility:** algorithm identifiers in object framing and `key_id`/`generation` markers allow rotating primitives and keys without a format break ([07 §7.4](07-encryption.md)).
- **CRDT wire protocol:** pinned by conformance tests across `ydotnet`/Yjs/`ykt` ([05 §5.11](05-realtime-collaboration.md)).

## 15.4 Risk register (server-relevant)

| Risk | Source | Mitigation |
|------|--------|------------|
| Key loss = data loss | [07 §7.8](07-encryption.md) | Recovery key UX; multi-device enrollment; clear user warnings |
| `ydotnet`/`ykt` maturity (now client-only) | OPEN-DECISIONS | Conformance tests; server runs no live CRDT engine, shrinking the blast radius |
| Key-directory trust (pubkey MITM) | [09](09-sharing-and-acl.md) | TLS now; key transparency/verification in Phase 6 |
| Weak web/Android search | [11](11-search.md) | Desktop is the full-search surface; accepted trade for privacy |
| Metadata leakage (structure/sizes/timestamps) | [13 §13.1](13-security.md) | Names encrypted; optional structure-hiding in Phase 6 |
| Relay tampering/withholding by server | [13](13-security.md) | Signed updates/directory entries (Ed25519) to detect |

## 15.5 Decisions & canonical docs

This spec now encodes **privacy-first, full E2EE** as the default. That **reverses** the master `Nyxite` repo's previously "resolved" encryption-at-rest decision and supersedes the Phase-6 opt-in zero-knowledge item. The canonical docs must be updated to match:

- `docs/SPECIFICATION.md` §6 (encryption), §5.2 (search → client-side), §7 (collaboration → encrypted relay), §8 (sharing → wrapped/fragment keys), §11 (admin → no break-glass), §16 (roadmap).
- `docs/OPEN-DECISIONS.md` — move the encryption-model line out of "Resolved (encryption at rest)" and record **E2EE/zero-knowledge default**; revisit [OD-2] (admin access — now moot) and [OD-5] (ZK — now the default).

**[OD-3]** (sync-policy semantics) and **[OD-4]** (CRDT-vs-LWW split) are now **resolved** here and should be marked resolved canonically: **[OD-3]** → server policies are `server-default`/`excluded` only, offline pinning is client-local (no `pinned-local` server value); **[OD-4]** → text (markdown/plaintext/sourcecode) = CRDT (Yrs), ink + binary (office/image) = LWW. The E2EE-specific choices — **recovery = a client-encrypted recovery blob (AES-256-GCM under Argon2id; no escrow)**, encrypted names, fragment-key sharing — are now **ratified** in `docs/OPEN-DECISIONS.md`.
