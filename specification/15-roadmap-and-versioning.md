# 15 — Roadmap & Versioning

> **E2EE is the default from Phase 0**, not a deferred opt-in. The roadmap below is the build order within v1.0.0.

## 15.1 v1.0.0 definition

**v1.0.0 = the complete, end-to-end-encrypted server platform.** Phases are build order, not separate product versions. Because E2EE is foundational, the key/device/recovery subsystem ships in Phase 0; later phases never have to retrofit encryption.

## 15.2 Phase → server deliverables

### Phase 0 — Foundations
- Solution/project scaffold ([01](01-architecture.md)); `NyxiteDbContext` + initial migration ([03](03-data-model.md)).
- Native auth (password + required TOTP, passkeys) with the server issuing its own tokens; pluggable enterprise Keycloak/OIDC IdP ([08](08-authentication.md)).
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

### Phase 4.3 — Key transparency (pulled into v1.0.0)
- **Key-transparency log** for the public-key directory ([09 §9.3](09-sharing-and-acl.md), [13](13-security.md)) — **pulled forward from the optional Phase 6 hardening item into the required v1.0.0 band** because enterprise/family groups depend on it (decision G-3): one substituted key would expose a whole group's corpus, so group enrollment wraps **only to transparency-log-verified public keys**. Blocks Phase 4.4.

### Phase 4.4 — Enterprise/family file-sharing groups
- **Group-key layer** on the envelope hierarchy (`personal key → group key → DEK → file`, [07 §7.2a](07-encryption.md)): a client-generated group keypair whose private half is **wrapped once per member** (`group_key_grants`, [03 §3.2b](03-data-model.md)) and file DEKs **wrapped to a group public key** — enrollment is **O(1) per member**, no file duplication. **No new primitive** (reuses the pinned HPKE/AES/Ed25519 suite); every wrap carries an **`alg_id`** for crypto-agility ([§15.3](#153-versioning-policy-p)).
- Serves **family** (all members read shared data) and **enterprise** (a *managers* group reads all of a team's files via a per-project/folder **reader-group attachment**; a worker reads only their own).
- **Transparency-gated enrollment** (Phase 4.3, G-3); **scope-scoped rotation** on removal (G-4, generation-guarded — `409`/`412` reusing the Phase-2.3 machinery, [09 §9.9](09-sharing-and-acl.md)); **server-enforced group-size limit** (metadata-only), **overridable per group** from `admin` (G-5, [12 §12.7](12-administration.md)).
- **Zero-knowledge preserved:** the server stores only opaque grants, DEK-to-group wraps, membership rows, opaque reader-group attachments, and public keys — no group private key, content key, or plaintext name; no break-glass ([13 §13.6b](13-security.md)). Server steps P4.4-SRV-1..4.

> **Re-sequencing note (2026-07-04):** groups is a **v1.0.0 feature**, so key transparency (formerly optional Phase 6.1) was pulled into the required band as **Phase 4.3**, groups follow as **Phase 4.4**, and polish/distribution moves to **Phase 4.5** so the release closer stays last. See `docs/OPEN-DECISIONS.md` (G-3) and `implementation/phase-4.4-groups.md`.

### Phase 5 — Format expansion
- Office docs, source-code text types, images as **encrypted** blobs; any processing (thumbnails, extraction) is **client-side** ([11](11-search.md)).
- Chunked/resumable ciphertext upload for large binaries ([04 §4.7](04-rest-api.md)).

### Phase 6 — Advanced hardening (optional)
- **Key transparency / verification** (safety numbers) to defend the key directory ([09 §9.3](09-sharing-and-acl.md), [13](13-security.md)). *(The transparency **log** itself was pulled forward to the required **Phase 4.3** for groups (G-3); remaining here are the optional client-facing verification affordances — safety numbers.)*
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
- **Crypto agility:** algorithm identifiers in object framing and `key_id`/`generation` markers allow rotating primitives and keys without a format break ([07 §7.4](07-encryption.md)); the enterprise/family group wraps additionally carry an **`alg_id`** ([07 §7.3](07-encryption.md), [03 §3.2b](03-data-model.md)) so a future hybrid-PQC swap re-wraps small keys without touching content.
- **CRDT wire protocol:** pinned by conformance tests across `ydotnet`/Yjs/android `yrs/UniFFI` ([05 §5.11](05-realtime-collaboration.md)).

## 15.4 Risk register (server-relevant)

| Risk | Source | Mitigation |
|------|--------|------------|
| Key loss = data loss | [07 §7.8](07-encryption.md) | Recovery key UX; multi-device enrollment; clear user warnings |
| `ydotnet` / android `yrs/UniFFI` maturity (now client-only) | OPEN-DECISIONS | Conformance tests; server runs no live CRDT engine, shrinking the blast radius |
| Key-directory trust (pubkey MITM) | [09](09-sharing-and-acl.md) | TLS now; key transparency/verification in Phase 6 |
| Weak web/Android search | [11](11-search.md) | Desktop is the full-search surface; accepted trade for privacy |
| Metadata leakage (structure/sizes/timestamps) | [13 §13.1](13-security.md) | Names encrypted; optional structure-hiding in Phase 6 |
| Relay tampering/withholding by server | [13](13-security.md) | Signed updates/directory entries (Ed25519) to detect |

## 15.5 Decisions & canonical docs

This spec now encodes **privacy-first, full E2EE** as the default. That **reverses** the master `Nyxite` repo's previously "resolved" encryption-at-rest decision and supersedes the Phase-6 opt-in zero-knowledge item. The canonical docs must be updated to match:

- `docs/SPECIFICATION.md` §6 (encryption), §5.2 (search → client-side), §7 (collaboration → encrypted relay), §8 (sharing → wrapped/fragment keys), §11 (admin → no break-glass), §16 (roadmap).
- `docs/OPEN-DECISIONS.md` — move the encryption-model line out of "Resolved (encryption at rest)" and record **E2EE/zero-knowledge default**; revisit [OD-2] (admin access — now moot) and [OD-5] (ZK — now the default).

**[OD-3]** (sync-policy semantics) and **[OD-4]** (CRDT-vs-LWW split) are now **resolved** here and should be marked resolved canonically: **[OD-3]** → server policies are `server-default`/`excluded` only, offline pinning is client-local (no `pinned-local` server value); **[OD-4]** → text (markdown/plaintext/sourcecode) = CRDT (Yrs), ink + binary (office/image) = LWW. The E2EE-specific choices — **recovery = a client-encrypted recovery blob (AES-256-GCM under Argon2id; no escrow)**, encrypted names, fragment-key sharing — are now **ratified** in `docs/OPEN-DECISIONS.md`.
