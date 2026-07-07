# Nyxite Server — Specification (v1.0.0)

This folder is the detailed, implementation-level specification for the **Nyxite Server** — the ASP.NET Core (C#) backend that provides the API, sync engine, real-time collaboration relay, access control, and the admin API for the Nyxite platform. (The operator dashboard itself is a separate component — the [`admin`](https://github.com/Nyxite/NyxiteAdmin) repo.)

It expands the architectural planning documents in the central [`Nyxite`](https://github.com/Nyxite/Nyxite) repository into a concrete server build specification covering the full v1.0.0 product across all roadmap phases.

## Guiding principle: privacy first (full E2EE)

**Nyxite is end-to-end encrypted everywhere.** Content keys are generated and held on clients; the **server stores only ciphertext, never holds a content key, and acts as a blind relay/store**. It cannot read notes, attachments, ink, file names, or collaboration traffic. Real-time editing uses **client-side CRDT merge** with the server relaying encrypted updates (the server does no merging — this maximizes privacy and saves resources). Full-text **search and diffs run on the clients** (desktop is the full-corpus surface). Sharing stays E2EE via keys wrapped to recipients' public keys (account shares) or carried in the link's URL fragment (guest shares).

> **This reverses the master repo's earlier "encryption at rest" decision** and makes the formerly deferred zero-knowledge mode the default. The canonical `Nyxite` docs (`docs/SPECIFICATION.md`, `docs/OPEN-DECISIONS.md`) must be updated to match — see [15 §15.5](15-roadmap-and-versioning.md).

## Scope of v1.0.0

v1.0.0 is the **complete, end-to-end-encrypted server platform** — Phases 0–6. The key/device/recovery subsystem is foundational (Phase 0); later phases never retrofit encryption. Where a capability is phased in, its section notes the phase.

## Source of truth

The central `Nyxite` repo is authoritative. This spec links to `docs/OPEN-DECISIONS.md` rather than restating decisions. Where this spec and the master `docs/SPECIFICATION.md` currently disagree, it is because the **privacy-first/E2EE decision postdates the master docs** and the master must be updated ([15 §15.5](15-roadmap-and-versioning.md)).

## Proposal convention

- **[P]** — *Proposed.* A concrete decision filled in by this spec (algorithms, routes, schemas, versions), subject to confirmation; not yet ratified in the master docs.
- **[OD-n]** — references a numbered item in `docs/OPEN-DECISIONS.md`.

Two privacy-maximal **[P]** defaults to note explicitly:
- **Names are encrypted** — the server sees structure by opaque ID only (a further step, hiding the structure graph itself, is deferred to Phase 6).
- **Key recovery is a user-held recovery key, no server/admin escrow** — losing all devices **and** the recovery key means permanent, unrecoverable data loss. This is the honest cost of zero-knowledge.

## Documents

| # | Document | Covers |
|---|----------|--------|
| 00 | [overview.md](00-overview.md) | Purpose, privacy-first principles, actors, glossary, phase map |
| 01 | [architecture.md](01-architecture.md) | Stack, solution layout, blind-relay topology, cross-cutting concerns |
| 02 | [domain-model.md](02-domain-model.md) | Entities (+ keys/devices/recovery), encrypted names, lifecycle |
| 03 | [data-model.md](03-data-model.md) | PostgreSQL schema (ciphertext, wrapped keys, encrypted names), blob store |
| 04 | [rest-api.md](04-rest-api.md) | REST surface (ciphertext + keys), error model, no server search/diff |
| 05 | [realtime-collaboration.md](05-realtime-collaboration.md) | Encrypted relay, client-side merge, guest sessions |
| 06 | [sync.md](06-sync.md) | Sync of ciphertext + structure, policies, CRDT/LWW split |
| 07 | [encryption.md](07-encryption.md) | **E2EE** key hierarchy, HPKE wrapping, recovery, content addressing |
| 08 | [authentication.md](08-authentication.md) | Native auth (password+TOTP / passkeys, server-issued tokens) + pluggable enterprise OIDC, device/identity keys, two-layer authz |
| 09 | [sharing-and-acl.md](09-sharing-and-acl.md) | Server ACL + crypto layer, wrapped/fragment keys, rotation revocation |
| 10 | [version-history.md](10-version-history.md) | Encrypted snapshots, client-side diffs/restore, dedup |
| 11 | [search.md](11-search.md) | **Client-side** search; server has no index |
| 12 | [administration.md](12-administration.md) | Server-owned admin API (structure/usage/audit), **no break-glass**, audit log — consumed by the separate `admin` dashboard |
| 13 | [security.md](13-security.md) | What the server can/can't see, threat model, rate limiting |
| 14 | [deployment-and-config.md](14-deployment-and-config.md) | Docker Compose, config (no KEK/no search), operations |
| 15 | [roadmap-and-versioning.md](15-roadmap-and-versioning.md) | Phase mapping, versioning, canonical-doc updates |
| 16 | [licensing-and-entitlement.md](16-licensing-and-entitlement.md) | Client side of self-hosting licensing: offline token verify, best-effort check-in/lease, enterprise feature gates, degrade/read-only enforcement (L-1–L-7) |

## Status

Specification for a greenfield build. No server code exists yet; the `server` repo currently holds only `FEATURES.md` and `LICENSE.md`. This document set defines what to build.

## License

PolyForm Noncommercial License 1.0.0 — see the repo `LICENSE.md`.
