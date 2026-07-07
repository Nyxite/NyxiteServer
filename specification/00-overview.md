# 00 — Overview

> **Guiding principle: privacy first.** Nyxite is **end-to-end encrypted everywhere**. The server stores only ciphertext, never holds content keys, and acts as a **blind relay/store**. Every design choice defaults to the server learning the *least*. This reverses the master repo's earlier encryption-at-rest decision; the canonical `Nyxite` docs must be updated to match.

## 0.1 Purpose

The Nyxite Server is the core service of the Nyxite platform: a single-tenant, self-hosted, **zero-knowledge** backend for notes and documents. It stores content in three forms — **markdown**, **handwritten ink**, and **plain text** — organized into **projects** and **folders**, and synchronizes them across the desktop, Android, and web clients under configurable per-file policies. Content (and even file names) is **encrypted on the client**; the server persists and relays ciphertext it cannot read. Real-time multi-user editing, including anonymous guests via share links, works over an **encrypted relay** — clients merge, the server does not. Authentication is **Nyxite-native** (server-owned accounts: password + required TOTP, or passkeys), with Keycloak/OIDC as a pluggable **enterprise** IdP.

The server is the authority for **persistence, routing, access control, and durable relay** — **not** for reading, merging, indexing, or processing content.

## 0.2 Design principles

1. **Privacy is the overriding priority.** When a feature appears to need server-readable content, that is a design smell to redesign around, not a default to accept.
2. **Zero-knowledge server.** Content keys are generated and held on clients. The server never has a key that decrypts user content. Theft of the database/blobs, a malicious operator, or a curious admin yields **no readable content**.
3. **Server does as little as possible.** Client-side CRDT merge is battle-tested, so the server does **not** merge — it stores and relays encrypted updates. This maximizes privacy and **saves server resources**.
4. **End-to-end, including collaboration and sharing.** Shared/collaborative documents stay E2EE: file keys are wrapped to each member's public key (account shares) or carried in the share-link URL fragment (link/guest shares). The server never sees a usable key.
5. **Content-addressed storage.** Bytes and history snapshots are addressed by the BLAKE3 hash of their *plaintext* (computed on the client), with ciphertext stored under that address. No convergent encryption (avoids confirmation-of-file attacks).
6. **Shared C# with desktop; contract to others.** Domain models, DTOs, crypto, and CRDT glue are shared C# with the Avalonia desktop client — the CRDT glue backs desktop editing and the server-side `Nyxite.CrdtConformanceTests` harness, **not** live merging (the server relays, see point 3). Web and Android consume the emitted OpenAPI contract (and the same wire protocols), not a shared library.
7. **Leave nothing for the server to leak.** Names/titles are encrypted; only structure, ACLs, sizes, timestamps, and public keys are server-visible — the minimum needed to sync and enforce access.

## 0.3 Actors

| Actor | Description | Auth |
|-------|-------------|------|
| **Owner / Admin** | Operates the instance; manages users; sees structure/usage/audit but **cannot read content** (cryptographically impossible). | Native (password+TOTP / passkey), admin role |
| **User** | Registered account; owns/encrypts projects/folders/files, shares them, collaborates. Holds their own keys. | Native (password+TOTP / passkey), device keys |
| **Guest** | Anonymous participant joining via a link share; gets the file key from the link's URL fragment, not the server. | Short-lived share token + fragment key |
| **Client app** | Desktop (Avalonia), Android (Compose), Web (Next.js). Does all encryption, decryption, merge, search, and diffing. | Bearer (the server's own access token) |
| **Keycloak** | **Enterprise-only** pluggable external IdP (OIDC + TOTP); resolves to the server's internal token. Absent in the default profile. | — |

## 0.4 Content forms

| Form | Editor model | Sync model | Storage (all ciphertext) |
|------|--------------|------------|--------------------------|
| **Markdown** | Text; CRDT | CRDT (Yrs), client-merged | Encrypted CRDT update log + encrypted snapshot blob |
| **Plain text** | Text; CRDT | CRDT (Yrs), client-merged | Encrypted CRDT update log + encrypted snapshot blob |
| **Handwritten ink** | Vector strokes | LWW | Encrypted blob (vector stroke format) |

The text/ink split — CRDT (Yrs) for text (`markdown`/`plaintext`/`sourcecode`), LWW for ink and binary (office/image) — is **decided ([OD-4] resolved: yes)**.

## 0.5 Capability summary

- **API** — REST (protected by the server's own access token — native auth by default; enterprise Keycloak/OIDC resolves to the same token) + WebSocket relay; public share endpoint for guests. Serves/relays **ciphertext only**.
- **Domain** — projects → folders → files; structure server-visible, **names and content encrypted**.
- **Sync** — cross-device engine; per-file server policies `server-default`, `excluded` (**[OD-3] resolved**). Offline pinning is purely **client-local** — the zero-knowledge server never sees it.
- **Collaboration** — **encrypted relay**; clients merge CRDT updates; per-document rooms; ephemeral awareness; anonymous guests via fragment-key links.
- **Sharing** — server-side ACLs; account shares wrap the file key to the recipient's public key; link shares carry the key in the URL fragment. Revocation = ACL cutoff + client-driven key rotation.
- **Version history** — full history of **encrypted** snapshots; **client-side** diffs and restore; content-addressed dedup.
- **Search** — **client-side** full-text (desktop indexes the full local corpus; web/Android over their local subset). No server index.
- **Encryption** — full E2EE; per-file AES-256-GCM keys generated and held on clients; wrapped to members via HPKE.
- **Authentication** — native auth (password + required TOTP, or passkeys) with the server issuing its own tokens; pluggable enterprise Keycloak/OIDC IdP; per-device key enrollment; user-held recovery key.
- **Administration** — instance/user management; structure/usage/audit only; **no content access path exists** (no break-glass — there is nothing to break into).

## 0.6 Phase map (full v1.0.0 spanning Phases 0–6)

| Phase | Server deliverables |
|-------|---------------------|
| **0 Foundations** | Native auth (password+TOTP, passkeys) with server-issued tokens + pluggable enterprise Keycloak/OIDC; **device-key enrollment + key directory + client-encrypted recovery blob**; Postgres + blob store (ciphertext); structure/metadata CRUD with encrypted names; OpenAPI. |
| **1 Notes that sync** | Markdown + plain text on the **encrypted** CRDT relay; encrypted blob sync; the three sync policies; on-demand download; **client-side search** support (server serves ciphertext + manifests). |
| **2 Collaboration & sharing** | Encrypted live relay; account shares (HPKE-wrapped keys) + link shares (fragment keys); anonymous guests; version history of encrypted snapshots with client-side diffs/restore; rotation-based revocation. |
| **3 Handwriting** | Ink vector strokes as encrypted blobs; LWW sync. |
| **4 Admin & polish** | Admin **API** (structure/usage/audit, no content) serving the separate `NyxiteAdmin` dashboard; rich encrypted config; audit-log surfacing + signed export. **Self-hosting licensing** ([16](16-licensing-and-entitlement.md)): offline-verified entitlement, enterprise feature gates, degrade/read-only enforcement; the vendor-side `NyxiteLicense` server (separate repo) issues tokens + leases. |
| **5 Format expansion** | Office docs, source-code text types, images — stored as encrypted blobs; any processing (thumbnails, extraction) is **client-side**. |
| **6 Advanced** | Hardening and optional features (e.g. metadata-graph hiding, key-transparency) — see [15](15-roadmap-and-versioning.md). E2EE itself is **not** deferred; it is the default from Phase 0. |

## 0.7 Glossary

- **E2EE / zero-knowledge** — content keys live only on clients; the server cannot decrypt.
- **CRDT** — Conflict-free Replicated Data Type (Yjs/Yrs family). Merged **on clients**; the server relays encrypted updates.
- **File key (FK)** — per-file AES-256-GCM key, client-generated, stored only wrapped.
- **Identity keypair** — per-user X25519+Ed25519; public key in the server directory, private key never on the server.
- **Recovery key** — user-held secret (recovery phrase) that unlocks a client-encrypted recovery blob (AES-256-GCM under Argon2id); the **only** recovery path (no server escrow).
- **HPKE** — Hybrid Public Key Encryption, used to wrap file keys to member public keys.
- **Fragment key** — a file key carried in a share-link URL fragment (`#key=…`), never sent to the server.
- **Encrypted relay** — the server stores/forwards encrypted CRDT updates without reading or merging them.
- **Content address** — client-computed BLAKE3 of plaintext; ciphertext stored under it.

## 0.8 Out of scope

- Multi-tenancy / federation (single-tenant by design).
- Any server-side reading, search, diff, merge, or processing of content (all client-side by principle).
- Server/admin key escrow or content recovery (no master key exists).
- Client-side editor implementations (each client owns its editor; the server owns the protocols).
- Samsung Notes `.sdoc` migration — its own roadmap item (master spec §16).
