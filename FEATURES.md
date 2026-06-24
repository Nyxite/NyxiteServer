# Nyxite Server — Features

ASP.NET Core (C#) backend. The core service: API, sync engine, real-time collaboration **relay**, end-to-end encryption support, authentication, and administration.

**Privacy first / full E2EE.** Content keys are generated and held on clients; the server stores only ciphertext, never holds a content key, and acts as a blind relay/store. It cannot read notes, attachments, ink, file names, or collaboration traffic. The detailed build spec lives in this repo's `specification/` folder.

## API

- REST (OIDC-protected) and WebSocket API for all clients; serves/relays ciphertext only
- Key-directory, device-enrollment, recovery, and wrapped-key endpoints
- Public share endpoint serving the guest collaboration client (decryption key rides the link's URL fragment)

## Domain

- Projects and folders
- Files: markdown, handwritten ink, plain text
- Structure, ACLs, wrapped keys, and **encrypted names** in PostgreSQL; ciphertext blobs content-addressed behind `IBlobStore`

## Sync

- Cross-device sync engine (moves ciphertext + structure, never plaintext)
- Per-file sync policies enforced server-side: server-default, pinned-local, excluded
- Per-file-type split: CRDT for text, last-write-wins for ink/binary

## Collaboration

- **Encrypted relay; client-side CRDT merge** (Yrs) — the server forwards encrypted updates but does not merge or read them
- Per-document WebSocket rooms; encrypted update broadcast plus encrypted ephemeral awareness
- Anonymous guests join via link; the file key comes from the URL fragment, so there is no server-mediated key exchange

## Sharing

- Two-layer access control: server-enforced ACL (reach) plus the cryptographic layer (decrypt)
- User-grant shares (file key wrapped to the recipient's public key via HPKE) and link shares (key in the URL fragment), read/write
- Revocation: instant server-ACL cutoff plus client-driven file-key rotation for forward secrecy

## Version history

- Full version history of encrypted content-addressed snapshots
- **Client-side** diffs and restore (the server cannot read either version); deduplicated via content-addressed snapshots

## Search

- **Client-side** full-text search — the server holds no index; the desktop indexes the full local corpus, web/Android over their local subset

## Encryption

- End-to-end encryption (zero-knowledge), default from Phase 0; **no server-held KEK**
- Per-file AES-256-GCM content keys generated client-side, stored only wrapped (to member public keys via HPKE, or carried in a share-link URL fragment)
- Identity keypair per user (public key in a server directory, private key never on the server); per-device enrollment; user-held recovery key with no server/admin escrow
- Plaintext-hash addressing with ciphertext stored under it; no convergent encryption

## Authentication

- Keycloak OIDC integration; TOTP two-factor (authenticates the account; decryption is governed by device/identity keys)

## Administration

- Instance and user management
- Admins see structure/usage/audit only; they **cannot read file contents** and there is **no break-glass** (the server holds no key)
- Audit log for auth events, device/key lifecycle, shares, admin actions, key rotations, and purges — never content

## Open questions

See [../docs/OPEN-DECISIONS.md](../docs/OPEN-DECISIONS.md). Server-owned items: key recovery model (no-escrow default), metadata boundary (encrypted names; defer structure-hiding), multi-device enrollment, fragment-key sharing, rotation-based revocation, key-directory trust, sync-policy semantics, and the CRDT/LWW split.
