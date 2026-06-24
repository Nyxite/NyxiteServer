# 07 — Encryption (End-to-End / Zero-Knowledge)

> **Model change (2026-06-24).** Nyxite is **privacy-first**: full **end-to-end encryption everywhere**. The server stores only ciphertext and **never holds content keys**. This replaces the earlier encryption-at-rest model and makes the formerly deferred zero-knowledge mode the **default from Phase 0**. This reverses a decision recorded as "resolved" in the master `Nyxite` repo — `docs/SPECIFICATION.md` §6 and `docs/OPEN-DECISIONS.md` must be updated to match. Concrete algorithms below are **[P]**.

## 7.1 Posture & threat model

- **Zero-knowledge server.** Content keys are generated and held **on clients**. The server sees only ciphertext, opaque identifiers, the structural graph, ACL grants, wrapped-key blobs, and timestamps. It **cannot decrypt** notes, attachments, ink, titles, or collaboration traffic.
- **What this defends:** theft of the database and/or blob store, a compromised or malicious server/operator, and a curious admin all yield **no readable content**. There is no server-side key that unlocks data.
- **The cost (accepted, by design):** no server-side search, diffs, or content processing (all move to clients); collaboration is a blind relay, not server-authoritative merge; revoking shared access needs key rotation; and **if a user loses all their devices and their recovery key, their data is unrecoverable** — the server cannot help. Privacy is the overriding priority (see project memory), so these trades are accepted.

## 7.2 Key hierarchy

```
User identity keypair (per user)            ── public key on server; private key NEVER on server
   ├─ X25519  (key agreement / wrapping, via HPKE)
   └─ Ed25519 (signing)                       [P]
        │
Device keys (per device)                     ── enrolled copies of/access to the identity private key
        │
Recovery key (user-held secret/phrase)       ── wraps an escrow of the identity private key for self-recovery
        │  unlocks
        ▼
Identity private key
        │  unwraps
        ▼
File key (FK, per file, AES-256-GCM)         ── generated on the client; stored ONLY wrapped
   ├─ wrapped to the owner's public key
   ├─ wrapped to each share member's public key      (account shares)
   └─ embedded in the share-link URL fragment         (link/guest shares)
        │  encrypts
        ▼
File content + CRDT updates + snapshots + encrypted name/title
```

- **File key (FK):** one AES-256-GCM 256-bit key **per file**, generated client-side with a CSPRNG. It encrypts that file's bytes, CRDT updates, history snapshots, and its encrypted name. The server only ever stores it **wrapped** (one wrapped copy per authorized member).
- **Identity keypair:** each user has a long-lived keypair. The **public** key is published to the server's key directory so others can wrap file keys to them; the **private** key never leaves the user's devices.
- **Device keys:** enrolling a new device gives it access to the identity private key (via device-to-device approval or recovery-key unwrap). **[P]**
- **Recovery key:** a high-entropy user-held secret (shown once as a phrase/file) that wraps an escrow blob of the identity private key, stored by the server **but unreadable to it**. This is the **only** recovery path — **no server escrow** ([§7.8](#78-key-recovery-od)). **[P]**

## 7.3 Algorithms **[P]**

| Purpose | Algorithm |
|---------|-----------|
| Content / CRDT / snapshot encryption | AES-256-GCM (96-bit nonce, 128-bit tag) |
| File-key wrapping to a member | HPKE (X25519 + HKDF-SHA256 + AES-256-GCM) |
| Identity key agreement | X25519 |
| Signing (updates, key directory entries) | Ed25519 |
| Recovery-key derivation | Argon2id → wrapping key |
| Plaintext hashing (content address) | BLAKE3 (256-bit) |

## 7.4 Encrypted object framing **[P]**

Each ciphertext object (blob, snapshot, CRDT update, encrypted name) is framed:
```
magic(4) | version(1) | key_id(16) | nonce(12) | ciphertext(...) | gcm_tag(16)
```
`key_id` identifies which **file key** (and rotation generation) was used; the server cannot resolve it to a usable key. AAD binds the frame to its `file_id` and object kind.

## 7.5 Content addressing & deduplication

- **Address = BLAKE3 of the *plaintext*** ([02](02-domain-model.md), [03](03-data-model.md)); the stored object is **ciphertext**. The plaintext hash is computed **on the client**; the server treats it as an opaque address.
- **No convergent encryption** — the file key is random, not derived from content; this resists confirmation-of-file attacks. Because keys are per-file and client-held, physical ciphertext dedup is **intra-file** (a file's unchanged versions dedup); cross-file dedup is not possible (and is not a goal under E2EE).
- The server cannot verify that the address matches the plaintext (it can't read plaintext); clients are trusted to address honestly. The server only enforces write-once at a given address. **[P]**

## 7.6 Where encryption happens (client, not server)

| Step | Location |
|------|----------|
| Generate file key | Client |
| Encrypt content / updates / snapshots / name | Client |
| Compute content address (BLAKE3 of plaintext) | Client |
| Wrap file key to members / put in link fragment | Client |
| Store ciphertext + wrapped keys | Server (blind) |
| Decrypt on read | Client (recipient), using its unwrapped file key |

The server's write path is: accept ciphertext + wrapped-key blobs → store. Its read path is: authorize via ACL → return ciphertext + the caller's wrapped key. It never decrypts.

## 7.7 Metadata boundary (what the server still sees) **[P]**

E2EE "in all places" is pushed as far as practical while keeping the server able to **sync and enforce access**:

| Server can see | Server cannot see |
|----------------|-------------------|
| Object IDs (UUIDv7) and the structural graph (which folder/project contains which item) | File / folder / project **names and titles** (stored encrypted) |
| `content_type`, sizes, timestamps | Any **content** (markdown, text, ink, attachments) |
| ACL grants and wrapped-key blobs (opaque) | Any **content key** (only wrapped copies it can't open) |
| CRDT **update sizes/ordering** (opaque bytes) | CRDT **update contents** |
| Public keys in the key directory | Any **private key** or **recovery key** |

> **[P] decision — names are encrypted.** Titles are sensitive, so they are E2EE like content; admins and the server see structure by opaque ID only. A *further* step (hiding the structural graph itself) is **not** taken, because the server needs the graph to route sync and evaluate ACLs. If you want structure hidden too, that's a larger, separate design.

## 7.8 Key recovery [OD] **[P]**

- **Default: user-held recovery key, no server escrow.** At enrollment the client generates a recovery key (shown once). It wraps an escrow of the identity private key; the server stores that **opaque** escrow blob and cannot open it.
- **Consequence:** losing **all** devices **and** the recovery key = permanent data loss. The server has no master key and cannot reset content. This is the honest cost of zero-knowledge.
- **Alternative (not chosen):** server-side or admin escrow would enable recovery but reintroduce a key the operator holds — rejected as contrary to the privacy-first principle. Flagged here so it can be revisited as an explicit, less-private opt-in.

## 7.9 Rotation & revocation

- **Member removal** ([09](09-sharing-and-acl.md)): the file key is **rotated** by a remaining member's client (new FK, re-encrypt head, re-wrap to remaining members); the server simultaneously drops the removed member's ACL grant so it is **cut off from the relay/storage immediately**, even before rotation completes. Past ciphertext the removed member already downloaded cannot be un-seen (inherent to any system).
- **Device loss:** revoke the device's enrollment; rotate the identity keypair if the device may be compromised, then re-wrap file keys (background, client-driven). **[P]**

## 7.10 Backups

- DB and blob backups contain **only ciphertext + wrapped keys + encrypted names** — useless to anyone without a member's private key. There is no KEK to protect or lose on the server side; the critical secret is the **user's recovery key**, held by the user.
