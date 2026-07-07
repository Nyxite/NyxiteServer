# 07 — Encryption (End-to-End / Zero-Knowledge)

> **Model change (2026-06-24).** Nyxite is **privacy-first**: full **end-to-end encryption everywhere**. The server stores only ciphertext and **never holds content keys**. This replaces the earlier encryption-at-rest model and makes the formerly deferred zero-knowledge mode the **default from Phase 0**. This reverses a decision recorded as "resolved" in the master `Nyxite` repo — `docs/SPECIFICATION.md` §6 and `docs/OPEN-DECISIONS.md` must be updated to match. Concrete algorithms below are **[P]**.

## 7.1 Posture & threat model

- **Zero-knowledge server.** Content keys are generated and held **on clients**. The server sees only ciphertext, opaque identifiers, the structural graph, ACL grants, wrapped-key blobs, and timestamps. It **cannot decrypt** notes, attachments, ink, titles, or collaboration traffic.
- **What this defends:** theft of the database and/or blob store, a compromised or malicious server/operator, and a curious admin all yield **no readable content**. There is no server-side key that unlocks data.
- **The cost (accepted, by design):** no server-side search, diffs, or content processing (all move to clients); collaboration is a blind relay, not server-authoritative merge; revoking shared access needs key rotation; and **if a user loses all their devices and their recovery key, their data is unrecoverable** — the server cannot help. Privacy is the overriding priority (see project memory), so these trades are accepted.

## 7.2 Key hierarchy

```
User identity keypair (per user)            ── public key on server; private key NEVER on server
   ├─ X25519 + ML-KEM-768  (hybrid key agreement / wrapping, via a hybrid-KEM HPKE)
   └─ Ed25519 + ML-DSA-65  (hybrid signing)   [P]
        │
Device keys (per device)                     ── enrolled copies of/access to the identity private key
        │
Recovery phrase (user-held secret)           ── Argon2id-derived key wraps the identity private key (AES-256-GCM) for self-recovery
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
- **Device keys:** enrolling a new device gives it access to the identity private key (via device-to-device approval or recovery-key unwrap). *(Ratified in `docs/OPEN-DECISIONS.md`.)*
- **Recovery key:** a high-entropy user-held secret (shown once as a phrase/file). A 256-bit key is derived from it via **Argon2id** and wraps the identity private key with **AES-256-GCM** (not HPKE — the recovery key is symmetric); the server stores that blob **but cannot read it**. This is the **only** recovery path — **no server escrow** ([§7.8](#78-key-recovery-decided)). *(Ratified in `docs/OPEN-DECISIONS.md`.)*

## 7.2a Group-key layer (enterprise/family sharing) **[P]**

Enterprise/family file-sharing groups ([03 §3.2b](03-data-model.md), [09 §9.9](09-sharing-and-acl.md)) insert **one middle layer** into the hierarchy so a file readable by a whole group is stored **once** and enrolling a reader is **one blob (O(1))** rather than a per-file re-wrap:

```
personal key  →  wraps  →  group key  →  wraps  →  DEK  →  encrypts  →  file
```

- **Group keypair** — a hybrid **X25519 + ML-KEM-768** (HPKE) + **Ed25519 + ML-DSA-65** (signing) pair, **generated client-side** by the group creator. Its **public** halves are published in the key directory (`groups.group_pubkey`/`ed25519_pubkey`, [03 §3.2b](03-data-model.md)) as just **another HPKE target** — **no new primitive** (it reuses the pinned hybrid suite, [§7.3](#73-algorithms-p)). Its **private** half is stored **only wrapped, once per member**, HPKE-sealed under each member's personal public key (a `group_key_grants` row). The server **never** holds a group private key.
- **DEK-to-group wrap** — a file's DEK is HPKE-wrapped **to the group public key** (a `file_keys` group-principal row, [03 §3.2b](03-data-model.md)), in addition to or instead of individual members. A member unwraps the group private key with their personal key, then unwraps the DEK.
- **Scoped keys (G-4)** — a group's key is **scoped per project/time-period** (`group_key_grants.scope_id`), not one key over all history; a file wraps to its **scope's** group key. Removing a keyholder re-wraps only the **affected scope**, bounding the revocation blast radius.
- **Enterprise "manager reads all"** — a worker wraps a DEK to **own key + the managers-group public key** (public half is in the directory), needing no membership in that group; managers hold the group key and read every worker's file. Driven by the **reader-group attachment** cascade ([09 §9.9](09-sharing-and-acl.md)).

Every wrapped group blob (grant and DEK-to-group wrap) carries an **`alg_id`** ([§7.3](#73-algorithms-p)) — because a group key wraps *many* DEKs it concentrates blast radius, so the wrap format is algorithm-agile from day one; v1 ships the **hybrid post-quantum suite** and the tag keeps any later primitive change re-wrappable without touching content ([15 §15.3](15-roadmap-and-versioning.md)). Group-key **rotation** reuses the generation-guarded machinery of [§7.9](#79-rotation--revocation), applied per scope ([09 §9.9](09-sharing-and-acl.md)).

## 7.3 Algorithms **[P]**

The **asymmetric** seams ship **hybrid classical + post-quantum (concatenated)** at **NIST security level 3** from v1.0.0 — safe unless **both** halves break. **Symmetric primitives are unchanged** (already quantum-safe — only Grover-halved).

| Purpose | Algorithm |
|---------|-----------|
| Symmetric AEAD everywhere (content / CRDT / snapshots / names / recovery blob) | **AES-256-GCM**, 96-bit (12B) nonce, 128-bit (16B) tag *(unchanged — quantum-safe)* |
| Public-key wrap to a recipient public key (file-key to members; device enrollment to a device pubkey) | **HPKE base mode** with a **hybrid KEM** — DHKEM(X25519, HKDF-SHA256) **concatenated with ML-KEM-768** / HKDF-SHA256 / AES-256-GCM. Hybrid suite id **`X25519MLKEM768`** (carried on `alg_id`) |
| Recovery blob wrap | **AES-256-GCM** under an **Argon2id**-derived key (NOT HPKE — see the rule below) *(unchanged)* |
| Identity key agreement | **X25519 + ML-KEM-768** (hybrid; classical DHKEM(X25519) half retained, ML-KEM-768 concatenated) |
| Signing (updates, key directory entries, device enrollment, key transparency, audit) | **Ed25519 + ML-DSA-65** (hybrid dual signature) |
| Recovery-key derivation | **Argon2id** — m=64 MiB, t=3, p=1 (tunable; persisted in `recovery_blobs.kdf_params`) *(unchanged)* |
| Plaintext hashing (content address) | **BLAKE3-256** of plaintext *(unchanged)* |

> **Size consequence.** Hybrid enlarges the small key material only, never content ciphertext: each wrapped-key row grows by the **ML-KEM-768 ciphertext (~+1.1 KB)** and each signature by the **ML-DSA-65 signature (≈ 3.3 KB)**. Level 3 (not level 5) was chosen partly to keep signatures smaller on the signed-CRDT-update hot path.

> **System rule — HPKE vs AES-256-GCM:** use **HPKE wherever the target is a public key** (file-key wrap to members, **DEK/group-key wrap to a group pubkey**, device enrollment to a device pubkey); use **AES-256-GCM wherever the key is symmetric** (all content + the recovery blob).

> **Crypto-agility — `alg_id` on group wraps.** Every enterprise/family group wrapped blob (`group_key_grants.wrapped_group_privkey` and DEK-to-group `file_keys` rows, [§7.2a](#72a-group-key-layer-enterprisefamily-sharing-p)) carries an **`alg_id`** naming the wrap primitive. v1 pins the **hybrid** HPKE suite above (`X25519MLKEM768`); because wraps cover only the **small** keys, a future primitive change **re-wraps the keys without touching content ciphertext** — the same "rotation re-wraps only the small keys" property already relied on ([15 §15.3](15-roadmap-and-versioning.md)).

## 7.4 Encrypted object framing **[P]**

Each ciphertext object (blob, snapshot, CRDT update, encrypted name) is framed:
```
magic(4) | version(1) | key_id(16) | nonce(12) | ciphertext(...) | gcm_tag(16)
```
- **magic** = ASCII `"NYXC"` (`0x4E 0x59 0x58 0x43`); **version** = `0x01`.
- **AAD** = `magic ‖ version ‖ key_id ‖ file_id(16) ‖ object_kind(1)` — binds the frame to its file and kind.
- **`object_kind`** enum: `blob=1`, `snapshot=2`, `crdt=3`, `name=4`, `metadata=5`, `awareness=6`, `settings=7`.
- **HPKE wrap output framing** (a wrapped file-key): `enc(HPKE encapsulated key) ‖ ciphertext ‖ tag(16)`. Under the hybrid KEM `enc` is the **X25519 share (32B) concatenated with the ML-KEM-768 ciphertext (~1088B)** rather than a bare 32B share; the `alg_id` fixes its length.

`key_id` identifies which **file key** (and its 1:1 rotation generation) was used; the server cannot resolve it to a usable key.

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

## 7.8 Key recovery (decided)

- **Decision: user-held recovery phrase, no server escrow.** At enrollment the client generates a high-entropy **recovery phrase** (shown once). A 256-bit key is derived from it via **Argon2id** (m=64 MiB, t=3, p=1; params persisted in `recovery_blobs.kdf_params`), and that key wraps the identity bundle (the hybrid X25519 + ML-KEM-768 priv ‖ Ed25519 + ML-DSA-65 priv) with **AES-256-GCM** — **not** HPKE, because the recovery key is symmetric. The recovery path itself is **unchanged** (symmetric, already quantum-safe, and **never peppered** — see [08 §8.1](08-authentication.md)); only the private-key material it wraps grows. The server stores the resulting **opaque** blob `{ version, kdf, nonce, ciphertext, tag }` (AAD = `userId ‖ version`) and cannot open it ([03 `recovery_blobs`](03-data-model.md)).
- **Consequence:** losing **all** devices **and** the recovery phrase = permanent data loss. The server has no master key and cannot reset content. This is the honest cost of zero-knowledge.
- **Alternative (not chosen):** server-side or admin escrow would enable recovery but reintroduce a key the operator holds — rejected as contrary to the privacy-first principle. Flagged here so it can be revisited as an explicit, less-private opt-in.

## 7.9 Rotation & revocation

- **Member removal** ([09](09-sharing-and-acl.md)): the file key is **rotated** by a remaining member's client (new FK, re-encrypt head, re-wrap to remaining members); the server simultaneously drops the removed member's ACL grant so it is **cut off from the relay/storage immediately**, even before rotation completes. Past ciphertext the removed member already downloaded cannot be un-seen (inherent to any system).
- **Device loss:** revoke the device's enrollment; rotate the identity keypair if the device may be compromised, then re-wrap file keys (background, client-driven). **[P]**

## 7.10 Backups

- DB and blob backups contain **only ciphertext + wrapped keys + encrypted names** — useless to anyone without a member's private key. There is no KEK to protect or lose on the server side; the critical secret is the **user's recovery key**, held by the user.
