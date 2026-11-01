# 17 — Key Transparency (Phase 4.3)

> **What this chapter pins.** The append-only **key-transparency (KT) log** over the public-key directory: what is logged, the byte-exact leaf format, the Merkle tree, the signed checkpoint, storage, REST endpoints, the proof formats, the client verification procedure, the server-side check at group enrollment, and the safety-number derivation for the optional Phase-6.1 UI. Required for **v1.0.0** because group enrollment depends on it (G-3, [09 §9.9](09-sharing-and-acl.md)). Steps `P4.3-CORE-1`, `P4.3-SRV-1`; consumed by `P4.4-SRV-1`.

## 17.1 Goal and threat model

- **Threat.** A malicious or compromised server hands a sharer a **substituted public key** for a grantee (its own key), so the sharer wraps a file key or a **group key** to the attacker. TLS and the directory self-signature ([09 §9.3](09-sharing-and-acl.md)) do not stop this, because the server controls the directory and can self-sign a key it generated itself.
- **Defence.** Every directory key event is appended to a public, append-only Merkle log whose head is signed. A client wraps only to a key it has **proven is in the log** (inclusion proof), and every client **monitors the log for its own account**, so a substituted key is either refused or **publicly visible to its victim**. A server can still lie, but it cannot lie **silently**.
- **Design choice.** A **plain Merkle log** ([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) tree algorithm, **SHA-256**, signed checkpoints in the [C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) format) was chosen over a **verifiable map** (AKD/CONIKS style). A map can additionally prove "this is the **latest** key" and non-inclusion, but needs VRFs, prefix trees and epochs in four independent implementations. The log reaches the same detection goal through **self-monitoring** (§17.7), at a fraction of the complexity. **SHA-256** was chosen over the project's BLAKE3 because it keeps the tree, the proofs and the checkpoint **compatible with existing tlog/CT tooling and witness networks**, which the project can join later without a format break. SHA-256 is already in the crypto ledger (HKDF-SHA256).

## 17.2 What is logged

One leaf per **directory key event**. The log is built from **public material only** — no content, no names, no private keys, no wrapped keys.

| `entry_type` | Event | Written by |
|---|---|---|
| `1` user_key_publish | A user publishes or rotates their identity keys (`PUT /keys`, [04](04-rest-api.md)) | `user_keys` insert |
| `2` user_key_revoke | A user's key is revoked (`user_keys.revoked_at` set, e.g. identity rotation or account deletion) | `user_keys` update |
| `3` group_key_publish | A file-sharing group's public key is published (`POST /groups`) or a scope rotation publishes a new group public key | `groups` insert / rotate |

> **Device keys are not logged.** A device public key is only the target of the one-time enrollment seal, and that seal is authenticated by the server-verified `pairingCode` plus the QR payload, which carries the device public-key fingerprint ([08 §8.3](08-authentication.md)). Logging it would add a leaf per device without closing a gap.

## 17.3 Leaf format (byte-exact)

All integers are **big-endian**. Variable-length fields are length-prefixed. This encoding is normative: the server and all three clients must produce **identical bytes** from the same directory entry, which the `P4.3-CORE-1` vectors enforce.

```text
leaf_data =
    "NYXKT-LEAF-v1"            13 bytes ASCII, domain separation
  ‖ entry_type                 u8   (1 | 2 | 3)
  ‖ subject_id                 16   users.id or groups.id (UUID bytes, RFC 9562 order)
  ‖ key_id                     16   user_keys.key_id; for groups the group key id
  ‖ generation                 u32
  ‖ alg_id_len  u16 ‖ alg_id        ASCII suite id, e.g. "X25519MLKEM768+Ed25519MLDSA65"
  ‖ kem_pub_len u32 ‖ kem_pub       hybrid KEM public key (X25519 ‖ ML-KEM-768)
  ‖ sig_pub_len u32 ‖ sig_pub       hybrid signing public key (Ed25519 ‖ ML-DSA-65)
  ‖ logged_at                  i64  milliseconds since Unix epoch, server clock at append
  ‖ self_sig_len u32 ‖ self_sig     hybrid self-signature by sig_pub over everything above
                                    except logged_at and self_sig itself
```

- For `entry_type = 2` (revoke), `kem_pub` and `sig_pub` repeat the revoked key's values, so a monitor can match the revocation to the publish leaf without a lookup.
- `self_sig` is the **directory self-signature** already required by [09 §9.3](09-sharing-and-acl.md) (stored in `user_keys.self_sig` / `groups.self_sig`). Including it in the leaf proves the key's holder signed it. The server cannot forge it, but it can generate a whole fresh keypair, which is exactly what monitoring (§17.7) catches.

## 17.4 Merkle tree

Exactly the RFC 9162 §2.1 Merkle Tree Hash:

- **Leaf hash:** `SHA-256(0x00 ‖ leaf_data)`.
- **Node hash:** `SHA-256(0x01 ‖ left ‖ right)`.
- The tree over `n` leaves splits at the largest power of two `k < n` (RFC 9162 §2.1.1). The empty tree hash is `SHA-256("")`.
- **Inclusion proofs** and **consistency proofs** are generated and verified with the RFC 9162 §2.1.3 / §2.1.4 algorithms, unchanged. Implementers port those algorithms literally, not from memory, because an off-by-one in the split rule produces proofs that verify locally and fail on every other surface.

## 17.5 Signed checkpoint

The log head is a **C2SP signed note** whose body is a **tlog-checkpoint**:

```text
<origin>
<tree_size>
<base64(root_hash)>

— <origin> <base64(key_hash_ed25519 ‖ ed25519_signature)>
— <origin> <base64(key_hash_mldsa ‖ mldsa65_signature)>
```

- **origin** = `<instance host>/nyxite-kt/v1`, e.g. `notes.example.org/nyxite-kt/v1`. It names the log, so checkpoints from two instances can never be confused.
- **Two signature lines, both required.** The Ed25519 line uses the standard C2SP signed-note Ed25519 type (`0x01`), so external witnesses and tlog tooling can verify it today. The ML-DSA-65 line uses signature type `0xFF` with an `"NYXITE-MLDSA65"` key-name suffix, because C2SP has no ML-DSA type yet. A client accepts a checkpoint **only if both lines verify** — the same "both halves" rule as every other hybrid signature ([07 §7.3](07-encryption.md)).
- **Log signing key.** A dedicated hybrid Ed25519 + ML-DSA-65 keypair, held as a secret **outside Postgres** (`NYXITE__KeyTransparency__SigningKey`, [14](14-deployment-and-config.md)), used for nothing else. Its public half is served at `GET /kt/log-key`.
- **Trust anchor = pin on first use.** A client pins the log public key **per account** when the account is added. A later change is shown as a hard, blocking warning and is never accepted silently. A log key rotation therefore means a new log (new `origin` version, `v2`), announced through the instance admin; this is rare by design.
- **One checkpoint per append.** The server signs a new checkpoint in the **same transaction** that appends a leaf. Key events are rare (one per account setup, rotation or group key), so per-append signing costs nothing, and it removes any "merge delay" in which a new key is published but not yet provable.

## 17.6 Storage

```sql
CREATE TABLE kt_leaves (
  leaf_index  bigint PRIMARY KEY,            -- 0-based, gapless, assigned under kt_state lock
  entry_type  smallint NOT NULL CHECK (entry_type IN (1,2,3)),
  subject_id  uuid NOT NULL,                 -- users.id or groups.id (no FK: the log outlives deletion)
  key_id      uuid NOT NULL,
  leaf_data   bytea NOT NULL,                -- §17.3, exactly as hashed
  leaf_hash   bytea NOT NULL,                -- SHA-256(0x00 ‖ leaf_data)
  logged_at   timestamptz NOT NULL
);
CREATE INDEX ix_kt_subject ON kt_leaves(subject_id, leaf_index);

CREATE TABLE kt_nodes (                      -- hashes of complete (perfect) subtrees only
  level       smallint NOT NULL,             -- 0 = leaf hashes; subtree covers 2^level leaves
  node_index  bigint NOT NULL,               -- position at that level
  hash        bytea NOT NULL,
  PRIMARY KEY (level, node_index)
);

CREATE TABLE kt_checkpoints (
  tree_size   bigint PRIMARY KEY,
  root_hash   bytea NOT NULL,
  note        text NOT NULL,                 -- the full signed note of §17.5, served verbatim
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kt_state (                      -- single row; serializes appends
  id          boolean PRIMARY KEY DEFAULT true CHECK (id),
  tree_size   bigint NOT NULL DEFAULT 0
);
```

- **Append-only.** No UPDATE or DELETE on `kt_leaves`, `kt_nodes`, `kt_checkpoints`; the migration role grants INSERT and SELECT only to the app role. `subject_id` has **no FK**, because the log must outlive account and group deletion; a deleted account's history is exactly what a monitor needs to see.
- **Append procedure (one transaction):** lock `kt_state` (`SELECT … FOR UPDATE`), `leaf_index = tree_size`, insert the leaf, insert every `kt_nodes` row that the new leaf completes, compute the root, sign and insert the checkpoint, `tree_size += 1`, then insert the triggering `user_keys` / `groups` row. A failure rolls back the directory change as well, so **a key can never be in the directory without being in the log**.
- **Proof generation** uses only `kt_nodes` (O(log n) lookups); no full-tree recomputation.

## 17.7 Client verification procedure (normative)

Every client (desktop, android, web) runs the same procedure; the `P4.3-CORE-1` vectors cover each step.

1. **Update the checkpoint.** `GET /kt/checkpoint`. Verify both signatures against the pinned log key. If `tree_size` is smaller than the last checkpoint this account stored, **fail** (rollback). If larger, fetch `GET /kt/consistency?from=<old>&to=<new>` and verify it (RFC 9162 §2.1.4.2); on failure, **fail**. Store the new checkpoint.
2. **Verify a key before wrapping to it.** The directory entry (`GET /keys/directory`) returns the fields of §17.3 plus `ktLeafIndex`. The client rebuilds `leaf_data` itself from those fields, hashes it, fetches `GET /kt/inclusion?leafIndex=&treeSize=<stored checkpoint size>` and verifies it against the stored root. It also checks the self-signature and that the entry is not revoked. **Only then** may it wrap (file-key share, group enrollment, reader-group auto-wrap). On any failure it **refuses to wrap** and surfaces the error (`P4.3-TC-2`).
3. **Monitor the own account.** On every app start and at least every 24 h while running, each client fetches all leaves added since its last monitored size (`GET /kt/leaves?start=&end=`), checks that they hash to the verified checkpoint, and looks for any leaf whose `subject_id` is **its own user** (or a group it administers) that **this account did not create**. Each client keeps the list of key ids its account published; an unknown one raises a **blocking security alert** ("a key you did not create was published for your account"). Leaf volume is tiny, so a full scan of new leaves is cheap.
4. **Cross-device gossip.** Each client stores its latest verified checkpoint in the account's encrypted settings blob (`settings_enc`). Another device of the same account that sees a checkpoint **inconsistent** with it (consistency proof fails) raises the same alert. This catches a server showing different logs to different devices of one user.

> **Residual risk, stated honestly.** A server could show **two different users** two different logs (a split view). Self-monitoring does not catch that alone. It is detectable by any party that sees both views, which is what external **witnesses** provide; the Ed25519 checkpoint line is witness-compatible so this can be added later without a format change. Not in v1.

## 17.8 REST endpoints

All under `/api/v1/kt`, authenticated (any signed-in user, like the directory itself), rate-limited per [13](13-security.md). Guests have no access, because guest shares never wrap to a directory key.

| Method | Path | Response |
|---|---|---|
| `GET` | `/kt/log-key` | `{ origin, ed25519PublicKey, mldsa65PublicKey }` (base64) |
| `GET` | `/kt/checkpoint` | The latest signed note, `text/plain; charset=utf-8`, served verbatim from `kt_checkpoints.note` |
| `GET` | `/kt/checkpoint?treeSize=` | A specific historical checkpoint (for gossip comparison) |
| `GET` | `/kt/inclusion?leafIndex=&treeSize=` | `{ leafIndex, treeSize, proof: [base64 SHA-256 …] }` (RFC 9162 audit path, leaf to root order) |
| `GET` | `/kt/consistency?from=&to=` | `{ from, to, proof: [base64 SHA-256 …] }` |
| `GET` | `/kt/leaves?start=&end=` | `{ items: [ { leafIndex, leafData: base64 } ] }`, `end` exclusive, at most **1000** leaves per call |

Errors: `400 validation_failed` for a `treeSize` beyond the current size or `start >= end`; `404 not_found` for an unknown historical checkpoint.

`GET /keys/directory` is extended: every returned key carries `keyId`, `generation`, `algId`, `kemPub`, `sigPub`, `loggedAt`, `selfSig` and **`ktLeafIndex`**, which is everything step 2 needs to rebuild the leaf.

## 17.9 Server-side check at group enrollment

`POST /groups/{id}/members` ([04](04-rest-api.md), [09 §9.9](09-sharing-and-acl.md)) carries `memberKeyId` (the directory key the client verified and wrapped to) in addition to its existing fields. Before writing the grant the server checks, in one transaction:

1. `memberKeyId` is a `user_keys` row of `memberId` with `revoked_at IS NULL`, and it is that member's **current** (highest-generation) key.
2. That key has a `kt_leaves` publish leaf with `leaf_index < tree_size` of the latest checkpoint.

Otherwise → `409 key_not_transparent`, nothing written, audited as `group.enroll_rejected`.

> **Why the server checks at all.** The server runs the log, so its own check does **not** defend against a malicious server; that defence is the client procedure in §17.7. The server check is a **correctness guard** against honest bugs and stale clients, such as wrapping a group key to a key that was revoked or rotated after the client looked it up. It is cheap and it keeps the `group_key_grants` table free of grants to dead keys.

## 17.10 Safety numbers (format pinned now, UI is optional Phase 6.1)

A safety number lets two users compare keys out of band ([15](15-roadmap-and-versioning.md), Phase 6.1). The derivation is pinned here so all clients agree before the UI exists:

```text
fp(user) = SHA-256("NYXKT-FP-v1" ‖ user_id(16) ‖ kem_pub ‖ sig_pub)       for the user's current key
safety   = SHA-256("NYXKT-SAFETY-v1" ‖ min(fp(A), fp(B)) ‖ max(fp(A), fp(B)))   byte-wise order
display  = bytes 0..29 of safety as 6 chunks of 5 bytes;
           each chunk = (big-endian u40) mod 100000, zero-padded to 5 digits
           → 30 digits shown as 6 groups of 5
```

Sorting the two fingerprints makes the number identical on both sides. It changes whenever either user rotates their key, which is the intended signal.

## 17.11 Conformance vectors (`P4.3-CORE-1`)

`P4.3-CORE-1` ships, in the shared conformance set: leaf encodings for each `entry_type` with expected `leaf_hash`; trees of sizes 1–8, 13 and 1024 with expected roots; inclusion proofs for every leaf of the size-13 tree; consistency proofs for every `(from, to)` pair up to 13; a valid checkpoint plus variants with each signature line corrupted (both must be rejected); and safety numbers for two fixed key pairs. Generators are written against this chapter; any surface that disagrees fails CI ([implementation README](https://github.com/Nyxite/Nyxite/blob/main/implementation/README.md)).
