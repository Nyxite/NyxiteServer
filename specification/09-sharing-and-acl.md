# 09 — Sharing & Access Control (E2EE)

> **Model change.** Sharing stays **end-to-end encrypted**: the server never sees a usable file key. Account shares wrap the file key to the recipient's **public key** (HPKE); link/guest shares carry the key in the **URL fragment**. Access control has **two layers** — a server-enforced ACL (who may reach the ciphertext/relay) and the cryptographic layer (who can decrypt). Concrete model below is **[P]**.

## 9.1 Principles

- **Two enforcement layers:**
  1. **Server ACL** — decides who can fetch ciphertext / join the relay. Enforced server-side; revocation here is **instant**.
  2. **Cryptographic access** — decides who can *decrypt*, via possession of the (wrapped or fragment) file key. The server can't grant or read this.
- **Two share kinds:** account (`user_grant`) and link.
- **Two permissions:** `read`, `write`.
- **Three target scopes:** file, folder (subtree), project — confirmed earlier.

## 9.2 Share entity

Backed by `shares` ([03](03-data-model.md)); wrapped keys for account shares live in `file_keys`.

| Concept | Field | Notes |
|---------|-------|-------|
| Target | one of `file_id` / `folder_id` / `project_id` | folder/project cascade to descendants |
| Kind | `user_grant` \| `link` | |
| Grantee | `grantee_id` (account share) | a Nyxite user with a published public key |
| Link secret | `link_token_hash` | only the token **hash**; the **key is in the URL fragment**, never stored |
| Permission | `read` \| `write` | |
| Lifetime | `expires_at`, `revoked_at` | |
| Wrapped key(s) | `file_keys` rows | FK wrapped to each member's public key (account shares) |

> **API target shape:** the API addresses a target uniformly via **`targetType` + `targetId`** (`file` \| `folder` \| `project`) everywhere — `GET /shares?targetType=&targetId=`, `CreateShareRequest { targetType, targetId, ... }` ([04](04-rest-api.md)). The DB columns `file_id`/`folder_id`/`project_id` are the persisted form of that one target.

## 9.3 Account (user-grant) shares — key wrapping

1. Sharer's client looks up the grantee's **public key** from the server key directory (`user_keys`, [03](03-data-model.md)).
2. Client **wraps the file key** to that public key via HPKE and uploads the wrapped blob (`file_keys` row) plus a `shares` row.
3. The grantee's client downloads the wrapped key and **unwraps it with their private key** — the server only ever held an opaque blob. ✅ Still E2EE.
4. For **folder/project (subtree) shares**, the client enumerates the subtree and wraps **each current file-key** to the grantee in batches via `POST /files/keys:batch { grants: [ { fileId, keyId, memberId, wrappedKey } ] }` (idempotent, partial-success per item; [04](04-rest-api.md)).

> **Completeness rule:** a subtree share is **"fully granted"** only once **every current file-key in the subtree** has a wrapped row for the grantee. Until then the client keeps draining its (resumable) batch queue.

> **Trust note:** the sharer trusts the directory's public key for the grantee. Key-transparency / verification (e.g. safety numbers) is a hardening item ([15](15-roadmap-and-versioning.md)).

## 9.4 Link & guest shares — fragment key

1. Sharer's client mints a high-entropy link **token** and assembles the URL with the **file key in the fragment**:
   `https://nyxite.app/share/{token}#k={base64url(fileKey)}`.
2. The server stores only `link_token_hash` and a `shares` row — **not** the key (the fragment never reaches it).
3. A visitor opens the link: the browser keeps the fragment locally; `GET /share/{token}` ([04 §4.8](04-rest-api.md)) resolves the token → serves ciphertext / authorizes the relay; the **fragment key** decrypts client-side.
4. **Anonymous guests** thus join with the key from the link, **no server key exchange** — the privacy-preserving analogue of the master spec's "no key exchange" guarantee (the key comes from the link, not the server).
5. Guest edits store `author_id = null`.

> The link **is** the secret: anyone with the full URL can decrypt. Mitigations: high-entropy token, short `expires_at`, revocation, rate-limited access, and the usual fragment caveats (browser history). **[P]**

## 9.5 Permission resolution

Effective permission for (principal, resource) = **max** over: ownership, direct grants, inherited folder/project grants, and (for guests) the resolving link's permission. The **server ACL** uses this to gate ciphertext access and relay writes; the **crypto layer** independently requires the right file key to decrypt. Admins get **structure/usage only — never content** (no key exists for them; no break-glass — [12](12-administration.md)).

> **No reach → `404`, not `403`.** When the resolved permission is **none** (the caller has no ownership/grant/link path to the addressed file/folder/project), the server returns **`404 not_found`** — identical to a non-existent id — so existence is never disclosed by an authz failure ([13 §13.6a](13-security.md)). `403 acl_denied` is used only when the caller **has read reach but lacks the action** (e.g. read-only collaborator writing, or a `blocked` account writing its own file), since existence is already known to them.

> **Account block (download-only).** If `users.status = 'blocked'` ([03](03-data-model.md)), the ACL layer **caps that principal's effective permission at read/download**: all writes (create/edit, `PUT …/blob`, relay `submit`, share create/rotate) are denied and **web-client sessions are refused**, while ciphertext **fetch/download** stays allowed so the user keeps local copies. Admin-set and reversible ([12 §12.6](12-administration.md)); every transition is audited. Purely metadata — no content or key is read to enforce it.

## 9.6 Revocation

Revocation is **two-layered** ([§9.1](#91-principles)):

1. **Instant ACL cutoff** — `DELETE /shares/{id}` sets `revoked_at`; the removed member can no longer fetch ciphertext or join the relay (enforced at every checkpoint: fetch, join, submit, periodic re-check). This is immediate.
2. **Cryptographic rotation** — to protect **future** content from a member who already holds the file key, a remaining member's client **rotates the file key** (new generation: new FK, re-encrypt head/snapshot, re-wrap to remaining members) and bumps `files.key_generation` ([03](03-data-model.md)). Done client-side, in the background.

> **Rotation concurrency:** the rotating client (owner or a writer driving revocation) generates a new FK (**new `key_id`, `generation + 1`**), re-encrypts the current head and writes a new snapshot under the new key, wraps the new FK to all remaining members, then `POST /files/{id}/keys/rotate { newKeyId, generation, wrappedKeys[], newHeadRef }`. The server commits **only if** the submitted `generation == current + 1`, else `409 conflict` (another rotation won). In-flight CRDT updates tagged with the **old** `key_id` are accepted **until commit**; after commit they are rejected `412 key_generation_stale`, and the client re-encrypts/re-submits under the new key.

> **Honest limitation:** content the removed member **already downloaded** can't be un-seen — true of any system. The combination (instant relay cutoff + forward-secrecy rotation) is the strongest practical revocation under E2EE. This differs from the master spec's "clean revocation, no key rotation," which was only possible when the server held keys.

## 9.7 Audit

Share creation, permission changes, revocations, and **key rotations** are written to the audit log with target/actor — **never** content or keys ([12](12-administration.md)). Link **access** by guests is auditable (token hash + IP/UA), never the fragment key.

## 9.8 Limits & abuse controls

- Share creation and link access are **rate-limited** ([13](13-security.md)).
- Link tokens ≥128-bit, stored hashed; fragment keys ≥256-bit, never transmitted to the server.
- Folder/project-scoped writes constrained to the shared subtree.

## 9.9 Group sharing (enterprise/family groups)

Group sharing is **additive** alongside the per-file/subtree account shares above (G-2) — a **group-key layer** ([07 §7.2a](07-encryption.md)) so a file readable by a whole group is stored **once** and enrolling a reader is **one blob (O(1))**, not a per-file re-wrap. It serves **family** (all members read shared data) and **enterprise** (a *managers* group reads all of a team's files; a worker reads only their own). Membership reuses the §3.2a `groups`/`group_members` rows ([03 §3.2b](03-data-model.md)); this section adds the two-layer access model for group-key blobs. Steps P4.4-SRV-1..4.

**Enrollment (transparency-gated, one grant).** A client that already holds the group key adds a member by wrapping the group private key under the newcomer's personal public key and writing **one** `group_key_grants` row via `POST /groups/{id}/members` ([04](04-rest-api.md)). Because a single substituted public key would expose the group's **entire** corpus (not one file), the server **verifies a key-transparency inclusion proof (Phase 4.3) for the member's directory key before accepting the grant** (G-3); a directory-substituted key is rejected `409 key_not_transparent`. No file is touched. Enrollment is subject to the **member-count limit** ([12 §12.7](12-administration.md), enforced by row count only).

**Grant a file to a group.** Wrap that file's DEK to the group **public key** and store one `file_keys` group-principal row (per scope, [03 §3.2b](03-data-model.md)); a subtree grant drains the same resumable batch queue as §9.3.

**Reader-group attachment (auto-wrap policy).** A project/folder may name a group whose public key **new files are auto-wrapped to** on creation, in addition to the author's own key — the enterprise "manager reads all" path. It rides the **existing per-project/folder/file cascade** (`inherit` / a specific group / none, same inheritance as sync policy [06](06-sync.md)); it is **client-enforced at file creation**, and the server stores only the **opaque** `reader_group_attachment` structure field and never learns which group it names ([03 §3.2b](03-data-model.md)). **Licensed enterprise feature (L-3):** reader-group auto-wrap is gated behind entitlement flag `ent.reader_groups` ([16 §16.5](16-licensing-and-entitlement.md)) — plain family group-read sharing stays free; in **community mode** (or a lapsed license) no new reader-group attachments are created and existing ones freeze read-only.

**Fetch-ACL for group-key blobs.** The two walls of §9.1 extend to groups: the **crypto wall** holds because the server stores only opaque grants and DEK-to-group wraps; the **server ACL** still decides **which client may fetch which group-key blob**. A member may pull a grant/DEK-to-group wrap only within the **target-aware RBAC `scope`** (AD-1, [12 §12.6](12-administration.md)) — group enrollment and key management are gated by the caller's scoped permission over that group; no reach → **`404`** (existence-hiding, [13 §13.6b](13-security.md)). Signed writes are unchanged: each client signs with the group **hybrid Ed25519 + ML-DSA-65** key ([07 §7.3](07-encryption.md)); others verify on read; the server verifies without decrypting.

**Removal & scope-scoped rotation.** Reuses the §9.6 spectrum at the group-key level, **scoped to the affected project/time-period** (G-4):

1. **Soft** (trusted departure) — `DELETE /groups/{id}/members/{uid}` deletes the member's live grant. Instant ACL cutoff.
2. **Rotate** (forward secrecy) — a remaining member's client mints a **new group key for the affected scope**, re-wraps it to the remaining members (new generation), and commits `POST /groups/{id}/keys/rotate { scopeId, newGeneration, grants[], dekWraps[] }`. The server commits **only if** `newGeneration == current + 1` **for that scope**, else `409 conflict` (concurrent-rotation loser); post-commit wraps tagged with the old generation → `412 key_generation_stale`. **Only the named scope is touched** — other scopes keep their keys.
3. **Full** (seal the scope) — rotate **and** re-seal the affected scope's file DEKs under the new group key (`dekWraps[]`), re-wrapping only the small DEKs, never the ciphertext.

> **Honest limitation (unchanged, [§9.6](#96-revocation)):** rotation only guarantees the removed member reads nothing **new** — content they already decrypted can't be recalled. Surfaced in UI + docs.

> **Recovery composes for free.** The group private key is wrapped under a member's personal public key, so recovering the personal key ([07 §7.8](07-encryption.md)) automatically restores group access — no special path. A member who lost all devices **and** their recovery phrase is **re-enrolled** by a group admin (one new grant).
