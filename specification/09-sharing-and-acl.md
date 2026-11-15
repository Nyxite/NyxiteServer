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

> **Trust note:** for a single share the sharer trusts the directory's public key (TLS + the directory's hybrid Ed25519 + ML-DSA-65 self-signature) for the grantee. The **key-transparency log is required at Phase 4.3** (G-3, v1.0.0) because group enrollment depends on it — a substituted key would expose a whole group's corpus — so group grants wrap **only to transparency-log-verified keys** (§9.9). Client-facing **safety-number verification** remains an optional Phase-6 hardening affordance ([15](15-roadmap-and-versioning.md)).

## 9.4 Link & guest shares — fragment key

1. Sharer's client mints a high-entropy link **token** and assembles the URL with the **file key in the fragment**:
   `https://nyxite.app/share/{token}#k={base64url(fileKey)}`.
2. The server stores only `link_token_hash` and a `shares` row — **not** the key (the fragment never reaches it).
3. A visitor opens the link: the browser keeps the fragment locally; `GET /share/{token}` ([04 §4.8](04-rest-api.md)) resolves the token → serves ciphertext / authorizes the relay; the **fragment key** decrypts client-side.
4. **Anonymous guests** thus join with the key from the link, **no server key exchange** — the privacy-preserving analogue of the master spec's "no key exchange" guarantee (the key comes from the link, not the server).
5. Guest edits store `author_id = null`.

> The link **is** the secret: anyone with the full URL can decrypt. Mitigations: high-entropy token, short `expires_at`, revocation, rate-limited access, and the usual fragment caveats (browser history). **[P]**

## 9.4a Points pinned in Phase 2.2 **[P]**

These fill gaps of §9.3 and §9.4 and are recorded as decisions in the planning repo (`OPEN-DECISIONS.md`, "Sharing, points pinned during Phase 2.2").
The fixtures `sharing.json` (P2.2-CORE-1) hold one example of each.

- Link token.
  The client mints 32 random bytes and encodes them as 43 base64url characters, well above the 128-bit minimum of §9.8.
  `POST /shares` sends only `linkTokenHash`, the SHA-256 of the token's ASCII characters, the hashing every other token of this server uses, so the server never sees the token before a visitor presents it.
  Letting the server mint the token was rejected, because the server would then hold the secret at creation.
- Share URL.
  `https://{host}/share/{token}#k={base64url(fileKey)}`, the file key of the current generation as 32 bytes.
  The fragment is never part of a request, and `GET /share/{token}` tells the guest the `keyId` its fragment key must match.
- A link share targets one file.
  Its fragment carries one file key, which opens no other file, so a folder or project link would be a link without keys.
  `POST /shares` answers `400` for a link to a folder or project.
- Object-key wraps.
  A client wraps the key of a file, folder or project to a member with hybrid HPKE, `info = "nyxite object key v1"` and `aad = object_id(16) ‖ key_id(16)`.
  The AAD binds a wrap to its object and its generation, so the server cannot hand a member one object's wrap as another's.
  The server stores the result as opaque bytes and never opens it.
- Subtree fan-out.
  Every folder has its own key (ST-1), so `POST /files/keys:batch` takes folder keys as well as file keys, each grant with exactly one of `fileId` and `folderId`.
  The share itself carries the target's key in `wrappedKeys`, the current generation at least.
  A batch entry is applied when the wrap is stored or was already stored, so a client drains its resumable queue without an `Idempotency-Key`, and rejected with `not_found`, `acl_denied`, `validation_failed` or `not_shared` otherwise.
- Who shares.
  The project owner creates, changes and revokes shares and hands out keys, as `resource:share` of [08 §8.5](08-authentication.md) says.
  A grantee may remove its own share, which leaves the object live for everyone else (DL-3).
  A grantee with read reach that tries to share gets `403 acl_denied`.
- What a write share covers.
  Content: blobs, the update log, snapshots and the relay.
  Structure changes in a shared tree (create, rename, move, delete) stay with the owner and answer `403 acl_denied`, because an object a grantee creates would need an owner, a quota and wraps to every member, which nothing specifies yet.
- Shared with me.
  `GET /shares` without a target lists the live account shares granted to the caller, so a recipient finds what it can open.
  Shared projects are not mixed into `GET /projects`, which stays the list of owned projects.
- One live account share per target and grantee.
  A second one answers `409 conflict`, and a change goes through `PATCH /shares/{id}`.
- Expiry and purge.
  A share counts while `revoked_at` is null and `expires_at` is null or in the future.
  The purge of an object deletes its shares, link hashes included, so no grant outlives what it grants.

## 9.5 Permission resolution

Effective permission for (principal, resource) = **max** over: ownership, direct grants, inherited folder/project grants, and (for guests) the resolving link's permission. The **server ACL** uses this to gate ciphertext access and relay writes; the **crypto layer** independently requires the right file key to decrypt. Admins get **structure/usage only — never content** (no key exists for them; no break-glass — [12](12-administration.md)).

> Implementation [P]: `ShareAccess` resolves this maximum for the content seam `IFileAccess` and for the structure endpoints alike, so every checkpoint, the relay's join, submit and periodic re-check included, sees one answer.
> Ownership is checked first, so an owner's checks cost the query they cost before shares existed.

> **No reach → `404`, not `403`.** When the resolved permission is **none** (the caller has no ownership/grant/link path to the addressed file/folder/project), the server returns **`404 not_found`** — identical to a non-existent id — so existence is never disclosed by an authz failure ([13 §13.6a](13-security.md)). `403 acl_denied` is used only when the caller **has read reach but lacks the action** (e.g. read-only collaborator writing, or a `blocked` account writing its own file), since existence is already known to them.

> **Account block (download-only).** If `users.status = 'blocked'` ([03](03-data-model.md)), the ACL layer **caps that principal's effective permission at read/download**: all writes (create/edit, `PUT …/blob`, relay `submit`, share create/rotate) are denied and **web-client sessions are refused**, while ciphertext **fetch/download** stays allowed so the user keeps local copies. Admin-set and reversible ([12 §12.6](12-administration.md)); every transition is audited. Purely metadata — no content or key is read to enforce it.

## 9.6 Revocation

Revocation is **two-layered** ([§9.1](#91-principles)):

1. **Instant ACL cutoff** — `DELETE /shares/{id}` sets `revoked_at`; the removed member can no longer fetch ciphertext or join the relay (enforced at every checkpoint: fetch, join, submit, periodic re-check). This is immediate.
   An open relay room is left at once as well, because the commit of the revoke, of a share change and of a move to Trash triggers a targeted re-check of the affected connections ([05 §5.4](05-realtime-collaboration.md)).
   The periodic re-check stays the backstop for a share that expires on its own.
2. **Cryptographic rotation** — to protect **future** content from a member who already holds the file key, a remaining member's client with write access **rotates the file key** (new generation: new FK, re-encrypt head/snapshot, re-wrap to remaining members) and bumps `files.key_generation` ([03](03-data-model.md)). Done client-side, in the background, by whichever eligible device comes online first.

> **Rotation concurrency:** the rotating client (any remaining member with write access, see below) generates a new FK (**new `key_id`, `generation + 1`**), re-encrypts the current head and writes a new snapshot under the new key, wraps the new FK to all remaining members, then `POST /files/{id}/keys/rotate { newKeyId, generation, wrappedKeys[], newHeadRef, nameEnc, metadataEnc, links }`. The server commits **only if** the submitted `generation == current + 1`, else `409 conflict` (another rotation won). In-flight CRDT updates tagged with the **old** `key_id` are accepted **until commit**; after commit they are rejected `412 key_generation_stale`, and the client re-encrypts/re-submits under the new key.

> Rotation as built in Phase 2.3, with the rules the user confirmed on 2026-11-15 [P]:
> the rotation is write-then-swap, so the new head exists before anything points to it.
> 1. The client stages the head sealed with the new key through `PUT /files/{id}/keys/rotate/head` (`Nyxite-Key-Id` = the new key, `Nyxite-Content-Hash`, and `Nyxite-Snapshot-Seq` for a text file or `If-Match` with the head seq it re-encrypts for any other file).
>    The server stores the ciphertext and a `file_rotation_heads` row ([03](03-data-model.md)), and the stage is no version yet, so every client keeps reading the old head.
> 2. The commit names the stage in `newHeadRef`, the base64url BLAKE3-256 content hash the stage carried, and the server turns it into the head version in the transaction that switches `files.key_generation`.
>    `newHeadRef` is required when the file has a head or its update log ever took an update, and absent when it has no content yet.
>    Uploading the new-key head through the normal upload paths before the commit was impossible, because they take only the current key, and committing first and uploading afterwards was rejected, because a client that fails in between leaves a head that a member added later with the new key only cannot open.
> 3. A text head must cover the whole log, its `Nyxite-Snapshot-Seq` equal to the last update the file has.
>    Anything that moved after staging, a newer update, a newer snapshot or a blob written in between, answers `409 version_conflict` and the newer state stays, so a rotation never replaces content it has not seen and never leaves an update sealed with the old key behind the new head (V1 of the review of 2026-11-15).
>    The client stages again and retries, with the retry and backoff rules of the client specs `12 §12.1`.
>    Refusing only a newer snapshot was rejected, because a member added later with the new key only would then load the new head without the edits after it and see a silently incomplete document.
>
> The commit also carries `nameEnc` and `metadataEnc` sealed again with the new key, because listings hand every member only its wrap of the current generation, which would no longer open a name sealed with the old key.
> `wrappedKeys` must wrap the new key to exactly the accounts that reach the file, the owner included, and the server checks the set against the live shares under the locks of the commit.
> A wrap to anyone else, a removed member above all, is `400`, and so is a commit that leaves out a member, who would otherwise keep its reach without a key for anything new.
>
> Any remaining member with write access rotates, from a session on an active device, and a reader gets `403 acl_denied` (decided by the user on 2026-11-15, replacing the owner-only rule of the first Phase 2.3 build).
> Owner-only rotation was rejected, because a revocation by an owner who then goes offline, or whose device is lost, would leave the file on the old key until the owner returns.
> The rules this needs:
> - `GET /files/{id}/keys/rotate/members` names the accounts to wrap to, for an account with write reach only.
>   It answers account ids, the file's generation and `rotationPending`, and nothing about how each member reaches the file, its permission or the file's links, because the rotating client needs no more to look up the directory keys and wrap.
>   A writer learns who else has access, which is the price of not waiting for the owner, and a reader, who cannot rotate, learns nothing.
> - Authorization is checked by the server under the locks of the commit, so a writer whose share was revoked a moment ago cannot carry a rotation through.
> - Concurrent rotations by different writers are ordered by the generation guard: exactly one commits, the others get `409 conflict` and read the file again, where they find the new generation and their own wrap of it.
> - The audit event `key.rotate` names the rotating account as its actor and records `byOwner`, so the owner sees who completed a revocation.
> - The owner's `DELETE /shares/{id}` marks every file the share reached with `files.rotation_pending_at`, the file itself, every file in a shared folder's subtree or every file of a shared project, and announces each in the change feed.
>   `FileDto.rotationPending` and the members listing show the mark to accounts with write reach only, and the next committed rotation clears it.
>   A grantee that removes its own share (DL-3) marks nothing, because it gave its access up and no rotation is needed.
>   A share that expires on its own marks nothing either, because no request marks its moment, so the owner's client queues that rotation itself.
>
> Lock order: the commit takes the project row `FOR NO KEY UPDATE`, then the file row `FOR UPDATE`, then the stage `FOR UPDATE`.
> Every share create, change and revoke takes the project row `FOR SHARE` before anything else, so a share of the file, of a folder above it or of the project lands wholly before the member check or wholly after the commit (V5).
> `FOR NO KEY UPDATE` was chosen over `FOR UPDATE`, because inserts that reference the project take `FOR KEY SHARE` and must not wait for a rotation.
> The stage lock keeps the cleaner of abandoned stages, which skips locked rows, from deleting a stage, and the collector its blob, while a commit turns it into the head (V6).
>
> Links follow the rotating account's choice in `links` (decided by the user on 2026-11-15, V2):
> - `revoke`, the default when absent, revokes every link of the file, frozen ones included, audited as `share.revoke` with `by: rotation`.
>   A revoked link answers `410 share_revoked`, and the rotating client offers to create new links under the new key when its account may create links.
> - `keep` freezes every link that still follows the file at the old generation: `shares.frozen_generation`, the head seq and the name and metadata ciphertexts as they were before the rotation.
>   A frozen link keeps serving exactly that content, which its fragment key opens, and nothing written later: `GET /share/{token}` answers `frozen: true` with the old `keyId`, name and head, `GET /share/{token}/blob` streams the frozen head, the link is read only, and its relay join and socket ticket answer `link_frozen`, because nothing in the room opens with its key.
>   A guest connected to the room at the commit is closed with `link_frozen` by a targeted re-check.
>   A link frozen by an earlier rotation stays at its generation.
>   Keeping the links of a text file needs a head snapshot under the old key that covers the whole log, otherwise `409 version_conflict`, because the frozen link would miss the updates after its head, which the log pruning removes once the new head covers them.
>   A file excluded from sync takes no snapshot, so its links freeze at the head it has, until the content purge removes it.
> Serving a link the current state, which the first build did, was rejected, because a link that answers as live while its key opens nothing is the worst outcome.
> Revoking unconditionally was rejected, because a rotation for one removed account would then end every unrelated link without a choice.
>
> An excluded file rotates without a head (decided by the user on 2026-11-15, V4): the commit moves key, name and metadata to the new generation, and the old content stays sealed with the old key until the content purge of [06 §6.2](06-sync.md) removes it.
> Waiting for the purge was rejected, because the second layer of revocation would be blocked for up to Trash plus grace window.
>
> The commit is idempotent under `Idempotency-Key`, which it requires, and the replay of a committed request answers `204` again.
> Older wraps and versions stay as they are, so a member who had a generation keeps reading the version history sealed with it, and `GET /files/{id}/keys` returns every generation.
> The commit records `keyrotate`, the file's `structure` upsert and the new head's `blob` change in the feed ([06](06-sync.md)) and audits `key.rotate` with the generation, the new `key_id`, the member count, the link choice and the numbers of revoked and frozen links.
> Stages that the commit did not take, a losing attempt's for example, are dropped with it, and an abandoned stage expires after `NYXITE__Retention__OrphanBlobAgeHours` and counts against the owner's quota until then.
> No rate limit is specified for rotation, and it needs none of its own, because it needs write reach, every commit moves the generation by one and stages are bounded by the quota.
> The relay sends no rotation event to account members, because a writer meets `key_generation_stale` on its next submit and a reader meets the new `keyId`.
> Rotating project and folder keys (ST-1) is not part of Phase 2.3, because no endpoint for it is specified, and stays open.
> A removed member keeps the old folder and project keys until then, so a later name sealed with them stays readable to it if its ciphertext ever reaches it again, which is why it is planned for Phase 4.4 at the latest.

> **Honest limitation:** content the removed member **already downloaded** can't be un-seen — true of any system. The combination (instant relay cutoff + forward-secrecy rotation) is the strongest practical revocation under E2EE. This differs from the master spec's "clean revocation, no key rotation," which was only possible when the server held keys.

## 9.7 Audit

Share creation, permission changes, revocations, and **key rotations** are written to the audit log with target/actor — **never** content or keys ([12](12-administration.md)). Link **access** by guests is auditable (token hash + IP/UA), never the fragment key.

## 9.8 Limits & abuse controls

- Share creation and link access are **rate-limited** ([13](13-security.md)).
- Link tokens ≥128-bit, stored hashed; fragment keys ≥256-bit, never transmitted to the server.
- Folder/project-scoped writes constrained to the shared subtree.

## 9.9 Group sharing (enterprise/family groups)

Group sharing is **additive** alongside the per-file/subtree account shares above (G-2) — a **group-key layer** ([07 §7.2a](07-encryption.md)) so a file readable by a whole group is stored **once** and enrolling a reader is **one blob (O(1))**, not a per-file re-wrap. It serves **family** (all members read shared data) and **enterprise** (a *managers* group reads all of a team's files; a worker reads only their own). Membership reuses the §3.2a `groups`/`group_members` rows ([03 §3.2b](03-data-model.md)); this section adds the two-layer access model for group-key blobs. Steps P4.4-SRV-1..4.

**Enrollment (transparency-gated, one grant).** A client that already holds the group key adds a member by wrapping the group private key under the newcomer's personal public key and writing **one** `group_key_grants` row via `POST /groups/{id}/members` ([04](04-rest-api.md)). Because a single substituted public key would expose the group's **entire** corpus (not one file), the enrolling **client** verifies the member's directory key against the key-transparency log before wrapping, and the server checks that the named `memberKeyId` is the member's current, logged, unrevoked key before accepting the grant (G-3, procedure and rationale in [17 §17.7, §17.9](17-key-transparency.md)); otherwise `409 key_not_transparent`. No file is touched. Enrollment is subject to the **member-count limit** ([12 §12.7](12-administration.md), enforced by row count only).

**Grant a file to a group.** Wrap that file's DEK to the group **public key** and store one `file_keys` group-principal row (per scope, [03 §3.2b](03-data-model.md)); a subtree grant drains the same resumable batch queue as §9.3.

**Reader-group attachment (auto-wrap policy).** A project/folder may name a group whose public key **new files are auto-wrapped to** on creation, in addition to the author's own key — the enterprise "manager reads all" path. It rides the **existing per-project/folder/file cascade** (`inherit` / a specific group / none, same inheritance as sync policy [06](06-sync.md)); it is **client-enforced at file creation**, and the server stores only the **opaque** `reader_group_attachment` structure field and never learns which group it names ([03 §3.2b](03-data-model.md)). **Licensed enterprise feature (L-3):** reader-group auto-wrap is gated behind entitlement flag `ent.reader_groups` ([16 §16.5](16-licensing-and-entitlement.md)) — plain family group-read sharing stays free; in **community mode** (or a lapsed license) no new reader-group attachments are created and existing ones freeze read-only.

**Fetch-ACL for group-key blobs.** The two walls of §9.1 extend to groups: the **crypto wall** holds because the server stores only opaque grants and DEK-to-group wraps; the **server ACL** still decides **which client may fetch which group-key blob**. A member may pull a grant/DEK-to-group wrap only within the **target-aware RBAC `scope`** (AD-1, [12 §12.6](12-administration.md)) — group enrollment and key management are gated by the caller's scoped permission over that group; no reach → **`404`** (existence-hiding, [13 §13.6b](13-security.md)). Signed writes are unchanged: each client signs with the group **hybrid Ed25519 + ML-DSA-65** key ([07 §7.3](07-encryption.md)); others verify on read; the server verifies without decrypting.

**Removal & scope-scoped rotation.** Reuses the §9.6 spectrum at the group-key level, **scoped to the affected project/time-period** (G-4):

1. **Soft** (trusted departure) — `DELETE /groups/{id}/members/{uid}` deletes the member's live grant. Instant ACL cutoff.
2. **Rotate** (forward secrecy) — a remaining member's client mints a **new group key for the affected scope**, re-wraps it to the remaining members (new generation), and commits `POST /groups/{id}/keys/rotate { scopeId, newGeneration, grants[], dekWraps[] }`. The server commits **only if** `newGeneration == current + 1` **for that scope**, else `409 conflict` (concurrent-rotation loser); post-commit wraps tagged with the old generation → `412 key_generation_stale`. **Only the named scope is touched** — other scopes keep their keys.
3. **Full** (seal the scope) — rotate **and** re-seal the affected scope's file DEKs under the new group key (`dekWraps[]`), re-wrapping only the small DEKs, never the ciphertext.

> **Honest limitation (unchanged, [§9.6](#96-revocation)):** rotation only guarantees the removed member reads nothing **new** — content they already decrypted can't be recalled. Surfaced in UI + docs.

> **Recovery composes for free.** The group private key is wrapped under a member's personal public key, so recovering the personal key ([07 §7.8](07-encryption.md)) automatically restores group access — no special path. A member who lost all devices **and** their recovery phrase is **re-enrolled** by a group admin (one new grant).
