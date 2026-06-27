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
