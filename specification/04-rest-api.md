# 04 — REST API

> **E2EE.** Endpoints serve/accept **ciphertext and wrapped keys**. There is **no server search** and **no server diff** (both client-side). New endpoints cover **key directory, device enrollment, recovery, and share-key wrapping**. All routes/DTOs/codes are **[P]**.

## 4.1 Conventions

- **Base path:** `/api/v1`. URL-versioned. **[P]**
- **Auth:** `Authorization: Bearer <token>` on `/api/v1/**` except the auth and public-share endpoints. The bearer is **the server's own access token** (native auth by default; the enterprise Keycloak/OIDC profile resolves to the same token — [08](08-authentication.md)). Auth endpoints live under `/api/v1/auth` ([§4.3](#43-endpoints)); public share endpoints under `/share/**` ([§4.8](#48-public-share-endpoints)).
- **Content type:** `application/json` for structure/metadata; binary streams for ciphertext blobs.
- **IDs:** UUIDv7. **Timestamps:** RFC 3339 UTC. **[P]**
- **Pagination:** query `?cursor=<opaque>&limit=<n>` (default `50`, max `200`); response envelope `{ "items": [...], "nextCursor": <opaque|null> }`. The cursor is an **opaque base64url server token** — clients must not parse it.
- **Idempotency:** `Idempotency-Key` is **required on POST creates**. The server stores `key → response` for **24h** scoped to `(user, endpoint)`; a replay returns the original response/status; the same key with a **different body** → `409 idempotency_conflict`. `POST /auth/register` is exempt: there is no user to scope the key to before the account exists, and a retried registration is already safe because the unique email answers `409 conflict`.
- **Names in payloads are ciphertext** (`nameEnc`), never plaintext.
- **Binary values in JSON** (ciphertext, wrapped keys, public keys, hashes) are **base64url without padding**, one encoding everywhere so no client has to guess per field.
- **OpenAPI: contract-first.** The canonical wire contract is the hand-maintained [`openapi/v1.yaml`](../openapi/v1.yaml) in this repo; the running server serves it as JSON at `/openapi/v1.json`. It was chosen over code-first generation so clients can be prepared and built against a fixed contract **before** server code exists. CI fails the server if its routes or DTOs drift from the document (contract tests), and every client generates or validates its API layer from the same file. The contract tests compare every mapped route and every JSON request type with the document, and they check the status, media type and body of every response the integration tests receive against it, where a property the document does not name counts as drift. The cross-cutting errors `400 validation_failed`, `401`, `403`, `429`, `500` and `503` are stated once in the document's conventions instead of on every operation, because they apply everywhere and repeating them would hide the errors that are specific to an operation. A change to the wire contract is a change to that file first, then to code.

## 4.2 Resource map

| Area | Base |
|------|------|
| Auth (native; enterprise OIDC) | `/api/v1/auth` |
| Projects / Folders / Files (structure) | `/api/v1/projects`, `/folders`, `/files` |
| File content (ciphertext) | `/api/v1/files/{id}/blob`, `/crdt/*` |
| File keys (wrapped) | `/api/v1/files/{id}/keys` |
| Versions / history | `/api/v1/files/{id}/versions` |
| Shares | `/api/v1/shares` |
| Groups (file-sharing / group-key) | `/api/v1/groups` |
| Keys & devices | `/api/v1/keys`, `/api/v1/devices`, `/api/v1/recovery` |
| Key transparency | `/api/v1/kt` ([17](17-key-transparency.md)) |
| Sync | `/api/v1/sync` |
| Me / settings | `/api/v1/me` |
| Admin | `/api/v1/admin/**` |
| Public share | `/share/**` (unauthenticated, token-scoped) |
| Support relay (only when `support.enabled`) | `/api/v1/support/**` ([§4.9](#49-support-relay-endpoints)) |

## 4.3 Endpoints

### Auth (native by default; enterprise OIDC)
Native, server-owned auth ([08 §8.1](08-authentication.md)); these endpoints issue/refresh **the server's own tokens**. Unauthenticated except where marked (auth'd). The enterprise profile adds `GET /auth/oidc/authorize` + `/auth/oidc/callback`, which resolve to the same internal token.
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/register` | Create a native account `{ email, displayName, password, clientKind }` (peppered Argon2id verifier — [08 §8.1](08-authentication.md)). Emails a verification code. Email verification, then factor enrollment, required before full login |
| `POST` | `/auth/email/verify` / `/auth/email/verify/resend` | (auth'd, limited session allowed) Confirm the email `{ code }` / send a new code |
| `POST` | `/auth/login` | Password step `{ email, password, clientKind }` → `{ challenge:"second_factor_required", mfaToken, methods }` (`methods` ⊆ `totp`, `email`, `backup_code`), or `{ challenge:"enrollment_required", accessToken, refreshToken, accessTokenExpiresAt }` of an enrollment-limited session when the account has no second factor yet (password alone never yields a full token) |
| `POST` | `/auth/login/totp` | Complete login `{ mfaToken, totpCode }` → `{ accessToken, refreshToken }` |
| `POST` | `/auth/login/email/send` / `/auth/login/email` | Email a sign-in code for `{ mfaToken }` / complete login `{ mfaToken, code }` (accounts with email codes only) |
| `POST` | `/auth/login/backup-code` | Complete login `{ mfaToken, code }` with a single-use backup code |
| `POST` | `/auth/totp/enroll` / `/auth/totp/verify` | (auth'd) Enroll/confirm a TOTP factor. Enroll takes `{ stepUpToken }` once the account has a factor |
| `POST` | `/auth/email-otp/enroll` / `/auth/email-otp/verify` | (auth'd) Enable emailed sign-in codes as a factor. Enroll takes `{ stepUpToken }` once the account has a factor |
| `POST` | `/auth/backup-codes` | (auth'd) `{ stepUpToken }` → a new set of backup codes, shown once |
| `POST` | `/auth/step-up` / `/auth/step-up/email` / `/auth/step-up/passkey/options` | (auth'd) Prove a factor again → single-use `stepUpToken` for one factor change ([08 §8.2](08-authentication.md)) |
| `POST` | `/auth/webauthn/register/options` / `/auth/webauthn/register` | (auth'd) Register a passkey (stores public credential only). Options take `{ stepUpToken }` once the account has a factor |
| `POST` | `/auth/webauthn/assert/options` / `/auth/webauthn/assert` | Passkey login → `{ accessToken, refreshToken }` (sufficient alone) |
| `POST` | `/auth/refresh` | Rotate a refresh token → new `{ accessToken, refreshToken }` |
| `POST` | `/auth/logout` | Revoke the presented refresh token / session |
| `POST` | `/auth/socket-ticket` | Mint a single-use relay socket ticket `{ ticket, expiresAt }` (60 s, [08 §8.4](08-authentication.md)). Needs a full session |
| `POST` | `/auth/password/forgot` / `/auth/password/reset` | Email-based reset — **restores login only**, never content ([08 §8.1](08-authentication.md)) |

### Projects / Folders / Files (structure)
Same shape as a normal CRUD tree, but **names are ciphertext**:
| Method | Path | Purpose |
|--------|------|---------|
| `GET/POST` | `/projects`, `/projects/{id}` (+ PATCH/DELETE) | Project CRUD (`nameEnc`) |
| `GET` | `/projects/{id}/folders` | List all folders of a project, flat; the client builds the tree from `parentFolderId` |
| `GET` | `/projects/{id}/files` | List all files of a project, flat; files at the project root have `folderId` null |
| `POST/GET/PATCH/DELETE` | `/folders`, `/folders/{id}` | Folder CRUD/move (`nameEnc`, `parentFolderId`) |
| `GET` | `/folders/{id}/files` | List files directly in a folder |
| `GET` | `/projects/{id}/keys`, `/folders/{id}/keys` | The caller's wrapped key(s) of the project or folder ([03 `structure_keys`](03-data-model.md)) |
| `POST` | `/keys/lookup` | The caller's wrapped keys of up to 500 projects, folders and files in one request |
| `GET` | `/trash` | What the caller deleted and can still restore |
| `POST` | `/trash/projects/{id}/restore`, `/trash/folders/{id}/restore`, `/trash/files/{id}/restore` | Restore from Trash |
| `POST/GET/PATCH/DELETE` | `/files`, `/files/{id}` | File CRUD/move/policy. `POST` sets `contentType` (**immutable**); `PATCH` updates **only** `nameEnc`, `syncPolicy`, `parentFolderId` (move), `metadataEnc` |

Rules of the structure endpoints **[P]**:

- **Create.** The client allocates `id` (UUIDv7) and sends `ownerWrappedKey`, the object's own key wrapped to itself, with every project, folder and file. The server checks what it can without a key: `nameEnc` and `metadataEnc` are NYXC frames within `NYXITE__Limits__NameEncMaxBytes` / `__MetadataEncMaxBytes`, their `key_id` is the key in `ownerWrappedKey`, and the wrapped key has the size of a 32-byte key sealed with hybrid HPKE. `Idempotency-Key` is required. A replay answers the stored response, an `id` that is taken answers `409 conflict`.
- **Update.** `PATCH` changes only what it names. A field sent as `null` is a value where null means something: `parentFolderId` null moves to the project root, `metadataEnc` null clears it, a folder's `syncPolicy` null follows the parent. A new `nameEnc` or `metadataEnc` must name the object's current key.
- **Move.** A parent must be a live folder of the same project, otherwise `404`. A folder cannot be moved into itself or its subtree (`400`). Moves of one project run one after the other, so two crossing moves cannot close a loop.
- **Delete.** Always a soft delete (DL-1). A folder takes its subtree with it and a project everything in it, with one `deleted_at` and one audit event that carries the counts. Trashed objects answer `404` and are left out of listings.
- **Trash.** `GET /trash` lists what the caller deleted directly and can still restore, newest first, each entry with the object, the end of its Trash window (`NYXITE__Retention__TrashWindowDays`) and the counts of folders and files that went along. What only went along is not listed on its own. `POST /trash/{projects|folders|files}/{id}/restore` brings an entry back with what its delete took along, as one audited event. The project and the folder it lies in must be live, otherwise `409 conflict` and the client restores those first. Restoring into the project root instead was rejected, because the object would reappear where nobody put it. Restoring something that is live answers `200` and changes nothing. After the window the entry answers `404`, because the grace period belongs to an admin (DL-4). The paths are under `/trash`, because `POST /files/{id}/restore` already restores a version.
- **Keys of many objects.** Every returned project, folder and file carries `wrappedKey`, the caller's wrap of the object's current key, so a fresh device lists a tree without a single key request. `?keys=false` on any read leaves it out, for a client whose cache is warm, which saves about 1.6 KB per object. `POST /keys/lookup` then returns the wrapped keys of up to 500 named objects, all live generations, also for objects in Trash, and leaves out what the caller cannot reach. Keys only in a separate request were rejected, because every first listing would cost a second round trip and clients would hold objects without keys.
- **Who may write.** A session on an **active device**, because only a device that holds the identity key can have produced the names and wrapped keys (`403 device_not_active` otherwise), and an account that is not blocked (`403 account_blocked`). Reading needs a full session only.
- **Reach.** Until shares exist (Phase 2.2) reach is ownership of the project. Everything else answers `404`.
- **Paging.** Lists run in id order, which for UUIDv7 is creation order, with the standard envelope and `limit` 1 to 200, default 50.

### File content (ciphertext)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/blob` | Stream current **ciphertext** (server never decrypts) |
| `PUT` | `/files/{id}/blob` | Upload new **ciphertext** for ink/binary (LWW); body is already encrypted. Client sends the parent version as **`If-Match: <seq>`**. If the server head `!= seq` (concurrent write) the server applies **last-write-wins by server-received time** and returns **`409 conflict`** with the winning version metadata, **retaining the losing bytes as a sibling `file_versions` row** (not head) so nothing is lost ([06 §6.5](06-sync.md)) |
| `GET` | `/files/{id}/crdt/log?since={seq}` | Encrypted CRDT updates after a cursor (REST fallback for the relay) |
| `POST` | `/files/{id}/crdt/log` | Submit **encrypted** CRDT update(s) (REST fallback) |
| `GET` | `/files/{id}/snapshot` | Stream of the latest **encrypted** snapshot; `Nyxite-Snapshot-Seq` names the last update it contains |
| `PUT` | `/files/{id}/snapshot` | Upload a client-made **encrypted** snapshot of a text file. Headers `Nyxite-Snapshot-Seq`, `Nyxite-Content-Hash`, `Nyxite-Key-Id`. It becomes the head version. A snapshot older than the stored head answers `409 conflict`, one that names an update the log does not have `400` |

Rules of the content endpoints **[P]**:

- **Bodies are raw NYXC frames**, at most `NYXITE__Limits__MaxInlineBlobBytes`. The server checks the frame layout and that the frame's `key_id` equals `Nyxite-Key-Id` and the file's current key, otherwise `412 key_generation_stale`. It cannot check that the content hash matches the content.
- **Text files have no blob upload.** A text file is written through its update log and snapshots, a blob file through `PUT /files/{id}/blob`. The other path answers `400`.
- **`If-Match` is the version `seq` the upload is based on**, `0` for the first version. The `409` of a lost write carries `winner` and `sibling`, the version the lost bytes were kept as.
- **`excluded` files take no content** (`409 excluded_content`). An upload that would exceed the owner's quota answers `413 payload_too_large`. Usage is the ciphertext size of all versions of all files the user owns, Trash included, and is reported as `usageBytes` by `GET /me`.
- **Update log.** `POST /files/{id}/crdt/log` takes up to 100 updates, each with a client-chosen `clientUpdateId`, and answers the `seq` of each. `GET` returns up to 500 updates after `since`. Updates a snapshot covers may be pruned, so a client that is behind the head snapshot loads the snapshot first.
- **Who may write** and **reach** are as for the structure endpoints.

#### Chunked upload / download (Phase 5.1, [07 §7.4a](07-encryption.md))
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/files/{id}/chunks:missing` | Body `{ addresses: [base64url …] }` (at most 1000) → `{ missing: [ … ] }`, the subset not yet stored **for this file**. Used to start and to resume an upload |
| `PUT` | `/files/{id}/chunks/{address}` | Upload one chunk ciphertext (at most 4 MiB + 61 B frame overhead, else `413`). Write-once: an existing address → `200` without rewriting, a new one → `201`. Counts against quota immediately |
| `POST` | `/files/{id}/blob:commit` | Commit a chunked version: header `If-Match: <parentSeq>`, body `{ manifestAddress, chunks: [address …], keyId }`. The manifest frame is uploaded beforehand through the same `PUT /files/{id}/chunks/{manifestAddress}`. The server checks that the manifest and every listed chunk exist for this file (`400 validation_failed` naming the first missing one otherwise), then applies **exactly** the LWW rules of `PUT /files/{id}/blob` (head advance or `409 conflict` + sibling version) and writes `file_versions.layout = 'chunked'` plus the `file_version_chunks` rows in one transaction. `Idempotency-Key` required |
| `GET` | `/files/{id}/chunks/{address}` | Stream one chunk ciphertext; ACL-checked like the file |

`GET /files/{id}/blob` and `GET /files/{id}/versions/{seq}/blob` return the **manifest** ciphertext for a chunked version, with response header `Nyxite-Blob-Layout: chunked` (absent or `single` otherwise), and the client then fetches chunks. Limits: at most `NYXITE__Limits__MaxChunksPerFile` chunks per version (`413` otherwise).

> No `/content` (decoded) endpoint and no `/crdt/state` server-diff: the server has no readable doc. Clients fetch ciphertext + log and reconstruct state vectors locally.

### File keys (wrapped)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/keys` | Get the caller's **wrapped** file key(s) for this file (to unwrap locally) |
| `POST` | `/files/{id}/keys` | Upload wrapped file key(s) for members (used when sharing / rotating) |
| `POST` | `/files/{id}/keys/rotate` | Commit a rotation. Body `{ newKeyId, generation, wrappedKeys[], newHeadRef }`. The server commits **only if** `generation == current + 1`, else `409 conflict` (another rotation won). In-flight CRDT updates tagged with the old `key_id` are accepted until commit, then rejected `412 key_generation_stale` |
| `POST` | `/files/keys:batch` | Batch wrap (subtree share fan-out). Body `{ grants: [ { fileId, keyId, memberId, wrappedKey } ] }`; **idempotent**, with **partial-success** reporting per item ([09 §9.3](09-sharing-and-acl.md)) |

### Keys, devices, recovery (E2EE)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/keys/directory?userId=` or `?email=` | Fetch a user's **public** keys (to wrap shares to them); each key carries `keyId`, `generation`, `algId`, `kemPub`, `sigPub`, `selfSig`, `loggedAt`, `ktLeafIndex` for KT verification ([17 §17.7](17-key-transparency.md)) |
| `GET` | `/kt/log-key`, `/kt/checkpoint`, `/kt/inclusion`, `/kt/consistency`, `/kt/leaves` | Key-transparency log ([17 §17.8](17-key-transparency.md)) |
| `PUT` | `/keys` | Publish/rotate the caller's own public identity keys `{ keyId, generation, algId, kemPub, sigPub, selfSig }`; the server verifies `selfSig` (both halves) and appends the KT leaf in the same transaction, else `400 validation_failed`. `generation` must be the user's highest generation + 1 (first publish = `1`), otherwise `409 conflict`. A rotation revokes the previous live key (KT `user_key_revoke` leaf) and needs a session bound to an **active** device (`403 device_not_active`). The first publish of an account is allowed from its pending first device, because no active device can exist before the identity key does |
| `GET/DELETE` | `/devices`, `/devices/{id}` | List / revoke devices |
| `POST` | `/devices` | Enroll: body `{ label, pubkey }` → `{ deviceId, status:"pending", pairingCode (6–8 digit), qrPayload }`. `pubkey` is the device's hybrid KEM public key (X25519 ‖ ML-KEM-768), the target of the enrollment seal. The new device is **bound to the calling session** (`sessions.device_id`), which is what `/devices/me/*` resolves through, so the pending device needs no second credential. A session already bound to a non-revoked device gets `409 conflict` |
| `POST` | `/devices/{id}/approve` | Approve a pending device from an enrolled one: body `{ pairingCode, wrappedIdentityKey }`. The server **verifies `pairingCode`** against `devices.pairing_code_hash` (constant-time compare, unexpired, under the attempt cap) **before** storing anything; a wrong code increments `pairing_attempts` → `403 pairing_code_invalid`, an expired or exhausted code → `410 pairing_expired` (the new device must re-register). On success `wrappedIdentityKey` = **HPKE-seal** of the identity bundle to the pending device's `pubkey` is stored in `pending_key_blob` and the pairing columns are cleared. The caller's session must be bound to an **active** device (`403 device_not_active`), because only a device that holds the identity key can seal it |
| `GET` | `/devices/me/enrollment` | Once approved → `{ wrappedIdentityKey }`; server **deletes** `pending_key_blob` after a successful fetch (**single-use**) and marks the device `active` |
| `POST` | `/devices/{id}/activate` | Activate the caller's own pending device **without an approval**: body `{ keyId, sig }`, where `sig` is a hybrid Ed25519 + ML-DSA-65 signature by the user's live directory key `keyId` over `"NYXDEV-ACTIVATE-v1" ‖ user_id(16) ‖ device_id(16) ‖ key_id(16) ‖ SHA-256(device pubkey)(32)` (UUIDs in RFC 9562 byte order). Covers the **first device** of an account (after its first `PUT /keys`) and a device restored from the **recovery phrase**, which have no device to approve them. The server verifies the signature itself, so only a holder of the identity private key can activate a device, and a bad signature gets `400 validation_failed`. Chosen over auto-activating the first device, which leaves the recovery path open, and over a client-declared status, which proves nothing |
| `GET/PUT` | `/recovery` | Get/set the server-opaque recovery blob: `{ version, kdf:{alg:"argon2id",m,t,p,salt}, nonce, ciphertext, tag }` — **AES-256-GCM under an Argon2id-derived key** from the recovery phrase (not HPKE; [07 §7.8](07-encryption.md)). **Replacing** an existing blob needs a session bound to an **active** device (`403 device_not_active`), so a stolen password and second factor alone cannot swap the owner's recovery path. The first blob of an account without an active device is accepted from any full session |

### Versions / history
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/versions` | List versions (paginated, newest first) |
| `GET` | `/files/{id}/versions/{seq}` | Version metadata |
| `GET` | `/files/{id}/versions/{seq}/blob` | Download a version's **ciphertext** |
| `POST` | `/files/{id}/restore` | Restore: body `{ "seq": n }` **only** (no ciphertext upload). The new head arrives via the normal write path — text → client submits a CRDT update via the relay then snapshots; ink/binary → client uploads restored bytes via `PUT /files/{id}/blob`. This endpoint records the restore (audit) linking the new head to source `seq` |

> **No `/diff` endpoint** — diffs are computed **client-side** from decrypted snapshots ([10](10-version-history.md)).

### Shares
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/shares?targetType={file\|folder\|project}&targetId={id}` | List shares on a target |
| `POST` | `/shares` | Create share. Account share: include wrapped key(s). Link share: server stores token hash only (key rides the URL fragment, never sent) |
| `PATCH` | `/shares/{id}` | Change permission / expiry |
| `DELETE` | `/shares/{id}` | Revoke (instant ACL cutoff; client rotates key separately) |

### Groups (enterprise/family file-sharing)
Group-key layer on the existing membership model ([03 §3.2b](03-data-model.md), [07 §7.2a](07-encryption.md), [09 §9.9](09-sharing-and-acl.md)). All bodies carry **opaque wrapped bytes and public keys only** — no key column, no plaintext name. Existence-hiding on `{id}` (no reach → `404`). Steps P4.4-SRV-1..4.
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/groups` | Create a file-sharing group `{ groupPubkey, ed25519Pubkey, groupKeyId, algId, selfSig, scopeKind, maxMembers? }`; the public key is appended to the key-transparency log in the same transaction ([17](17-key-transparency.md)) (the creator generated the keypair client-side; only the public halves are sent) |
| `GET` | `/groups` | List the file-sharing groups the caller is a member of (metadata + public keys; paginated) |
| `GET` | `/groups/{id}/pubkey?scopeId=` | The **current** public key of a scope (`keyId`, `generation`, `groupPubkey`, `sigPubkey`, `algId`, `selfSig`, `loggedAt`, `ktLeafIndex`), the target for DEK-to-group wraps; verified by the client against the KT log before wrapping ([17 §17.7](17-key-transparency.md)) |
| `POST` | `/groups/{id}/members` | **Enroll** one member: body `{ memberId, memberKeyId, scopeId, wrappedGroupPrivkey, generation, algId }` = the group privkey **HPKE-wrapped to the member's transparency-verified public key**. Appends **one** `group_key_grants` row. The server verifies a **key-transparency inclusion proof** (Phase 4.3) for `memberId`'s pubkey **before** accepting the grant, and enforces the **member-count limit** ([12 §12.7](12-administration.md)) — both metadata-only |
| `DELETE` | `/groups/{id}/members/{uid}` | **Soft removal** — delete the member's live grant (instant ACL cutoff). Forward secrecy is a separate scope-scoped rotation |
| `GET` | `/groups/{id}/keys?scopeId=` | Get the caller's **wrapped** group key grant(s) + the DEK-to-group wraps for a scope (to unwrap locally) |
| `POST` | `/groups/{id}/keys` | Upload wrapped material: DEK-to-group wraps (`file_keys` group-principal rows) and/or re-wrapped grants (used when sharing a file/subtree to the group) |
| `POST` | `/groups/{id}/keys/rotate` | Commit a **scope-scoped** group-key rotation. Body `{ scopeId, newGeneration, newKey: { keyId, groupPubkey, sigPubkey, algId, selfSig }, grants[], dekWraps[] }`; `newKey` is inserted into `group_scope_keys` and appended to the KT log in the same transaction. Committed **only if** `newGeneration == current + 1` for that scope, else `409 conflict` (another rotation won); post-commit wraps tagged with the old generation → `412 key_generation_stale`. Only the named scope is touched — the Phase-2.3 machinery at the group-key level ([09 §9.9](09-sharing-and-acl.md), P4.4-SRV-3) |

### Sync
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/sync/changes` | Delta sync of **structure + ciphertext refs** since a cursor; returns `nextCursor`. The cursor is **opaque base64url**, monotonic and resumable, tied to the global change-log seq ([06 §6.3](06-sync.md)) |
| `GET` | `/sync/manifest?projectId=` | Manifest (ids, contentType, versions, hashes, policies) for client reconcile/index; payloads in [06 §6.3](06-sync.md) |

### Me / Admin / Public share — see below and [12](12-administration.md), [§4.8](#48-public-share-endpoints).
`GET /me` (account, usage and **instance capabilities**: `support` = `support.enabled`, the active `ent.*` flags and the license state, so clients show or hide gated features without probing), `GET/PUT /me/settings` (settings body is **ciphertext**).

## 4.4 Error model

RFC 9457 `application/problem+json`. Selected codes:

| HTTP | `code` | When |
|------|--------|------|
| 400 | `validation_failed`, `bad_sync_policy` | Malformed structure/ACL request |
| 401 | `unauthenticated`, `token_expired` | Missing/invalid bearer — uniform across all ids, reveals no specific resource |
| 403 | `acl_denied`, `2fa_required`, `email_unverified`, `account_blocked`, `pairing_code_invalid`, `device_not_active` | Authz denied **only when the caller already has read reach** to the resource (existence not secret to them) or on capability/collection denials that expose no id; **no** `breakglass`. `2fa_required` also covers a missing or invalid step-up token, `email_unverified` a factor enrollment before email verification, `account_blocked` a web session for a blocked account ([08](08-authentication.md)), `device_not_active` a key-management write (device approval, key rotation, recovery-blob replacement) from a session that is not bound to an active device |
| 404 | `not_found` | Resource missing **or** the caller has no reach to it — **the two are indistinguishable** (existence-hiding, see below) |
| 409 | `conflict`, `version_conflict`, `excluded_content`, `address_exists`, `idempotency_conflict`, `group_full`, `key_not_transparent` | LWW conflict / policy / write-once / rotation lost (file or group scope) / same key + different body / group at member limit ([12 §12.7](12-administration.md)) / enrollment key failed the transparency inclusion proof ([09 §9.9](09-sharing-and-acl.md)) |
| 410 | `share_revoked`, `link_expired`, `pairing_expired`, `cursor_expired` | Dead share/link / pairing code expired or attempt cap reached / sync cursor older than the change-log retention ([06 §6.3.2](06-sync.md)) |
| 412 | `key_generation_stale` | Client used a superseded file-key generation (rotate/refetch) |
| 413 | `payload_too_large` | Ciphertext exceeds the upload limit **or the per-user storage quota** ([§4.7](#47-limits--validation-p), [12 §12.6](12-administration.md)) |
| 507 | `insufficient_storage` | Instance-level storage exhausted (per-user quota → `413`) |
| 429 | `rate_limited` | [13](13-security.md) |
| 5xx | `internal`, `unavailable` | Server/dependency failure |

> **Existence-hiding (no resource enumeration) — `404`, not `403`.** For any resource addressed by an id or token (files, projects, folders, users, **admin resources**, share URLs), an authenticated caller who has **no reach** to it gets the **same `404 not_found`** as for a non-existent id — identical `code`, body, and (as far as practical) timing. An attacker must not be able to tell "exists but I'm not authorized" from "nothing is there"; only a **correct token + actual access** yields a `200`. `403` is reserved for the case where the caller **demonstrably already knows the resource exists** (has read reach but lacks the specific action) or for capability/collection denials that reveal no id. `401` (no valid auth) is uniform across all ids and so leaks nothing. See [13 §13.6a](13-security.md). *(For share tokens: a never-issued/unauthorized token → `404`; a genuinely-issued but dead token → `410` `share_revoked`/`link_expired`, since presenting it already proves the holder knew it existed.)*

## 4.5 Representative DTOs **[P]**

```csharp
public record FileDto(
    Guid Id, Guid ProjectId, Guid? FolderId, Guid OwnerId,
    byte[] NameEnc, string ContentType, string SyncPolicy,
    long? CurrentVersionSeq,                        // = file_versions.seq of current_version_id
    Guid? CrdtDocId, int KeyGeneration,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public record CreateFileRequest(
    Guid ProjectId, Guid? FolderId, byte[] NameEnc,
    string ContentType, string? SyncPolicy, byte[]? MetadataEnc,
    Guid? CrdtDocId,                               // client-allocated UUIDv7; REQUIRED for text types, null otherwise
    WrappedKey OwnerWrappedKey);                 // owner's file key, wrapped to themselves

public record WrappedKey(Guid KeyId, Guid? MemberId, byte[] Ciphertext, int Generation);

public record CreateShareRequest(
    string TargetType, Guid TargetId,             // file|folder|project
    string Kind,                                   // user_grant|link
    Guid? GranteeId, string Permission,            // read|write
    WrappedKey[]? WrappedKeys,                      // account share: keys wrapped to grantee pubkey
    byte[]? LinkTokenHash,                          // link share: hash only; KEY stays in the URL fragment
    DateTimeOffset? ExpiresAt);

// X25519/Ed25519 byte[]s carry the HYBRID public keys (X25519 ‖ ML-KEM-768, Ed25519 ‖ ML-DSA-65); AlgId pins the suite ([07 §7.3](07-encryption.md))
public record PublicKeyDto(Guid KeyId, byte[] X25519, byte[] Ed25519, string AlgId, int Generation);

// Recovery blob (GET/PUT /recovery): AES-256-GCM under an Argon2id-derived key ([07 §7.8](07-encryption.md))
public record RecoveryBlobDto(int Version, KdfParams Kdf, byte[] Nonce, byte[] Ciphertext, byte[] Tag);
public record KdfParams(string Alg, int M, int T, int P, byte[] Salt);   // alg = "argon2id"

// Batch wrap (POST /files/keys:batch) — subtree share fan-out
public record BatchWrapRequest(BatchGrant[] Grants);
public record BatchGrant(Guid FileId, Guid KeyId, Guid MemberId, byte[] WrappedKey);

// Enterprise/family file-sharing groups ([03 §3.2b](03-data-model.md), [09 §9.9](09-sharing-and-acl.md))
public record CreateGroupRequest(
    byte[] GroupPubkey, byte[] Ed25519Pubkey,      // PUBLIC halves only (hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65); private key never leaves the creator
    string ScopeKind,                              // project|time_period
    int? MaxMembers);                              // per-group size override (G-5); null → instance default
public record GroupDto(
    Guid Id, byte[] GroupPubkey, byte[] Ed25519Pubkey,
    string ScopeKind, int? MaxMembers, int MemberCount,
    DateTimeOffset CreatedAt);

// Enroll one member — appends ONE grant; server transparency-verifies MemberId's pubkey first
public record EnrollMemberRequest(
    Guid MemberId, Guid ScopeId,
    byte[] WrappedGroupPrivkey,                     // group privkey HPKE-wrapped to the member's pubkey — opaque
    int Generation, string AlgId);                 // AlgId = wrap-algorithm identifier (crypto-agility)

// Scope-scoped group-key rotation (generation-guarded per scope)
public record GroupKeyRotateRequest(
    Guid ScopeId, int NewGeneration,
    GroupGrant[] Grants,                            // re-wrapped group privkey to each remaining member
    WrappedKey[] DekWraps);                        // optional DEK re-seal to the new group key (full removal)
public record GroupGrant(Guid MemberId, byte[] WrappedGroupPrivkey, string AlgId);

// Generic paginated envelope; cursor is opaque base64url
public record Paged<T>(IReadOnlyList<T> Items, string? NextCursor);
```

## 4.6 Authorization summary

Every endpoint resolves the target and evaluates the **server ACL** ([09](09-sharing-and-acl.md)): owner → full; grantee → read/write; admin → structure/usage only. **Content endpoints serve ciphertext** to anyone the ACL permits to fetch it — but only a holder of the (wrapped/fragment) key can decrypt. There is **no content-read permission for admins and no break-glass**, because the server holds no key.

## 4.7 Limits & validation **[P]**

- Max ciphertext upload: **100 MB inline** via `PUT /files/{id}/blob`. Files above the 16 MiB chunk threshold use the **chunked** path below (Phase 5.1); the inline path stays the only one in the required v1.0.0 band.
- **Per-user storage quota:** when `users.storage_quota_bytes` is set, an upload that would push the user's counted **ciphertext bytes** over the quota is rejected with **`413 payload_too_large`** (or `507` for instance-level exhaustion); enforced by size only — no content is read ([12 §12.6](12-administration.md), [03](03-data-model.md)).
- **Blocked accounts** (`users.status='blocked'`) are denied all write endpoints (download stays allowed) — see [09 §9.5](09-sharing-and-acl.md), [12 §12.6](12-administration.md).
- `nameEnc`/`metadataEnc` size caps; structural fields validated; `excluded` uploads rejected (`409`).
- The server validates **structure and ACL**, and write-once addressing — it **cannot** validate plaintext or that ciphertext matches its claimed address ([07 §7.5](07-encryption.md)).

## 4.8 Public share endpoints

Unauthenticated, token-scoped; the **decryption key is in the URL fragment**, never received by the server.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/share/{token}` | Resolve a link → guest bootstrap (serves the guest client; fragment key used client-side) |
| `POST` | `/share/{token}/session` | Issue or **renew** the 15-minute guest share-session token (JWT `typ: nyx-guest+jwt`, [08 §8.2](08-authentication.md)); every call re-checks the `shares` row, so a revoked share stops renewals at once (`410`) |
| `GET` | `/share/{token}/blob` | Serve **ciphertext** if the link is read/write |
| `WS` | `/share/{token}/ws` | Guest WebSocket into the encrypted relay — serves **both read and write links**. Read-only guests receive `OnUpdate`/`OnAwareness` but are rejected (`OnError`) on `SubmitUpdate` ([05 §5.8](05-realtime-collaboration.md)) |

`{token}` validated against `shares.link_token_hash`; expired/revoked → `410`. Guests get a short-lived relay-scoped session token; they **never** receive a key from the server ([09 §9.4](09-sharing-and-acl.md)).

## 4.9 Support relay endpoints

> **Consensual, non-E2EE support plane — disjoint from the content plane.** These endpoints belong to the in-app bug-reporting helpdesk (feature: [Nyxite `features/support.md`](https://github.com/Nyxite/Nyxite), OPEN-DECISIONS **SUP-1..SUP-9**). The server here is an **authenticating relay only — it stores no ticket** (SUP-7); the ticket store, lifecycle, and all operator/management endpoints live on the central vendor-side `NyxiteSupport` service (its [`specification/02`](https://github.com/Nyxite/NyxiteSupport) and [`04`](https://github.com/Nyxite/NyxiteSupport)), which is **not** part of the self-hosted stack. A report carries **no content key and no content-plane ciphertext**; the content-plane zero-knowledge guarantee is untouched (SUP-1).

**Exposed only when the instance advertises `support.enabled`** ([14 §14.9](14-deployment-and-config.md)). In v1 this is true **only on the maintainer's official instance(s)**; a third-party self-hosted instance has **no** reporting surface and these routes are absent (SUP-9). Where present they are the **only** support endpoints on the server.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/support/reports` | **Authenticated report intake + relay** (SUP-7). Authenticates the submitter — an **account session** or a valid **guest-share session** (SUP-6) — then forwards the composed report (multipart: JSON body + flattened, destructively client-redacted screenshot blobs — SUP-2) to the central `NyxiteSupport` service, tagged server-side with the **`instance_fingerprint`** (the same opaque per-instance anchor used for `NyxiteLicense /register`) and an **opaque `user_ref`** the client cannot forge. Best-effort, off the critical path; no partial report is persisted (`NyxiteSupport specification/02 §2.5`) |
| `GET` | `/support/tickets` | List the **reporter's own** tickets (status + replies for the "My tickets" view), proxied to `NyxiteSupport`'s reporter API scoped to the caller's `user_ref` — never another reporter's tickets |
| `GET` | `/support/tickets/{id}` | Read one of the reporter's own tickets (existence-hiding applies — no reach → `404`, [§4.4](#44-error-model)) |
| `POST` | `/support/tickets/{id}/replies` | Reporter reply on their own ticket, proxied by `user_ref` |

All operator surfaces — triage, tags, priority, assignee, internal notes, transitions, merge/close/reopen, webhooks, API tokens — are **never** exposed by a self-hosted instance; they live only on `NyxiteSupport` (its `specification/04`, SUP-4/SUP-5).
