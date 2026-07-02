# 04 — REST API

> **E2EE.** Endpoints serve/accept **ciphertext and wrapped keys**. There is **no server search** and **no server diff** (both client-side). New endpoints cover **key directory, device enrollment, recovery, and share-key wrapping**. All routes/DTOs/codes are **[P]**.

## 4.1 Conventions

- **Base path:** `/api/v1`. URL-versioned. **[P]**
- **Auth:** `Authorization: Bearer <token>` on `/api/v1/**` except the auth and public-share endpoints. The bearer is **the server's own access token** (native auth by default; the enterprise Keycloak/OIDC profile resolves to the same token — [08](08-authentication.md)). Auth endpoints live under `/api/v1/auth` ([§4.3](#43-endpoints)); public share endpoints under `/share/**` ([§4.8](#48-public-share-endpoints)).
- **Content type:** `application/json` for structure/metadata; binary streams for ciphertext blobs.
- **IDs:** UUIDv7. **Timestamps:** RFC 3339 UTC. **[P]**
- **Pagination:** query `?cursor=<opaque>&limit=<n>` (default `50`, max `200`); response envelope `{ "items": [...], "nextCursor": <opaque|null> }`. The cursor is an **opaque base64url server token** — clients must not parse it.
- **Idempotency:** `Idempotency-Key` is **required on POST creates**. The server stores `key → response` for **24h** scoped to `(user, endpoint)`; a replay returns the original response/status; the same key with a **different body** → `409 idempotency_conflict`.
- **Names in payloads are ciphertext** (`nameEnc`), never plaintext.
- **OpenAPI:** `/openapi/v1.json` (code-first).

## 4.2 Resource map

| Area | Base |
|------|------|
| Auth (native; enterprise OIDC) | `/api/v1/auth` |
| Projects / Folders / Files (structure) | `/api/v1/projects`, `/folders`, `/files` |
| File content (ciphertext) | `/api/v1/files/{id}/blob`, `/crdt/*` |
| File keys (wrapped) | `/api/v1/files/{id}/keys` |
| Versions / history | `/api/v1/files/{id}/versions` |
| Shares | `/api/v1/shares` |
| Keys & devices | `/api/v1/keys`, `/api/v1/devices`, `/api/v1/recovery` |
| Sync | `/api/v1/sync` |
| Me / settings | `/api/v1/me` |
| Admin | `/api/v1/admin/**` |
| Public share | `/share/**` (unauthenticated, token-scoped) |

## 4.3 Endpoints

### Auth (native by default; enterprise OIDC)
Native, server-owned auth ([08 §8.1](08-authentication.md)); these endpoints issue/refresh **the server's own tokens**. Unauthenticated except where marked (auth'd). The enterprise profile adds `GET /auth/oidc/authorize` + `/auth/oidc/callback`, which resolve to the same internal token.
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/register` | Create a native account `{ email, displayName, password }` (Argon2id verifier); TOTP enrollment required before full login |
| `POST` | `/auth/login` | Password step `{ email, password }` → `{ challenge:"totp_required", mfaToken }` (password alone never yields a full token) |
| `POST` | `/auth/login/totp` | Complete login `{ mfaToken, totpCode }` → `{ accessToken, refreshToken }` |
| `POST` | `/auth/totp/enroll` / `/auth/totp/verify` | (auth'd) Enroll/confirm the required TOTP factor |
| `POST` | `/auth/webauthn/register/options` / `/auth/webauthn/register` | (auth'd) Register a passkey (stores public credential only) |
| `POST` | `/auth/webauthn/assert/options` / `/auth/webauthn/assert` | Passkey login → `{ accessToken, refreshToken }` (sufficient alone) |
| `POST` | `/auth/refresh` | Rotate a refresh token → new `{ accessToken, refreshToken }` |
| `POST` | `/auth/logout` | Revoke the presented refresh token / session |
| `POST` | `/auth/password/forgot` / `/auth/password/reset` | Email-based reset — **restores login only**, never content ([08 §8.1](08-authentication.md)) |

### Projects / Folders / Files (structure)
Same shape as a normal CRUD tree, but **names are ciphertext**:
| Method | Path | Purpose |
|--------|------|---------|
| `GET/POST` | `/projects`, `/projects/{id}` (+ PATCH/DELETE) | Project CRUD (`nameEnc`) |
| `GET` | `/projects/{id}/folders` | List folders (tree/flat) |
| `POST/GET/PATCH/DELETE` | `/folders`, `/folders/{id}` | Folder CRUD/move (`nameEnc`, `parentFolderId`) |
| `GET` | `/folders/{id}/files` | List files in a folder |
| `POST/GET/PATCH/DELETE` | `/files`, `/files/{id}` | File CRUD/move/policy. `POST` sets `contentType` (**immutable**); `PATCH` updates **only** `nameEnc`, `syncPolicy`, `parentFolderId` (move), `metadataEnc` |

### File content (ciphertext)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/blob` | Stream current **ciphertext** (server never decrypts) |
| `PUT` | `/files/{id}/blob` | Upload new **ciphertext** for ink/binary (LWW); body is already encrypted. Client sends the parent version as **`If-Match: <seq>`**. If the server head `!= seq` (concurrent write) the server applies **last-write-wins by server-received time** and returns **`409 conflict`** with the winning version metadata, **retaining the losing bytes as a sibling `file_versions` row** (not head) so nothing is lost ([06 §6.5](06-sync.md)) |
| `GET` | `/files/{id}/crdt/log?since={seq}` | Encrypted CRDT updates after a cursor (REST fallback for the relay) |
| `POST` | `/files/{id}/crdt/log` | Submit **encrypted** CRDT update(s) (REST fallback) |
| `GET` | `/files/{id}/snapshot` | Pointer/stream of the latest **encrypted** snapshot blob |

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
| `GET` | `/keys/directory?userId=` or `?email=` | Fetch a user's **public** keys (to wrap shares to them) |
| `PUT` | `/keys` | Publish/rotate the caller's own public identity keys |
| `GET/DELETE` | `/devices`, `/devices/{id}` | List / revoke devices |
| `POST` | `/devices` | Enroll: body `{ label, pubkey }` → `{ deviceId, status:"pending", pairingCode (6–8 digit), qrPayload }` |
| `POST` | `/devices/{id}/approve` | Approve a pending device from an enrolled one: body `{ wrappedIdentityKey }` = **HPKE-seal** of the identity bundle to the pending device's `pubkey`; server stores it in `pending_key_blob` |
| `GET` | `/devices/me/enrollment` | Once approved → `{ wrappedIdentityKey }`; server **deletes** `pending_key_blob` after a successful fetch (**single-use**) and marks the device `active` |
| `GET/PUT` | `/recovery` | Get/set the server-opaque recovery blob: `{ version, kdf:{alg:"argon2id",m,t,p,salt}, nonce, ciphertext, tag }` — **AES-256-GCM under an Argon2id-derived key** from the recovery phrase (not HPKE; [07 §7.8](07-encryption.md)) |

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

### Sync
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/sync/changes` | Delta sync of **structure + ciphertext refs** since a cursor; returns `nextCursor`. The cursor is **opaque base64url**, monotonic and resumable, tied to the global change-log seq ([06 §6.3](06-sync.md)) |
| `GET` | `/sync/manifest?projectId=` | Manifest (ids, contentType, versions, hashes, policies) for client reconcile/index |

### Me / Admin / Public share — see below and [12](12-administration.md), [§4.8](#48-public-share-endpoints).
`GET /me`, `GET/PUT /me/settings` (settings body is **ciphertext**).

## 4.4 Error model

RFC 9457 `application/problem+json`. Selected codes:

| HTTP | `code` | When |
|------|--------|------|
| 400 | `validation_failed`, `bad_sync_policy` | Malformed structure/ACL request |
| 401 | `unauthenticated`, `token_expired` | Missing/invalid bearer — uniform across all ids, reveals no specific resource |
| 403 | `acl_denied`, `2fa_required` | Authz denied **only when the caller already has read reach** to the resource (existence not secret to them) or on capability/collection denials that expose no id; **no** `breakglass` |
| 404 | `not_found` | Resource missing **or** the caller has no reach to it — **the two are indistinguishable** (existence-hiding, see below) |
| 409 | `conflict`, `version_conflict`, `excluded_content`, `address_exists`, `idempotency_conflict` | LWW conflict / policy / write-once / rotation lost / same key + different body |
| 410 | `share_revoked`, `link_expired` | Dead share/link |
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

public record PublicKeyDto(Guid KeyId, byte[] X25519, byte[] Ed25519, int Generation);

// Recovery blob (GET/PUT /recovery): AES-256-GCM under an Argon2id-derived key ([07 §7.8](07-encryption.md))
public record RecoveryBlobDto(int Version, KdfParams Kdf, byte[] Nonce, byte[] Ciphertext, byte[] Tag);
public record KdfParams(string Alg, int M, int T, int P, byte[] Salt);   // alg = "argon2id"

// Batch wrap (POST /files/keys:batch) — subtree share fan-out
public record BatchWrapRequest(BatchGrant[] Grants);
public record BatchGrant(Guid FileId, Guid KeyId, Guid MemberId, byte[] WrappedKey);

// Generic paginated envelope; cursor is opaque base64url
public record Paged<T>(IReadOnlyList<T> Items, string? NextCursor);
```

## 4.6 Authorization summary

Every endpoint resolves the target and evaluates the **server ACL** ([09](09-sharing-and-acl.md)): owner → full; grantee → read/write; admin → structure/usage only. **Content endpoints serve ciphertext** to anyone the ACL permits to fetch it — but only a holder of the (wrapped/fragment) key can decrypt. There is **no content-read permission for admins and no break-glass**, because the server holds no key.

## 4.7 Limits & validation **[P]**

- Max ciphertext upload: 100 MB inline (larger → chunked, Phase 5).
- **Per-user storage quota:** when `users.storage_quota_bytes` is set, an upload that would push the user's counted **ciphertext bytes** over the quota is rejected with **`413 payload_too_large`** (or `507` for instance-level exhaustion); enforced by size only — no content is read ([12 §12.6](12-administration.md), [03](03-data-model.md)).
- **Blocked accounts** (`users.status='blocked'`) are denied all write endpoints (download stays allowed) — see [09 §9.5](09-sharing-and-acl.md), [12 §12.6](12-administration.md).
- `nameEnc`/`metadataEnc` size caps; structural fields validated; `excluded` uploads rejected (`409`).
- The server validates **structure and ACL**, and write-once addressing — it **cannot** validate plaintext or that ciphertext matches its claimed address ([07 §7.5](07-encryption.md)).

## 4.8 Public share endpoints

Unauthenticated, token-scoped; the **decryption key is in the URL fragment**, never received by the server.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/share/{token}` | Resolve a link → guest bootstrap (serves the guest client; fragment key used client-side) |
| `GET` | `/share/{token}/blob` | Serve **ciphertext** if the link is read/write |
| `WS` | `/share/{token}/ws` | Guest WebSocket into the encrypted relay — serves **both read and write links**. Read-only guests receive `OnUpdate`/`OnAwareness` but are rejected (`OnError`) on `SubmitUpdate` ([05 §5.8](05-realtime-collaboration.md)) |

`{token}` validated against `shares.link_token_hash`; expired/revoked → `410`. Guests get a short-lived relay-scoped session token; they **never** receive a key from the server ([09 §9.4](09-sharing-and-acl.md)).
