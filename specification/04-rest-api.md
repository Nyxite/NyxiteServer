# 04 — REST API

> **E2EE.** Endpoints serve/accept **ciphertext and wrapped keys**. There is **no server search** and **no server diff** (both client-side). New endpoints cover **key directory, device enrollment, recovery, and share-key wrapping**. All routes/DTOs/codes are **[P]**.

## 4.1 Conventions

- **Base path:** `/api/v1`. URL-versioned. **[P]**
- **Auth:** `Authorization: Bearer <OIDC token>` on `/api/v1/**` except public share endpoints ([§4.8](#48-public-share-endpoints)).
- **Content type:** `application/json` for structure/metadata; binary streams for ciphertext blobs.
- **IDs:** UUIDv7. **Timestamps:** RFC 3339 UTC. **Pagination:** cursor-based. **Idempotency:** `Idempotency-Key` on creates. **[P]**
- **Names in payloads are ciphertext** (`nameEnc`), never plaintext.
- **OpenAPI:** `/openapi/v1.json` (code-first).

## 4.2 Resource map

| Area | Base |
|------|------|
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

### Projects / Folders / Files (structure)
Same shape as a normal CRUD tree, but **names are ciphertext**:
| Method | Path | Purpose |
|--------|------|---------|
| `GET/POST` | `/projects`, `/projects/{id}` (+ PATCH/DELETE) | Project CRUD (`nameEnc`) |
| `GET` | `/projects/{id}/folders` | List folders (tree/flat) |
| `POST/GET/PATCH/DELETE` | `/folders`, `/folders/{id}` | Folder CRUD/move (`nameEnc`, `parentFolderId`) |
| `GET` | `/folders/{id}/files` | List files in a folder |
| `POST/GET/PATCH/DELETE` | `/files`, `/files/{id}` | File CRUD/move/policy (`nameEnc`, `contentType`, `syncPolicy`) |

### File content (ciphertext)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/blob` | Stream current **ciphertext** (server never decrypts) |
| `PUT` | `/files/{id}/blob` | Upload new **ciphertext** for ink/binary (LWW); body is already encrypted |
| `GET` | `/files/{id}/crdt/log?since={seq}` | Encrypted CRDT updates after a cursor (REST fallback for the relay) |
| `POST` | `/files/{id}/crdt/log` | Submit **encrypted** CRDT update(s) (REST fallback) |
| `GET` | `/files/{id}/snapshot` | Pointer/stream of the latest **encrypted** snapshot blob |

> No `/content` (decoded) endpoint and no `/crdt/state` server-diff: the server has no readable doc. Clients fetch ciphertext + log and reconstruct state vectors locally.

### File keys (wrapped)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/keys` | Get the caller's **wrapped** file key(s) for this file (to unwrap locally) |
| `POST` | `/files/{id}/keys` | Upload wrapped file key(s) for members (used when sharing / rotating) |
| `POST` | `/files/{id}/keys/rotate` | Register a new key generation (bumps `keyGeneration`); body carries re-wrapped keys + new head ciphertext ref |

### Keys, devices, recovery (E2EE)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/keys/directory?userId=` or `?email=` | Fetch a user's **public** keys (to wrap shares to them) |
| `PUT` | `/keys` | Publish/rotate the caller's own public identity keys |
| `GET/POST/DELETE` | `/devices`, `/devices/{id}` | List / enroll / revoke devices |
| `POST` | `/devices/{id}/approve` | Approve a new device from an existing one (device-to-device enrollment) |
| `GET/PUT` | `/recovery` | Get/set the server-opaque recovery escrow blob (wrapped by the user's recovery key) |

### Versions / history
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/files/{id}/versions` | List versions (paginated, newest first) |
| `GET` | `/files/{id}/versions/{seq}` | Version metadata |
| `GET` | `/files/{id}/versions/{seq}/blob` | Download a version's **ciphertext** |
| `POST` | `/files/{id}/restore` | Restore: client uploads new head ciphertext derived from version `n` (server records the new head) |

> **No `/diff` endpoint** — diffs are computed **client-side** from decrypted snapshots ([10](10-version-history.md)).

### Shares
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/shares?target=files/{id}` | List shares on a target |
| `POST` | `/shares` | Create share. Account share: include wrapped key(s). Link share: server stores token hash only (key rides the URL fragment, never sent) |
| `PATCH` | `/shares/{id}` | Change permission / expiry |
| `DELETE` | `/shares/{id}` | Revoke (instant ACL cutoff; client rotates key separately) |

### Sync
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/sync/changes` | Delta sync of **structure + ciphertext refs** since a cursor |
| `GET` | `/sync/manifest?projectId=` | Manifest (ids, contentType, versions, hashes, policies) for client reconcile/index |

### Me / Admin / Public share — see below and [12](12-administration.md), [§4.8](#48-public-share-endpoints).
`GET /me`, `GET/PUT /me/settings` (settings body is **ciphertext**).

## 4.4 Error model

RFC 9457 `application/problem+json`. Selected codes:

| HTTP | `code` | When |
|------|--------|------|
| 400 | `validation_failed`, `bad_sync_policy` | Malformed structure/ACL request |
| 401 | `unauthenticated`, `token_expired` | Missing/invalid bearer |
| 403 | `acl_denied`, `2fa_required` | Authz denied (note: **no** `breakglass` — content access can't exist) |
| 404 | `not_found` | Missing/not visible |
| 409 | `conflict`, `version_conflict`, `excluded_content`, `address_exists` | LWW conflict / policy / write-once |
| 410 | `share_revoked`, `link_expired` | Dead share/link |
| 412 | `key_generation_stale` | Client used a superseded file-key generation (rotate/refetch) |
| 413 | `payload_too_large` | Ciphertext exceeds limit |
| 429 | `rate_limited` | [13](13-security.md) |
| 5xx | `internal`, `unavailable` | Server/dependency failure |

## 4.5 Representative DTOs **[P]**

```csharp
public record FileDto(
    Guid Id, Guid ProjectId, Guid? FolderId, Guid OwnerId,
    byte[] NameEnc, string ContentType, string SyncPolicy,
    long? CurrentVersionSeq, int KeyGeneration,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public record CreateFileRequest(
    Guid ProjectId, Guid? FolderId, byte[] NameEnc,
    string ContentType, string? SyncPolicy, byte[]? MetadataEnc,
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
```

## 4.6 Authorization summary

Every endpoint resolves the target and evaluates the **server ACL** ([09](09-sharing-and-acl.md)): owner → full; grantee → read/write; admin → structure/usage only. **Content endpoints serve ciphertext** to anyone the ACL permits to fetch it — but only a holder of the (wrapped/fragment) key can decrypt. There is **no content-read permission for admins and no break-glass**, because the server holds no key.

## 4.7 Limits & validation **[P]**

- Max ciphertext upload: 100 MB inline (larger → chunked, Phase 5).
- `nameEnc`/`metadataEnc` size caps; structural fields validated; `excluded` uploads rejected (`409`).
- The server validates **structure and ACL**, and write-once addressing — it **cannot** validate plaintext or that ciphertext matches its claimed address ([07 §7.5](07-encryption.md)).

## 4.8 Public share endpoints

Unauthenticated, token-scoped; the **decryption key is in the URL fragment**, never received by the server.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/share/{token}` | Resolve a link → guest bootstrap (serves the guest client; fragment key used client-side) |
| `GET` | `/share/{token}/blob` | Serve **ciphertext** if the link is read/write |
| `WS` | `/share/{token}/ws` | Guest WebSocket into the encrypted relay (write links) |

`{token}` validated against `shares.link_token_hash`; expired/revoked → `410`. Guests get a short-lived relay-scoped session token; they **never** receive a key from the server ([09 §9.4](09-sharing-and-acl.md)).
