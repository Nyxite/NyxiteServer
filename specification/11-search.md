# 11 — Search (Client-side)

> **Model change.** Under full E2EE the server **cannot read content**, so there is **no server-side search**. Full-text search runs **on the clients**, primarily the desktop app, over locally-held plaintext. The server provides only the encrypted content and sync manifests clients need to build their own indexes. This replaces the previous Postgres-FTS/Meilisearch design. Concrete pipeline below is **[P]**.

## 11.1 Why search is client-side

Server-side search would require the server to read plaintext — incompatible with zero-knowledge. So the index lives where the keys and plaintext live: the client. The **desktop** client holds the full local corpus (master spec calls out S-Pen/desktop as primary surfaces) and is the natural place for full-corpus search. **Web** and **Android** can only search the subset they have locally cached.

## 11.2 Per-surface behavior

| Surface | Search scope |
|---------|--------------|
| **Desktop** | Full local corpus (all synced files decrypted and indexed locally) — the primary, complete search experience |
| **Android** | Local cache subset (`pinned-local` + recently opened); battery/storage-bounded |
| **Web** | Whatever the session has decrypted/cached; weakest — a browser can't hold the whole corpus |

This is the direct, accepted consequence of privacy-first ([00](00-overview.md), [07](07-encryption.md)).

## 11.3 Server's role (no index)

The server exposes **no search endpoint**. It supports client indexing by serving:
- **Sync manifests** (`GET /sync/manifest`, [06](06-sync.md)) — file ids, content-types, versions, hashes, policies — so clients know what to fetch.
- **Ciphertext** (`/files/{id}/blob`, snapshots, CRDT logs) for the client to decrypt and index locally.

There is **no `search_index` table, no FTS, no Meilisearch** server-side ([03 §3.3a](03-data-model.md)). The former `GET /api/v1/search` endpoint is **removed** ([04](04-rest-api.md)).

## 11.4 Client index (informative, not server scope)

For completeness — the clients (specified in their own repos) typically:
- Decrypt content locally and maintain a local full-text index (e.g. SQLite FTS5 on desktop/Android; an in-memory/IndexedDB index on web). **[P, client-side]**
- Update the index incrementally as sync delivers new encrypted snapshots/updates that the client decrypts.
- Keep the index in the client's **local encrypted store**, never uploaded.

The server neither builds nor sees this index.

## 11.5 Implications

- **Cross-device search consistency** is weaker than server-side search: each device searches what it holds. Desktop is the reference for "search everything."
- **Shared docs**: searchable on a member's device once decrypted there; never searchable server-side.
- A future, still-zero-knowledge option (encrypted searchable indexes / blind indexing on the server) is a **possible later hardening**, not in v1.0.0 — and only if it can be done without leaking content ([15](15-roadmap-and-versioning.md)).
