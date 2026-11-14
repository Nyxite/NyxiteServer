# 05 — Real-time Collaboration (Encrypted Relay)

> **Model change.** Collaboration is **end-to-end encrypted**. The server is a **blind relay + durable store** of encrypted CRDT updates — it does **not** load, merge, or read documents. Clients merge (Yjs/Yrs client-side merge is battle-tested). This reverses the master spec's "server-authoritative CRDT" design and is the privacy-first choice; it also **saves server resources**. Concrete protocol below is **[P]**.

## 5.1 Model

- **Client-authoritative, server-relayed.** Each participating client holds the Yrs document and merges updates locally. The server stores the encrypted update log and broadcasts encrypted updates to the room. Convergence is guaranteed by the CRDT, independent of the server.
- **The server cannot read collaboration traffic.** Updates are encrypted with the file key ([07](07-encryption.md)) before they reach the server. The server sees update **size and ordering**, not content.
- **Applies to text** types (`markdown`, `plaintext`, later `sourcecode`). Ink/binary sync via LWW ([06](06-sync.md)), also encrypted.

## 5.2 Transport

- **SignalR** over WebSocket. A single hub, `RelayHub`, at `/hubs/relay` (outside `/api/v1`), multiplexes per-document rooms via SignalR groups keyed by `file:{fileId}`. **[P]** The access token travels as `Authorization: Bearer` or, because a browser cannot set a header on a WebSocket upgrade, as the `access_token` query value on that path only. A browser sends a single-use socket ticket there instead of its access token ([08 §8.4](08-authentication.md)), so no reusable credential lands in a URL.
- **Upgrade auth:** the server's own access token (users) or a short-lived **share token** (guests) ([08](08-authentication.md)). The share token authorizes **relay access**; the **decryption key** comes from the link's URL fragment, never the server ([09](09-sharing-and-acl.md)).
- **Fallback:** REST encrypted-update endpoints ([04](04-rest-api.md)) for offline catch-up.

## 5.3 Hub contract **[P]**

```csharp
public interface IRelayHub          // server → client callbacks (all payloads are ciphertext)
{
    Task OnSnapshot(string fileId, long crdtSeq, long versionSeq); // on join, when a snapshot exists: where to start from
    Task OnUpdates(string fileId, EncryptedUpdate[] updates);  // encrypted CRDT updates, on join and whenever new ones are stored
    Task OnUpdate(string fileId, EncryptedUpdate update);      // a peer's encrypted update, relayed
    Task OnAwareness(string fileId, byte[] awarenessCipher);   // encrypted ephemeral presence/cursors
    Task OnPresence(string fileId, PresenceDto[] peers);       // join/leave roster (identities only, no content)
    Task OnError(string fileId, string code, string message);
}

// client → server (hub methods)
Task JoinDocument(string fileId, long sinceSeq);              // server replies OnUpdates with everything after sinceSeq
Task<long> SubmitUpdate(string fileId, EncryptedUpdate update); // server persists + relays; never decrypts; returns the assigned seq
Task SubmitAwareness(string fileId, byte[] awarenessCipher);  // relayed, not persisted
Task LeaveDocument(string fileId);

public record EncryptedUpdate(long Seq, byte[] Ciphertext, Guid KeyId);
public record PresenceDto(string Kind, string? UserId, string? DisplayName); // Kind "user" or "guest"
```

> **Wire encoding [P]:** over the SignalR **MessagePack** protocol, `Seq` is an int64, `Ciphertext` raw bytes, and `KeyId` a **canonical UUID string** (e.g. `018f…`); clients map it to their native `Guid`/`UUID` type. (The on-disk frame's `key_id` is the same value as 16 raw bytes — [07 §7.4](07-encryption.md).)
> A record travels as a MessagePack map keyed by its PascalCase property names (`Seq`, `Ciphertext`, `KeyId`, `Kind`, `UserId`, `DisplayName`), which is what SignalR's default MessagePack resolver writes.
> Pinning the names lets every client decode without a shared schema compiler, and an array encoding was rejected, because it would tie the wire to the property order of the C# records.
> The vector `relay-wire.json` holds one encoded message per hub method and callback, length prefix included, so the four codebases can check their encoders and decoders byte for byte.

> **Delivery [P]:** every stored update reaches the room as `OnUpdates`, the sender included, whether it was submitted over the hub or over REST. A client therefore sees all updates of a document in `seq` order from one source and drops what it has already applied by `seq`. Sending to the others only was rejected, because the sender would then have to merge its own acknowledgements with the room's stream. The return value of `SubmitUpdate` is the acknowledgement that the update is durable. `OnUpdate` stays in the contract for a single relayed update and is not sent by the server today.
> **Errors [P]:** an expected failure reaches the caller as `OnError(fileId, code, message)` and as the failed call, whose message is the stable problem code of [04 §4.4](04-rest-api.md).

## 5.4 Join handshake

1. Client opens the socket (authenticated) and calls `JoinDocument(fileId, sinceSeq)`.
2. Server checks **ACL** (read to receive; **write** to `SubmitUpdate`). Guests' permission comes from the link share. Read reach without write reach answers `SubmitUpdate` with `acl_denied`, no reach with `not_found` ([09 §9.5](09-sharing-and-acl.md)).
3. Server returns, via `OnUpdates`, all encrypted updates with `seq > sinceSeq` (and points the client at the latest encrypted snapshot blob to bootstrap from). The server does **not** compute a state-vector diff — it has no readable document; the **client** reconciles using the Yrs state vector it reconstructs locally.
4. Client is added to the `file:{fileId}` group; presence roster sent via `OnPresence`.

> ACL re-checks [P]:
> reach is checked at `JoinDocument` and at every `SubmitUpdate`, and again for every connection in a room every `NYXITE__Relay__AccessRecheckInterval` (default 30 s, [14](14-deployment-and-config.md)).
> The periodic pass exists because an open connection keeps receiving updates and awareness after its join, so a revoked reader would otherwise listen on until it disconnects.
> A connection whose account lost reach to the file leaves that room and gets `OnError(fileId, "not_found", ...)`, and the room gets the new roster.
> The connection itself stays open, because it may be in other rooms the account still reaches.
> A connection whose session was revoked or expired gets `OnError(fileId, "unauthenticated", ...)` for each of its rooms and is then closed, because no room is open to a dead session.
> `SubmitAwareness` is not checked against the ACL per message, because awareness flows at caret rate.
> It requires the connection to be in the room, so its reach is the one of the join, kept current by the periodic pass.

## 5.5 Update flow

1. Client edits → Yrs update → **encrypts** with the file key → `SubmitUpdate(fileId, EncryptedUpdate)`.
2. Server: authorize (write) → assign `seq` → **persist** the ciphertext to `crdt_updates` → broadcast `OnUpdate` to the rest of the group. **No decryption, no merge, no validation of contents.**
3. Peers receive the encrypted update, decrypt locally, and merge into their Yrs doc.
4. Awareness is relayed **encrypted** and **not persisted**. It is an NYXC frame of `object_kind` `awareness = 6` ([07 §7.4](07-encryption.md)) around a y-protocols awareness update, at most `NYXITE__Limits__MaxAwarenessBytes`. The server forwards the bytes unchanged to the others in the room, the sender excluded, because a client already knows its own cursor.

## 5.6 Snapshotting & compaction (client-driven)

- The server cannot compact an encrypted log it can't read. **Clients** periodically produce an **encrypted snapshot** (serialized merged doc, encrypted with the file key) and upload it as a content-addressed blob + a `file_versions` row ([10](10-version-history.md)). **[P]**
- **Snapshot triggers (client-side):** a client snapshots when **≥ 200 CRDT updates since the last snapshot**, **OR ≥ 5 min of accumulated edits**, **OR on the last participant leaving**. Any participating client may snapshot.
- **Server prune (`PruneAfterSnapshotSeq`):** the server may delete `crdt_updates` with `seq ≤` the latest snapshot's `seq`, but **retains a safety tail** = updates from the **last 7 days OR the most recent 1000 updates, whichever is larger** (enough for in-flight clients).
- This also produces version history ([10](10-version-history.md)).

## 5.7 Presence & awareness

- **Awareness** (cursors/selection/label) is **encrypted** and ephemeral; relayed via `OnAwareness`, never stored.
- **Presence roster** (`OnPresence`) reflects group membership by **account identity** (display name from the user's account) or "guest" — no content. On multi-node it is Redis-backed; single-node keeps it in memory.
- Roster shape [P]:
  an account appears once as `{ Kind: "user", UserId, DisplayName }`, however many of its devices are in the room, because the roster answers who is editing and not how many sockets are open.
  A guest appears as `{ Kind: "guest", UserId: null, DisplayName: null }`, once per guest connection, because a guest has no identity to merge by.
  Accounts come first, ordered by `UserId`, then guests, so every peer renders the same order.
  The roster is sent to the whole room on every join, leave, disconnect and removal by the ACL re-check (§5.4).
- Readers may send awareness [P], so a read-only collaborator's caret and selection are visible to the others.
  Awareness carries no content change, and the read/write split of the ACL concerns content.
- The awareness vectors `awareness.json` (P2.1-CORE-1) hold real y-protocols 1.0.6 updates with the client id, clock and state JSON each decodes to, sealed as `awareness` frames.

## 5.8 Guest sessions

- A guest enters via a **link share** ([09](09-sharing-and-acl.md)); `/share/{token}/ws` upgrades them into the relay room.
- The guest's browser holds the **file key from the URL fragment** — the server never sees it. The guest gets a short-lived scoped session token authorizing **relay access only** ([08](08-authentication.md)).
- `/share/{token}/ws` serves **both read and write links**. Read-only guests receive `OnUpdate`/`OnAwareness` but are rejected via `OnError` on `SubmitUpdate`.
- Guest-authored updates/snapshots store `author_id = null` ([03](03-data-model.md)).

## 5.9 Ordering, durability, conflict

- The server assigns a monotonic `seq` per doc for the encrypted log; CRDT convergence does not depend on order, but `seq` gives the relay a durable cursor and snapshot watermark.
- A write is acknowledged after it is **persisted** (durable) — even though the server can't read it, it won't lose it.
- Room lifecycle: a room is purely a relay group; when empty, the server retains the encrypted log/snapshots and forgets in-memory presence.

## 5.10 Scale-out seam

Multi-node relay uses the Redis SignalR backplane (encrypted fan-out) + Redis presence. v1.0.0 ships single-node; the hub contract is unchanged when the backplane is enabled. The server's reduced role (no merge) makes scaling cheaper than a server-authoritative design.

## 5.11 Conformance testing

`Nyxite.CrdtConformanceTests` pins the Yrs **wire protocol** across `ydotnet` (desktop), Yjs (web), and `yrs/UniFFI` (Android) — independent implementations of the same protocol. Under the relay model the **server does not run a CRDT engine in the live path**, which removes server-side merge as a risk surface; the binding-maturity risk now lives entirely in the clients (the desktop still uses `ydotnet` for local merge/snapshotting).
