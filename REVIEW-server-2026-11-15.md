# Server review 2026-11-15

Review of commit `e0aface`, the Phase 2.2 server (P2.2-SRV-1 to P2.2-SRV-3 and the P2.2-CORE-1 sharing fixtures).
It checks the code against the Phase 2.2 plan, the invariants of `implementation/README.md` and the server chapters 04, 05, 08, 09 and 13.
It also follows up the open points of [Server review 2026-11-14](REVIEW-server-2026-11-14.md) that were due with Phase 2.2.
Unlike the previous review, the findings are not yet reproduced by tests.

> Verified 2026-11-15 against Testcontainers Postgres 17: 220 unit tests and 235 integration tests, all green.

## Decisions that fit the project

- The server stays zero-knowledge for shares.
  An account share stores the wrap as opaque bytes of the one supported suite and length, a link share stores only the SHA-256 of the token, and the fragment key never reaches any endpoint.
- Guest and account tokens cannot stand in for each other.
  The guest token has its own `typ` (`nyx-guest+jwt`), each scheme accepts only its own type, and `OnTokenValidated` binds a guest token to the link whose token is in the path.
- Every ACL decision goes through `ShareAccess`, so structure, content, the relay join and submit and the periodic re-check give the same answer.
  A guest's level is read from the share row and not from the `perm` claim, so a downgrade from write to read applies at once and not only after the token expires.
- Trash cascades `deleted_at` to every descendant, so the ancestor walk of `ShareAccess.AncestorsAsync` needs no `deleted_at` filter for a live file.
- The purge deletes the shares of what it purges, link hashes included, so no grant outlives its object.
- Request-line logging of the hosting diagnostics is lowered to `Warning`, because the line carries the link token and the socket ticket.

## Issues

### R1 The per-IP share limit does not count rejected credentials (medium)

`Program.cs` runs `UseRateLimiter` after `UseAuthentication` and `UseAuthorization`.
The authorization middleware answers a failed policy with its challenge and never calls the rate limiter, so a request with a missing, wrong or foreign guest token on `/share/{token}/blob`, `/share/{token}/socket-ticket` or `/share/{token}/ws` is never counted against `share-access`.
Each such request still costs database work, because the guest scheme runs `PathMatchesAsync` and, for a ticket, `RedeemTicketAsync`.
The same holds for a bad socket ticket on `/hubs/relay`, which predates this phase.
Only `GET /share/{token}` and `POST /share/{token}/session` are counted for every request, because they need no authorization.
Tokens and tickets are 256-bit random values, so this is not a guessing risk but an unbounded unauthenticated load on Postgres, which only the nginx flood guard of P2.2-DEP-1 limits.
The fix is to run the per-IP policies before authentication, for example a second `UseRateLimiter` with a global limiter for the `/share` and `/hubs/relay` prefixes ahead of `UseAuthentication`, and keep the per-user policies where they are, because they partition on the authenticated subject.
A test should send 31 requests with a wrong guest token to the blob endpoint and expect `429` on the last one.

### R2 Relay limits are still missing, now with anonymous members (medium)

D2 of the previous review asked for a per-connection awareness rate and room caps "before the relay is exposed to guests".
Phase 2.2 exposes it to anyone holding a link, read-only links included, without such limits.
A guest may send awareness of up to 64 KiB as fast as the socket carries it, and each message is copied to every member of the room, the owner's devices included.
The per-IP `share-access` bucket counts only the handshake, so one connection floods without bound.
A per-connection awareness rate, a cap on connections per room and a cap on rooms per connection need a decision in `docs/OPEN-DECISIONS.md` and an entry in 13 §13.5.

### R3 One live account share per target and grantee is not enforced by the database (low)

`ShareService.AccountShareAsync` checks for a live share and then inserts, inside a transaction at the default isolation level `read committed`.
Two concurrent `POST /shares` with different idempotency keys for the same target and grantee both pass the check and store two live shares, against the decision recorded in `docs/OPEN-DECISIONS.md`.
The consequence is small, two rows that both grant the same level and appear twice in `GET /shares`, but a later revoke of one of them leaves the grantee's reach intact, which the owner would not expect.
A partial unique index over target and grantee where `kind = 'user_grant' AND revoked_at IS NULL` closes the race.
An expired but not revoked share would then block a new one, so the create should revoke an expired share of the same pair first.

### R4 Every unique violation of a share create answers "link token in use" (low)

`ShareService.CreateAsync` maps any `UniqueViolation` on save to `409` with the title "This link token is already in use".
The same save inserts the idempotency row, whose key is `(user_id, endpoint, key)`, so two concurrent requests with the same idempotency key make the second one fail with a link-token message, also for an account share.
The catch should look at the constraint name, answer `uq_shares_link` with the link message and let the idempotency case retry the replay lookup.
After R3 the new index needs its own message as well.

### R5 Revocation of an account share is still timer-driven (low)

Decision 2 of the previous review recommended event-driven eviction "no later than Phase 2.2".
`ShareService.RevokeAsync` and `UpdateAsync` only change the row, so a grantee or guest keeps receiving updates of the room for up to `Relay:AccessRecheckInterval`, 30 s by default.
This is acceptable if the instant cutoff of 09 §9.6 is planned for Phase 2.3, whose capability is the two-layer revocation, but neither the plan nor `docs/OPEN-DECISIONS.md` says so.
Either evict the affected rooms right after the revoke commits, or record the deferral to Phase 2.3.

## Decisions worth revisiting

### Q1 A blocked owner does not stop guest writes

An account grantee is refused when its own account is blocked, but a guest has no account, and `ContentService.WriterAsync` lets every guest through.
When an admin blocks the owner of a project, write links of that project keep accepting edits.
Whether a block of the owner should also make the owner's links read-only is a policy question for Phase 4.2, but it should be written down before the admin dashboard exists.

### Q2 Thirty requests per minute per IP is shared by every guest behind one address

Opening a link costs about five requests, bootstrap, session, socket ticket, the WebSocket handshake and one blob fetch, and all of them share the `share-access` bucket of the client IP.
Guests behind one NAT, such as a class or an office, can therefore open only about six links per minute together.
The value comes from 13 §13.5, so this is not a defect, but the bucket could exempt requests that carry a valid guest token, since R1 already moves the guessing protection to the unauthenticated requests.

## Judgment calls of this phase

The implementation recorded four points in `docs/OPEN-DECISIONS.md` that are the user's to confirm.

1. HPKE `info` and AAD binding of a wrap to another account: consistent with the wrap of the owner's own keys and pinned by `sharing.json`.
   Recommendation: approve, since all three clients consume the same fixture.
2. Link shares target one file only: follows from the URL fragment carrying one file key, and the database enforces it with `ck_shares_kind_fields`.
   Recommendation: approve, a folder link would need a key bundle in the fragment, which 09 §9.4 does not define.
3. A write share covers content only, structure changes stay with the owner: keeps the structure keys and the Trash lifecycle with one account.
   It means a grantee with write access cannot create a note in a shared folder.
   Recommendation: approve for v1.0.0 and track "grantee creates files in a shared folder" as a backlog idea, because users will expect it.
4. `GET /shares` without a target lists the shares granted to the caller: a cheap way to build "shared with me".
   Recommendation: approve.

## Open points

- Move the per-IP limits ahead of authentication and test the rejected-credential case (R1).
- Decide and implement the relay limits for awareness, connections per room and rooms per connection (R2).
- Enforce one live account share per target and grantee in the database and fix the conflict message (R3, R4).
- Decide whether eviction on revoke is part of Phase 2.2 or of Phase 2.3 and record it (R5).
- Decide the effect of a blocked owner on write links (Q1).
- Confirm the four judgment calls of this phase.
- Sync for shared trees is still owner-only, so a grantee reaches shared items only through structure, content and the relay, which the client specs must reflect.
