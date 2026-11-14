# Server review 2026-11-14

Review of commit `03b72c6`, the Phase 2.1 server (P2.1-SRV-1: multi-account relay rooms, presence roster, awareness relay, ACL re-checks, and the P2.1-CORE-1 awareness and relay-wire vectors).
It checks the code against the Phase 2.1 plan, the invariants of `implementation/README.md`, `docs/OPEN-DECISIONS.md` and the server chapters 05, 09, 14 and 15.
Every finding that the code can show is reproduced by a test in [RelayReviewFindingsTests.cs](tests/Nyxite.IntegrationTests/Review/RelayReviewFindingsTests.cs).
Tests with trait `issue` assert the specified behaviour and fail today, tests with trait `decision` assert the current behaviour and pass, so they document a consequence instead of a defect.

```bash
dotnet run --project tests/Nyxite.IntegrationTests -- --filter-class "Nyxite.IntegrationTests.Review.RelayReviewFindingsTests"
```

> Verified 2026-11-14 against Testcontainers Postgres 17: 9 tests, 7 failed (F1 to F5, F6 x2), 2 passed (D1, D2).
> The existing suite stays green: 209 unit tests, 215 integration tests, so the full integration run has 224 tests of which exactly the 7 review tests fail.

## Decisions that fit the project

These choices match the zero-knowledge relay and are covered by the existing tests or were checked for this review.

- The server never decodes, merges or validates update or awareness content, and awareness reaches no table and no blob, which `CollaborationTests.Awareness_is_relayed_byte_for_byte_and_never_stored` checks against every table of the schema and every file of the blob store.
- Nothing content-like or awareness-related is logged or measured.
  The worker logs only a count, the metrics listener only sees the hosting meter, whose route label is `/hubs/relay` without a file id, and SignalR logs invocation arguments only at `Debug`, where a `byte[]` prints as its type name.
- The roster carries only `Kind`, `UserId` and `DisplayName`, which 05 §5.7 allows, and merges devices per account, because the roster answers who is in the room and not how many sockets are open.
- `IFileAccess` is the seam where Phase 2.2 plugs in shares, and every content read, write, join, submit and the re-check go through it, so a revoked share ends at all checkpoints at once (09 §9.6).
- Read reach without write reach answers `403 acl_denied`, no reach `404 not_found`, as 09 §9.5 requires (`CollaborationTests.Two_accounts_co_edit_in_one_room_with_a_roster_of_identities_only`).
- The awareness vectors are genuine.
  They were regenerated for this review with `y-protocols@1.0.6` and `yjs@13.6.33` (client ids 101 and 202, the states of `awareness.json`), and all four updates match byte for byte.
- The relay-wire vectors are genuine as well.
  `@microsoft/signalr-protocol-msgpack@8.0.7` decodes every message of `relay-wire.json` to the contract names, and its own encoding of `SubmitUpdate` and `SubmitAwareness` equals the vector byte for byte, so the web client and the server agree on the map encoding of decision 6.

## Issues

### F1 A failed join leaves a listener outside the roster and the re-check (medium)

`RelayHub.JoinDocument` adds the connection to the SignalR group `file:{fileId}` before it reads the log and enters `RelayPresence` only at the very end.
When anything throws in between, `GuardAsync` reports the error but never removes the connection from the group.
The connection then receives every `OnUpdates` and every `OnAwareness` of the room, while it is neither in the roster nor in `presence.Members()`, which is the only list the periodic re-check judges.
No later revocation removes it, so it listens until it disconnects, against 05 §5.4 and the "periodic re-check" checkpoint of 09 §9.6.
Triggers are a revocation or a move to Trash racing the join (reach is read twice, by `SnapshotPointerAsync` and `ReadUpdatesAsync`) and a transient database error during the log read, after which even a legitimate reader is never evicted once its share ends.
A client cannot force it on its own for a text file, which is why this is medium and not high.
Test `F1_a_failed_join_leaves_no_listener_outside_the_roster_and_the_recheck` lets reach end after the first check, the join fails with `not_found`, the re-check removes nothing, and the failed peer still receives the owner's next update.
The fix is to remove the connection from the group on every failure of the join, or to enter presence together with the group and roll both back, and 05 §5.4 step 4 should then say that the group is joined before the log is read, which the code comment already explains.

### F2 One failing access check stops the whole pass (low)

`RelayAccessCheck.RunAsync` has no error handling per connection.
An exception of one check, such as a timed out query, leaves the method, so every membership after it in that pass is not judged, and the worker only logs a warning.
The order inside a removal makes it worse, because `presence.Leave` runs before `RemoveFromGroupAsync`, so an exception between the two would leave the same orphan as F1.
Test `F2_one_failing_access_check_does_not_stop_the_pass_for_the_others` makes the check of one account throw, and the pass throws instead of removing the revoked reader next to it.
Each check should be isolated, with the group removal before the presence removal, so a failure costs one connection one pass and never more.

### F3 Empty rooms are never forgotten (low)

05 §5.9 says that the server forgets in-memory presence when a room is empty.
`RelayPresence` removes connections but never the room entry, so `_rooms` keeps one dictionary per document joined since the process started, and `Members()` and the re-check walk all of them.
Test `F3_an_empty_room_is_forgotten` joins two documents, leaves one and disconnects, and finds two empty rooms left.
The removal has to be race-free against a concurrent join, for example by removing a room only with `TryRemove` of the exact empty instance and retrying a join that lands in a removed instance.

### F4 A connection of a dead session can still join rooms (low)

The new text of 05 §5.4 says that no room is open to a dead session.
`JoinDocument` reads through `ContentService.FileAsync`, which checks reach but not the session, so a connection whose session was logged out joins new rooms and reads their log until the next pass closes it, and `SubmitAwareness` works as well.
`SubmitUpdate` already checks the session through `DeviceGuard`.
Test `F4_a_connection_of_a_logged_out_session_cannot_join_a_room` logs a session out and its open connection still joins.
The window is bounded by the re-check interval and, after the close, by the 5 minute access token of 08 §8.2, so one session query at join time closes it at little cost.

### F5 Awareness that is not an NYXC frame is relayed (low)

05 §5.5 step 4 defines awareness as an NYXC frame of `object_kind` 6, and the Phase 2.1 exit criterion demands that the server relays ciphertext only.
`SubmitUpdatesAsync` refuses anything that does not parse as an NYXC header, `SubmitAwareness` checks only the size.
A client that forgets to seal its cursor therefore sends plaintext through the relay, and the existing tests even send `new byte[] { 7 }` as awareness.
Test `F5_awareness_that_is_not_an_nyxc_frame_is_refused` sends a plaintext cursor JSON and it reaches the other device.
`NyxcFrame.TryParseHeader` costs nothing at caret rate and cannot tell the `object_kind`, which sits in the AAD, but it rejects every unframed payload, and a key id check against the file key is optional on top.

### F6 A non-positive re-check interval spins the worker (low)

`Relay:AccessRecheckInterval` is not validated.
Zero makes `Task.Delay` complete at once, so the worker runs passes without pause, and a negative value makes `Task.Delay` throw on every turn, which the catch-all logs and loops on.
Test `F6_a_non_positive_recheck_interval_does_not_spin_the_worker` measured 22684 passes per second for `00:00:00` and 344687 warnings per second for `-00:00:01`.
The host does not crash, but one wrong setting burns a core and floods the log, while 14 makes the server refuse to start on other invalid settings.
The option should be validated at startup with `ValidateOnStart`, which fits the fail fast rule of 14 §14.4.

### F7 Concurrent roster broadcasts can arrive out of order (low, not reproduced)

Every join, leave, disconnect and removal computes the full roster and sends it to the room, without a version.
Two concurrent changes compute their rosters independently, and the older one can be delivered last, so a client can show a stale roster until the next change.
This was found by reading and is not reproduced, because the interleaving is not deterministic in the test host.
A monotonic roster version per room, which clients compare before replacing their roster, closes it without a lock on the send path.

## Spec mismatches

- 05 §5.5 step 2 still says "broadcast `OnUpdate` to the rest of the group", against the delivery note of 05 §5.3, which sends `OnUpdates` to the whole room.
  The same old wording sits in 05 §5.8, in the `/share/{token}/ws` row of 04 and in the desktop and android 09 chapters ("receives `OnUpdate`/`OnAwareness`"), so all of them should name `OnUpdates`.
- 05 §5.4 lists "client is added to the group" as step 4, after the log, while the code joins before reading so that no update falls in between.
  The code is right, the step order of the spec should follow it (see F1).
- The points pinned in this phase (decisions 2 to 7 below) have no entry in `docs/OPEN-DECISIONS.md`, unlike Phase 1.1 and 1.2, and the client 09 chapters do not name `Kind` or the reader awareness rule.
  This is expected while the decisions wait for approval and is listed so it is not forgotten afterwards.

## Test gaps

- The last assertion of `Two_accounts_co_edit_in_one_room_with_a_roster_of_identities_only` cannot fail for the reason it states.
  The roster before the phone disconnects is already Ada and Reader, so after a fixed 100 ms delay it compares the old roster with the expected one, whether or not a new roster arrived.
- No test covers a failing join (F1), a throwing pass (F2), a worker failure that the next turn survives, or two devices of one revoked account being removed together.
- The guest branch of `RelayPresence.Roster` and `PresenceDto.ForGuest` are unreachable from the hub, so the guest ordering of 05 §5.7 is only checked by the wire vector.
- `RelayPeer` reads its lists outside the locks that the callbacks take, which can make assertions flaky under load.

## Evaluation of the open decisions

1. Simulated co-editing through a test `IFileAccess`: sound.
   It replaces exactly the seam Phase 2.2 fills and keeps the real ownership path in the maximum, as 09 §9.5 resolves it.
   The consequence is that P2.1-TC-1 (U1 and U2 in the same note) cannot run against a real deployment before Phase 2.2, so the plan should say that TC-1 is closed with 2.2, rather than adding a test-only grant path to production code.
   Recommendation: approve, and note the TC-1 dependency in the phase plan.
2. Re-check every 30 s as `Relay:AccessRecheckInterval`: sound as a backstop, the value and the setting fit 14.
   It does not make the cutoff "instant" as 09 §9.6 promises for the ACL layer, so the events the server sees itself, a share revocation, a move to Trash and a session revocation, should evict the affected room at once and leave the timer for what no event covers.
   Recommendation: approve with validation (F6) and event-driven eviction no later than Phase 2.2.
3. Lost reach leaves only that room with `OnError(not_found)`, a dead session closes the connection with `unauthenticated`: sound.
   A connection serves several rooms, and `not_found` matches the existence hiding of 09 §9.5, while a dead session has no room it may stay in.
   Recommendation: approve, together with the session check at join (F4).
4. Awareness without an ACL check per message: sound.
   Membership is required, so the reach is the one of the join, and a query per caret move would be the most frequent query of the server.
   It only holds if membership is exact, which F1 breaks, and without a rate limit (D2) the shortcut also removes the only natural brake.
   Recommendation: approve once F1 is fixed, and decide on a per-connection awareness rate limit.
5. Readers may send awareness: sound.
   Awareness changes no content, and a reader's caret is useful to the others.
   A reader can put arbitrary JSON into its own awareness state, which clients must render only through known fields, and the flood risk of D2 applies to readers as well.
   Recommendation: approve, and pin in the client specs that unknown awareness fields are ignored.
6. `Kind` in the presence entry and PascalCase MessagePack maps: sound.
   No client implements the 1.1 shape yet and the client specs never named its fields, so nothing breaks, and the JS reference client decodes and encodes the maps byte-identically (see above).
   Recommendation: approve, and record it in `docs/OPEN-DECISIONS.md` and the client 09 chapters.
7. Guests skipped by the re-check: acceptable for Phase 2.1 only, because no guest can join yet.
   As written it fails open, test `D1_a_member_without_a_session_is_never_removed_by_the_recheck` shows that a member without a session is never judged, which would let a guest of a revoked link listen on against 09 §9.6 and 08 §8.7.
   Recommendation: approve only with a fail-closed default, so the re-check removes any member it cannot judge until Phase 2.2 adds the link-share check.

## Decisions worth revisiting

### D1 Members without a session are never re-checked

See decision 7.
Test `D1_a_member_without_a_session_is_never_removed_by_the_recheck` puts a guest entry into a room, and the pass leaves it there.

### D2 No relay limits

A member, a reader included, may send awareness as fast as the socket carries it, up to 64 KiB each, and each message is copied to everyone else in the room.
The clients throttle to 20 to 30 Hz (desktop, android and web 09), the server does not, and the number of rooms per connection and connections per room is unbounded as well.
Test `D2_awareness_is_not_rate_limited` sends 500 awareness messages in a burst from a reader and all of them are relayed.
13 §13.5 defines no relay bucket yet, so a per-connection awareness rate and a room size cap need a decision before the relay is exposed to guests.

## Open points

- Decide whether eviction on share revocation, Trash and session revocation is event-driven (decision 2).
- Decide on a per-connection awareness rate limit and on caps for rooms per connection and connections per room (D2).
- Decide the fail-closed rule for members the re-check cannot judge (decision 7).
- Record the approved Phase 2.1 points in `docs/OPEN-DECISIONS.md` and the client 09 chapters, and replace the remaining `OnUpdate` wording.
- State in the Phase 2.1 plan that P2.1-TC-1 needs the shares of Phase 2.2 to run against a real deployment.
