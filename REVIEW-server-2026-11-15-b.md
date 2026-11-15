# Server review 2026-11-15 (b)

Review of the Phase 2.3 part of commit `3b1dbcb` (P2.3-SRV-1, revocation and rotation) and of commit `68a832b` (P2.4-SRV-1, version history).
The R1 to R5 fixes in `3b1dbcb` are checked only as far as Phase 2.3 builds on them, because they answer [Server review 2026-11-15](REVIEW-server-2026-11-15.md).
It checks the code against the Phase 2.3 and 2.4 plans, the invariants of `implementation/README.md`, `docs/CLAUDE-MEMORY.md`, the server chapters 03, 04, 05, 07, 09, 10 and 13 and `openapi/v1.yaml`.
It also checks the Phase 2.4 spec commits of `NyxiteDesktop` (`a5cc6fa`), `NyxiteAndroid` (`ec92742`), `NyxiteWeb` (`ca6e11a`) and `Nyxite` (`7401015`) for consistency with the server.
V1 to V4 are reproduced in `tests/Nyxite.IntegrationTests/Review/RotationReviewFindingsTests.cs`.

> Verified 2026-11-15 against Testcontainers Postgres 17: 227 unit tests, 1 CRDT conformance test and 251 integration tests, all green before the reproductions were added.
> With them, V1, V2 and V3 (trait `issue`) fail as expected and V4 (trait `decision`) passes, because it documents the consequence of a decision.

## Decisions that fit the project

- The server stays zero-knowledge through both phases.
  The rotation commit checks frame headers, wrap sizes and the member set only, the staged head is ciphertext under a content address, and the restore takes a `seq` and no content.
  The P2.3-TC-2 and P2.4 tests end with the "nothing leaks" inspection over every table, every blob and the log.
- The rotation is write-then-swap.
  The new head is stored before anything points to it, the commit turns it into the head in the transaction that switches the generation, and a head that moved since staging is `409 version_conflict` instead of a silent replacement, which keeps the data-safety invariant.
- The generation guard and the stale-key check sit under the file row lock, the same lock every content write takes.
  Of two concurrent rotations exactly one commits, and an old-key update is accepted until the commit and `412 key_generation_stale` after it, over REST and the relay, as 09 §9.6 requires and `RotationTests` shows.
- The member check is enforced by the server and not left to the client.
  A wrap to a removed member and a commit that leaves out a remaining member are both `400`, and a file share created during a rotation reads the generation under `FOR SHARE`, so it cannot slip past the check.
- Old generations stay readable.
  Wraps and versions are never rewritten, so version history keeps working for members who had a generation, and a rotation never destroys anything.
- The instant ACL cutoff is now event-driven.
  Revoke, share change, Trash and every session end post a scope after their commit, and `RelayAccessWorker` runs a targeted pass of the same check, so P2.3-TC-1 holds without waiting for the periodic pass.
- Restore is a record only, as the zero-knowledge invariant demands.
  The mark binds to the restoring account, so a collaborator's concurrent write is never labelled a restore, and a replay under the same `Idempotency-Key` does not double the audit.
- There is no `/diff` route, and P2.4-TC-1 checks the route table and `openapi/v1.yaml` for one.

## Issues

### V1 A text rotation leaves old-key updates behind the new head (medium)

For a text file the staged head is a snapshot at `crdtSeq` S, and `KeyRotationService.StagedHeadAsync` only refuses the commit when a newer snapshot exists (`KeyRotationService.cs:159-161`).
Updates S+1 to H that collaborators submitted between staging and commit are still accepted with the old key, which 09 §9.6 allows "until commit", and they stay in the log behind the new head, sealed with the old key.
`RotationTests` even asserts this outcome, the log `[old, old, old, new, new]` after a head at S = 2 (`RotationTests.cs:217`, `RotationTests.cs:275`).
The same holds for a text file with updates but no snapshot yet, because `newHeadRef` is then optional (`KeyRotationService.cs:146-150`) and the whole log stays under the old key.
The staged head exists precisely so that "a member added later with the new key only" can open the file (09 §9.6, decision of Phase 2.3), and the client specs state that such a member gets wraps of the new generation only (desktop, android and web `12 §12.1`).
That member then loads the new snapshot but cannot open S+1 to H, so it sees a document without those edits until some client with the old key writes a newer snapshot.
What it displays is then silently incomplete, and nothing tells the member or the owner.
The reproduction `V1_a_text_rotation_leaves_no_old_key_update_behind_the_new_head` stages at S = 1, lets a collaborator submit one update and commits, and finds an old-key update behind the head.
The smallest fix is to refuse the commit with `409 version_conflict` when `file.CrdtHeadSeq` is above the staged `crdtSeq`, the same rule a blob file already has with `ParentSeq`, and to require a staged head for every text file whose log is not empty.
Retries then race a busy document, see W2.

### V2 A rotation makes every link of the file unreadable while it stays live (medium)

The Phase 2.3 decision keeps link shares on a rotation, because "the owner's revocation of one account would silently end unrelated links", and 09 §9.6 says a live link "opens nothing written after a rotation".
In fact the link opens nothing at all after a rotation.
The commit re-seals the head and the name with the new key, and the guest surface serves only the current state: `GET /share/{token}` returns the new `keyId` and the new `nameEnc` (`GuestShareService.cs:53-62`), and `GET /share/{token}/blob` streams the new head (`ShareEndpoints.cs:72-81`).
The fragment holds the old key, so the guest's client fails to open the name and the content, while bootstrap still answers `200` and the audit records `share.link_access`.
The content written before the rotation is not reachable either, because the old head is only in the version history, which guests do not have, and the old updates are pruned once the new snapshot covers them.
So the outcome the decision rejected, unrelated links ending silently, happens anyway, only worse, as a link that looks live and fails with a decryption error.
The reproduction `V2_a_link_that_stays_live_after_a_rotation_still_opens_its_file` creates a read link, rotates and finds the new key in the bootstrap.
This needs a product decision, see "Judgment calls" point 6.
The options are to revoke the file's links with the rotation and let the owner's client re-issue them, to keep serving a link the head of its own generation, or to accept that a rotation ends every link and say so in the UI and in 09 §9.6.

### V3 The restore's idempotency row does not name the file (low)

`ContentService.RecordRestoreAsync` stores the idempotency row under `(user_id, "POST /files/{id}/restore", key)` with the hash of the body `{ seq }` only (`ContentService.cs:148`, `ContentService.cs:152`).
The path id is in neither, so the same key with the same `seq` on a second file is taken as a replay of the first and answered `204`, with no mark and no `version.restore` event for the second file.
Every earlier idempotent endpoint either has no path id or a body that names a fresh id, like `newKeyId` of the rotation, so this is the first endpoint where the gap shows.
A client normally sends a fresh key per restore, but a client that derives the key from the restore action or reuses a key across files gets a silent success that recorded nothing, and the history then lacks the link.
The reproduction `V3_a_restore_key_reused_on_another_file_is_not_a_silent_replay` restores seq 1 on two files with one key and finds no mark on the second.
The fix is to hash `{ fileId, seq }`, or to put the file id into the endpoint string, so a reuse on another file is `409 idempotency_conflict`.

### V4 An excluded file cannot be rotated until its content is purged (low)

A file switched to `excluded` keeps its head until `TrashPurger.PurgeExcludedContentAsync` runs after Trash plus grace window, 60 days by default (`TrashPurger.cs:74`).
In that time the commit requires `newHeadRef`, because the file has a head (`KeyRotationService.cs:148`), and both the stage and a commit with a head answer `409 excluded_content` (`ContentService.cs:357`, `KeyRotationService.cs:152-153`).
So the second layer of revocation cannot run for such a file for up to 60 days, and the name and metadata stay sealed with the key the removed member holds, while remaining members can still fetch the old head.
The ACL layer still cuts the removed member off, so this is no leak, but it is a gap in P2.3-TC-2 that nobody would notice.
The reproduction `V4_an_excluded_file_cannot_be_rotated_until_its_content_is_purged` documents the current behaviour and passes.
The likely fix is to allow a rotation without a head for an excluded file, which re-seals name and metadata and leaves the old head to the purge, but whether an excluded file should be rotatable at all is a product decision.
The excluded purge also clears `pending_restore_seq` but not `pending_restore_by` (`TrashPurger.cs:107`), which is harmless because the mark needs both, but leaves a stale account id.

### V5 The member check is not ordered against folder and project shares or against revokes (low)

The commit locks the file row and reads the members at `read committed` (`KeyRotationService.cs:56`, `ShareAccess.cs:112`).
Only an account share of the file itself takes that row lock (`ShareService.cs:129`), so a share of the file's folder or project created concurrently can commit after the member read and before the rotation commits.
Its grantee then reaches the file but holds no wrap of the new generation, which the Phase 2.3 decision rules out, and `POST /files/keys:batch` would hand it the old key only, because the owner's client wrapped what it saw.
In the other direction, a `DELETE /shares/{id}` of another member that commits after the member read leaves a new-key wrap for an account that no longer reaches the file.
That wrap cannot be fetched, because `GET /files/{id}/keys` needs reach, so the ACL layer holds, but the server keeps a wrap the decision says no removed member ever gets.
Both need concurrent owner actions on two devices and are not reproduced.
The fix is to take the same order for every share change that can change the members of a file, for example a `FOR SHARE` on the project row in the share create and revoke and a `FOR UPDATE` on it in the rotation commit, and to state the order in 09 §9.6.

### V6 A stage that expires during its commit can leave a head without bytes (low)

The commit reads the stage without a lock (`KeyRotationService.cs:156`), and only takes the address lock afterwards (`KeyRotationService.cs:86`).
`ExpiredRowCleaner` deletes stages older than `OrphanBlobAgeHours` without the file lock (`ExpiredRowCleaner.cs:68-69`), and `BlobCollector` then deletes the blob as soon as no row names it.
If both run between the commit's read and its address lock, the commit creates a head version whose blob is gone, and the final `ExecuteDeleteAsync` of the stages does not notice that the row it used had already vanished (`KeyRotationService.cs:97`).
`ContentService.AddVersionAsync` does not have this problem, because it writes the blob again under the address lock.
The window needs a stage exactly at its expiry, 24 h by default, so it is unlikely, but it is a data-loss path in a write-then-swap design.
The fix is to read the stage with `FOR UPDATE` and let the cleaner skip locked rows, or to take the address lock before the stage read and check the stage again under it.

### V7 A failed targeted re-check is neither retried nor fail-closed (low)

The instant layer of 09 §9.6 now depends on one targeted pass per event.
`RelayAccessCheck.RunAsync` logs and skips a member whose check throws (`RelayAccessCheck.cs:87-91`), and the worker does not queue the scope again, so a revoked member whose check hit a transient database error stays in the room until the periodic pass, 30 s by default.
That is the open point "the fail-closed rule for members the re-check cannot judge" of [Server review 2026-11-14](REVIEW-server-2026-11-14.md), which is due now that Phase 2.3 promises the instant cutoff.
Submit is still checked on every call, so the member can only listen in that window.
Either re-queue the scope of a failed targeted pass once, or remove a member whose targeted check fails, and record the rule in 05 §5.4.

### V8 The specification still lets any remaining member rotate (low)

The Phase 2.3 decision and 09 §9.6 say that only the project owner rotates, and the code enforces it.
The older wording was not updated in three places: 09 §9.6 item 2 says "a remaining member's client rotates the file key" (`09-sharing-and-acl.md:109`), 07 §7.9 says the key "is rotated by a remaining member's client" (`07-encryption.md:143`), and P2.3-TC-2 in the phase plan says "a remaining member's client rotates the FK".
A client team reading 07 would build a rotation path for grantees that the server answers with `403 acl_denied`.
These sentences should say "the owner's client", and the plan's TC-2 should name the owner.

### V9 The client specs flag LWW losers from a feed grantees do not get (low)

The three client `12` chapters flag a version as a kept loser when "the change feed delivered it with `isHead: false`" (`NyxiteDesktop` `12-version-history.md:59`, `NyxiteAndroid` `12-version-history.md:60`, `NyxiteWeb` `12-version-history.md:74`).
The feed is still owner-scoped, because shared-tree sync is not part of Phase 2.2, so a grantee never receives such an entry.
For a grantee only the `409` sibling of its own write and a `seq` above the head remain, so a collaborator's lost edit looks like any earlier version in a grantee's history, which widens the open point on unmarked LWW losers.
The chapters should say that the feed signal is the owner's only, until shared-tree sync exists.

### V10 Acceptance coverage misses the cases that span both phases (low)

P2.3-TC-1 and TC-2 and P2.4-TC-1 and TC-2 are covered as written, but four paths that the new rules define have no test:

- a rotation whose members reach the file through a folder or a project share, which is how most files are shared, so the ancestor walk of `MembersAsync` is untested
- a rotation of a file with a live link, which would have shown V2
- a restore of a version sealed with an older generation after a rotation, which 10 §10.5 says must be sealed again and otherwise answers `412`
- a rotation or stage by a blocked owner, which answers `account_blocked`

Each is a short integration test next to `RotationTests` and `VersionHistoryTests`.

## Decisions worth revisiting

### W1 Owner-only rotation leaves revocation half done while the owner is offline

Only the owner rotates, so a revocation by an owner who then goes offline, or by an owner whose device is lost, leaves the file on the old key until the owner returns.
The privacy argument for it, that a writer would need the member list, is sound and fits the privacy focus.
But the clients must then queue the rotation durably on the owner's devices and show the owner that a revocation is not complete yet, which the client specs of Phase 2.3 should state.
A grantee who removes its own share (DL-3) needs no rotation, because it leaves voluntarily, and the specs could say so to avoid needless rotations.

### W2 The moved-head rule can starve a rotation of a busy document

A rotation is refused whenever the head moved since staging, and the fix of V1 adds every update to that rule.
In a document under constant editing, staging, wrapping and committing take several round trips, so the owner's client may lose the race repeatedly.
Holding back the old-key writes while a rotation is staged, or letting the commit name the log position the client re-sealed up to and taking the remaining updates as a re-sealed batch, would bound it.
Neither is needed for the alpha, but a retry limit and backoff should be written into the client specs, and the case should be measured once clients exist.

## Judgment calls of this phase

The implementation recorded the points below in `docs/OPEN-DECISIONS.md` as proposed, and they are the user's to confirm.

1. Rotation as write-then-swap with a staged head and `newHeadRef` as its content hash: fills the gap 2.2 left open without a hidden version row.
   Recommendation: approve, with V1 and V6 fixed.
2. A head that moved since staging is `409 version_conflict`: required by the data-safety invariant.
   Recommendation: approve, and extend it to text updates (V1).
3. Only the project owner rotates: consistent with "only the owner hands out keys" and with the privacy focus.
   Recommendation: approve, with the client-side queue of W1 and the wording of V8.
4. The wraps must go to exactly the accounts that reach the file, checked under the file lock: the right server-side check.
   Recommendation: approve, with the ordering of V5.
5. The commit re-seals `nameEnc` and `metadataEnc`: necessary, because listings hand out only the current generation's wrap.
   Recommendation: approve.
6. Old generations stay and link shares are left alone: the first half fits version history, the second half does not work as described (V2).
   Recommendation: approve keeping old generations, and decide again on links, preferably revoking them with the rotation and letting the owner's client offer new links, because a dead link that answers as live is the worst of the three outcomes.
7. No relay event for a rotation: the existing `412` and the new `keyId` give the hint without a contract change.
   Recommendation: approve.
8. No rate limit of its own for rotation: only the owner rotates and each commit moves the generation by one.
   Recommendation: approve, stages are bounded by the quota.
9. Project and folder key rotation (ST-1) stays open: no endpoint is specified.
   Recommendation: keep open, but note that a removed member keeps the old folder and project keys, so later names stay readable to it if their ciphertext ever reaches it again, and plan it for Phase 4.4 at the latest.
10. Relay limits of 60 awareness messages per second, 100 connections per room and 50 rooms per connection, per-IP buckets before authentication, eviction on revoke, Trash and session end: they close R1, R2 and R5 and D2 of the earlier reviews.
    Recommendation: approve, with V7.
11. The restore mark binds to the restoring account, a lost LWW upload still takes it, and one mark per file: sound, because the audit is the record.
    Recommendation: approve.
12. The restore is idempotent and refused for an excluded file, every account with read reach sees the history, and clients verify before they diff or restore.
    Recommendation: approve, with V3 fixed.
13. A pending mark does not expire, and kept LWW losers are not marked in the version record: both stay open.
    Recommendation: add `parentSeq` to the version record before the sync shapes freeze for v1.0.0, because V9 shows that grantees otherwise cannot flag losers at all, and expire the mark with the account's next write that is not a restore, signalled by a header on the write.

## Open points

- Refuse a text rotation that would leave old-key updates behind the new head (V1).
- Decide what a rotation does to the file's links, and make the server and 09 §9.6 match (V2).
- Scope the restore's idempotency row to the file (V3).
- Decide whether an excluded file can be rotated without a head (V4).
- Order share changes on folders and projects and revokes against the rotation commit (V5).
- Lock the stage during its commit (V6).
- Decide the rule for a failed targeted re-check (V7), which was open since the Phase 2.1 review.
- Align 07 §7.9, 09 §9.6 item 2 and the phase plan with owner-only rotation (V8), and the client `12` chapters with the owner-scoped feed (V9).
- Add the four missing tests (V10).
- Confirm the judgment calls of Phases 2.3 and 2.4 above.
- Q1 and Q2 of [Server review 2026-11-15](REVIEW-server-2026-11-15.md), a blocked owner and guest writes and the shared per-IP bucket, are not addressed yet and stay with Phase 4.2.
