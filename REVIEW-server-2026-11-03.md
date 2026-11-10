# Server review 2026-11-03

Review of the current `NyxiteServer` implementation (P0.1-SRV-1 to SRV-3: scaffold, identity schema, native auth, sessions) against the server specification and the Phase 0.1 plan.
Every finding is reproduced by a test in [ReviewFindingsTests.cs](tests/Nyxite.IntegrationTests/Review/ReviewFindingsTests.cs).
Tests with trait `issue` or `scope` assert the specified behaviour and fail today, tests with trait `decision` assert the current behaviour and pass, so they document a consequence instead of a defect.

```bash
dotnet run --project tests/Nyxite.IntegrationTests -- --filter-class "Nyxite.IntegrationTests.Review.ReviewFindingsTests"
```

> Verified 2026-11-03 against Testcontainers Postgres 17: 11 tests, 9 failed (R1 to R5, S x3), 2 passed (D1, D2).
> The existing suite stays green: 120 unit tests, 65 integration tests.

## Decisions that fit the project

These choices match the privacy-first, zero-knowledge goal and are already covered by the existing tests.

- HS256 access tokens with versioned `kid`, `typ: at+jwt` pinned and a 5 min lifetime fit, because only the issuing server verifies them and no hybrid signature overhead lands in every header (`SessionTests.Token_signed_with_rotated_out_key_is_rejected_and_previous_key_accepted`).
- Opaque, SHA-256-hashed refresh tokens with rotation, reuse detection and a conditional update against double spending follow the OAuth Security BCP (`SessionTests.Reusing_a_refresh_token_revokes_the_whole_session`, `Concurrent_refreshes_of_one_token_produce_at_most_one_child`).
- Single-statement `UPDATE ... RETURNING` consumption of `ephemeral_tokens` in Postgres keeps single use correct across nodes without making Redis mandatory.
- The peppered Argon2id verifier with lazy re-pepper, a dummy verification for unknown accounts and identical 401 bodies avoids account enumeration through login (`NativeAuthTests.Wrong_password_and_unknown_account_get_the_same_401`).
- Discoverable passkeys with an ignored `email` on `assert/options` reveal nothing about which accounts have passkeys (`PasskeyTests.Assert_options_reveal_nothing_about_the_email`).
- No code path derives a key from the password, and the schema has no plaintext name, KEK or private-key column (`SchemaTests`).

## Issues

### R1 Blocked accounts still get web sessions

[12 §12.6](specification/12-administration.md) and [09 §9.5](specification/09-sharing-and-acl.md) require that a `blocked` account is refused web-client sessions.
`NativeAuthService.LoginAsync`, `CompleteTotpLoginAsync` and `PasskeyService.FinishAssertionAsync` never read `users.status`, so a blocked user completes a `clientKind = web` login.
Test `R1_blocked_account_cannot_start_a_web_session` gets `200` with tokens.

### R2 TOTP codes can be replayed

`TotpCodes.Verify` accepts any code inside the +-1 step window and nothing records the last accepted time step.
A code seen once, for example over a shoulder or from a log, signs in again within about 90 s after a fresh password step.
RFC 6238 §5.2 forbids accepting the same code twice, and the fix is a `totp_last_step` per user that every successful check must exceed.
Test `R2_totp_code_cannot_be_replayed_for_a_second_login` gets `200` for the replay.

### R3 No rate limiting

[08 §8.9](specification/08-authentication.md) and [13 §13.5](specification/13-security.md) specify 10/min/IP on auth with `429 rate_limited` and `Retry-After`, and nothing in `Program.cs` limits requests.
Combined with `MfaMaxAttempts` counting per `mfaToken` only, an attacker with the password can open unlimited new `mfaToken`s and guess TOTP codes without any account-wide cap.
Test `R3_login_is_rate_limited` gets `401` on the eleventh attempt instead of `429`.

### R4 No step-up for factor changes

[08 §8.2](specification/08-authentication.md) requires a recent second factor for sensitive account actions.
`NativeAuthService.RequireEnrollmentRightAsync` only checks that the token carries `amr: mfa`, and a refresh keeps that claim for the whole 90-day session.
So any full access token, including a stolen 5-minute one, can add a passkey, which alone is enough to sign in, or replace the TOTP secret and thereby revoke the owner's other sessions.
Tests `R4a_adding_a_passkey_requires_a_recent_second_factor` and `R4b_replacing_totp_requires_a_recent_second_factor` succeed 13 days after the last factor with `204` and `200`.
The spec does not define "recent", so the window has to be decided and should be a setting.
Since a fresh stolen token passes any window, requiring proof of an existing factor (current TOTP code or a passkey assertion) for factor changes is the stronger fix.

### R5 Adding a passkey does not revoke other sessions

[03 §3.2](specification/03-data-model.md) lists "a password/TOTP/passkey change" as a revocation trigger.
Replacing TOTP revokes the other sessions, registering a passkey on an already enrolled account does not.
Test `R5_adding_a_passkey_to_an_enrolled_account_revokes_the_other_sessions` can still refresh the other session.
The spec wording leaves open whether adding (rather than replacing) counts as a change, so this needs a decision before the fix.

## Phase 0.1 scope still missing

P0.1-SRV-5 asks for `/openapi/v1.json`, `/health/live` and `/health/ready`, and all three answer `404` (test `S_phase_0_1_operational_endpoints_are_served`).
`openapi/v1.yaml` is embedded and `YamlDotNet` is referenced, but nothing serves it, and the contract drift tests of [04 §4.1](specification/04-rest-api.md) do not exist yet.
P0.1-SRV-4 (keys, devices, recovery), the app-role GRANTs that make `audit_log` append-only (P0.1-TC-9), P0.1-SRV-6 (license seam) and `/auth/password/forgot|reset` are not implemented.
These are listed for completeness and not as defects of the existing code.

## Decisions worth revisiting

### D1 Email addresses are not verified

Registration accepts any address without proof of control, and the unique email then answers `409` for the real owner.
A squatter who also enrolls a TOTP secret keeps the account even after a future email password reset, because the reset restores the password but not the second factor.
Test `D1_unverified_email_can_be_squatted_with_the_squatters_second_factor` demonstrates the `409`.
Email verification before the account becomes usable, or a reset flow that also clears unconfirmed factors, would close it.

### D2 Password alone takes over an account without a factor

The `enrollment_required` answer on login is specified so a lost registration session cannot lock an account out.
The consequence is that, until the first factor exists, the password alone gives a full takeover, and the owner's registration session stays alive for up to 90 days without being able to enroll.
Test `D2_password_alone_takes_over_an_account_that_has_not_enrolled_yet` demonstrates both.
A short absolute lifetime for enrollment-limited sessions and an audit or notification on first enrollment would reduce the exposure without giving up the lockout protection.

## Open points

- Define the step-up window of R4 and whether factor changes need proof of an existing factor.
- Decide whether adding a passkey counts as a credential change in the sense of R5.
- Decide on email verification (D1) and on the lifetime of enrollment-limited sessions (D2).
