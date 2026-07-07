# 16 — Licensing and entitlement (client-side of the license plane)

> **The server owns the *client* side of self-hosting licensing.** It embeds the license public key(s), verifies the per-instance token **offline**, runs the best-effort **check-in client**, resolves **feature-flag gates**, and enforces the **degrade → read-only** escalation for lapsed licenses. The **vendor-side** issuance / registry / lease / revocation plane is the separate [`NyxiteLicense`](https://github.com/Nyxite/NyxiteLicense) component (its `specification/01`). **Boot never depends on the license server.** This is a licensing plane, **disjoint from the E2EE content plane** — no content, key, or count is involved. Wire schemas mirror `license 01` and are **[P]**.

## 16.1 Modes

- **Community (default, free non-commercial):** unlimited seats, group cap **16**, full E2EE / personal / family / sync / search / history / collaboration. No token required; no telemetry. Reached whenever no valid entitlement is present.
- **Licensed (commercial + enterprise):** a valid, in-lease token (online) or an unexpired offline token unlocks the enterprise gates (§16.5).
- Selection is by **entitlement evaluation** (§16.4); an absent/invalid/expired token silently resolves to community. See OPEN-DECISIONS L-1/L-2.

## 16.2 Token & embedded keys (L-2/L-5)

- The server embeds **two license Ed25519 public keys** (rotation slots). A token is authentic if it verifies under **either**.
- Token format is defined by `license 01 §1.2` (`{v, instance_id, email, tier, mode, issued_at, entitlement_exp}` + Ed25519 sig). The server treats it as **opaque config** supplied via `NYXITE_LICENSE_TOKEN` (deploy `14`), not a secret to protect (it is per-instance and non-sensitive).
- **Signing keys are never on the server** — only public keys are embedded; the vendor signs out-of-band.

## 16.3 Offline verification (no network) — startup + timer

1. Read `NYXITE_LICENSE_TOKEN`. Absent ⇒ community.
2. **Ed25519 verify** against the embedded public keys. Fail ⇒ community (log `license_invalid`), **never block boot**.
3. Determine the authenticity layer; entitlement then comes from the **lease** (online, §16.4) or `entitlement_exp` (offline, §16.7).

## 16.4 Check-in client & lease (L-7) **[P]**

Online tokens only. Best-effort, off the request path.

- **Call:** `POST {pinned license origin}/register` with `{token, instance_fingerprint}` on a ~daily timer (jittered) — see `license 01 §1.5`. The **origin + TLS pin are embedded** (L-5); redirecting requires source edits.
- **On success:** cache the returned signed **lease** `{instance_id, tier, lease_exp≈now+30d, revoked, sig}`. Enterprise stays enabled while `now < lease_exp`; each renewal slides `lease_exp` forward.
- **On any failure** (timeout, 5xx, DNS, offline): **no-op** — the cached lease continues until it expires; the escalation clock (§16.6) is simply time-since-last-renewal.
- `instance_fingerprint` = a first-boot random UUID persisted locally; carries no user or host-identifying data.
- **Community never checks in** (zero telemetry). **GDPR:** only `{token, operator-email (in token), fingerprint}` leave the instance; disclosed at issuance + deploy docs.

## 16.5 Feature-flag gates (L-3)

Entitlement resolves to flags, each checked once at its feature site (mirrors the RBAC guard pattern in `12`). Community = all off.

| Flag | Gated capability | Cross-ref |
|---|---|---|
| `ent.sso` | Keycloak/OIDC enterprise IdP (native password+TOTP / passkeys always free) | `08` |
| `ent.reader_groups` | Enterprise "manager reads all" auto-wrap reader-groups (family group-read free) | `09 §9.9` |
| `ent.admin_overrides` | Per-user quota override, per-group `max_members` override, scoped/custom RBAC | `03 §3.2a`, `12 §12.6` |
| `ent.audit_export` | Signed audit-bundle export + long retention (basic audit view free) | `12` |
| `ent.large_groups` | Group size > 16; community pins `group_max_members = 16` **and** disables the per-group override | `07 §7.2a`, `09 §9.9` |

- **G-5 interlock:** in community, `group_max_members` is forced to 16 and `groups.max_members` overrides are rejected; a license lifts both. No schema change — the flag tier-conditions existing G-5 columns.
- Gates are **fail-closed to community**: if entitlement is indeterminate, the enterprise flag is off.

## 16.6 Degrade → read-only enforcement (lapsed only, L-4/L-5)

Applies **only** to an instance whose token is present but whose lease/entitlement has lapsed. A **never-licensed community instance is exempt** and writes documents indefinitely.

| Since last renewal | State | Server behavior |
|---|---|---|
| `now < lease_exp` (≤30 d) | in lease | full enterprise |
| lease expired (day 30) | **degrade** | enterprise flags off; existing enterprise resources (groups > 16, reader-groups, active SSO) **frozen read-only**; create-enterprise / add-member refused `409 license_degraded`; community writes OK |
| day 60 (degrade + 30) | **read-only lockout** | **all** new document writes refused `409 license_readonly`; reads/exports unaffected; **no deletion or corruption** (durability principle, `13`/`15`) |
| any successful check-in | **restored** | flags + write access reinstated immediately |

- **Anchor = token presence only (L-5).** State derives from the configured lapsed token + cached lease timestamps; **removing** the token ⇒ clean community (accepted speed bump — enterprise data (>16 groups, SSO) is unusable in community anyway). No persistent "once-licensed" flag.
- **Revocation (§16.8)** short-circuits: a lease with `revoked:true` degrades at next evaluation.
- Enforcement lives at the write/ACL path (like block/quota in `09`), audited (`12`).

## 16.7 Air-gapped / offline token (L-6)

- `mode:"offline"` tokens carry `entitlement_exp ≈ issue+1yr` and **never check in / never register**. The server honors enterprise flags until `entitlement_exp`, then runs §16.6 dated from expiry.
- Renewal = operator installs a freshly-signed offline token (vendor-issued). No revocation reaches an air-gapped instance before expiry — accepted for this vetted segment.

## 16.8 Revocation **[P]**

- **At check-in:** a `revoked:true` lease (or short/empty lease) from `/register` degrades the instance.
- **Signed revocation feed:** the server may pull an Ed25519-signed revoked-`instance_id` list (`license 01 §1.10`) and honor it on fetch.
- **Best-effort:** firewalled/air-gapped instances are unreachable before lease/`entitlement_exp` — legal terms are the ultimate recourse (§16.9).

## 16.9 Anti-bypass & honest limit (L-5)

- **Light hardening:** the check-in origin + cert/pubkey are pinned in-binary; no obfuscation.
- **Stated plainly:** public source ⇒ the gate is patchable and the token-only anchor deletable. The deterrent is **legal / compliance + friction on compliant companies**, not cryptographic lock-in. Nothing in this component should be treated as tamper-proof.

## 16.10 Config & operations

- `NYXITE_LICENSE_TOKEN` (optional; absent = community) — deploy `14`.
- No new server-held secret (only embedded **public** keys). Health/status of entitlement (tier, lease_exp, degrade state) is exposed to the **admin API** (`12`) read-only for the dashboard's license-status view; it is **not** an enforcement input (the server enforces).
- Audit events: `license_invalid`, `license_degraded`, `license_readonly`, `license_restored`, `license_revoked` — metadata only, never content.
