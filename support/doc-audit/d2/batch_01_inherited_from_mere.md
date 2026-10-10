# Inherited D2 records

Founded 2026-10-09 with the repository (dramatis repo plan, DR-D, ruling
D19). Each moved document's latest judgment record in mere's ledger
(`repos/mere/support/doc-audit/d2/`), copied verbatim under the document's
path here. Paths inside a record are mere-relative and describe mere's tree
at that record's audit base; they are evidence, not navigation. A later
record in this directory supersedes the one below for its document.

## 2026-09-30_dramatis_tier_architecture.md

*From mere's `batch_24_dramatis_tier_architecture.md`, recorded for `dramatis_docs/technical_architecture/2026-09-30_dramatis_tier_architecture.md`.*

- disposition: current
- status line: "Status: current. The tier's architecture of record … It synthesises the plans listed in §8 and does not replace them" — accurate: yes
- claims checked: 31 — holds: 31, stale: 0, unverifiable: 0

### Stale claims

- none.

### Contradictions

- none. The document's rulings amend the credential brief's "gazette carries
  discovery inward", gazette's README boundary "gazette reads what is already
  public", the tier plan's empty-facade checkbox, and the djinn plan's
  ownership table; each carries a dated amendment pointing here.

### Recommended action

- none for this record. Every 2026-10-01 ruling is marked unbuilt in the
  document.

### Notes

The claims checked, against source at the audit base: djinn owning one
`CastellanResident` (`ports/djinn/src/resident.rs`); personae's `Issue`
(`delegation.rs`) and `AttestationKeys` and `IdentityProvider`
(`provider.rs`); castellan's `PersonaeHost` (`authority.rs`), `OtpReleaseGate`
(`otp/release.rs`), `DeviceGrantView` (`view.rs`) and `sealed_backend`
(`sealed_storage.rs`); insigne's `CheckedAttestation`, `CheckedCertificate`,
`CheckedRevocation` and `CheckFault`; gaz's `Anchor`, `root`, `keys_for`,
`verify_scope`, `alarms`, `is_alarming`, `intake_addresses` and the
`jscontact` `PublicCard`; gaz's manifest (insigne as the only tier runtime
dependency, personae and insigne `verify` as dev-dependencies); gazette's
`WebFingerIntake::from_import`, its blocking `reqwest`, and its README's
"already public" boundary; the crate consolidation plan's 2026-09-23 limit
that castellan's sealed OTP store stays in castellan.

Added 2026-10-01: djinn's site service binding loopback Gemini only
(`ports/djinn/src/resident_site.rs:1007`); the djinn plan's split of lifetime
and scheduling from domain policy, and its scheduler's first two consumers;
finger-protocol's `webfinger` feature compiling for wasm32-unknown-unknown
(checked from smolweb's workspace, exit 0); reqwest 0.12.28 compiling
`blocking` out on wasm32 through `if_hyper!` (its `src/lib.rs`, the version in
mere's lock); finger-protocol's `Jrd` and `Link` deriving `Serialize` and
`Deserialize` with RFC 7033 §4.4's fields; gazette's `WebFingerDocument`
deriving `Deserialize` only, with a required `subject` and a link of `rel`,
`type` and `href`; errand taking finger-protocol without `webfinger`
(`crates/system/errand/src/finger.rs`); CXF v1.0's 17 credential types
(Proposed Standard, 2026-03-09, read from the FIDO Alliance specification);
castellan's `ImportSshKeyNativeIntentV1` (`authority.rs`) and its `OtpItemId`
and `OtpItem` (`otp/item.rs`); and the sibling pins, eight repos at four mere
revisions, read from their manifests.

## 2026-07-08_personae_founding.md

*From mere's `snapshot_281_aggregate.json (batch 14)`, recorded for `dramatis_docs/technical_architecture/2026-07-08_personae_founding.md`.*

- disposition: historical-unmarked
- status line: "founded... mere keeps its in-tree `persona/identity` until a deliberate re-base" — accurate: no
- claims checked: 8 — holds: 5, stale: 3, unverifiable: 0

### Stale claims

- "mere keeps its in-tree `persona/identity` until a deliberate re-base" — `crates/persona` does not exist at all in the pinned tree; it was deleted as "the dead duplicate" during the 2026-07-23 repo consolidation (repo_consolidation_plan.md, C3a: "Delete `crates/persona/identity`; the `identity` alias becomes a workspace path").
- Roadmap item 3, "mere re-base (last)... deliberately deferred so the app re-bases once, at the end" — reads as still-pending. It in fact landed 2026-07-23, *before* the doc's own most recent inline edit (item 1's "Done 2026-08-10" strikethrough), so the doc has been touched since the re-base happened but item 3 was never marked done.
- "MIT OR Apache-2.0, edition 2024 — the ecosystem default" — superseded: `crates/dramatis/personae/Cargo.toml` has `license.workspace = true`, and mere's workspace license is now `MPL-2.0` (`Cargo.toml:126`) per the 2026-08-22 license posture brief, which explicitly named MPL-2.0 as now covering "mere and genet" platform code. `design_docs/DOC_README.md:254` independently corroborates the drift: it still describes "personae 0.1.0 published 2026-07-08 (MIT/Apache...)" while the in-tree crate is at version 0.2.1.

### Contradictions

- none.

### Recommended action

- mark-historical (banner: the identity core's fate is settled — it landed in-tree via the 2026-07-23 consolidation, not via an external re-base)

### Notes

- Held: "personae subsumes signet... `signet` / `signaculum` is dropped" — no trace of either name in the pinned tree's crates. "32 tests + doctest" is an as-of-founding-day snapshot and is treated as holding (not falsifiable against a later commit). `wallet_carry_foldin_plan.md` exists. The `identity` workspace alias does point at `personae` today, which is what this doc's roadmap ultimately wanted, just accomplished by full absorption rather than a git dependency.


## 2026-07-08_personae_across_the_suite.md

*From mere's `snapshot_281_aggregate.json (batch 14)`, recorded for `dramatis_docs/research/2026-07-08_personae_across_the_suite.md`.*

- disposition: current
- status line: "vision / architecture brief" — accurate: yes
- claims checked: 7 — holds: 5, stale: 1, unverifiable: 1

### Stale claims

- "mere... re-bases onto personae last (the wallet carry layer plan's arc)" is framed as pending/future. It has since landed: the 2026-07-23 repo consolidation deleted `crates/persona/identity` and made the workspace `identity` alias a path pointing at `crates/dramatis/personae` (`Cargo.toml:350`, `identity = { package = "personae", ... path = "crates/dramatis/personae" }`). The doc, dated 2026-07-08, predates this and isn't updated.

### Contradictions

- none.

### Recommended action

- none.

### Notes

- Held: both cited companion docs exist (`signet_trust_plane_plan.md`, `persona_wallet_carry_layer_plan.md`); `SealedIdentityProvider`, `DerivedKeyAttestation`, and a `PayloadSealer`-shaped seal type all exist in `crates/dramatis/personae/src/` and `crates/eidetic/eidetic-core/src/seal.rs`; isometry and woodshed both depend on `personae` per their `Cargo.toml`s (`repos/isometry/Cargo.toml`, `repos/woodshed/Cargo.toml`).
- "Strophe hand-off v2 is the first consumer" of `DerivedKeyAttestation` is unverifiable: no `strophe` checkout exists under `repos/` or `crates/` on this machine (only a proposal stub at `Code/readme-proposals/strophe.md` and an empty `Code/testing/strophe`), so the claim cannot be checked either way.


## 2026-08-08_gaz_founding_plan.md

*From mere's `batch_39_s14_phase_b1.md`, recorded for `dramatis_docs/implementation_strategy/2026-08-08_gaz_founding_plan.md`.*

- disposition: current
- status line: "Status: M0 landed 2026-08-08. On 2026-09-23 Mark ruled the anchor (a typed key, a `did:plc`, or a local id), reaffirmed it over the standards survey's first-pass DID grading (amended to match), and accepted the three M0.5 proposals from that day's critical pass: anchoring on a peer's root with attested keys held concurrently, a whole-identity Reticulum key (verified against Reticulum's reference implementation), and `Anchor::Local` for keyless contacts. JSContact is ruled *an* exchange format (M1). M0.5 landed the same day, and `TypedKey` then moved to insigne, as Mark ruled. M1 keeps sealing at the host and JSContact at the exchange boundary. M2 is drafted with done-conditions. The retained-proof slice of M2 landed on 2026-09-29 under Insigne phase D; M1's storage gate is implemented on 2026-09-29 and its host sealing gate on 2026-09-30; JSContact exchange landed 2026-09-30, completing the M1 library gates. The first M2 address-intake and WebFinger adapter slice landed 2026-09-30; checked key/PLC intake and application wiring remain open." — accurate: yes
- claims checked: 13 — holds: 11, stale: 1, unverifiable: 1

### Stale claims

- **M0.5 says no book was ever stored and nothing outside gaz consumes it.** The claims are at lines 194-196 ("Nothing stores a book yet and nothing outside gaz consumes it (checked 2026-09-23), so there is no migration and no legacy decoder") and §5 lines 475-476 ("no book was ever stored"). Both were false on their date:
  - Retinue's `apps/signalman-desktop/src/messages.rs:5,50,128` imports `gaz::{ContactBook, ContactKey, ...}` and loads and saves a `ContactBook` through Muniment slots.
  - It does this at Mere `d82afa17` (`apps/signalman-desktop/Cargo.toml:72`), and has since retinue `864645e` (2026-08-19).
  - M0.5 then changed the stored shape (a list instead of a map, hex map keys gone).

### Contradictions

- The insigne proofs plan's phase D (lines 487-489) records the same Signalman consumer still importing the pre-M0.5 `ContactKey`.

### Recommended action

- Correct M0.5 and §5 with the retinue finding, and record how Signalman's stored books are handled at its repin (fork).

### Notes

- Present at base: `lib.rs:109` re-exports, `anchor.rs:69` (`LocalId(Uuid)`), `persistence.rs:83,97`, `jscontact/exchange.rs:53-115`, `intake/apply.rs:23`, gazette `intake.rs:30,76`, castellan `tests/sealed_contacts.rs` and `tests/sealed_webfinger_intake.rs`, `sealed_storage.rs:24`, pandect `wallet_sealed_backend.rs:51`.
- `5364dfa0`, `cf901f3d`, `ca2351b3` and `8425cd73` are all ancestors of the base.
- The last gaz commit is `c388babb` (2026-09-30), so the open M2 gates and application wiring are still open. Gaz is only a castellan dev-dependency.
- Test counts were not re-run.

## 2026-10-06_dramatis_repo_plan.md

*From mere's `batch_38_dramatis_repo_plan.md`, recorded for `dramatis_docs/implementation_strategy/2026-10-06_dramatis_repo_plan.md`.*

- disposition: current
- status line: "Status (2026-10-06): assessed; rulings D1 to D21 (§3). Nothing built. The vault lock finishes first (D18), then phases DR-A to DR-E (§4)." — accurate: yes
- claims checked: 4 — holds: 4, stale: 0, unverifiable: 0

### Stale claims

- none.

### Contradictions

- none.

### Recommended action

- none for this record.

### Notes

The claims checked:
- castellan's size (3,626 lines over `ports/castellan/src/*.rs`) and the
  split of `view.rs` plus `projection.rs` (1,210 lines) and `authority.rs`
  (1,600 lines), by `wc -l`;
- the reference counts (62 code files, 48 doc files, 605 lines), by
  `git grep -i castellan`;
- crates.io ownership of castellan, chatelaine and dramatis (mark-ik), by
  the crates.io owners API on 2026-10-06;
- `DOC_POLICY.md`'s area-root invariant, in its local addendum.

## 2026-10-01_chatelaine_cxf_plan.md

*From mere's `batch_45_s14_phase_b7.md`, recorded for `dramatis_docs/implementation_strategy/2026-10-01_chatelaine_cxf_plan.md`.*

- disposition: current
- status line: "Status (2026-10-04): in progress. Shape ruled by Mark on 2026-10-01 (rulings 7 and 10 to 15 in the dramatis tier architecture; rulings 16 to 65 below). P0 met; P1 landed on `main` (`da3c50bc`); P2 landed (`3e4992ec`); P3 landed (`ff68e86c`), meeting the Mere 0.4 baseline's chatelaine condition. The review stop ended 2026-10-04 (ruling 51), and P4a landed (`007fbe7c`, rulings 51 to 63): the agent signs RSA through ring and ECDSA (P-256, P-384) beside Ed25519; held keys are never rewritten; unsignable keys and P-521 are refused at all three doors. P4 (CXF import) waits for the vault lock, in its own plan (rulings 64, 65)." — accurate: yes
- claims checked: 9 — holds: 9, stale: 0, unverifiable: 0

### Stale claims

- none.

### Contradictions

- Internal: P4a's four done-condition boxes (l.559-571) are still unchecked ([ ]), while the status and Progress (l.912) say P4a landed as `007fbe7c`. The box "ECDSA on the curves `ssh-key` supports" also conflicts with the P-521 refusal (ruling 55; `personae/src/ssh_sign.rs:16,45-47`).
- DOC_README.md:610: the dramatis tier architecture entry ends "and dramatis is the facade sibling repos pin; all unbuilt", although chatelaine's P1-P3 have landed. This doc's own DOC_README entry is consistent.

### Recommended action

- Tick the P4a boxes, amending the ECDSA box to record P-521's refusal under ruling 55.
- Separately, correct DOC_README's "all unbuilt" on the tier architecture entry.

### Notes

- Ancestors of the base:
  - phase merges `da3c50bc`, `3e4992ec`, `ff68e86c` and `007fbe7c`;
  - `f0141e3a`, `ff78acca` and `f7b31b9a`;
  - lane commits `71a91267`, `23e2b43b`, `e7c8acbd`, `0891771f`, `2d2a36c6` and `dfee134a`.
- `f8734195` and `eb79b36e` are worktree verification merges and are correctly not on main.
- At the base:
  - `chatelaine/src/kind.rs:57` carries `#[non_exhaustive]`, and `disposition.rs:35` is present;
  - castellan has `ItemStore` (`items.rs:138`) and `SecretServiceStore { items, limits }` (`secret_service/store.rs:238-241`);
  - `OtpItem`, `castellan/otp/v1` and `castellan/secret-service/v1` are gone;
  - personae has no vault lock method, and castellan hard-codes `VaultLockView::Unlocked` (`authority.rs:224`; the plan's l.940 cites :201, an older line number).
- After the base, HEAD records vault-lock L1 landing (`2556a20c`, not an ancestor of the base), so P4's gate may move soon.

## 2026-08-12_ssh_ca_projection_plan.md

*From mere's `batch_39_s14_phase_b1.md`, recorded for `dramatis_docs/implementation_strategy/2026-08-12_ssh_ca_projection_plan.md`.*

- disposition: historical-marked
- status line: "Status: T1–T5 landed 2026-08-12, the same day this was drafted; see Progress for what the building of it corrected. Drafted the evening the wgpu-weld parity sweep ran its Intel-iMac leg over SSH and paid the bilateral toll three ways in one afternoon." — accurate: no
- claims checked: 12 — holds: 10, stale: 1, unverifiable: 1

### Stale claims

- **Status says T1–T5 landed, but T2's host certificates were never built** (the plan's own 2026-10-02 correction says so):
  - `SshCertAuthority::mint_host_cert` (`crates/dramatis/personae/src/ssh_ca.rs:276`) is called only from `ssh_ca.rs:646` (inside `mod tests` at line 410) and `tests/ssh_ca_live.rs:146`.
  - `enroll-host` prints "host-key prompts still apply" (`src/bin/personae-vault/certs.rs:185`).
  - The follow-on, device pairing D4, has all four boxes open (`2026-10-02_device_pairing_by_key_plan.md:765`).
  - Progress itself records T4 as one-third validated and no real machine enrolled.

### Contradictions

- The status line contradicts the "Corrected 2026-10-02" line directly below it.
- DOC_README's entry ("T1–T5 landed 2026-08-12") carries no correction.

### Recommended action

- Restate the status:
  - landed 2026-08-12: T1, T3;
  - partial: T2 (user-CA half only, no host certificates); T4 (validated on one OS); T5 (the KRL deploy stops at the file, lines 202-204, while T5's validation, lines 123-125, needs a deploy to enrolled hosts);
  - moved: host certificates to device pairing D4.
- Mirror this in DOC_README.

### Notes

The correction's own anchors hold: `certs.rs:34` derives the CA from the profile's master, and `bootstrap.rs:135` generates a fresh `Ed25519Keypair`. Also present: modules `ssh_ca`, `ssh_face`, `ssh_krl`, `enroll`; vault subcommands at `main.rs:129-134`; `install-agent-linux.sh`; `SSH_CA_MOD_ID` (`ssh_ca.rs:43`); `mint_user_cert` checks `request.ledger` (`ssh_ca.rs:202-215`). All five Related links resolve. The 121-test count was not re-run.
