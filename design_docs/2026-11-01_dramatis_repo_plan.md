# Dramatis repo plan: open work

**Date:** 2026-11-01
**Status (2026-11-01):** cut from [the repository plan](archive_docs/2026-11-01/2026-10-06_dramatis_repo_plan.md), archived whole with its rulings, findings, progress and inline run evidence. DR-A, DR-C, DR-D's migrations and DR-E landed; the six crates were published on 2026-10-11 (personae 0.3.0, insigne 0.0.2, gaz 0.0.2, chatelaine 0.0.3, notochord 0.1.1, dramatis 0.0.3). DR-B's gates are met except the control-crate run. Open work follows.

## Rulings in force

The numbered rulings D1 to D39 live in the archived plan and are grandfathered: they keep their numbers, other repositories cite them by number (mere's `deny.toml` cites "D4 and D16"), and they still bind. New decisions are keyed `dramatis_repo D<n>`, below.

## Decisions

### dramatis_repo D1: apply the audit's edits (2026-11-01)

Mark, 2026-11-01: "Apply all". The audit's class A and B edits are applied: stale statuses, dead cites, moved paths. The two items Mark kept open are DR-B's control-crate run (O1) and the Tucket custody line (O7). Edits that belonged to this plan's old text are carried by its Findings and Open work, not made in the archived plan.

Links: area documentation · summary class A and B audit edits applied; the control-crate run and Tucket custody stay open

### dramatis_repo D2: cut the plan, draft first (2026-11-01)

Mark, 2026-11-01: "Cut all three, draft first" (this plan, the chatelaine plan and the gaz plan). The 1,085-line repository plan is cut under DOC_POLICY §8: its open, deferred and follow-on items become this plan, and the old plan is archived whole after this draft is reviewed.

Links: area documentation · replaces 2026-10-06_dramatis_repo_plan · summary old plan cut to open work and archived whole

### dramatis_repo D3: receipts leave the repository (2026-11-01)

Mark, 2026-11-01: "Move both out". `testing/receipts/` (9 files) and `support/receipts/` (7 files) now live in `Code/testing/dramatis/testing/` and `Code/testing/dramatis/support-receipts/`; nothing in code, tests or build configuration read them. Their paths, sizes and SHA-256 values are in [the receipts file](archive_docs/receipts/2026-10-06_dramatis_repo_plan_receipts.md).

Links: area receipts · applies DOC_POLICY §8 · summary 16 files, 2,310,082 bytes, moved to Code/testing/dramatis

### dramatis_repo D4: old rulings keep their numbers (2026-11-01)

Mark, 2026-11-01: "Grandfather, §11 forward". D1 to D39 keep their numbers and live in the archived plan; this plan's decisions use `dramatis_repo D<n>` keys. DOC_POLICY's local addendum says so.

Links: area documentation · governs 2026-10-06_dramatis_repo_plan D1-D39 · summary no renumbering; §11 keys from 2026-11-01

### dramatis_repo D5: vault lock cites (2026-11-01)

Mark, 2026-11-01: "Archive for rulings, custody for state". A cite of a vault lock ruling points at `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md`; a cite of the lock's current state points at the custody plan, `repos/dramatis/design_docs/2026-10-28_custody_plan.md`.

Links: area documentation · summary ruling cites go to the archive, state cites to the live custody plan

### dramatis_repo D6: Hocket's standalone repository is retired (2026-11-01)

Mark, 2026-11-01: "Retired". The archived plan's ruling D13 left one reading open, retire or repoint the standalone `hocket/` repository. It is retired; Hocket lives at `repos/woodshed/ports/hocket`. D13 is dropped from the open lists.

Links: area custody · amends D13 · summary standalone hocket repository retired; D13 closed

### dramatis_repo D7: old hashes (2026-11-01)

Mark, 2026-11-01: "Same: live docs only". Live documents cite main hashes (this plan, the tier architecture, the vault threat statement, the ssh_ca plan, the subject plan). The archived plan and the receipts keep the hashes they were written with; the old-to-main table is in [the receipts file](archive_docs/receipts/2026-10-06_dramatis_repo_plan_receipts.md), with a note on the ambiguous and unmatched ones.

Links: area documentation · summary live docs cite main hashes; archived docs keep old ones

### dramatis_repo D8: mere-resident, not djinn, for the port (2026-11-01)

*Withdrawn by D10.*

Mark, 2026-11-01: "Rename the prose". Where the text means mere's resident port, it says mere-resident (`repos/mere/ports/mere-resident`, whose installed executable is still named djinn); where it means the Djinn crate, now `repos/armillary/crates/djinn`, it keeps Djinn.

Links: area documentation · summary prose says mere-resident for the port, Djinn for the crate

### dramatis_repo D9: the remaining Djinn prose (2026-11-02)

*Withdrawn by D10.*

Mark, 2026-11-02: "Docs now, crate at next publish". The remaining prose in live documents and in `deny.toml`'s ban reason says mere-resident wherever it means mere's resident port; it never changes inside Mark's quoted rulings or inside archived documents, and it keeps Djinn where the sentence means the Djinn crate or the djinn executable name. `crates/dramatis` (Cargo description, README, lib.rs docs) is published metadata and changes at the next dramatis publish (O8).

Links: area documentation · refines dramatis_repo D8 · summary live-doc and deny.toml prose now; crates/dramatis at the next publish

### dramatis_repo D10: revert to Djinn, mere's wording (2026-11-02)

Mark, 2026-11-02: "Revert to Djinn, mere's wording". New evidence contradicted D8 and D9: mere's `deny.toml` bans castellan with wrappers `djinn` and `djinn-custodian` and says "only Djinn and its independently launched custodian link it", the mere-resident package's binary is named djinn, and the djinn-slimming work keeps "djinn" in this repository's README. The prose renames are dropped; the `ports/mere-resident/...` path fixes stay, since a path is a path. Where a document says who links castellan, it uses mere's current wording: Djinn and its independently launched custodian. Outcome: contradicts D8 and D9. The open item O8 (renaming djinn in `crates/dramatis` at the next publish) is withdrawn with them.

Links: area documentation · withdraws dramatis_repo D8, D9 · summary prose says Djinn in mere's wording; paths stay under ports/mere-resident

### dramatis_repo D11: castellan moves here, off pandect (2026-11-03)

Mark, 2026-11-03: "decouple Castellan from Pandect and then move Castellan into Dramatis, because are we trying to slim down mere? ... move stuff out now that we've clarified some of the boundaries in the subsystems", then "take the wallet from pandect to dramatis". The archived plan's ruling D6 kept castellan in mere "beside djinn" with no repo cycle; Djinn left mere on 2026-10-23, and castellan's one remaining mere dependency was `pandect`'s wallet store. `crates/castellan` (0.0.4) is here, with its 362 tests, off `pandect`. The custodian and `custody-wire` stay in mere.

Links: area custody · amends archived D6 · summary castellan lives in dramatis; its wallet store comes with it as sporran

### dramatis_repo D12: sporran holds the wallet store (2026-11-03)

Mark, 2026-11-03: "New crate: sporran (Recommended)", over `personae-wallet`, `scrip`/`almonry`, or folding it into personae. `personae::carry` is the wallet's model and, by the 2026-07-08 fold-in, knows no filesystem, policy or seal seam; the store adapter (wallet_store, wallet_grant, device_settings_store, wallet_sealed_backend and the `WalletEpochSealer` seam, 64 tests) is `crates/sporran`, built on personae, eidetic and muniment. Callers repoint to it with no re-export left in `pandect`: "Repoint callers, no re-export (Recommended)".

Links: area custody · summary the pandect wallet store is the sporran crate; callers repoint

### dramatis_repo D13: gazette splits; its directory domain comes here (2026-11-03)

Mark, 2026-11-03: "Take gazette to dramatis too", then "Split: domain moves (Recommended)" over moving it whole or leaving it in mere. `crates/gazette` (0.0.2) holds WebFinger discovery and `intake` into gaz and links nothing from mere. The contact-ledger projection stays in mere as `gazette-ledger`, published as 0.0.1 on 2026-11-03 (Mark: "You can publish the ledger"); the reading-room extractor, whose Fleece dependency is unpublished, went to `mere-fleece` behind its `article` feature. The archived D7 condition, domain logic split from the Cambium projection, is met.

Links: area custody · amends archived D7 · summary gazette's WebFinger domain is a dramatis crate; the ledger projection stays in mere as the published gazette-ledger

### dramatis_repo D14: the custodian and its contract move here (2026-11-03)

Mark, 2026-11-03: "Go ahead", approving the next extraction: move the
custodian and `custody-wire` into Dramatis after removing their Pandect edges.
The station-grant policy follows the wallet store into Sporran, with callers
repointed directly. The custodian's process, installers and synthetic native
receiving harness follow their implementation. Mere retains resident service
composition and its identity integration. This refines D11's remaining-code
boundary without changing wire messages, vault layout or custody policy.

Links: area custody · refines dramatis_repo D11 · summary custodian and custody-wire move to dramatis; station grants move to sporran

### dramatis_repo D15: resident identity service follows its domain (2026-11-03)

Mark, 2026-11-03: "Proceed", with the intended direction that "mere would call
on dramatis for auth". The reusable resident identity and custody service moves
into `dramatis-resident`: installed-custodian access, startup/profile resolution,
public read models and intent execution, release policy and native-interaction
commands. It takes owner declarations and a native-UI callback. Mere keeps the
graph projection, door wiring and platform dialog implementation; those call
this service. Pairing's graph sync and application settings retain their owners.
The standalone custodian remains the production vault authority; in-process
custody stays an explicit test feature, with no fallback.

Links: area custody · draws on dramatis_repo D14 · summary reusable resident identity service moves to dramatis; projections and host wiring stay with their owners

## Resident identity extraction, 2026-11-03

**Status:** in progress. Move the developed service as one package, preserving
custody refusals, grants, wire messages, derivation labels, profile environment
selection and sealed formats. Repoint callers directly; keep actual host/door
adapters where they serve the host. The crate's normal graph excludes Mere,
Genet, Djinn, native dialog implementations and Castellan. Its explicit
`in-process-custody` feature supports tests only.

**Done when:** default and all-feature service checks/tests pass independently;
the existing resident baseline is measured and new failures are separated;
Mere and concrete receiving callers build locked with one source identity;
IPC refusal and sealed-payload controls pass; source and pin commits are pushed;
plans retain the exact platform and publication limits.

Receipts: source move hashes, default/all-feature dependency graphs, baseline
and moved test counts, receiving and IPC gates, immutable source pins and
cleanup. Retain at most 100 MB total under
`Code/testing/dramatis/resident-identity-20261103`, indexed in this plan's
archived receipt file. Reuse stable per-repository Cargo targets.

## Custodian extraction, 2026-11-03

**Status:** complete, 2026-11-03. Scope is `djinn-custodian`, `custody-wire`, their
packaging and native receiving harness, Sporran's station-grant policy, and
Mere's receiving edges. The resident identity layer and GUI remain later work.

**Done when:** the custodian and contract build and test from this workspace
without Mere or Genet; station-grant policy and refusal tests pass in Sporran;
Mere's locked receiving checks and custody tests preserve the process boundary;
all live paths and size-inventory ownership follow the files; source and pin
commits are pushed on main. Existing Windows adoption failures must be measured
before the move and reported separately from regressions. Linux and signed
macOS deployment gates remain open under the [custody plan](2026-10-28_custody_plan.md).

Required receipts: source-move hashes, baseline and receiving test summaries,
resolved source identities, negative custody-boundary checks, packaging/harness
checks and final commits. Retain at most 100 MB total at
`Code/testing/dramatis/custodian-extraction-20261103`; index the compact records
in this plan's [extraction receipt file](archive_docs/receipts/2026-11-01_dramatis_repo_plan_receipts.md). Reuse stable repository Cargo targets.

## Open work

### O1. DR-B: the control-crate run

The cargo-deny check (ruling D16) passes: `cargo deny check bans` was ok for mere, Knot, woodshed, embedded hocket and Turnstone on 2026-10-10. Its failing case has no record.

**Done when:** a throwaway crate that adds castellan to a graph under mere's `deny.toml` fails `cargo deny check bans`, the run is indexed in the receipts file, and the crate is removed.

### O2. DR-D: both doc audits

Existing index, citation and D2-coverage findings were left outside DR-D's lane. This repository has no audit commands of its own (DOC_POLICY, local addendum: founding them is open work), and the D2 ledger in `support/doc-audit/d2/` is keyed by the document names that moved on 2026-11-01.

**Done when:** audit commands exist here, or mere's two scripts (`repos/mere/scripts/mere_doc_audit.py`, `repos/mere/scripts/mere_doc_judgment_audit.py`) run with this repository as a target, they cover the live documents and the archive, and they report no blocking finding.

### O3. Cooperative key revocation

Released keys are revoked at lock only cooperatively, when an app watches Djinn's lock broadcast (archived plan, Progress 2026-10-10 and 2026-10-11).

**Done when:** a released key stops working at lock without the holding app's cooperation, shown by a test in which the app ignores the broadcast; or Mark rules the cooperative model final and the vault threat statement says so.

### O4. Wallet-carry gaps

Inherited from the S14 archive pass: PAKE/QR chrome and transport UI; copy-mode export and import; epoch history beyond the current epoch; a migration pass for cleartext private blobs (`repos/mere/design_docs/archive_docs/2026-10-06_completed_plans/2026-06-25_persona_wallet_carry_layer_plan.md`). They touch pandect's wallet, whose secret half moved to castellan under ruling D8; the old plan said they were "assessed with DR-B", and no assessment is recorded.

**Done when:** an assessment is recorded here, and each of the four is built with a receipt in mere's custody plan (`repos/dramatis/design_docs/2026-10-28_custody_plan.md`) or dropped by a ruling.

### O5. Splitting castellan's `keeper` feature

Reading, not ruled: rulings D14 and D15 make the split unnecessary, since the view types moved to the dramatis facade and graphshell stopped naming castellan. The feature still exists (`crates/castellan/Cargo.toml`, `keeper = ["agent", "wallet"]`).

**Done when:** Mark confirms the reading and a decision records it, or a consumer appears that needs views without castellan's authority.

### O6. A facade name for gazette

Open since DR-A: whether gazette gets a matching facade name over gaz, the way chatelaine is the keychain.

**Done when:** Mark rules yes or no, recorded as a decision here.

### O7. Tucket custody (in progress since 2026-10-15)

`crates/personae/src/tucket.rs` adds a canonical, length-delimited Tucket station salt bound to the durable device UUID and realm, with redacted transient seed material. Djinn owns release policy; Signalman requests only that scope and must stop when custody is unavailable or locked. Reticulum salts are unchanged. Consumer work is murm's R6 (`repos/murm/design_docs/2026-11-02_murm_family_move_plan.md`). The Sennet continuations (R7, R8) share the same custody route: `crates/personae/src/sennet.rs` derives the scoped public node number and `SennetStationMaterial`, qualified by 71, 73 and 74 Personae tests; durable packet-ID reservations and the native and RF receipts are murm's.

**Done when:** scoped release and refusal, stable identity, lock shutdown and a restored forbidden fallback control are receipted through the actual custody route (Mark has kept this line open); and, for Sennet, durable packet-ID reservations are owned by the murm host before any radio use.

## Findings

- 2026-11-01, DR-B boxes 583, 585 and 589 are met (box 587 is O1). **Personae's tree** reaches no root loader or passphrase storage: `crates/personae/Cargo.toml` declares no argon2 or windows crate, `cargo tree -p personae --all-features -e normal --locked --offline` lists no argon2 or windows-sys (control: blake3 is listed), and the only windows crate is `windows-link`, through `gethostname`, which is not a root loader, and `crates/personae/src/startup_unlock.rs` is the 26-line `StartupUnlockMode` enum. Pandect's manifest (`repos/mere/crates/system/pandect/Cargo.toml`) declares none of argon2, windows, dpapi or castellan; its resolved tree was measured on 2026-11-02 from `repos/mere` with `cargo tree -p pandect -e normal --offline --locked` (218 lines, exit 0; Mark, 2026-11-02: "Measure pandect first"): no argon2, castellan, dpapi or keyring crate appears (control: blake3 v1.8.7 is listed), and the only Windows crate is windows-sys v0.48.0, which arrives through dirs-sys v0.4.1 and dirs v5.0.1 for pandect's known-folder lookup, not a root loader. Box 583 stays met. **The residue instrument** lives in castellan: `tests/vault_residue.rs` and `tests/no_residue.rs` under `repos/mere/ports/mere-resident/castellan/` (`vault_residue.rs` documents a positive control that runs first in the same process); the vault threat statement §2 lists both. **The gate** passed in the combined test run of 2026-10-10 (archived plan, Progress).
- 2026-11-01, DR-D box "every graph resolves exactly one personae source" is met: measured 2026-10-10 in Mere's, Knot's, Turnstone's, Woodshed's and Hocket's graphs, and again for the final consumer graphs on 2026-10-11 (archived plan, Progress).
- 2026-11-01, the dramatis facade is built: `crates/dramatis/src/lib.rs:28-31` and the modules at `:40-50` (DR-A, ruling D24). The old plan's "unbuilt" lines are superseded.
- 2026-11-01, insigne's repins are done: Woodshed pins dramatis.git (`repos/woodshed/Cargo.toml:163`, `insigne`), Hocket rides Woodshed, and mer3ly's `Cargo.toml` has no dramatis dependency, so its repin is moot. Turnstone repinned earlier.
- 2026-11-01, personae's `html_root_url` is 0.3.0 (`crates/personae/src/lib.rs:59`), so the 0.1.0 mismatch the old plan recorded is gone.
- 2026-11-01, Notochord secure-channel admission: the contract (additive v2 transcript, separate carrier, channel and subject facts, the explicit native endpoint association of 2026-10-30) stays recorded in the archived plan's section "Notochord secure-channel admission (2026-10-29)" and in `crates/notochord/src/secure.rs` and `handshake.rs`. Murm's plan records N1 as landed 2026-10-29 across Murm, Dramatis and Knot publishing (`repos/murm/design_docs/2026-10-29_secure_sessions_and_live_interaction_plan.md`); the archived sentence that Murm's carrier conversion and Knot's publishing consumer still needed adoption checks is superseded. Nothing is open here.
- 2026-11-01, the standalone Hocket repository is gone (`repos/hocket` does not exist); see D6.
- 2026-11-01, the Clippy allowances the old plan cites: `crates/personae/src/seal.rs:60` still holds `&nonce[..]`, but `carry/mod.rs:538` is no longer a Clippy site (it is a JSON fixture assertion). The allowances were not re-measured; no Clippy run was made.
- 2026-11-01, `repos/mere/deny.toml` now names two wrappers for castellan (Djinn and its independently launched custodian); this repository's `deny.toml` banned castellan with none until castellan moved here (D11).
- 2026-11-02, carried from main `baa4ed2` (djinn-slimming S3): `crates/castellan-client` in this repository holds the custody route's application side (the custody calls and answers, payloads, quarantine review, and the custody and identity clients), moved out of Djinn. It speaks over Armillary's door contract, `ostiary`, and never links Djinn; castellan stays in Mere (D6). The archived plan's DR-C list carries the same note as history, at its line 603.
- 2026-11-03: castellan, the wallet store and gazette's domain came here (D11 to D13). At the source move, the only non-registry suppliers were Eidetic and Armillary. The registry release pass replaces those edges with published dependencies; the final lock contains no Git package. `deny.toml` bans nothing now, because cargo-deny cannot tell the castellan member from a dependency on it; the castellan-client fixtures hold the boundary instead. Still in mere: the custodian, `custody-wire`, `mere-resident`'s identity door and UI, `ports/dramatis`, `persona-picker` and `station-custody`. Published in the registry pass: `gaz` 0.0.3, `dramatis` 0.0.5, `castellan-client` 0.0.2, `sporran` 0.0.1, `gazette` 0.0.2 and `castellan` 0.0.4. Their packaged all-feature/all-target tests pass against registry dependencies, including both custody residue harnesses. The client boundary fixtures pass with the expected forbidden-import control. This closes the missing Muniment atomic-file API blocker; storage and dependency pins remain under the receiving pass. Mere's, Knot's and Cleromancy's pins moved to this layout (Mere `e98d58812`, Knot `9129628`, Cleromancy `472cbb9`).

## Progress

- 2026-11-03: registry publication and receiving alignment are in progress,
  including Pandect's release closure, under
  `mere/design_docs/mere_docs/implementation_strategy/2026-10-28_workspace_hygiene_plan.md`.
  Gaz takes a new release for its Muniment 0.2 storage types; Dramatis and
  Castellan Client take new releases so their public Gaz and Eidetic types
  come from that same registry cohort. Ostiary already has a registry release.
  This changes dependency packaging and versions, not custody policy or formats.

- 2026-11-01: plan cut from the repository plan; decisions D1 to D8 recorded (D9 and D10 on 2026-11-02; D10 withdraws D8 and D9). Receipts moved out (commit `6ca6d3a`), cites and hashes repaired, and the archived plan's run-evidence index and hash table written to `archive_docs/receipts/2026-10-06_dramatis_repo_plan_receipts.md`.

- 2026-11-03: the six registry releases above were qualified and published from `57a6760`; all-feature workspace tests passed 813 libtest cases and the two custom residue harnesses. Windows client cones contain 116 and 129 normal/build packages with no forbidden custody or host dependency. Detailed package logs and the compact source/gate ledger are at `Code/testing/mere/registry-releases-20261103`, indexed by Mere's workspace hygiene receipt file. Other-platform runtime gates remain open.

- 2026-11-03, D14 implementation: the custodian and authenticated contract now
  build here with registry-only external dependencies. Station-grant policy
  and its three tests moved into Sporran; the error and test modules are split
  at existing seams to satisfy the source-size ceiling. Custody operation,
  message and persisted-data semantics are unchanged. The Windows baseline's
  two adoption failures reproduce after the move; Mere receiving is next.

- 2026-11-03, D14 receiving complete: Mere consumes the moved crates through
  one Dramatis source and shared Armillary peer facts. Its production resident
  normal/build graph includes custody-wire and excludes both Castellan and the
  custodian. Locked workspace checking, grant suites, three Windows IPC tests,
  full-tree hooks and commit hooks pass. The Unix-only process fixture and
  signed native macOS receiving remain platform gates; the two pre-existing
  Windows OS-vault adoption failures are unchanged. The resident identity
  layer, GUI and service composition remain in Mere.
- 2026-11-03, release boundary: this extraction updates Git source trees;
  existing registry archives retain their published APIs. The next registry
  release must version Sporran's new station-grant surface and Pandect's removed
  module. This pass performs no registry upload.
