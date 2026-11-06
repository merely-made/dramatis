# Chatelaine and CXF import plan: open work

**Date:** 2026-11-01
**Status (2026-11-01):** cut from [the chatelaine and CXF import plan](archive_docs/2026-11-01/2026-10-01_chatelaine_cxf_plan.md), archived whole with its rulings 16 to 68, findings, progress and inline run evidence. P0 met; P1 (`59475aefd`), P2 (`b9d4cebbf`), P3 (`becbff0a2`) and P4a (`6f4b88b73`) landed on mere main; P4, CXF import through castellan's `cxf` feature, landed on 2026-10-11 and the six crates were published. P5's first Windows slice, persona selection and quarantine review with Djinn custody and native consent, is qualified in mere. Open: P5's other platforms and packaging, and P6 export.

## Rulings in force

Chatelaine's own rulings 16 to 68 live in the archived plan's section 2 and are grandfathered: they keep their numbers. Rulings 7 and 10 to 15, the shape of chatelaine and the CXF import table, are in the [tier architecture](2026-09-30_dramatis_tier_architecture.md) sections 7 and 9. New decisions are keyed `chatelaine_cxf D<n>`, below.

## Decisions

### chatelaine_cxf D1: apply the audit's edits (2026-11-01)

Mark, 2026-11-01: "Apply all". The audit's class A and B edits are applied. The ones that belonged to this plan's old text (a stale review clause, a wrong section cite, moved source paths) are carried by Findings below, not made in the archived plan.

Links: area documentation · summary class A and B audit edits applied

### chatelaine_cxf D2: cut the plan, draft first (2026-11-01)

Mark, 2026-11-01: "Cut all three, draft first". The 1,160-line chatelaine plan is cut under DOC_POLICY §8: its open items become this plan, and the old plan is archived whole after this draft is reviewed.

Links: area documentation · replaces 2026-10-01_chatelaine_cxf_plan · summary old plan cut to open work and archived whole

### chatelaine_cxf D3: receipts leave the repository (2026-11-01)

Mark, 2026-11-01: "Move both out". The CXF manifest and log bundle (`chatelaine_cxf.json`, `chatelaine_cxf_logs.zip`) now live in `Code/testing/dramatis/support-receipts/`, with their SHA-256 values in [the receipts file](archive_docs/receipts/2026-10-01_chatelaine_cxf_plan_receipts.md).

Links: area receipts · applies DOC_POLICY §8 · summary CXF receipts moved to Code/testing/dramatis

### chatelaine_cxf D4: old rulings keep their numbers (2026-11-01)

Mark, 2026-11-01: "Grandfather, §11 forward". Rulings 1 to 68 keep their numbers; this plan's decisions use `chatelaine_cxf D<n>` keys.

Links: area documentation · governs 2026-10-01_chatelaine_cxf_plan rulings 16-68 · summary no renumbering

### chatelaine_cxf D5: old hashes (2026-11-01)

Mark, 2026-11-01: "Same: live docs only". This plan cites main hashes; the archived plan keeps the ones it was written with. The mapping, including the two merges with no identical subject and the two strings that are not commits, is in [the receipts file](archive_docs/receipts/2026-10-01_chatelaine_cxf_plan_receipts.md).

Links: area documentation · summary live docs cite main hashes; archived docs keep old ones

### chatelaine_cxf D6: mere-resident, not djinn, for the port (2026-11-01)

*Withdrawn by dramatis_repo D10.*

Mark, 2026-11-01: "Rename the prose". Where the text means mere's resident port it says mere-resident; the Djinn crate, now `repos/armillary/crates/djinn`, keeps its name.

Links: area documentation · summary prose says mere-resident for the port, Djinn for the crate

### chatelaine_cxf D7: V4 is closed by P4 (2026-11-02)

Mark, 2026-11-02: "Closed by P4". V4, "broader item types", inherited from the identity vault SSH agent plan, is fulfilled by P4's import of every CXF v1.0 kind and unknown types (see Findings).

Links: area documentation · draws on 2026-10-01_chatelaine_cxf_plan P4 · summary V4 closed by P4

## Open work

### O1. P5: other native platforms and distribution packaging

The first slice is the Dramatis app (package `dramatis-app`, binary `dramatis-ui`), Mere's `ports/dramatis` until it moved to `apps/dramatis` here on 2026-11-06. It selects existing personae, shows public quarantined cards for the bound destination, and requests exact-item accept, delete or older-import assignment; Djinn owns sealed records, profile authority and native consent. It is qualified on Windows only, with synthetic fixtures (evidence: `repos/mere/support/receipts/dramatis-app/README.md`; app plan: `2026-10-11_dramatis_app_plan.md`).

**Done when:** the same receipt (persona selection, public quarantined cards, accept and delete with native consent, absent and Locked custody) repeats on Linux and macOS with the machine and commit recorded; and Mark names the distribution packaging targets, each of which installs and passes that receipt.

### O2. P6: CXF export (ruling 22)

**Done when:**

- a persona's items export as a CXF document behind a warning the caller cannot skip: the file will be plaintext, because CXP, the encrypted transfer, is still a 2024 working draft;
- import, then export, then import is lossless for every kind, quarantined and unknown items included, by the P4 fixture;
- exporting is an authority intent with consent, never a view.

## Findings

- 2026-11-01: P4a's review stop ended on 2026-10-04 (ruling 51), so the old P4a clause "Waits for Mark's review after P3 (ruling 28)" (old plan lines 563-564) is stale.
- 2026-11-01: the old Status cites "(§8)" for the Signalman desktop's separate stack and custody refresh; the plan has no §8, and the closing box is P4's last one (§3). It is met: `repos/murm/design_docs/archive_docs/2026-11-02/2026-10-11_signalman_stack_refresh_plan.md`.
- 2026-11-01: `ssh_slot.rs` and `ssh_sign.rs` moved from personae to castellan with the custody split (DR-B): `repos/mere/ports/mere-resident/castellan/src/custody/ssh_slot.rs` and `ssh_sign.rs`. The archived plan's `crates/personae/src/ssh_*.rs` cites are historical.
- 2026-11-01: unsupported OTP digit counts are preserved in quarantine (ruling 68), which settles the digit-count policy that the repository plan's 2026-10-11 entry said awaited Mark.
- 2026-11-01: persona creation, contacts and fill, named in the P5 receipt as follow-on work, belong to the app plan (`2026-10-11_dramatis_app_plan.md`), not to a chatelaine phase.

- 2026-11-02: V4, "broader item types" (archived plan line 1111, inherited from the identity vault SSH agent plan), is fulfilled by P4. `CredentialKind` covers CXF v1.0's 17 kinds, the Secret Service generic secret and `Unknown` (archived plan lines 497-499), and the P4 fixture holds all 17 kinds plus one unknown type, each asserted (lines 588-589 and 965-966).

## Progress

- 2026-11-01: plan cut from the chatelaine and CXF import plan; decisions D1 to D6 recorded (D7 on 2026-11-02). Receipts moved out, and the run-evidence index and hash table written to `archive_docs/receipts/2026-10-01_chatelaine_cxf_plan_receipts.md`.
