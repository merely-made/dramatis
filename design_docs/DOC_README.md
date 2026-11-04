Resident identity service extraction (2026-11-03), complete: D15 in the
[repository plan](2026-11-01_dramatis_repo_plan.md) moves developed identity and
custody service logic into `dramatis-resident`. Mere keeps its projection,
door wiring and concrete platform dialogs. Default and all-feature supplier
qualification and locked Mere/Cleromancy receiving checks are recorded in the
plan's archived receipts. Native dialogs and graph projections remain host-owned.

# Dramatis Documentation Index

The design-docs index for the [dramatis](../README.md) repository, the
identity tier of the Merely stack. Entries are one line each; the rationale
lives in the doc itself.

The tier left Mere on 2026-10-09 (the repository plan's DR-D). Castellan,
Sporran and Gazette's portable domain joined it on 2026-11-03 under
dramatis_repo D11-D13. D14 brings the custodian, custody-wire, station-grant
policy and native receiving harness here. Mere retains resident client integration;
see `repos/mere/design_docs/DOC_README.md`. Registry release and receiving work
is tracked in the repository plan and Mere's workspace hygiene plan.

## Working principles

- Read this index first, then [`DOC_POLICY.md`](DOC_POLICY.md).
- Nothing here depends on a mere crate. mere pins this repository by git
  revision, and so does every sibling. Two revisions of personae in one
  graph split its types, so every pin of this repository in one graph must
  name the same revision.
- Custody and release policy belong to Castellan and its host. Sporran supplies
  the host-instantiated wallet store and sealer adapters. Portable identity
  models and views must preserve that authority boundary.
- Rust: working toolchain 1.99.1 (`rust-toolchain.toml`) and shared MSRV
  1.97.1, qualified separately. Canonical policy:
  `repos/mere/design_docs/2026-08-12_family_composition_thesis_brief.md`,
  section "Shared Rust toolchain and minimum version".
- Windows vault adoption must flush a write-enabled file handle: a read-only
  open succeeds but `sync_all` fails with AccessDenied on this host.
- Secure-channel authentication never fills an absent carrier-authenticated
  peer. Notochord's secure entrypoints bind both observations and the attested
  subject separately; service policy decides whether their identities must match.

## Required reading order

1. [`DOC_POLICY.md`](DOC_POLICY.md): documentation governance.
2. [dramatis_tier_architecture](2026-09-30_dramatis_tier_architecture.md):
   the tier's architecture of record. Start here.
3. [dramatis_repo_plan](2026-11-01_dramatis_repo_plan.md): the repository
   plan's open work. Why this repository exists, and what each phase moved,
   is in the [archived plan](archive_docs/2026-11-01/2026-10-06_dramatis_repo_plan.md).

## Active documents

- [custody_plan](2026-10-28_custody_plan.md): custody isolation, vault lock,
  tested absolute unlock expiry, fleet-wide one-week policy and the portable
  root/device approval, durable enrollment and consent execution (VL-U;
  network/UI/opening integration open), production
  receiving gates and the parked Secret Service design; moved with
  the custodian under D14. [Current receipts](archive_docs/receipts/2026-10-28_custody_plan_receipts.md);
  historical sources and receipts retain Mere paths.
- [castellan_custodian_integration](2026-10-22_castellan_custodian_integration.md):
  signed macOS native receiving design and evidence boundaries.


- [subject_reference_plan](2026-10-16_subject_reference_plan.md): **reference
  and reusable birth/resource contracts published on main (`7fb544e`); resident
  persistence, admission and consumer adoption remain parent-owned.**
  Plain subject, resource-association and biographical facts for Cleromancy C8;
  resident personal-facts domain owns durable revisions and admission, with
  historical-time conversion and consumer qualification in the receiving lane.
- [dramatis_tier_architecture](2026-09-30_dramatis_tier_architecture.md):
  **the tier's architecture of record.** personae, insigne, chatelaine, gaz,
  castellan and gazette as one account of identity along three axes
  (me/them, shown/exercised, embeddable/authority), with the cross-person
  lifecycle and its invariants cited to code.
- [dramatis_repo_plan](2026-11-01_dramatis_repo_plan.md): **open work, cut
  2026-11-01** from the [repository plan](archive_docs/2026-11-01/2026-10-06_dramatis_repo_plan.md)
  (rulings D1 to D39, DR-A to DR-E, archived whole). Open: DR-B's
  control-crate run, the doc audits, cooperative key revocation, the
  wallet-carry gaps, the `keeper` split, the gazette facade name and Tucket
  custody. Custodian extraction D14 is complete: the process, contract and
  native harness are here; Mere receives them through one qualified source.
  The archived plan also records the Sennet and Tucket continuations
  and the [Notochord secure-channel admission](archive_docs/2026-11-01/2026-10-06_dramatis_repo_plan.md#notochord-secure-channel-admission-2026-10-29)
  contract; murm's N1 (`repos/murm/design_docs/2026-10-29_secure_sessions_and_live_interaction_plan.md`) is its canonical acceptance.
- [vault_threat_statement](2026-10-08_vault_threat_statement.md): what the
  identity vault's lock defends, what it leaves open, and what is known only
  by reading. The lock itself is castellan's, in mere.
- [chatelaine_cxf_plan](2026-11-01_chatelaine_cxf_plan.md): **open work, cut
  2026-11-01** from the [chatelaine and CXF plan](archive_docs/2026-11-01/2026-10-01_chatelaine_cxf_plan.md)
  (rulings 16 to 68, archived whole). P0 to P4 landed; P5's first Windows
  slice is qualified. Open: P5 on other native platforms and packaging, and
  P6 export.
- [personae_across_the_suite](2026-07-08_personae_across_the_suite.md):
  vision brief: the identity spine of the Merely apps.
- [gaz_plan](2026-11-01_gaz_plan.md): **open work, cut 2026-11-01** from the
  [gaz founding plan](archive_docs/2026-11-01/2026-08-08_gaz_founding_plan.md)
  (M0, M0.5, M1 and M2's first slice landed; archived whole). Open: checked
  key and PLC intake, back-claims, Signalman's pre-M0.5 stored books, M3 and
  M4.
- [ssh_ca_projection_plan](2026-08-12_ssh_ca_projection_plan.md): **T1 and
  T3 landed 2026-08-12; T2, T4 and T5 partial.** The SSH certificate
  authority on personae's `ssh` feature.

## Archive

- [personae_founding](archive_docs/2026-11-01/2026-07-08_personae_founding.md):
  **archived 2026-11-01.** The identity core ported from mere's
  `persona/identity`; roadmap 2's sync-gate seam now lives in the tier
  architecture's section 2.
- [dramatis_tier_plan](archive_docs/2026-10-06_completed_plans/2026-08-10_dramatis_tier_plan.md):
  **archived 2026-10-06.** The persona tier renamed dramatis, gaz
  subtree-merged in, the facade name claimed.
- [insigne_proofs_plan](archive_docs/2026-10-06_completed_plans/2026-09-23_insigne_proofs_plan.md):
  **archived 2026-10-06.** Checks return unforgeable conclusions or a
  `CheckFault`; personae's delegation and attestation types moved into
  insigne's plain-data core.
- [notochord_session_policy_spine_plan](archive_docs/2026-08-06_completed_plans/2026-07-26_notochord_session_policy_spine_plan.md):
  **N0 to N4 complete 2026-07-27.** Notochord as the typed facts, claims
  and admitted-session spine.
- [dramatis_repo_plan (archived)](archive_docs/2026-11-01/2026-10-06_dramatis_repo_plan.md),
  [chatelaine_cxf_plan (archived)](archive_docs/2026-11-01/2026-10-01_chatelaine_cxf_plan.md)
  and [gaz_founding_plan (archived)](archive_docs/2026-11-01/2026-08-08_gaz_founding_plan.md):
  **archived whole 2026-11-01 (cut; history only).** Each holds its rulings,
  findings, progress and inline run evidence as written, with the hashes it
  was written with; the open work moved to the plans above.
- [receipts](archive_docs/receipts/): **pointer files, 2026-11-01.** Per-plan
  receipt files naming run evidence kept outside the repository in
  `Code/testing/dramatis/` (path cites, not links), and old-to-main hash tables
  for documents that cite pre-merge hashes.

- [source_splits_plan](2026-11-03_source_splits_plan.md): H5 twenty-file responsibility and fixture splits, in progress.
