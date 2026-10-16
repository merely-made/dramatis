# Dramatis Documentation Index

Sennet custody (2026-10-16): the [repo plan](2026-10-06_dramatis_repo_plan.md)
records the qualified scoped public-node derivation for Murm R7, with 73
passing Personae tests and Mere's six real-Keeper cases. Durable packet IDs,
native/RF qualification and private-channel provisioning retain their own gates.

Rust policy (2026-10-13): working toolchain 1.99.0 and shared MSRV 1.97.1, qualified separately. Canonical policy: `mere/design_docs/2026-08-12_family_composition_thesis_brief.md`, section "Shared Rust toolchain and minimum version".

Tucket custody (2026-10-15): the [repo plan](2026-10-06_dramatis_repo_plan.md)
records the in-progress scoped station derivation for Djinn/Signalman. Custody
and radio qualification remain separate gates.

The design-docs index for the [dramatis](../README.md) repository, the
identity tier of the Merely stack. Entries are one line each; the rationale
lives in the doc itself.

The tier left mere on 2026-10-09 (the repository plan's DR-D). castellan,
the custody crate only djinn links, stays in mere, and so do its documents;
see `repos/mere/design_docs/DOC_README.md`.

## Working principles

- Read this index first, then [`DOC_POLICY.md`](DOC_POLICY.md).
- Nothing here depends on a mere crate. mere pins this repository by git
  revision, and so does every sibling. Two revisions of personae in one
  graph split its types, so every pin of this repository in one graph must
  name the same revision.
- Secrets at rest and in hand are castellan's, in mere. A crate here that
  starts holding one is a boundary break, not a feature.

## Required reading order

1. [`DOC_POLICY.md`](DOC_POLICY.md): documentation governance.
2. [dramatis_tier_architecture](2026-09-30_dramatis_tier_architecture.md):
   the tier's architecture of record. Start here.
3. [dramatis_repo_plan](2026-10-06_dramatis_repo_plan.md): why this
   repository exists and what each phase moved.

## Active documents

- [dramatis_tier_architecture](2026-09-30_dramatis_tier_architecture.md):
  **the tier's architecture of record.** personae, insigne, chatelaine, gaz,
  castellan and gazette as one account of identity along three axes
  (me/them, shown/exercised, embeddable/authority), with the cross-person
  lifecycle and its invariants cited to code.
- [dramatis_repo_plan](2026-10-06_dramatis_repo_plan.md): **plan,
  2026-10-06; rulings D1 to D39; DR-A to DR-D's migrations landed;
  DR-C closed with per-app absent/Locked receipts and a failing fallback control;
  Hocket DPAPI adoption proven and DR-E published all six crates on 2026-10-11.** The identity tier
  leaves mere for this repository; castellan stays in mere, narrowed to
  custody, and only djinn links it; every app calls djinn.
- [vault_threat_statement](2026-10-08_vault_threat_statement.md): what the
  identity vault's lock defends, what it leaves open, and what is known only
  by reading. The lock itself is castellan's, in mere.
- [chatelaine_cxf_plan](2026-10-01_chatelaine_cxf_plan.md): **plan,
  2026-10-01; P0 to P3 and P4a landed; P4 (CXF import) landed
  on 2026-10-11 after DR-C closure; P5 first Windows app slice qualified;
  other native platforms and packaging remain open, as does P6 export.** chatelaine as the plain secret-item taxonomy, castellan's OTP
  items and Secret Service store moved onto it, then CXF import through
  castellan.
- [personae_founding](2026-07-08_personae_founding.md): **founded.** The
  identity core ported from mere's `persona/identity`.
- [personae_across_the_suite](2026-07-08_personae_across_the_suite.md):
  vision brief: the identity spine of the Merely apps.
- [gaz_founding_plan](2026-08-08_gaz_founding_plan.md): **M0, M1 and M2's
  first slice landed.** Contacts filed under a root anchor (a typed key, a
  `did:plc`, or a local id), with retained proofs, Muniment storage, host
  sealing, JSContact exchange and address intake; checked key/PLC intake
  and application wiring remain open.
- [ssh_ca_projection_plan](2026-08-12_ssh_ca_projection_plan.md): **T1 and
  T3 landed 2026-08-12; T2, T4 and T5 partial.** The SSH certificate
  authority on personae's `ssh` feature.

## Archive

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
