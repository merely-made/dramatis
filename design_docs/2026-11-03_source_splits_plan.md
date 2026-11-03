# Source splits: H5 Dramatis batch

**Status (2026-11-03):** landed, 20/20 paths qualified.

## Phases and done-conditions

- **S1. Wire and identity boundaries.** Separate client replies, actor
  operations, storage paths and handshake encoding from their owners.
- **S2. Vault and custody boundaries.** Separate existing persistence,
  resident actions and authority operations; group regression fixtures by
  behavior. Keep private authority, key release, revocation and timeout rules.
- **S3. Qualification.** All twenty original paths and new modules fit the
  600-line ceiling, obsolete exceptions are removed, scoped workspace tests,
  feature checks and the full local gate pass, and the batch is pushed.

No new design ruling. This implements Mark's request for 50 additional
oversize-file splits under Mere's house-style H5. The live SSH daemon
fixture is outside this batch. Public paths and security policy stay intact.

## Findings

- 2026-11-03: twenty exceptions span independent wire, storage, authority,
  client and regression-fixture responsibilities. Castellan's authority and
  agent fixtures each need multiple behavior groups, rather than one new
  oversize test file. Private implementation children retain parent authority.
- Compact baseline/post receipts append to
  [the receipt](archive_docs/receipts/2026-11-03_source_splits_plan_receipts.md).
  Total H5 retained receipt cap: 100 MB across repositories.

## Progress

- 2026-11-03: selected twenty paths in a clean checkout; baseline started.

- 2026-11-03: S1–S3 landed. Twenty exceptions retired, preserving source APIs and fixture names. Full workspace tests, all-feature/all-target checks, resident all-feature tests, docs and full local gates pass. The baseline exposed Windows adoption flushing a read-only handle; a write-enabled handle fixes the two existing failing tests. Owned stale documentation links were reconciled.
