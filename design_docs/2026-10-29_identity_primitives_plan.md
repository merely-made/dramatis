# Identity primitive comparison branch

**Status, 2026-10-29: implemented supplier subset, published for comparison; further work paused.** This covers one Personae MAC comparison and Insigne Base58/hex, not all of R01/R02 across the family.

## Change and contracts

Personae replaces its freshness-ledger slice/XOR helper with constant_time_eq 0.4.2’s fixed-array primitive. Insigne uses bs58 0.5.1 (Bitcoin alphabet, alloc, no checksum) and hex 0.4.3 behind the existing functions. Fixed sizes, leading zeros, empty inputs, case acceptance, errors and key/DID encodings stay intact. Authority, signing and serialization ownership do not change.

constant_time_eq and hex were already locked; their direct package edges change. The selected bs58 alloc closure adds bs58 and tinyvec. This is a small Rust-only candidate, not evidence that every new dependency is worthwhile.

## Exact source and evidence

- Original base: `6711105e0284adb3e881fc9aebcc56f25000c1ca`.
- MAC implementation: `c15a65b410313824d18dd8df8ceb3752877becb6`.
- Codec implementation and tested product tree: `27b731f0d2c885c84a943094e54461c744060766`.
- Pre-merge combined Personae/Insigne Linux gate on Rust 1.99.1: **121 passed, 0 failed, 4 existing local-sshd ignores**. Default/all-feature codec tests and no-default-feature check passed. Independent task and whole-branch source reviews approved; review/docs followed through `fd2c3a5`.
- Existing detailed results: [receipt notes](archive_docs/2026-10-29/2026-10-29_identity_primitives_plan_receipts.md) and `support/receipts/identity-primitives-20261029/`. Their publication status describes the time recorded, not current branch state.
- Upstream `051e95a68011072f172b9ec4c0f04d4e5259df5b` was merged at `e79db34d360161ca3f612e087bd957fd95aba38f`. The queued merged-head gate was stopped on user steering. **That merged revision is not requalified.**

The branch is pushed as `stack-reduction-identity-20261029`; no implementation was pushed to main and no consumer pins were adopted. MSRV 1.97.1, Wasm, downstream receiving, installed custody and runtime side-channel assurances remain unqualified. Pre-existing warnings/format differences and raw logs remain preserved.

## Remaining scope

Mere’s corrected stack audit records four more handwritten comparisons in Castellan/Murm. Other Base32/Base64/hex/percent copies also remain. R01/R02 need a family pattern census before completion can be claimed. No additional substitution or downstream integration is running.

Compare this diff before deciding whether to keep it. Small future primitive changes can use ordinary commit notes and relevant tests; the earlier per-helper planning/review ceremony is not a standing requirement.

Remote worktree: `/home/markik/Code/worktrees/dramatis-stack-reduction-20261029` on S-PC. Preserve it and its branch for comparison. If builds resume, retain the existing serialized gate and caps: MemoryMax=3G, MemorySwapMax=0, CPUQuota=150%, one Cargo job/test thread, timeout 600 seconds. No attribution trailers or shared-main pushes.
