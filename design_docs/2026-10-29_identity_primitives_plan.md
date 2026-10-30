# Identity primitives implementation plan

**Status (2026-10-29): Tasks 1 and 2 implemented and qualified on the isolated S-PC supplier branch; whole-branch review and downstream receiving remain separate.**

**Goal:** remove independent fixed-width MAC comparison and public-key text codecs while preserving the identity tier's exact public behavior.

**Architecture:** Personae uses a direct dependency on the already-locked constant-time equality crate. Insigne retains its small existing functions and error/length contracts as adapters over maintained Base58/hex codecs. Authority, signing, key-family parsing and serialization formats retain their current ownership.

**Spec:** `mere/design_docs/mere_docs/research/2026-10-29_stack_ownership_audit/REPORT.md`, R01 and the identity subset of R02. The cross-stack implementation sequence is `mere/design_docs/mere_docs/implementation_strategy/2026-10-29_stack_reduction_plan.md`.

## Global constraints

- Base is Dramatis `6711105e0284adb3e881fc9aebcc56f25000c1ca`; recheck an upstream advance before integration.
- Remote host `s-pc`; worktree `/home/markik/Code/worktrees/dramatis-stack-reduction-20261029`, branch `stack-reduction-identity-20261029`.
- Rust working toolchain 1.99.1; declared MSRV remains 1.97.1. Do not edit rust-toolchain or the declared MSRV.
- One build at a time through `/home/markik/Code/testing/machine-heavy.lock`, systemd `MemoryMax=3G`, `MemorySwapMax=0`, `CPUQuota=150%`, one Cargo job/test thread, timeout 600 seconds. Keep stable target lane `/home/markik/Code/targets/lanes/stack-reduction-identity/build`.
- Retain logs under `/home/markik/Code/output/stack-reduction-20261029`. Set systemd WorkingDirectory explicitly; it does not inherit the shell's checkout.
- Use existing crypto/identity APIs. No wire changes, new secret exposure, changes to authority or additional crypto construction.
- Keep Insigne digest/verify features unchanged and forbid unrelated Cargo.lock updates.
- Use existing maintainer commit identity `markik <mark_ik@outlook.com>` with command-local Git configuration. No attribution trailers; do not push or merge shared main in these tasks.

## Review focus

1. Persisted ledger MAC tampering must refuse before authoritative records are served, even when the data record itself remains valid.
2. Base58 leading zeros, empty values and the Bitcoin alphabet must remain exact; an unintended checksum/prefix is a wire change.
3. Hex decoding must continue accepting both cases and refusing every wrong size or non-ASCII/invalid digit.
4. Default Insigne remains usable without digest/verify; optional crypto features retain their existing boundaries.
5. A successful Linux supplier gate does not establish MSRV, browser runtime or downstream same-revision type identity.

### Task 1: replace fixed-width MAC equality

**Files:** modify `crates/personae/Cargo.toml`, `Cargo.lock`, `crates/personae/src/sealed_record_storage/freshness.rs`, and `crates/personae/src/sealed_record_storage_tests.rs`.

**Interface:** the persisted ledger and expected digest are `[u8; 32]`. Use `constant_time_eq::constant_time_eq_n` rather than a new wrapper algorithm. Add a direct compatible 0.4.2 dependency, keeping its existing resolved package.

- [x] Confirm the unchanged Personae/Insigne package baseline and preserve its command/result.
- [x] Add an integration regression that creates a valid authoritative sealed record and separate ledger, changes one persisted ledger MAC byte without altering the sealed record, and asserts the read fails with the existing authentication refusal. Exercise mismatches at the first and last byte without changing ledger structure.
- [x] Run that regression on the existing code to establish its behavioral baseline. This is a behavior-preserving primitive migration; a deliberately failing test is not evidence of a timing guarantee.
- [x] Replace the local slice/XOR helper call with the fixed-array library function and remove the local helper. Update the direct dependency edge narrowly.
- [x] Run the tamper case and existing external-freshness rollback, unauthenticated legacy and tombstone resurrection tests. Run Personae's library/integration suite with all its features once, plus formatting and diff checks.
- [x] Commit only Task 1 changes and record test counts/commands and commit in the task report. Independent review must check both spec compliance and code quality before Task 2.

### Task 2: replace Insigne Base58 and hex algorithms

**Files:** modify `crates/insigne/Cargo.toml`, `Cargo.lock`, and `crates/insigne/src/encoding.rs`; update `crates/insigne/README.md` only if it states a dependency claim that becomes false.

**Interfaces:** preserve `base58_encode(&[u8]) -> String`, `base58_decode(&str) -> Option<Vec<u8>>`, `hex_encode(&[u8]) -> String`, and `hex_decode<const N: usize>(&str) -> Option<[u8; N]>`.

- [x] Preserve the existing draft/reference Base58 vectors, zero/empty round trips, bad-alphabet refusals, mixed-case hex and wrong-size/invalid-digit tests. Add only uncovered independent adapter boundary vectors; do not mirror the dependency implementation.
- [x] Add `bs58` 0.5.1 using the Bitcoin alphabet explicitly and without checksum features. Use only the allocation features the existing API needs. Add a direct `hex` 0.4.3 dependency using the already-locked package. It is currently a different package's dev dependency, not an Insigne dev dependency to promote.
- [x] Implement thin adapters: lowercase hex output, fixed-array `decode_to_slice` returning None on error, and Base58 errors mapped to None. Remove independent arithmetic/alphabet-scanning code and correct the source comment claiming a serde-only core.
- [x] Resolve only the newly required dependency closure, inspect the complete lock diff, then use `--locked` for validation. A small new closure is acceptable; unrelated package upgrades are not.
- [x] Run Insigne's library/integration/reference/key tests with default and all features, plus a no-default-features check. Run the combined Personae/Insigne all-feature gate after both tasks, and formatting/diff checks. Keep the heavy gate and existing limits.
- [x] Commit only Task 2 changes. Record actual dependency additions, test counts and any unqualified targets in the report. Independent review must assess wire and feature compatibility.

## Findings

- 2026-10-29: `freshness.rs` compares two `[u8; 32]` MACs using a handwritten XOR loop. Its use is authentication, not an ordinary display digest comparison.
- 2026-10-29: Insigne Base58 preserves leading zeros and empty values; hex writes lowercase and reads either case at an exact generic array size. Existing public key/DID vectors protect those contracts.
- 2026-10-29: the first baseline launch failed before compiling because systemd did not inherit the shell working directory. Specify it in every service. The repository pins Rust 1.99.1, which is being prepared on this host.

## Progress

- 2026-10-29: current-main isolated lane and source preflight founded.
- 2026-10-29: Task 1 committed at `c15a65b`; Task 2 committed at `27b731f`; both independent task reviews approved. Working-toolchain supplier and feature checks are qualified on the isolated branch. Evidence: [receipt record](archive_docs/2026-10-29/2026-10-29_identity_primitives_plan_receipts.md). Downstream receiving, MSRV, Wasm and installed custody remain open.

## Deferred receiving work

After supplier review, update consumers together at a single Dramatis revision and run relevant acceptance tests in their own lanes. This supplier branch alone does not qualify Mere/Turnstone, Wasm, MSRV or installed identity custody. Remaining stack reductions are tracked by the Mere plan and are outside these two tasks.
