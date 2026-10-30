# Task 1 report

Status: implemented; independent review pending. Commit: c15a65b410313824d18dd8df8ceb3752877becb6. No push or merge.

Baseline: controller-provided unchanged Personae/Insigne all-feature gate, cargo +1.99.1 test --locked -j 1 -p personae -p insigne --all-features -- --test-threads=1, at source 6711105e0284adb3e881fc9aebcc56f25000c1ca, Rust 1.99.1: 119 passed, 0 failed, 4 existing sshd ignores. Wrapped in flock -n /home/markik/Code/testing/machine-heavy.lock timeout 600 systemd-run --user --quiet --wait --pipe --collect --unit=stack-reduction-baseline-20261029b --working-directory=/home/markik/Code/worktrees/dramatis-stack-reduction-20261029 -p MemoryMax=3G -p MemorySwapMax=0 -p CPUQuota=150% -p TasksMax=256 nice -n 10 env CARGO_TARGET_DIR=/home/markik/Code/targets/lanes/stack-reduction-identity/build CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 PATH=existingpath. Logs: /home/markik/Code/output/stack-reduction-20261029/baseline-corrected.log and baseline-summary.json.

All test commands below ran in the specified worktree with flock -n /home/markik/Code/testing/machine-heavy.lock, timeout 600s, systemd-run --user --quiet --wait --pipe --collect with explicit --working-directory, MemoryMax=3G, MemorySwapMax=0, CPUQuota=150%, TasksMax=256, nice -n 10, CARGO_BUILD_JOBS=1, RUST_TEST_THREADS=1, CARGO_TARGET_DIR=/home/markik/Code/targets/lanes/stack-reduction-identity/build. Cargo executable /home/markik/.cargo/bin/cargo +1.99.1.

- Before migration, with regression added: cargo test -p personae --all-features persisted_freshness_mac_tampering_rejects_authoritative_record. 1 passed, 0 failed; log /home/markik/Code/output/stack-reduction-20261029/task1-before.log. It tests first and last MAC byte and is a behavioral baseline, not timing evidence.
- After migration: cargo test -p personae --all-features with each filter persisted_freshness_mac_tampering_rejects_authoritative_record, external_freshness_evidence_rejects_an_older_valid_record, unauthenticated_legacy_record_does_not_establish_a_freshness_baseline, authoritative_tombstone_rejects_resurrection_after_delete. Four runs, each 1 passed, 0 failed; log /home/markik/Code/output/stack-reduction-20261029/task1-focused.log.
- cargo test -p personae --all-features --lib --tests --locked: 96 passed, 0 failed, 4 pre-existing sshd tests ignored; log /home/markik/Code/output/stack-reduction-20261029/task1-full.log.
- git diff --check passed before commit.
- cargo +1.99.1 fmt --all -- --check failed on pre-existing formatting in crates/chatelaine/src/kind_tests.rs, crates/personae/src/lib.rs, and two untouched lines in crates/personae/src/sealed_record_storage_tests.rs. The added test was formatted. Log /home/markik/Code/output/stack-reduction-20261029/task1-fmt.log. Unrelated formatting was retained.
- Lock delta: only adds constant_time_eq to Personae's dependency list, reusing the existing resolved 0.4.2 package.

Concerns: all-feature Linux tests do not establish MSRV, browser, or downstream qualification. Existing warnings and four sshd ignores remain. The explicit library call preserves the persisted format and refusal behavior; timing is not established by the tamper test.
