# Task 2 report

Status: implemented, awaiting independent review. Commit: `27b731f0d2c885c84a943094e54461c744060766`.

Insigne now wraps bs58 with the explicit Bitcoin alphabet and no checksum features, and hex with fixed-array decode-to-slice. Existing vectors remain; added empty-array and non-ASCII/whitespace refusal boundaries. The new boundary test passed on the original implementation (6 focused tests); this is a behavior-preserving refactor, not a deliberately failing behavioral change. README needed no correction.

Lock diff: bs58 0.5.1 with alloc and its tinyvec 1.13.3 closure added; existing hex 0.4.3 added as an Insigne direct edge. No other package versions changed. digest and verify feature declarations are unchanged; default test feature unification still enables verify through the existing self dev-dependency. The separate no-default-features check covers the library without that test dependency.

All Cargo commands used Rust 1.99.1, the requested flock, 600 second timeout, explicit systemd working directory, MemoryMax 3G, MemorySwapMax 0, CPUQuota 150%, TasksMax 256, nice 10, one Cargo job/test thread, and the specified target directory. The initial boundary launch failed before Cargo because noninteractive SSH PATH omitted cargo; rerun with /home/markik/.cargo/bin added succeeded. The initial unlocked dependency resolution `cargo +1.99.1 check -p insigne --no-default-features` succeeded and its complete lock diff was inspected before the following locked commands:

- `cargo +1.99.1 test --locked -p insigne --lib encoding::tests`: 6 passed.
- `cargo +1.99.1 test --locked -p insigne`: 24 passed, 0 failed.
- `cargo +1.99.1 test --locked -p insigne --all-features`: 24 passed, 0 failed.
- `cargo +1.99.1 check --locked -p insigne --no-default-features`: passed.
- `cargo +1.99.1 test --locked -p personae -p insigne --all-features`: 121 passed, 0 failed, 4 existing sshd-dependent ignores.
- `rustfmt +1.99.1 --edition 2024 --check crates/insigne/src/encoding.rs` and `git diff --check`: passed. Workspace-wide pre-existing formatting differences were not modified.

Logs: `/home/markik/Code/output/stack-reduction-20261029/task2-{boundary-baseline,resolve,focused,default,all,no-default,combined}.log`. Linux supplier tests do not qualify MSRV 1.97.1, Wasm/browser, downstream consumers, or installed custody. No push or merge.
