# Source splits: H5 Dramatis receipts

## 2026-11-03: twenty identity and custody source paths

Owner: house-style H5 / 01a19f86-cb71-7820-a6ac-aaec39d8bfd4.
Baseline source: `798a1a7c42e058d4438013eea7db332bf63466e0`. Compact text only, within H5's
shared 100 MB retained cap. Prior receipts and SSH fixtures are intact.

| Original source | Before | After |
|---|---:|---:|
| `crates/castellan-client/src/custody.rs` | 727 | 556 |
| `crates/castellan-client/src/custody_client.rs` | 932 | 451 |
| `crates/castellan-client/src/custody_identity.rs` | 1158 | 567 |
| `crates/notochord/src/handshake.rs` | 654 | 577 |
| `crates/notochord/tests/secure_channel.rs` | 634 | 469 |
| `crates/personae/src/carry/mod.rs` | 610 | 507 |
| `crates/personae/src/sealed_record_storage.rs` | 730 | 580 |
| `crates/personae/src/ssh_ca.rs` | 663 | 410 |
| `crates/castellan/src/authority.rs` | 2217 | 579 |
| `crates/castellan/src/authority_lock_tests.rs` | 607 | 529 |
| `crates/castellan/src/custody/agent.rs` | 1269 | 501 |
| `crates/castellan/src/custody/passphrase_storage.rs` | 751 | 453 |
| `crates/castellan/src/custody/vault.rs` | 766 | 512 |
| `crates/castellan/src/cxf/parse.rs` | 688 | 367 |
| `crates/castellan/src/cxf/tests.rs` | 777 | 544 |
| `crates/sporran/src/wallet_grant/certificate.rs` | 601 | 376 |
| `crates/djinn-custodian/src/core.rs` | 992 | 549 |
| `crates/dramatis-resident/src/custody_host/remote.rs` | 670 | 334 |
| `crates/dramatis-resident/src/custody.rs` | 672 | 538 |
| `crates/dramatis-resident/src/startup_vault.rs` | 732 | 529 |

All replacement modules also fit 600 physical lines. Twenty exceptions
retired; only the live SSH daemon fixture remains exempt. No receiving
pins, manifests or lockfiles were changed. API facades/reexports, exact
wire-transcript logic, authority, timeout, key release and revocation remain.

- Baseline `cargo test --workspace --locked` found two existing adoption
  failures: Windows AccessDenied during `sync_all` on a read-only handle.
  The repair opens that staged file with write access before flushing.
  Atomic publication and non-overwrite behavior remain covered by the same
  tests. This is the batch's only production behavior repair.
- Post `cargo test --workspace --locked`: 833 passed test/doctest cases,
  zero failed, including both original adoption fixtures.
- `cargo check --workspace --all-features --all-targets --locked`: pass.
- `cargo test -p dramatis-resident --all-features --locked`: 21 passed.
- `cargo doc --workspace --all-features --locked --no-deps`: pass. Relevant
  owned links repaired; unrelated pre-existing rustdoc warnings remain.
- `prek run --all-files`: ceiling, Clippy and dependency bans pass.
- Structural review compared 349 old/new function bodies: scope/include-path
  adjustments and rustfmt block/separator formatting, plus the explicit
  adoption handle repair. Function names/case counts are preserved. License
  headers are retained on extracted source. No native Unix/live-sshd,
  platform-dialog or new hardware acceptance claim follows.
