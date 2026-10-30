# Identity primitive reduction receipts, 2026-10-29

Supplier source: Dramatis `6711105e0284adb3e881fc9aebcc56f25000c1ca` plus `c15a65b` (MAC comparison/tamper regression) and `27b731f` (Base58/hex adapters/boundary regression). Both tasks passed independent source review.

[Qualification record](../../../support/receipts/identity-primitives-20261029/qualification.json), [test summary](../../../support/receipts/identity-primitives-20261029/verified-test-summary.json), and [host admission](../../../support/receipts/identity-primitives-20261029/host-admission.json). Full commands, baseline/final logs, task reports, reviews and progress ledger are retained in that same receipt directory. The live remote lane is `/home/markik/Code/worktrees/dramatis-stack-reduction-20261029` on S-PC; intermediates remain outside the repository in the stable target lane.

The unchanged all-feature Personae/Insigne baseline passed 119 tests with four existing sshd-dependent ignores. The final combined gate passed 121, failed zero and retained those four ignores. Insigne default and all-feature gates each passed 24; its no-default-features check passed. Tests ran on Rust 1.99.1 with a 3 GiB cgroup limit, zero allowed cgroup swap, 150% CPU, one build job and one test thread.

The first baseline launch failed before compiling because the service used its default working directory; its failed log is preserved alongside the corrected run. Existing deprecation/unused-import warnings and unrelated workspace formatting differences remain explicit. These runs do not establish MSRV 1.97.1, Wasm/browser behavior, timing properties, downstream dependency adoption or installed custody qualification. Branch commits are not publication.
