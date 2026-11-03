
## Custodian extraction, 2026-11-03

Run evidence: `Code/testing/dramatis/custodian-extraction-20261103` (100 MB cap).
`source-move.json` records SHA-256 and old/new homes for all 63 tracked source,
installer and native-harness files. The custody plan and native integration
record also followed their implementation; historical archives stayed in Mere.

Before relocation, the native Windows custody gate passed four wire tests and
47 custodian tests; two adoption tests failed with Access is denied (os error
5). The moved Dramatis all-feature/all-target workspace gate passes 867 libtest
cases and both custom residue harnesses, with exactly those same two failures.
Sporran passes 67 tests, including the three relocated station-grant
policy tests. `baseline-custody.log`, `dramatis-custody.log` and
`supplier-summary.json` retain the comparison.

`supplier-cones.json` shows no Mere or Genet supplier and no custody
implementation in the wire client's normal graph. The final supplier lock is
registry-only externally. Installer PowerShell parsing and Linux/macOS shell
syntax checks pass. Native Python sources parse and `native-source-stamps.json`
verifies the relocated Rust supplier/header paths. The macOS harness unit suite
cannot import on Windows because `pwd` is unavailable; its failed invocation
is retained. No new native macOS or Linux receiving run is claimed.

### Receiving and closeout

- Supplier move: Dramatis `b4bce8bb82bbbdef7d9e92e9ff32a547fd1d5181`.
  `452e450c00ea975d2eaf10fdfb05c2e2dc9f44c5` restores the installers' original
  executable modes and qualifies the moved custody plan's source references;
  Rust, Cargo manifests and Cargo.lock are identical to the tested move.
  `source-equivalence.json` records this comparison. Mere locks `452e450`;
  subsequent supplier documentation commits do not require reciprocal repins.
- Receiving: Mere `3fe2499a04d1aeab808653719260c222885eb1c8`, pushed on main.
  Its whole workspace passed locked all-target checking. Pandect and
  station-custody's all-feature/all-target suites passed 359 tests, 2 ignored.
  On the final supplier source, custody_route passes 2 Windows IPC tests and
  custody_payload passes 1; custodian_client is Unix-only and runs no cases
  on Windows. `mere-custody-ipc.log` records the exact feature selection.
- `mere-source-identities-final.json` and `resident-normal-build-final.txt`
  establish one selected identity for the custody packages and peer facts.
  The production resident links the wire client and no custody implementation.
  Genet remains on the events-release revision `ad362723109b`.
- Both repositories' full-tree and commit hooks pass. Mere's include locked
  all-target Clippy, Responsa and dependency bans. Source changes were staged
  from `mere-staging-allowlist.json`; unrelated changes were absent.
- The two baseline Windows adoption failures are retained, as is the macOS
  Python suite's unavailable `pwd` import. Installer syntax and source paths
  were checked; no service was installed and no signed native run is claimed.
  There are no retained isolated targets, Cargo homes or worktrees; existing
  stable per-repository targets were reused.

Registry archives from the preceding release pass remain unchanged. This
source extraction leaves the next Sporran/Pandect registry version updates to
the next release; it does not claim that unpublished APIs are in old archives.

## Resident identity extraction, 2026-11-03

Run evidence: `Code/testing/dramatis/resident-identity-20261103` (100 MB cap).
The pre-move Mere resident feature-selected library baseline passed 276 tests
and failed `resident_mere::tests::the_dialable_host_serves_only_what_the_grant_and_the_owner_name`;
a separate pre-move control reproduced that failure. `baseline-resident.log`
and `baseline-resident-control.log` retain both results.

The new service passes its no-default-feature test and 21 all-feature tests.
The initial compile identified a missing signing-test dependency, repaired
without changing signing logic. Default and CXF normal/build cones exclude
Mere, Genet, Djinn, Castellan and dialog implementations. Source move hashes,
feature-specific commands and dependency cones are retained beside the logs.
Mere receiving and concrete caller migration follow supplier publication to Git.
