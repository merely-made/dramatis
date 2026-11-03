
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
