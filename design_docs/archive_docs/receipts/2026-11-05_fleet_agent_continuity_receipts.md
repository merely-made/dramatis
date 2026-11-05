# Fleet SSH-agent continuity receipts

Owner: [fleet custody rollout](../../2026-11-05_fleet_custody_rollout_plan.md).
Earlier receiving/rollback history remains in the
[continuation receipts](2026-11-05_fleet_custody_rollout_plan_receipts.md).
The same cross-host 160000000-byte receiving peak and 100000000-byte retained
receipt/recovery caps apply. Records now reserve 3000000 bytes for accumulated
failed attempts and qualification; this reallocates headroom within the peak.

## 2026-11-05: real agent failure after native application admission

S-PC's d89 continuation passed the corrected product loaders, native custody
unlock, selected weekly trigger reload, actual application admission and original
vault-slot digest comparison. It stopped at `verify-original-agent-identities`.
The saved public outcome reports original-restored/new-custody-disabled. Exact
helper assertions independently reverified all seven original files' bytes,
uid/gid/modes/sizes, complete custody inventory and links. Legacy resident261760
was active afterward; custody and both sockets were inactive/disabled.

The restored original agent again returned exit0 and its baseline text digest,
`7c61f8783f0f35cc2fcf51bb9378e308c4597616f21a21ce72ffcb2d64ac77c7`.
Its certificate and bare-key rows name the same underlying subject. The new
agent's actual response was not retained by d89, so the public outcome alone did
not establish a presentation-only difference. Public custodian logs instead show
an agent-thread panic at rustix1.1.5 `linux_raw/conv.rs:912` with EPERM, followed
by a poisoned-vault-mutex panic in the signing thread. The continuity check
correctly prevented acceptance. The accepted application decision is preserved
as owner evidence; it must not be silently revoked or replaced by a fixture grant.

Private controller `fleet-agent-failure-01.json`, SHA256
`c346ffc399e6fbbe72cb073f8cda316fb0a05196da82bf693d9651fe648882c9`,
retains the bounded public outcome/fault boundary without terminal contents,
personal vault contents or private phase-log access. Installed custodian remained
the exact prior bb0d candidate; no service or source mutation was used to diagnose it.

## 2026-11-05: synthetic reproduction and narrow confinement fix

The linked source at producer base `8bc195976838507c7d405bbdf4d1cc87bd1dc4e9`
uses gethostname1.1.0, whose Unix implementation calls rustix `uname`. Certificate
listing derives the local device id through that function while holding the vault
mutex. The confinement allowlist omitted the syscall. This is a runtime failure,
not evidence that the original SSH key changed.

The previous native Linux gate exercised a locked agent connection and synthetic
storage unlock using an empty SSH profile. Its passing results did not qualify
certificate-bearing agent use. The extended existing gate adds one seeded SSH
identity, two certificate-plus-bare-key listings, subject/CA/principal/type/current
certificate validation, four verifying signatures, continued custody health and
an explicit successful raw `uname` result. Existing outside-file/config-write,
network-socket and exec denials remain required.

T-PC red/green qualification uses its maintained Mere target/build with two jobs,
development debuginfo0 and unchanged enabled debug assertions. No new target,
Cargo home, lock or feature selection was introduced.

- `agent-uname-before-01.json`: the extended test fails, exit101, at the same
  rustix EPERM panic and an agent-response EOF.
- `agent-uname-before-syscall-01.json`: a focused 655-byte synthetic trace shows
  `uname` returning EPERM for that exact pre-fix test executable.
- `agent-uname-after-01.json`: **1 passed**, exit0, including both fixture children
  and the certificate/signature/health/denial checks above.

The sole production change is adding read-only `SYS_uname` with a purpose comment.
No unrelated syscall or filesystem permission was added. Both test runs use the
8bc producer cohort plus recorded owned-file overlays; their lock hash is identical.
This does not claim that later main-branch dependency selections were built.

Normal corrected-custodian build, exact-binary interoperability, expanded S/Y/R/X
qualification and reviewed personal installation remain pending at this entry.
The next native attempt must reuse existing adopted state/recovery and the verified
actual owner grant, without repeating initialization or synthesizing consent.

## 2026-11-05: producer and expanded remaining-Linux qualification

Published source fix `05183e8` contains only the allowlist addition and expanded
existing test. Required line-ceiling, Clippy and dependency-bans hooks pass.
The normal candidate is 31734408 bytes, SHA256
`e356ce3143ecb54968902afefcc568d2fb6ea187197ac5df3da2ca3216e5fb0d`.
`agent-uname-cohort-01.json` binds its actual 8bc-base-plus-overlay source and
unchanged lock. The copied Linux source used CRLF on T-PC; normalized Git blobs
match the published fix. This is recorded provenance, not another semantic patch.
No fixture feature was enabled and T-PC's installed bb0d product was not replaced.

Fresh exact-normal-binary `production-no-wallet-05.json`, SHA256
`5065db2736d26b2a0cb15781b8f898f273b5ed18478cde5383ff5bdd054fab26`,
passes all ten interoperability/no-wallet checks with the unchanged c538 resident,
23c CLI and 528 helper. Namespace exit0; generated fixtures removed. This is a
development-custody namespace result, separate from enforced-confinement tests.

The extended gate executable is 29129128 bytes, SHA256
`d726beacbf1b91c0bb60ad89d314966fa5bd97b613fba1fda61103a6fb7b58a1`.
The fleet lane independently streamed it serially to S/Y/R/X, ran exactly the
native ignored test in a marked temporary root, verified each process group had
quiesced, and removed every generated delivery/fixture copy. Each receipt reports
exit0, pass, quiescence and cleanup. No personal daemon or vault was changed.

| Host | Kernel | Private controller receipt |
|---|---|---|
| S-PC | 7.0.0-42-generic | `agent-certificate-native-s-pc-01.json` |
| Y-PC | 7.2.15-300.fc45.x86_64 | `agent-certificate-native-y-pc-01.json` |
| R-PC | 7.0.0-42-generic | `agent-certificate-native-r-pc-01.json` |
| X-PC | 7.0.0-42-generic | `agent-certificate-native-x-pc-01.json` |

Delivery used at most 1MiB controller buffers and retained no T/controller archive
copy. One raw fixture plus full shared recovery/record/transient reserves reaches
93729128 bytes. Generated copies were removed before personal updater staging.
S-PC personal acceptance and T-PC's installed Linux runtime update remain open.
