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

## 2026-11-05: corrected receiving packet and preserved actual approval

The unchanged c538 resident and 23c CLI produced an approval through their real
OwnerConsent path in a synthetic namespace, with no preseeded grant. The measured
S-PC service umask0002 produces mode0664 and 328 policy bytes. Those exact bytes
pass the receiving validator. `production-owner-grant-01.json` also passes all ten
interoperability/no-wallet checks and records fixture cleanup. Synthetic native
confirmation here qualifies serialization, not a new personal authorization.

The updater requires the prior d89 native failure lineage and protected preserved
policy, validates its exact authority/client cohort under attended sudo, and
restores those unchanged approval bytes before resident startup. The actual S-PC
policy is not read or replaced by a synthetic grant during preparation. Another
application-consent ceremony is not required for that same recorded decision.

Frozen receiver SHA256
`2928dabb3b4a7e06cdd0ba2c286c57bb80cab76c650a649f40d13c902eda4ded`
pins support SHA256
`f92bbbe1ad7d355789ab08a82a1da8c4732326e3e24b22056539b2a8b71212ce`.
Ten synthetic receiving checks cover atomic single-copy replacement, interrupted
replacement before/after rename, changed products, unowned stages, invalid raw
hashes, exact approval lineage, and descriptor-pinned changed/indirect compressed
inputs. Twelve manifest/loader checks also pass. Custodian validation uses the
actual new product's pure `validate-config` success and measured empty outputs;
resident help retains its measured exit2 contract. No guessed loader exit is used.

Replacement records intent before same-parent atomic rename and fsyncs the parent.
If a later receiving gate fails, the corrected product is an explicit installed,
stopped baseline while original resident/custody paths are restored. There is one
raw custodian stage and no additional product backup hidden outside the budget.

Final review `637e4d4e66adfa222459c4f706db88209601b28967b6b843b79093aec815b963`
binds sixteen qualification/history receipts. The v3 manifest SHA256 is
`fc2a2b5196f55f7db479d025aa452923de3877bca7688b94fe3b9fbf65f119eb`;
qualification receipt SHA256 is
`b8700295f1aa54c9037c46cde41f6cad6eeab62df2331ac39d5efed8fa41cfca`.
Custodian/client/resident gzip inputs were streamed serially T-PC through O-PC to
S-PC, verified at both ends, and retained only on the receiving host. Staging peaks
at 105014460 bytes; atomic custodian receiving at 136748868; the resident/CLI raw
pair at 156972520. All include 60600000 recovery, 3000000 records and 1000000 other
transient bytes within the 160000000 cap. No new Cargo target/home/worktree exists.

The old held terminal was closed only after exact ownership, exited children and
the failed-agent rollback were verified. Original resident261760 remains active.
New native receiving, cold reopen, fresh outbound SSH and shared-root custody
authorization remain separate pending gates at this packet-staging checkpoint.

Actual Windows PowerShell5.1.26100.9836 `-NoProfile -NonInteractive -File` checks
then passed against that exact manifest: VerifyOnly exits0 with read-only preflight
success; an all-zero manifest hash exits1 locally before SSH. Dispatcher SHA256
`9e5b967994bd81a52f55cadaf90dbb29778edc020686f460dfa065853ed5e135`
has zero PS5 parser errors. `agent-dispatcher-qualification-01.json`, SHA256
`9bbab24740efcbfcf81b2275063cec47d6640772ea5d63a2e9aa66839d4b837d`,
retains those outcomes. New terminal/root/state markers were absent afterward;
original resident261760 remained active. One paused native handoff was authorized
under the existing rollout instruction; personal acceptance is still pending.

The exact dispatcher then exited0 and opened one independent paused Konsole:
unit `djinn-custody-resume-agent.service`, invocation
`040e2ba911664158955f8d03609a5e6c`, Konsole267374, owner267397 on pts/1.
`agent-native-handoff-01.json` records matching source/manifest arguments, the
initial Enter gate, no owner children, absent root/baseline state and original
resident261760 still active. Only process/unit metadata was observed; terminal
contents were not captured. The fleet chat issued one native sudo/vault completion
card. The already accepted application decision is to be verified and reused.

## 2026-11-05: S-PC native receiving passed and outbound SSH restored

`agent-native-result-01.json`, SHA256
`2f7437432751e529856634d6f30c30faab947e6a2a313488e45b1382268fb245`, records native
unlock, original public master and vault slots, the exact original SSH identity
listing, and reuse of the actual owner approval. The three exact loader checks
passed. The original recovery and failed-attempt evidence remain. The corrected
e356 custodian and resident were observed active, both sockets enabled, temporary
unit drop-in removed and compressed delivery inputs consumed. S-PC's installed
config sets 604800 seconds and its reloaded idle policy sets 10080 minutes.
The owner process exited. Konsole's hold option kept the completion text visible.

Fresh SSH to O-PC and T-PC first passed with an explicit corrected agent socket.
The saved SSH aliases still pointed to the absent legacy socket. The fleet lane
updated exactly four `IdentityAgent` paths in S-PC's owner SSH config, retaining
an owner-only copy of the original. The normal aliases then authenticated using
the original agent key to O-PC, T-PC, iMac-M4 and Q-PC. All four used strict host
key checking and fresh connections. `ssh-alias-custody-01.json`, SHA256
`fa51cb61e4b5f19096095777393f535dcd6597e757c4e69c4016410fdc13accd`, records the
config hashes and four successes. Cold reopen, O-PC root pin and live remote
approval still require their own receipts.

## 2026-11-05: S-PC cold reopen and root-pin qualification

The proposed policy pins O-PC as both authority and issuer for S-PC's existing
default profile. It allows consent with 604800-second grant and unlock caps and
adds the local owner bridge. The original policy, compared field by field, is
otherwise preserved. Candidate SHA256
`467cd776f1a4a9a01b31188b0dbb046e92eeafe271d18523468816000529a71a`
binds this config. The current O-PC public identity matches its root pin.

`root-pin-native-fixture-03.json`, SHA256
`06b53b2879b2212108b601559a39107d5e1b4cb0ae938cb68c06b26ac833899c`, exercises the
installed e356 custodian and 528 helper on S-PC in an isolated synthetic vault
with inherited sockets and enforced Landlock/seccomp. Cold instances differed,
the locked agent refused access, and local unlock restored the same synthetic
master and encrypted vault. The consent-only state stayed empty. Duplicate
initialization, the wrong root and remote unlock were refused. The fixture exited
cleanly and was removed. Personal cold reopen and live root setup follow through
the attended transaction.

The reviewed follow-up packet SHA256 is
`fae61f25abfda31b6624d6c7693f2104e6382069331be83045d6b1656a76c0d5`.
It binds the driver, dispatcher, candidate, synthetic checks, retained recovery
lineage and the release of the finished receiving terminal. The config-only
transaction passed five isolated checks for guarded replacement, rollback and
changed input. Actual Windows PowerShell 5.1 read-only preflight passed and a
changed packet hash was refused locally. Rollback verifies the original config,
vault, settings and SSH hashes, service activation and restored bridge denial.
The prospective empty authority database is about 4.2 MB logical. The follow-up
reuses the retained archives and stages only small policy records and scripts.

`root-pin-native-handoff-01.json` records one paused window on S-PC. The dispatcher
returned zero, Konsole275089 started owner275113 on pts/1, and metadata confirmed
the initial Enter gate without reading the terminal. The original policy and
running custodian/resident were still live at handoff. One native sudo/vault
completion card is pending in the fleet chat.
