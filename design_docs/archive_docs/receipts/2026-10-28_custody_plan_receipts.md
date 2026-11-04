# Custody plan receipts

## 2026-11-04: one-week policy and O-PC idle setting

Custody D2 records the requested one-week elapsed unlock, idle timeout and new
remote authorization grant lifetime. This entry qualifies only the live idle
configuration; the elapsed timer and remote vault-unlock issuance remain
planned. Existing device-grant issuance still requires an explicit signed
expiry. No grant was issued, renewed or edited, and no vault was unlocked.

Resolved the active resident's app directory from its installed launcher and
the `settings::default_app_dir` source. Created its previously absent
`lock.toml` with `idle_minutes = 10080`. Readback through a TOML parser gives
604,800 seconds. The running resident logged at **2026-11-04 18:16:33 UTC**:
`LockSettings { session_lock: true, suspend: true, idle: true, idle_minutes: 10080 }`.
The existing sampler reloaded it without restarting the service. This does
not qualify a full-week idle run or the unimplemented elapsed-duration gate.

Validated document whitespace with `git diff --check`. No Rust source changed,
so no build or new test suite was required. No isolated Cargo target, Cargo
home, worktree or provider was created. No new raw log capture was retained;
the compact receipt is within the plan's 100 MB cap. Existing dirty custody
and pairing documentation was preserved.

## 2026-11-04: fleet scope, absolute expiry and deployment preparation

Custody D3 makes the selected week apply to all existing authorized work on
the configured fleet. This is not a Gemot/test-only override. Scope and
revocation checks remain independent of duration.

### Receiving implementation and checks

The existing custodian core now takes owner-policy `max_unlocked_seconds`,
default **604800**; an explicit `null` selects indefinite duration. Successful
unlock fixes the deadline. Activity, reconnect and duplicate unlock leave it
unchanged. Expiry follows the existing lock path: root access ends, generation
advances, cached approvals clear and pending petitions are cancelled. The
service ticker and new agent admission check expiry. A calendar fence counts
suspended time and rejects backwards movement alongside the monotonic bound.
Every service start remains locked; this is not unattended cold-start unlock.

On Windows, using the stable `C:\t\cargo-targets\dramatis` target, its `build`
directory and one Cargo job:

```text
cargo test -p djinn-custodian --lib --locked -- --test-threads=1
cargo clippy -p djinn-custodian --all-targets --locked --no-deps
cargo build -p djinn-custodian --bin djinn-custodian --locked
```

Final core/supplier run: **53 passed**, zero failures, **52.67 s**. Five new
controls cover activity/reconnect/duplicate unlock, timed cancellation,
failed/indefinite unlock, malformed duration and sleep/clock rollback. These
advance injected time rather than waiting a week. Clippy exits zero with
existing warnings. Ordinary executable build passes, size **15,878,656 bytes**
(measure the receiving file before deployment). Its SHA256 is
`7F3693D2833FF1B8F5876F3B36E139E5C42019A208300A8956325C87847C567B`.

`support/update-week-policy-windows.ps1` parses under PowerShell. It requires
an elevated process, pins the reviewed binary hash and existing service
command, backs up the current executable/configuration under the protected
custodian root, preserves grants and vault state, and restores the old files
on failure. It changes only the service build and maximum unlocked duration;
it does not adopt/migrate a vault or turn off other lock triggers. A native
administrator prompt was opened for this prepared update. Windows returned
"The operation was canceled by the user" before the elevated process started.
The launcher printed an empty child exit code: that is not installer success.
The installed service stayed running at its previous SHA256,
`3356778098629E7875FF8BCAAFB0DC2FB90472292DC484205D2492631731751E`.
No protected policy/binary update, installer backup or new service activation
occurred. Installation, post-restart unlock and physical lock/sleep qualification
remain pending. Parser success is not deployment proof.

### Fleet receiving facts

Before native unlock, the local agent had no identities and reachable peers
refused SSH authentication. The owner completed Djinn's O-PC unlock prompt;
the agent then listed the same SSH identity and authenticated remote probes
succeeded. No new SSH key or host trust was installed.

| Machine | Observed state |
|---|---|
| O-PC | Active idle setting 10080 minutes, reload logged; maximum-duration update did not run because Windows canceled elevation |
| S-PC | Idle setting written/read back; running resident logged reload with 10080 minutes |
| Q-PC | Active launchd `XDG_DATA_HOME` override resolved; its actual lock file already has 10080 minutes and the resident log records that setting; normal-root fallback is also configured |
| X-PC | Idle setting written/read back; resident was not running |
| iMac-M4 | Idle setting written/read back through its reachable mesh alias; resident was not running; independent-uplink behavior unqualified |
| T-PC, Y-PC, R-PC | SSH timed out; wake packets sent, without a verified wake/update |

Reachable remote UTC clocks matched the controller to within the probe's few
seconds. No clock was changed. Private addresses, MACs and installation paths
stay in the existing private fleet inventory and device configuration.
Older combined residents are not claimed to enforce the new separate-custodian
deadline. Native custody receiving and independent-operator/I2P trials remain
open; the supplier run above does not close them. Lock-fault tests must use
isolated trial custody so they do not cancel the owner's fleet authorization.

No isolated target, Cargo home or worktree was created. Compiler outputs reuse
the normal target; no new full raw logs or fleet payload capture were retained.
Protected installer backups, if created, belong to this fleet policy update and
must be measured in the final deployment receipt. The plan retains its 100 MB cap.

### Fleet follow-up after network wake

At approximately 2026-11-04 19:00 UTC, T-PC, Y-PC and R-PC became reachable
after the wake attempt. Authentication succeeded with the existing agent key.
Each selected application directory was resolved against the running resident's
environment where available; all three idle settings were written and parsed
back as **10080 minutes**, preserving other settings. All three residents were
not running, so this proves saved configuration, not a live reload. This
supersedes their earlier unreachable status above. All eight inventory machines
now have the selected idle configuration; O-PC, S-PC and Q-PC are the running
resident cases. No independent-uplink or independent-operator gate follows.

The native administrator update remains unperformed after Windows canceled
elevation. The source/binary receiving checks do not establish a live absolute
weekly deadline on any older installed resident. The owner was asked whether
to reopen the native prompt or leave the tested update ready. Early session
lock and suspend flags were preserved until finite expiry is deployed.

### Inactive launcher path verification

Systemd user-unit environment checks found T-PC's configured `XDG_DATA_HOME`
override. Its actual `graphshell/lock.toml` was then written and parsed back
as 10080 minutes, in addition to the standard-root file. R-PC and X-PC reported
no installed `djinn.service`; their saved standard-root files are therefore
configuration preparation, not active service deployment. iMac-M4's launchd
environment has no data-root override. Q-PC's actual launchd override and its
current file were checked directly; the recorded reload predates this pass.
Y-PC became unreachable again before its inactive unit environment could be
verified: its standard-root setting was written/read back, but its configured
launcher-path verification remains open. These distinctions limit the earlier
all-eight statement to saved configuration; they do not establish eight live
residents or a fleet-wide enforced absolute deadline.

## 2026-11-04: portable root/device enrollment and remote custody approval

Bounded source slice for VL-U and custody D4. `custody-wire` adds public
request/proof records; `djinn-custodian` adds an explicit-owner-policy gate.
It reuses Insigne's existing signed delegation statements and Notochord's
chain validator/current revocation ledger. No new crypto scheme, executable,
network listener, native consent mechanism or automatic vault opening is added.

The initial focused run passed 11/12: the remaining test restored only an
unlock action in its target policy while presenting a grant also allowing
consent. The gate correctly rejected that broader grant. The fixture now
restores both intended actions; the failed-run summary is retained here.
The succeeding full run passed 65 custodian library and four wire tests;
two further boundary tests then brought the focused proof suite to 14/14.
The final exact-source run passed **67/67 custodian library tests and 4/4
wire tests**. The final all-target Clippy check passed, with no diagnostics
in the new modules; pre-existing warnings elsewhere remain.

The controls cover direct trusted-root approval; root-enrolled device proof;
wrong root/action/profile/target; every request binding; replay, withdrawal,
generation/restart invalidation; revocation rechecked from a serialized ledger;
short request expiry under both clocks and rollback; bounded proof/request
work; fixed-week expiry, shorter owner settings and arithmetic overflow.
An approval in the final valid millisecond is capped at the root grant's
original expiry; reconnecting at expiry cannot restart the week. Direct root
approval keeps the short proof window separate from the selected unlock bound.

The approving fixtures sign with synthetic local providers; the target gate
holds only public policy and pending requests. This does not qualify O-PC/T-PC
enrollment, approving-host native consent, durable policy/ledger handling,
the target's Core execution barrier, any storage-opening backend, Iroh/relay
delivery or independent-network behavior. OS administrator prompts remain
native mechanisms. The other lane owns the installed O-PC updater/relay work.

Builds reuse `C:\t\cargo-targets\dramatis` and its `build` directory, one job.
Library tests and Clippy leave the reviewed `debug/djinn-custodian.exe` at
SHA256 `7F3693D2833FF1B8F5876F3B36E139E5C42019A208300A8956325C87847C567B`.
No native unlock/deployment was requested by this lane. No isolated target,
Cargo home, worktree or full new capture/log was created; this compact summary
is the retained receipt and stays within the plan's aggregate 100 MB cap.

Final commands (the existing target/build directory overrides above applied):

```text
cargo test -p djinn-custodian -p custody-wire --lib --locked --offline -- --test-threads=1
cargo clippy -p djinn-custodian -p custody-wire --all-targets --locked --offline --no-deps
git diff --check
```

## 2026-11-04: O-PC receiving failure, recovery and Windows parity

Native elevation eventually ran the first extracted weekly receiver. The
initial `update-attempt-04.json` reported success at 19:55:52 UTC, but the
service subsequently stopped with SCM exit code zero. That initial result
does not qualify sustained receiving. The earlier `update-attempt-02.json`
failed at policy replacement and rolled back: Windows PowerShell 5 binds
the null backup argument of `File.Replace` as an invalid empty path. A real
unique backup path fixes that binding; an isolated native-PS5 replacement
control preserves both old and new bytes. Attempts 03 and recovery 01 never
executed after Windows canceled elevation; their result files do not exist.

`support/restore-custodian-windows.ps1` restored the verified previous image
and exact original policy at 20:21:29 UTC. It selects the protected backup by
hash and policy equivalence with only the weekly field removed, checks the
existing service/helper identity, waits for stopped image handles, and holds
the restored service Running for ten seconds. `restore-attempt-02.json`
records success; a later controller read still found it Running. Restored
SHA256: `3356778098629E7875FF8BCAAFB0DC2FB90472292DC484205D2492631731751E`.
No vault migration, seed export, grant issuance or root enrollment occurred.

The extracted supplier omitted four qualified Windows receiving fixes from
the historical Mere lane: `ae90e8e2c` (limited process/token identification
admission, reject unidentified clients without ending the listener, service
stderr diagnostics), `b734b94ae` (overlapped full-duplex pipe I/O), `5570b218e`
(OpenSSH client SID by pipe impersonation), and `a5dc790ea` (SCM stop-pending
and return-before-exit). Their earlier receiving record is
`repos/mere/design_docs/archive_docs/receipts/2026-11-02_custodian_windows_receiving_receipts.md`
on `mere-d3-ssh-by-key`. These changes are now lifted to Dramatis's wire,
platform, agent and executable owners. Windows transport is a submodule to
keep each source below the repository line ceiling. Identification admission
grants only process limited-query and token-query rights to configured SIDs;
pipe DACLs and the custodian's operation grants still determine admission.

The updater now refuses a stopped baseline, waits for installed image exit,
uses a valid atomic-replacement backup, writes create-new diagnostic results,
and requires fifteen seconds of Running before accepting the update. Failure
restores the pre-update executable/policy. This checks startup, not native
unlock, real agent signing, or a week-long live authorization boundary.

Private compact results are retained under
`Code/testing/dramatis/fleet-policy`; original binaries and policies remain
under the protected `ProgramData/djinn-custodian/week-policy-backup` for
rollback. They are receiving evidence, not cleanup candidates. The previously
reviewed image `7F3693D2833FF1B8F5876F3B36E139E5C42019A208300A8956325C87847C567B`
is superseded and must not be deployed. One-week idle remains saved locally;
screen-lock and suspend triggers remain enabled pending compatible receiving.
The remote-approval lane isolates its new Core/policy work in the approved
`Code/worktrees/dramatis-remote-approval` worktree during this receiving gate.

The parity source passes **67/67 custodian library tests and 7/7 wire tests**,
including real Windows pipe identification before data, concurrent read/write
and repeatable limited-query admission with malformed-SID refusal. Relevant
all-target Clippy passes; existing documentation/style warnings remain.
Clippy required the raw pipe-SID function to declare its handle-validity
contract unsafe; both callers document their live connected handles. The
post-check replacement executable is 15,922,688 bytes, SHA256
`F9FD7C325BC06F54A7DBD29AD9C08EC5C5DA9F822A9C8EDAF972E626861B430D`.
It includes committed timer/proof plus receiving parity; the isolated new
Core integration is excluded. Native receiving is pending at this checkpoint.

### Corrected native receiving and fleet SSH

`update-attempt-05.json` records successful native elevated installation at
20:31:59 UTC, without rollback, of the exact F9FD image above and the protected
604800-second policy. The fifteen-second startup check passed. Independent
controller reads verified the installed hash, SCM Running/PID 28048, and
Running consent task. The installed Djinn native unlock returned exit zero;
the resident logged unlocked at 20:32:41 UTC. The real Windows agent then
listed the same pre-existing Ed25519 key and certificate. Authenticated SSH
using that key succeeded to Q-PC, iMac-M4, T-PC, Y-PC, S-PC, R-PC and X-PC.
The M4 connection used its existing mesh fallback, not its independent uplink.
X-PC requires its existing SSH HostKeyAlias: the inventory-address probe
refused an unknown raw-address host key, and the configured alias succeeded
with strict host-key checking. Host-key verification was never disabled.

The first fleet inspection passed CRLF input to Unix `sh` and failed remote
command parsing after authentication; the corrected byte-input probe passed.
Those parsing failures were not network reachability failures. An Application
event-log query by unregistered provider name also failed; it is not claimed
as a receiving or diagnostic-channel receipt. SCM/hash/native unlock and real
agent/SSH are the receiving evidence.

Only after finite custodian receiving succeeded, O-PC's existing `lock.toml`
was set to `session_lock=false`, `suspend=false`, `idle=true`, and
`idle_minutes=10080`. Its resident logged the exact reload at 20:34:48 UTC.
The original settings backup remains. Explicit lock and restart still lock;
ordinary screen lock, sleep, activity and reconnect do not renew the fixed
week. The source's injected-time controls qualify the expiry boundary; this
deployment has not been observed running for a full week.

All seven remote standard-root idle files were re-read as 10080. Active
Q-PC launchd and T-PC systemd XDG overrides were also checked at their actual
paths, both 10080. Fresh process/service inventory found T-PC, S-PC, Q-PC and
iMac-M4 residents running; this lane did not start them. Y-PC and R-PC reported
no user service; X-PC's saved setting was read via its configured SSH alias.
Y-PC's now-readable unit reports not-found, closing the earlier unresolved
inactive-launcher lookup. Remote Linux hosts checked do not have a separate
custodian service. This does not deploy absolute elapsed expiry or remote
root/device grants to those legacy residents; their other lock triggers were
preserved. New cross-network approval integration stays in its source lane.

Receiving/parity source is pushed as `f83c641`. Its full commit hooks passed
line ceiling, workspace all-target Clippy and dependency bans. No new isolated
target or Cargo home was used. Protected original policies/image and compact
private attempt results remain owned by `fleet-weekly-policy` for rollback;
the remote-approval worktree is owned by its separate source-integration lane.

## 2026-11-04: durable enrollment and custody consent integration

Mark authorized continuing this source lane while Windows receiving recovered.
The actual Core/manifest collision was isolated in
`Code/worktrees/dramatis-remote-approval`, branch `lane/remote-approval`, from
`0c59e2d`. Source checkpoint `a05217b` was then merged onto `e004e8a`, retaining
the qualified Windows parity and native deployment receipts above. The merge
also gives each queued petition a fresh identity, so caller-reused ids cannot
move approval between immutable operations.

Protected configuration gains optional `remote_approval`; absent means disabled.
Explicit owner setup creates `remote-approval.redb` under the existing vault
directory, and service startup only opens existing state. Muniment/redb provides
exclusive ownership and transactional public authority records. Root/target/
profile pins, every certificate and signed withdrawal are checked on load.
Missing/corrupt state refuses activation; it never creates an empty replacement.
Unix ownership/mode and indirect paths are checked; Windows parent ACLs remain
the installed host's responsibility. These synthetic supplier tests do not add
a cross-account filesystem or power-loss qualification. Restoring an entire
administrator database snapshot remains outside the live revision check.

Signed withdrawals survive restart and also arrive safely before enrollment.
An old certificate cannot undo that tombstone. Duplicate enrollment does not
renew its signed expiry; replayed withdrawal does not repeatedly advance Core's
generation. Narrower owner settings preserve history and revocations while
refusing authority those settings no longer permit. The bounded state budget
is 1 MiB, 256 enrollments and 1024 withdrawals, with refusal rather than eviction.

Core's trusted host API completes exact active consent petitions through the
same serialized barrier as local consent. It rechecks requester permission,
request/digest, profile, generation, clocks, registration and revocation. Remote
per-generation consent has a separate cache that re-reads storage on every use;
its original grant/vault bounds never slide. Per-operation consent stays one-use.
The host API's approval result contains no secret; operation output remains
addressed to the originally admitted requester. No wire operation is added.

Derived-key release was executed with both registered-device and direct-root
consent. Actual per-use SSH signing through Castellan's broker was executed
with registered-device consent only. Direct-root SSH signing has shared-path
coverage, without a separate executed receipt. Other integration controls
cover duplicate-id petition substitution, requester permission removed before
commit, closed requester, lock, revocation, expiry, replay and restart.
Store controls cover exclusive ownership, damaged/missing data,
root/target/profile mismatch, invalid signature/scope, out-of-order withdrawal,
duplicate delivery, historical expiry and live revision regression. Cache
controls independently change the stored ledger, test invalid withdrawal
without canceling good authority, and exercise both clocks and rollback.

Initial failures are retained in summary: a sibling visibility error was
corrected to Core-only visibility; the first focused test run passed 21/29,
with eight fixtures using an invalid profile-scope JSON form. The fixtures now
use the existing `named` scope grammar, without weakening policy validation.
The isolated full run then passed 87 tests; the added policy-history and
out-of-order controls passed separately, as did all 12 final Core remote tests.
Final integrated checks passed **91/91 custodian library tests and 7/7 Windows
wire tests**. Relevant all-target Clippy passed with no new-module diagnostics.
The isolated source commit and the published main merge `dde7e52` both passed
the required line-ceiling, workspace Clippy and dependency-ban hooks.

The current passphrase opening backend explicitly refuses approval-only
unlock. Native approving UI/admission, protected setup UI, authenticated
locked-state network delivery, independent-uplink O-PC/T-PC enrollment and
OS-elevation bridges remain separate gates. This source change enables none
of them on the installed fleet. The native receiving executable remains
`F9FD7C325BC06F54A7DBD29AD9C08EC5C5DA9F822A9C8EDAF972E626861B430D`.
Builds reuse the normal Dramatis target/build directory, one job. Only compact
summaries are retained; full new logs/captures and live fleet fault tests were
not created. The temporary worktree and `lane/remote-approval` branch were
removed after `dde7e52` was integrated and pushed. No isolated Cargo home or
target is retained. The receipt stays within the 100 MB lane cap.

Final source commands, with the stable Dramatis target/build overrides:

```text
cargo test -p djinn-custodian -p custody-wire --lib --locked --offline -- --test-threads=1
cargo clippy -p djinn-custodian -p custody-wire --all-targets --locked --offline --no-deps
git diff --check
```

## 2026-11-04: public approval route source checkpoint

- `custody-wire::remote_approval::route` admits only public state, challenges,
  signed enrollment/withdrawal and exact-request proofs. A separate local
  `remote-approval-bridge` grant is required. General signing, secret release
  and passphrases cannot be forwarded through this command schema.
- Core returns a public acknowledgement to the bridge; successful consent's
  result is delivered to its original admitted requester only. Existing
  generation, requester, proof/revocation and unsupported-opening barriers
  remain in force. Active enrollment readback is checked against storage.
- `djinn-approval` uses the installed OS-authenticated client and native
  consent for signing under the approval delegation audience. The Python
  carrier requires pinned SSH host keys and separate custody root/target/
  profile pins; SSH server keys are outside target custody. Resident P2P
  integration and independent-uplink qualification remain open.
- Windows source gates: custody-wire 8/8 and custodian 94/94 library tests;
  scoped all-target Clippy completed without diagnostics in the added route
  or signer files. Initial compile found a digest argument type mismatch;
  corrected before tests. Three Python pin/shell/refusal controls pass;
  Python and PowerShell activation scripts parse. Native activation tools
  are prepared, not qualified.
- Live inventory correction: T-PC has an active **templated** isolated system
  service `djinn-custodian@markik.service` and an unlocked resident. Older
  absence claims based on the untemplated service name are superseded.
  Its existing config remains remote-disabled. O-PC also remains unlocked
  under the previously installed F9FD cohort at this checkpoint.
- O-PC public custody view reports selected `default`, no wallet manifests
  and no device roster. Root enrollment must pin its actual persona public
  key; earlier architecture/roster assumptions are not deployment evidence.
- No vault adoption, secret export, binary install, service restart, root
  enrollment, remote vault opening or OS elevation occurred in this checkpoint.
  Retained receipts remain compact text, within the plan's 100 MB budget.
