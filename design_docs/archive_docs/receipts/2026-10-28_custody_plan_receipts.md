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
