# Fleet custody rollout receipts

## 2026-11-05: remaining-fleet inventory and Linux native qualification

Continuation of custody D3/D4 and the original fleet-wide weekly authorization
request. The parent custody receipt retains the O-PC/T-PC personal receiving,
weekly settings and root/device trust evidence. No native prompts, personal
installations, adoptions, service changes, identity creation or enrollment were
performed in this continuation pass.

### Current inventory

All six remaining hosts authenticated over their pinned SSH aliases. The M4
uses its mesh alias where needed; this establishes no independent-uplink result.
Selected idle settings and active launcher XDG overrides were re-read.

| Host | OS/kernel | Resident | Idle minutes | Personal custodian |
|---|---|---|---|---|
| Q-PC | macOS/Darwin 24.6.0, Intel | Running | 10080; active override checked | Not installed at checked signed installation/launchers |
| iMac-M4 | macOS/Darwin 25.5.0, arm64 | Running | 10080 | Not installed at checked signed installation/launchers |
| S-PC | Linux 7.0.0-42-generic, x86_64 | Running | 10080 | No checked instance/regular unit |
| Y-PC | Linux 7.2.15-300.fc45.x86_64 | None running | 10080 saved | No checked instance/regular unit |
| R-PC | Linux 7.0.0-42-generic, x86_64 | None running | 10080 saved | No checked instance/regular unit |
| X-PC | Linux 7.0.0-42-generic, x86_64 | None running | 10080 saved | No checked instance/regular unit |

Linux checks included `djinn-custodian@markik.service`, the regular system
service, user services and active custodian unit inventory. macOS checks
included user/system LaunchAgents and LaunchDaemons, current owner launchd
state and the expected personal custodian binary. These findings concern the
personal operator, not another test account's historical synthetic package.

S-PC/Q-PC/M4 have standard `vault.json` and data locations present. The checked
standard stores were absent on Y/R/X; no exhaustive identity-absence claim is
made. Private snapshots are `testing/dramatis/fleet-policy/remaining-fleet-01.json`
and `remaining-fleet-platforms-01.json` (7708 and 2186 bytes respectively).

### Explicit Linux native test

The existing current native gate was reused, not replaced by a new crypto or
key service. Source checkpoint `bc18c5f`; maintained Cargo source executable:
`T-PC: Code/repos/mere/target/build/debug/deps/linux_agent_confinement-aa8d7da303824494`.
Its 147584104-byte input was preserved. `strip --strip-debug -o` created an
owned delivery copy; its remaining 30441120 bytes exceeded the initial compact
delivery threshold, so it was transported as a 7196402-byte gzip packet.

The stripped copy executed successfully on T-PC before distribution. Exact gate
SHA256: `a689c3f0756676f79870d18e687b6c5d0fd61272eb2574d9a9f182814aff90d0`.
Compressed packet SHA256: `ab1ed1354fbc3fae1f70909c6f6c5937404a255ef2996a514b2202ccf0c82382`.
Per-host calls explicitly selected the ignored test:

```text
linux-agent-gate --exact agent_and_unlock_run_inside_linux_confinement --ignored --nocapture
```

| Host | Landlock ABI | Executed result | Owned test group reaped | Generated delivery removed |
|---|---|---|---|---|
| S-PC | 8 | 1 passed | Yes | Yes |
| Y-PC | 10 | 1 passed | Yes | Yes |
| R-PC | 8 | 1 passed | Yes | Yes |
| X-PC | 8 | 1 passed | Yes | Yes |

The gate enforces Landlock/seccomp in a synthetic child, accepts/closes the
owner's locked-agent connection, performs real synthetic unlock/catalog
initialization, reproduces the omitted-data-root refusal and checks denied
sibling reads/config writes. No personal data or existing services are used.
This qualifies synthetic confinement on those OS/architecture combinations;
personal adoption, deployed services, enrollment and remote-consent execution
remain unqualified.

### Retention and cleanup

Delivery ran sequentially with compact result capture and bounded process groups.
Each generated executable was hash/marker checked and removed only after its
test group was gone. The source Cargo executable and all earlier receipts were
preserved. The controller compressed packet was removed after all four passes
and completed transfers; no live compiler/test/application owned that copy.

New controller results remain under
`testing/dramatis/fleet-policy/native-qualification/remaining-linux-native-gates-01.json`
and `cleanup-01.json`; target-local `native-result-01.json` preserves bounded
test tails. Marker/metadata files identify `fleet-weekly-policy-generated-native-test`
as their owner. Controller retention before its small cleanup receipt was
2593 bytes. No copied gate executable remains. No isolated Cargo target, Cargo
home or Git worktree was created; normal targets and unrelated work are preserved.
