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

### S-PC first-install review packet

Read-only packet `testing/dramatis/fleet-policy/s-pc-receiving/packet-01.json`
is 17479 bytes, SHA256 `2134e3050a0e54d5c4ca6a1ee7343aff573b1d0aa1f564bef4d5d309fc66d44e`.
Its immutable `baseline-01.json` is 3483 bytes, SHA256
`1a5eda066e3bad4848d35e1c7e386343f1ee0d7daed97bbfc69b95263e8da643`.
Both hashes and JSON parse were independently checked by the fleet lane.
The legacy resident is locked; only the standard catalog, not an identity or
personas directory, was observed. No replacement wallet was created.

The packet defines original-preserving quiescent inputs, confinement, finite
604800-second policy, actual-data/identity/client/SSH acceptance, trust and
rollback. A compatible production resident/client build with exact dependency
and feature receipt, native original master/profile readback and final mutation/
recovery accounting remain open. Its old resident is 294078912 bytes: duplicating
it uncompressed would exceed the 100 MB budget, so verified compressed recovery
is required. No classification exception exempts that backup. There was no
personal installation/adoption, service stop, new identity or native prompt.

### S-PC production graph and recovery-size preparation

On clean T-PC Mere `ae0321429`, both selected production graphs built with the
locked dependencies unchanged. The resident's default `cxf/personal-sync`
runtime graph uses Dramatis family `6b65ea4`; graphshell's `native/webrtc-join`
CLI graph uses `798a1a7`. Each selected normal runtime graph contains one coherent
Dramatis revision and excludes `castellan`, `djinn-custodian`, in-process custody
and passphrase-fd. This is graph/build evidence; installed protocol and personal
receiving acceptance remain separate requirements. O-PC Mere's unrelated dirty
work was left untouched.

The debug resident was about 286 MB; Cargo rustc stripping reduced it to about
154 MB, still unsuitable for this receiving budget. A release-profile resident
build with explicit opt-level 1 and strip=symbols is in progress, using two jobs
in the existing T-PC Mere target and its build directory. Candidate hashes and
exact staging peak accounting remain open; no qualified runtime result is inferred
from these compile checks.

Read-only S-PC gzip level 6 roundtrips matched the original file hashes: resident
56211399 compressed bytes and CLI 4299480, total **60510879 bytes**, before small
vault/catalog/unit/settings recovery records. No archives were retained by that
measurement. Private `s-pc-receiving/mutation-journal-01.json` prepares before hashes,
touched paths, acceptance, retirement and rollback; it is a draft, not a finalized
immutable ceremony receipt. The locked legacy resident and all personal state
remain in place. Protected installation paths/account/drop-ins are still absent.

### macOS signature and Linux identity-location follow-up

Direct `codesign -d --verbose=4` and `codesign --verify --strict` probes checked
the actual installed resident paths from the process/launchd inventory, rather
than a launcher wrapper. Q-PC's 271994944-byte consumer is unsigned, SHA256
`2aaec49c73d2231c1e37f3913ac5f2049b32484694b7b5255e4ad0671eb6bea2`;
both display and verification refused it as unsigned. M4's 279351792-byte consumer,
SHA256 `268f973f3953af2bb29504785828f795d74a49ffd7fa8cf2b4ed957c0dad54f7`,
passes strict integrity verification but has an ad hoc linker signature, no
hardened runtime and no Team ID. Neither qualifies the production signed-client
contract. These were metadata checks only, with no Keychain access or prompts.

Y/R/X were checked under known Djinn/personae/Graphshell application roots,
including declared XDG overrides, with a maximum depth of five and excluded
content/cache trees. Only `/home/markik/.local/share/graphshell/lock.toml` was
found (21 bytes per host); no XDG override was set. Secret contents were not
read. This is bounded location evidence, not proof of identity absence. The
existing-store versus fresh device-vault question remains pending before setup.

Private immutable `testing/dramatis/fleet-policy/remaining-readiness-followup-01.json`
is 2342 bytes, SHA256
`eea0a96af30248358da0db14254f283c52087807706f0a15728bf8828cff8555`.
Its JSON parse, two macOS and three Linux host records were independently checked.
The initial `mac-signature-readiness-01.json` is retained as well. No personal
state, installed service, identity, authority grant or native setting was changed.

### S-PC optimized delivery and explicit receiving budget

The unchanged locked Mere `ae0321429` default production resident built in the
existing T-PC release target with opt-level 1 and strip=symbols. Candidate:
84872960 bytes, SHA256
`821a2888d49c880a95fad41af4ac8d319739fd32e71b81580e6b3d00a33c14a2`.
The source lane reports the selected graph remains free of forbidden custody
host/harness features. Build evidence is private `resident-release-build-01.json`;
it is not installed personal-runtime acceptance.

The reviewed conservative sequence needs 84.873 MB of raw resident staging and
60.6 MB of reserved compressed rollback capacity, approximately 145.473 MB before
compact records. The continuation brief explicitly raises its receiving peak to
160000000 bytes across hosts/controller, limits raw staging to one candidate,
and requires cleanup back below 100000000 bytes. Backups and staging remain in
the count. The final packet must independently account for its whole peak before
copying; no over-cap staging or personal mutation occurred under the old cap.

The first exact-binary synthetic run reached source-master agreement and the
resident's custodian-agent route, then refused CLI use because the synthetic
application settings lacked the required owner grant. Its failed receipt is
preserved as `production-interop-01.json`; no passing result is inferred. A fresh
run must configure the declared synthetic grant, prove successful CLI use, verify
locked refusal, then re-unlock and prove successful use before the custodian-loss
negative so that loss is not confused with the preceding locked state.

### S-PC corrected exact-binary protocol and native checks

`production-interop-02.json` independently parses as seven passing checks:
same synthetic master, production resident uses custodian agent, CLI roster,
CLI vault command, locked-use refusal, successful re-unlocked CLI use immediately
before outage, and custodian-loss refusal without fallback. Namespace exit is
zero; owned fixture state was removed and children reaped. Scope remains an
unprivileged private namespace with a development custodian, not required
confinement, installed personal state or polkit qualification. The corrected
fixture supplies only the exact declared synthetic CLI application grant.

Exact binaries are resident `821a2888d49c880a95fad41af4ac8d319739fd32e71b81580e6b3d00a33c14a2`,
CLI `23c66b92769a4f32b50e3a9e675afccd86fed9fef988c5bffef026128dd1205c`,
custodian `bb0d9c9dc7cfe9c83cdcaf6c34e19b967beb1bb82325b5226fc1b5d315fd4c9f`,
and helper `528e0b25a7e990b2a9bf7fb8080ca6bd9b4a0a4cb1763194186e0bb7128a0715`.
The 1219-byte receipt SHA256 is
`11e3022f23eb8b7971e130c27e9c386773cce42ec3a7da3f90ad2203a5ad5359`;
driver SHA256 `49f410dca16c298116304a54fb5bdebf0af7a79cc7f22efa03a05ef70c2038b5`.
The failed first receipt and original driver remain intact.

S-PC separately passed four exact resident loader/argument/refusal checks and
two CLI loader/argument checks. Their generated deliveries were removed after
marker/hash/no-live-owner checks. Legacy PID 3866 remained active and the original
vault hash remained `5649db6557c12087fde83c66298445e33bdad7eed97e95f5855ee025cad2ffc3`.
Private `resident-native-01.json` is 1977 bytes, SHA256
`c1f1ce64e4a885a36a79bd1bdc2ee8643d63cba3bfb3c093ce03eebe8c47c2bc`;
`client-native-01.json` is 1412 bytes, SHA256
`8824e293f987bae84dfffecf570eb02b73cc1301ca16311a90b29e03c2648355`.
These checks did not start a candidate personal resident or perform custody use.

Known fleet-policy receipt/delivery roots across all eight hosts totaled 184132
bytes with no large retained files (`receipt-budget-inventory-01.json`, 1474 bytes,
SHA256 `a5736bf8edd17c156fcfdb1b875b48d48ea333b4a968b5fb3f13aedf34f180ef`).
Mere's reviewed `ports/mere-resident/install-linux.sh` takes both binaries and
copies them in one receiving invocation. The final serial reserve therefore uses
60600000 bytes recovery, 92382504 resident/CLI package (84872960 + 7509544),
1000000 all-host/controller records and 1000000 secret-source/public-template
staging, total **154982504 bytes**, below the 160000000-byte peak cap by 5017496
bytes. The 33181128-byte custodian and 8646912-byte helper are staged/installed/
removed separately before the pair. This supersedes the preliminary resident-only
staging estimate; no custom decompression installer or product behavior change is
needed. Final receiving must enforce these boundaries. No personal installation
has occurred.

The source lane additionally measured a SHA-matching resident gzip roundtrip of
31677695 bytes. Compressed candidates together with the original recovery would
still total 103279543 bytes before records. Compression alone therefore does
not remove the measured need for the brief-specific receiving cap.

The missing personal owner-application grant remains a separate prerequisite.
Receiving must use the real owner's supported admission surface and the exact
CLI declaration; the fixture's synthetic grant cannot be copied into personal
settings or inferred from sudo/root approval. Original master/profile readback,
protected personal receiving and live remote consent remain unqualified.

Read-only Mere source review further bounds application consent:
`ports/mere-resident/src/applications.rs` grants the reviewed declaration after
`OwnerConsent::decide`, but `peer_identity` returns an identity pin only for a
Windows image. Linux's Unix peer produces no executable identity pin, which the
dialog describes as unpinned. File hashes in this receipt identify tested
artifacts; they do not turn that owner grant into executable-bound admission.
`identity_ui::SystemNativeIdentityUi::confirm_application` requires a graphical
backend. The first ungranted connection is refused while an asynchronous dialog
is requested; success requires a subsequent connection. UI-unavailable attempts
are asked again only after a resident restart. The receiving launcher must name
the actual S-PC desktop/backend and preserve these existing semantics; a terminal
on O-PC and a root custody proof do not provide that application-consent UI.

### S-PC reviewed packet and attended identity-readback entry

The frozen `s-pc-receiving/packet-02.json` is 23555 bytes, SHA256
`8a2afc5940e91b37e14eb82ecd935985194a530e04760d0fe7b0dfc155290217`.
Its independently reviewed `receiving-budget-02.json` includes two-copy protected
transfer windows for custodian/helper and the later resident/CLI pair. Its maximum
remains 154982504 bytes; actual installed product payload is separately enumerated
as 134210544 bytes. Existing stable Cargo products remain build output. Runtime
interop qualifies the differing coherent per-process supplier graphs; the packet
does not require repinning those already-qualified graphs to one common revision.

The foreground `start-s-pc-identity.ps1` SHA256 is
`2da1b6525990fdf46ab3d87275e698b736a4a1e8e1488d35922857b62fe8993b`.
Its remote `identity-step.sh` and `read-personal-status.py` hashes are respectively
`f27a57deda41590224954c4868e650601fd5c43223f41436ec6bf6dbc8516a80`
and `81c15f3d14e8c30380f81293b8cac9cffa553519d3322cd4cca5602ed4108989`.
Independent source review and PowerShell AST check passed. The source lane's
`launcher-preflight-01.json` also records bash syntax and remote hash dispatch
with execution disabled; its SHA256 is
`a160c8157306d9807b27409659483bb7156085e3475ed744d341e8fc6561378d`.

The scripts check the original resident/vault hashes, unlock the existing vault
in the foreground SSH terminal only if locked, and create only a public profile/
master receipt. They neither create a replacement identity nor perform privileged
installation, authority changes or application-grant writes. A public-status probe
was checked on locked S and unlocked T; it is not an S personal-unlock receipt.

The controller opened the unchanged launcher after correcting its own Windows
Terminal title quoting. One matching launcher process was observed; the user was
asked for Enter and any required existing-vault passphrase directly in that
terminal. Native completion remains pending. Private `controller-handoff-01.json`
is 901 bytes, SHA256
`36ef630f0107a054389dc3828182f395f5f3454e25ea3b40ae3fb422945317ff`.
GUI metadata readiness is separately retained in the 731-byte
`graphical-readiness-01.json`, SHA256
`9e6caa90bc4fa2fb554cbeb7959abdfb83bd53423c7ced1cf1a625819172fdb2`.
That snapshot found active local KDE Wayland and kdialog/zenity; it does not prove
execution of the later native application-consent dialog.

The current frozen handoff supersedes packet02 with `packet-03.json` (23972 bytes,
SHA256 `bcd1e48ea5678b301d931d8a439d140702dd4efeb8d4a19ad4ae6185068939eb`)
and `mutation-journal-02.json` (15331 bytes, SHA256
`e8c54c7745f7a7a18e5b0099e9005cbc217c4d3aaf11e272c0eeee12c47958e2`).
`manifest-03.json` is 3374 bytes, SHA256
`86d63cf81566ed9845adc10decdd6cf2798926403a1210927276aca0727574af`.
The fleet lane independently verified all 19 bound files (92050 bytes) and the
three receiving-window sums. Packet02-to03 comparison changes only journal/handoff
references and the final pre-receiving-gate reference; receiving behavior, launcher
and budget bytes are unchanged. Historical inputs remain intact. Budget02 SHA256:
`ecba2d4db63e1d3d4e7a2f3b275538fc3ed77205f592f00b91de28efe17683bc`.
