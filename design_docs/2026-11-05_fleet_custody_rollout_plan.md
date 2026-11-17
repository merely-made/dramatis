# Fleet custody rollout

**Status, 2026-11-14: in progress.** O-PC/T-PC have qualified personal receiving
and root-trust setup. S-PC passed local receiving, cold reopen, outbound SSH and
one live consent from O-PC over SSH. R-PC passed fresh receiving and O-PC consent
pin readback. Y-PC passed the same on Fedora/GNOME under SELinux
enforcing. All eight have saved weekly idle settings. The expanded synthetic
Linux confinement gate passed on S-PC, Y-PC, R-PC and X-PC.

The certificate-bearing agent path subsequently exposed a confined-hostname
syscall failure on S-PC. The [agent continuity receipts](archive_docs/receipts/2026-11-05_fleet_agent_continuity_receipts.md)
record the native failure, synthetic reproduction and expanded qualification.

This is the fleet receiving continuation of custody D3/D4 and VL-U in the
[custody plan](2026-10-28_custody_plan.md). That plan retains authority over
custody mechanisms and platform security requirements. This plan owns the
remaining machine rollout; its [receipts](archive_docs/receipts/2026-11-05_fleet_custody_rollout_plan_receipts.md)
separate inventory, synthetic tests, personal receiving and live approval.
It does not reopen the completed Gemot router-only rehearsal.

## Required behavior and ownership

Apply the user's existing fleet-wide one-week choice: configurable 604800-second
maximum unlocked duration, 10080-minute idle window, and fixed one-week new
device approval grants. Activity, reconnects, duplicate unlock and idempotent
grant delivery must not renew the original deadline. Enable the selected
session-lock/suspend behavior only after compatible finite custody expiry and
native receiving are established on that host. Explicit lock remains available.

Dramatis owns protected custody, delegation/enrollment and expiry enforcement.
Mere owns the installed resident, client integration, settings and native UI.
Use existing Insigne/Notochord/public custody routes; this deployment does not
introduce group/key orchestration or change Gemot's I2P privacy gates.

Retain each machine's original persona, profile, wallet and device keys. Pin
O-PC's existing root on each target through the protected owner configuration.
Direct root authority needs no redundant root-self certificate on every target.
A peer approval grant binds its exact target/profile/actions and original expiry;
its presence on O-PC does not grant that peer approval over every other host.
Additional approval directions must be explicit in the reviewed setup.

## Receiving cohorts

| Machines | Current receiving position | Next required work |
|---|---|---|
| O-PC | Personal update/unlock and mutual root/device trust qualified for tested flows | Preserve baseline; later live remote consent |
| T-PC | On the fleet cohort (e356/c538/23c) with its vault, root pin, persona drop-in and settings preserved; `bin_t` labels | Preserve baseline; later live remote consent |
| S-PC | Original vault/CLI/SSH continuity, cold reopen and live O-PC consent over strict SSH verified | Preserve this baseline and its receipts |
| R-PC | New protected vault, native first unlock, weekly settings and O-PC consent pin verified | Preserve fresh baseline and empty SSH agent until credentials are needed |
| Y-PC | New protected vault, native first unlock through Zenity, weekly settings, `bin_t` custody labels and O-PC consent pin verified | Preserve fresh baseline and empty SSH agent until credentials are needed |
| X-PC | New protected vault, native unlock through Ubuntu's zenity 4.2.1 on Xfce/X11, weekly settings and O-PC consent pin verified | Preserve fresh baseline and empty SSH agent until credentials are needed |
| Q-PC | Signed Intel resident and custodian running; native Keychain, consent, identity continuity and live O-PC Luggage upgrade to `0.0.2` verified | Preserve this baseline; complete temporary-account cleanup after relocating the signing key |
| iMac-M4 | Signed ARM custody and live O-PC Luggage upgrade to `0.0.2` verified; original SSH identity preserved | Finish signing separation: the retained Apple Development key shares the accepted signing team |

Saved idle settings alone do not prove a running service, absolute expiry,
custody isolation, native approval, enrollment or remote-consent execution.
An absent standard-path store does not establish that a device has no identity.

## F0. Inventory and Linux confinement readiness

Read current launchers, actual XDG overrides, service instances, native platform
prerequisites and file presence without opening personal secrets. Include the
templated Linux service and macOS system LaunchAgents, not only generic service
names or the current user's launch-agent directory.

Use the existing `linux_agent_confinement` gate from Dramatis. Its child applies
required Landlock/seccomp, serves the locked agent, and performs a real synthetic
unlock with credential-catalog initialization. It must reproduce storage refusal
when the data-root rule is omitted while allowing the configured positive case;
unrelated sibling reads and configuration writes must remain denied.

**Done when:** each selected Linux OS/architecture explicitly executes the gate
and retains compact pass/fail, kernel, ABI and exact executable/source identity.
Every owned child is reaped. Temporary generated delivery copies are removed
after marker/hash and ownership checks; maintained Cargo artifacts are preserved.
This phase is complete for the four remaining x86_64 Linux hosts. It provides
no personal vault adoption, service or enrollment qualification.
The earlier receipts covered an empty SSH profile. The expanded gate now lists
and signs through a seeded key and its certificate under enforced confinement,
verifies continued custody health and retains the previous negative controls.
It passes on T/S/Y/R/X with the qualified fixture. This is distinct from an
installed personal daemon accepting its real identity and operator policy.

## F1. Linux personal receiving, starting with S-PC

S-PC's first native ceremony reached isolated unlock and weekly trigger reload,
then rolled back at application admission. Later attempts preserved the original
resident and retained the failed refusal. The successful corrected-agent retry
reused the protected account, adopted identity, retained recovery and actual owner
approval. The corrected resident and custodian are active with both custody
sockets enabled. The original profile, vault slots and SSH identities matched.
The initial-install recipe below still applies to unprovisioned hosts.
For the corrected-agent retry, validate the actual prior owner-approved settings
against the unchanged CLI and exact declaration, then restore those bytes before
resident start. Preserve every prior decision snapshot as history. Stage the new
custodian once under root control and atomically rename it into the product on
the same filesystem; remove its delivery inputs before resident/CLI expansion.
Rollback restores the original seven files and legacy resident while keeping a
verified corrected custodian installed but stopped. This is an explicit product
baseline, not a claim that the former custodian executable was restored.

Prepare a reviewable packet before native administration: exact service and
resident binaries, installed-client contract, target/profile/root pins, current
source locations, private backups, expected identity fingerprints, and rollback.
The remote-approval updater assumes an existing working isolated custodian; it
cannot replace the missing first-install/adoption step on these hosts.

S-PC comes first because its legacy resident and standard vault/data are present.
The packet must preserve that identity and retire active embedded custody only
after the separate service and compatible resident have passed receiving. Review
the installer's data-moving behavior; do not invoke it blindly on personal state.
Keep original encrypted state and rollback evidence. Avoid new identities where
an existing one may be elsewhere, especially on Y-PC/R-PC/X-PC.

S-PC's checked data root has a credential catalog and non-custody content but
no `identity/` or `personas/` directory. Prepare vault/catalog-only adoption unless
further location review finds an existing wallet; do not mint one. Keep content
and published sites host-owned. The stock installer activates sockets immediately
and retires data-from originals, so use quiescent copies as its inputs and keep
authoritative originals through actual-data acceptance. Prove the existing
master/profile before initializing remote authority. A production resident/client
binary and exact dependency/feature receipt are separate receiving inputs.

S-PC initially had no checked owner application-settings grant for `personae-vault`.
Obtain the owner's application consent through its supported admission surface
for the exact CLI declaration before using it for personal readback/acceptance.
Preserve that consent across replacement where its identity contract permits.
Application admission is separate from sudo, vault unlock, polkit and root
authorization. A synthetic fixture grant is not a personal application grant.
Current Mere `applications::peer_identity` pins Windows images only; the Linux
grant is unpinned and records the reviewed declaration, not an executable hash.
Record this boundary without adding identity machinery to the receiving slice.
`SystemNativeIdentityUi::confirm_application` requires a graphical backend.
Name the actual target desktop/backend and the initial refusal/dialog/retry
sequence; SSH on O-PC does not relocate S-PC's dialog. Root custody approval
does not yet provide resident application admission across networks.

The protected recipe requires a non-login service account, root-owned config and
client files, private state, and exact configured vault/data-root Landlock grants.
Custody remains without networking, execution or tracing permission. Preserve the
qualified fcntl socket setup and readlink/readlinkat metadata support. File/content
access stays restricted to the configured roots; granting their parent is unnecessary.

**Done when, per host:** native administration and vault unlock succeed; persona,
wallet/device identity and supported operations match the before-state; original
unencrypted secret exposure is accounted for under the custody plan's receiving
requirements; the installed resident uses the isolated custodian without fallback.
Verify finite weekly policy, actual resident hot reload, locked-use refusal and
rollback. Apply session-lock/suspend settings after finite receiving succeeds.
Track service readiness, personal unlock and root enrollment as distinct results.

## F2. Signed macOS personal receiving

Q-PC's Intel cohort is installed and its live Luggage upgrade is verified.
iMac-M4 still needs its Apple Silicon receiving cohort. Protected mode
requires the correct hardened-runtime signatures without get-task-allow,
signed/audit-token peer checks, root-owned installation and the owner's GUI
launchd session. Signing-account separation and native Keychain/presence handling
remain the existing macOS host's responsibilities.

The historical Q-PC signed synthetic lifecycle receipt does not authorize a
current personal-root migration or qualify the Apple Silicon host. The generic
installer's `consent: deny` and absent production data-protection integration
must be resolved through the signed host design, not hidden by replacing a binary.
Both are now source (2026-11-14, D11's work; Findings): a signed consent helper and
a data-protection Keychain envelope behind an installer that writes `consent: channel`.
Q-PC's signed native run and live upgrade receipts are recorded below.
The Apple Silicon native receiving run remains open.

The last inspected M4 resident had an ad hoc linker signature without hardened
runtime or a Team ID. Refresh its installation and prepare the signed
host/consumer cohort before requesting native receiving.

**Done when:** an exact signed host/resident cohort passes the required native
boundaries on that machine; identity-preserving adoption and cold reopen work;
personal wallet/catalog and agent receiving pass; finite weekly settings and
selected triggers are verified. Preserve original keychain/state ownership and
record any remaining native lifecycle or at-rest gap before claiming completion.

## F3. Trust and actual remote consent

After personal receiving, install/read back the existing root pin and only the
required peer grants. Verify replay preserves expiry, wrong target/profile/action
is refused, and revocation and generation changes invalidate cached authority.
Check Hello timeout UI cleanup before a large signing batch; clearing stale
brokers manually is not an automatic cleanup fix.

**Done when:** each selected direction executes an actual native consent petition
through the declared route while preserving requester binding and original vault
deadline. Public enrollment delivery is a separate result from executing consent.
P2P routing and approval-only opening remain explicit gates: current passphrase
backends cannot open a locked vault using a public approval proof alone.

## Receipts and operator interaction

Receiving peak cap: **160000000 bytes across this rollout's repositories and
hosts**. S-PC's installer requires its resident/CLI pair together. The measured
pair, compressed rollback allocation and staging/record reserves require about
155 MB. The four verified public gzip inputs may be staged together. Unpack
custody/helper raw candidates separately and remove their raw/archive delivery
copies before the single resident/CLI receiving package. Count every staged
file and backup and verify the full peak before copying; do not overlap receiving
packages from different hosts.
For S-PC's existing-state resume, custody/helper remain installed. Deliver only
the qualified replacement resident and unchanged CLI. Reallocate the all-host
small-record reserve to 3000000 bytes, including the accumulated failed attempts and
new private resume code/journals;
keep recovery at 60600000 and other transient state at 1000000 bytes. The
verified replacement pair makes the controlling window 156972520 bytes. Stream
compressed delivery without persistent T-PC/controller archives; never retain
an upstream archive copy while S-PC expands the raw pair. This reallocates
headroom within the same peak cap.
After owned delivery cleanup, retain at most **100000000 bytes** of receipts and
rollback artifacts. Preserve existing receipts and personal state; this cap does
not authorize deleting them. Maintained Cargo artifacts stay in their existing
stable build target. Create no isolated target/home/worktree without an actual
collision or reproducibility need.

For the resident/CLI pair, a verified compressed input may be held in a bounded
volatile public-input buffer (at most 80000000 bytes) while its generated archive
is removed before unpacking. Stream raw output with an exact expected size/hash;
release the input buffer before the next executable. Retained disk copies remain
counted. Preserve protected recovery and compact failure diagnostics if extraction
fails after archive removal. Verify execution code into root-private storage
before privileged use. This transport sequence still requires implementation
review and synthetic preflight; the plan does not qualify an untested runner.

Stage and qualify everything possible before human interaction. Use target-local
or foreground Enter-triggered launchers. Human readiness is not a short test
deadline; preserve diagnostics and reuse verified state after an expired prompt.
For S-PC's full receiving ceremony, use one fresh Konsole window on S-PC with
an initial Enter before baseline prompts or source stop. The O-PC dispatcher
verifies inputs/preflight and opens that window; passwords and native dialogs
stay on S-PC, with terminal contents uncaptured.
Avoid overlapping password, Hello and administrator dialogs. A native prompt is
an OS input boundary, not a request to repeat authorization already given in chat.
Preflight the exact shell executable used to launch, including native argument
transport with privileged/unlock execution disabled. Preserve failed launchers
and bind any replacement explicitly; a successful run through PowerShell 7 does
not qualify Windows PowerShell 5's quoting path.

## Decisions

- **fleet_custody_rollout D1 (2026-11-05).** Y-PC's bounded inventory found no
  vault, custodian, resident, custodian account or private SSH key. Asked which
  vault Y-PC should use, Mark chose "Fresh vault": a new local vault at
  `/var/lib/djinn-custodian/markik`, first unlock in a native prompt, an empty
  SSH agent, and activation deferred until the protected profile and O-PC
  consent pin are ready, as on R-PC.
  Links: area receiving · draws on R-PC fresh receiving · summary Y-PC gets a fresh vault
- **fleet_custody_rollout D2 (2026-11-05).** Y-PC runs SELinux enforcing, and
  the default type for `/usr/local/libexec/djinn-*` is `usr_t`. Mark chose
  "Persistent bin_t rule": a `semanage fcontext` rule giving
  `/usr/local/libexec/djinn-.*` the `bin_t` type, `restorecon` over every
  installed path, and a journal/AVC denial check before relying on it. Stock
  types only; no custom policy module. Refined the same day: T-PC's bb0d
  custodian had run as `usr_t` under enforcing since 2026-11-04, so the exec
  failure the question cited does not occur. Asked again, Mark chose "Keep
  rule, fleet-wide": the explicit stock `bin_t` rule is for consistency on
  every SELinux host, T-PC included at its update.
  Links: area platform · plans Fedora receiving · summary label custody binaries bin_t on every SELinux host
- **fleet_custody_rollout D3 (2026-11-05).** On GNOME the resident prompts
  through Zenity, and Mere's only exact-binary confirmation test fakes KDialog.
  Mark chose "Both": run Y-PC's real Zenity 4.2.2 with the exact unlock and
  approval arguments plus a one-second timeout, which must end in the timeout
  exit with no parser error, and add a Zenity variant of Mere's synthetic
  confirmation test.
  Links: area platform · draws on the S-PC KDialog parser failure · summary qualify Zenity both ways before Y-PC's window
- **fleet_custody_rollout D4 (2026-11-05).** Ptyxis has no hold option. Mark
  chose "Driver waits for Enter": the receiver's owner mode ends with a
  close prompt on success or failure, launched as `ptyxis -s --new-window --`.
  Links: area receiving · summary the driver holds Y-PC's window open
- **fleet_custody_rollout D5 (2026-11-05).** T-PC runs custodian bb0d9c9 and
  an unrecorded personal resident build (`9f634052…`, 119714632 bytes) behind a
  persona drop-in. Asked what its update should replace, Mark chose "Custodian
  and resident": move T-PC onto the qualified cohort (e356 custodian, c538
  resident, 23c client), after showing c538 accepts the drop-in's arguments,
  keeping config, protected state, root pin and grants.
  Links: area receiving · draws on S-PC and R-PC cohort qualification · summary T-PC joins the fleet cohort
- **fleet_custody_rollout D6 (2026-11-05).** X-PC (Xubuntu 26.04, Xfce on X11,
  MATE polkit agent) has no zenity, kdialog or yad, so the resident cannot
  prompt. Mark chose "zenity": install it from Ubuntu's archive, then repeat the
  real-dialog timeout check and pin its version before the attended window.
  Links: area platform · draws on D3 · summary X-PC prompts through Ubuntu's zenity
- **fleet_custody_rollout D7 (2026-11-05).** X-PC's bounded inventory was empty.
  Mark chose "Fresh vault", as on R-PC and Y-PC.
  Links: area receiving · draws on D1 · summary X-PC gets a fresh vault
- **fleet_custody_rollout D8 (2026-11-05).** Protected macOS custody requires a
  hardened-runtime signature, and its peer check is `anchor apple generic` plus
  the certificate's Team ID, so ad hoc and self-signed identities cannot pass.
  Asked what identity the Mac cohort signs with, Mark chose "Paid Developer
  ID": an Apple Developer Program team with a Developer ID Application
  certificate, the production path that also allows notarization.
  Links: area platform · plans F2 · summary Mac cohorts sign with a Developer ID team
- **fleet_custody_rollout D9 (2026-11-05).** The Developer ID identity (team
  `HWVZ5S7ACJ`) is in `markik`'s login Keychain on the M4, which is also the
  receiving account, against H1-F1. Asked where signing should happen, Mark
  answered: "consider: delete it afterwards. no lingering test profile. very
  annoying. not my computer; a favor, letting me use it, and you take terrible
  advantage using up the storage and permissions. not respectful". The M4 is
  Mayola's machine on loan: any signing account made there is temporary and
  removed when signing ends, and work there keeps its storage and permissions
  footprint minimal and cleans up after itself.
  Links: area platform · plans F2 · summary temporary signing user on the M4, nothing lingers
- **fleet_custody_rollout D10 (2026-11-05).** Asked whether the Mac binaries
  build from the Linux cohort revisions (Mere 6f542e515, Dramatis 8bc1959 plus
  05183e8) or current mains, Mark answered: "there better be a way to bump the
  fleet at the end of this :<". Mac cohorts build from the Linux cohort
  revisions, and the rollout owes a fleet-wide update path that moves every
  host to a newer qualified cohort, rather than one-off receivers per host.
  Links: area receiving · plans F2 · summary one cohort now, a fleet bump path owed
- **fleet_custody_rollout D11 (2026-11-05).** macOS installs write `consent:
  deny`: no native consent channel (per-use SSH keys refused) and no
  data-protection Keychain envelope in the binary. Mark chose "Wait for consent
  work": the native macOS consent dialog and the envelope are built first, as
  separate Dramatis work, and Q-PC and the M4 are received afterwards.
  Links: area platform · plans F2 · summary Mac receiving waits for consent and envelope

## Findings

- 2026-11-05: the six remaining machines are reachable and selected idle files
  remain 10080 minutes. Only S-PC/Q-PC/iMac-M4 have running residents in this cohort.
- 2026-11-05: no remaining Linux host has the isolated custodian installed under
  the checked instance/regular units; the two Macs lack the personal signed installation.
- 2026-11-05: S/Y/R/X meet the checked systemd/polkit/Landlock prerequisites and
  explicitly pass `agent_and_unlock_run_inside_linux_confinement`. Their personal
  services, identities, configuration and enrollment were not changed by the gate.
- 2026-11-05: direct signature checks of the actual Q-PC/M4 resident paths confirm
  unsigned/ad hoc consumers respectively. No Keychain, signing or runtime changes
  were needed to establish the missing production signed-consumer requirement.
- 2026-11-05: bounded known-application-root inventory on Y/R/X found only the
  weekly Graphshell settings and no XDG overrides or Djinn/personae stores. This
  does not establish exhaustive identity absence; existing-store location versus
  fresh device-vault provisioning remains a user choice before personal setup.
- 2026-11-05: the exact production resident/CLI/custodian combination passes seven
  synthetic protocol checks, including re-unlocked successful use before outage
  refusal. S-PC separately passes native loader/argument checks. These results
  do not qualify installed personal custody, polkit or owner application consent.
- 2026-11-05: S-PC's attended original-identity readback succeeded through the
  original launcher under PowerShell 7. The source profile/master were verified;
  the original vault bytes and running legacy service remained unchanged. A
  separate Windows PowerShell 5 quoting failure was reproduced and repaired in
  a new launcher, whose safe dispatch and wrong-hash refusal both pass.
- 2026-11-05: initial receiving-driver review found incomplete rollback shutdown
  verification, source-inventory coverage, actual catalog acceptance and weekly
  trigger application. These existing receiving requirements must be qualified
  in the executable ceremony before native installation; public status alone
  does not prove credential-catalog use.
- 2026-11-05: a bounded synthetic run of the unchanged exact production binaries
  preserved identity/personas absence in custody, resident and XDG data roots
  before startup, after default startup and after the tested CLI/lifecycle sequence.
  This closes the pre-personal no-wallet prerequisite for that sequence; native
  personal acceptance and the revised receiving-driver qualification remain open.
- 2026-11-05: final executable review and nineteen synthetic helper-safety checks
  qualify the S-PC receiving driver for the native handoff. Explicit root-start
  indication prevents ambiguous double restoration across the privilege boundary.
  Exact PS5 noninteractive dispatch/read-only S preflight also pass. These are
  execution prerequisites; personal installation results remain separate.
- 2026-11-05: S-PC's native attempt reached isolated custody, original-master
  readback and selected trigger hot reload, then failed application admission.
  A KDialog parser error was converted into a remembered false answer. Rollback
  restored the original seven-file baseline and active resident while disabling
  the new custodian/sockets. Mere owns the checked-confirmation repair; S-PC now
  needs a reviewed resume against existing protected state.
- 2026-11-05: Y-PC's metadata-only inventory found Fedora 45 Workstation with
  glibc 2.44, an active local GNOME Shell 51.1 Wayland session (gnome-shell is
  the polkit agent; no `plasma-polkit-agent.service`), Ptyxis 50.1, Zenity 4.2.2,
  polkit 127, `gcr-ssh-agent` as the session agent, and SELinux enforcing. A
  name search of home, `/var/lib`, `/etc`, `/opt` and `/srv` to depth six found
  no vault, custody or persona artefacts, and `~/.ssh` holds only
  `authorized_keys`. Default labels: `usr_t` for `/usr/local/libexec`,
  `var_lib_t`, `etc_t` and `var_run_t` for state, config and run paths. The
  R-PC receiver's KDE agent check and terminal do not carry over unchanged.
- 2026-11-14 (D11 work; choices made where the plans left them open, for Mark to
  confirm or overturn): **Consent channel.** macOS mirrors the Windows contract, not
  Linux's resident dialogs: Zenity (D3, D6) is Mere's resident prompt, while the Linux
  custodian's own consent is polkit `auth_self`. The macOS equivalent of `auth_self` and
  Windows Hello is LocalAuthentication's `deviceOwnerAuthentication` (Touch ID, else the
  account password), asked by `djinn-custodian consent`, a launchd agent signed as
  `com.merely.djinn.custodian.consent` and admitted as the channel by that code
  signature (`consent: channel`, helper holds a status grant only). No message box is
  consent (custody plan, constraint on presence). Djinn's grants use the Linux values:
  once per generation, a guest delegation per signature. Source:
  `crates/djinn-custodian/src/platform/macos/consent.rs`, `src/helper.rs`; executed:
  the signature-matched helper over real sockets decides, its requester and a plain
  process of the owner cannot (`helper::tests`); the query `canEvaluatePolicy` is true
  on this M4 without showing a prompt. Not executed: a dialog answered by a person.
- 2026-11-14: **Envelope.** The seam is the one Windows already uses: Castellan's
  `AutoUnlockRootProvider` (new, `custody/auto_unlock_provider.rs`) replaces DPAPI's
  wrapped file with a root kept by the host process. The signed custodian installs a
  data-protection Keychain item under its own access group (`WhenUnlockedThisDeviceOnly`,
  not synchronized); the root file beside the wallet names the backend and item and
  holds no secret. The wallet's identity seed, and through it every record sealed under
  the seed, is sealed under that root: a legacy raw seed becomes a sealed record at
  `adopt` (test: `tests/envelope.rs`, no raw bytes left, no raw fallback without the
  provider, a lost item is a refusal and mints nothing). The vault stays passphrase-
  sealed, as on Linux. Protected macOS mode refuses to start without the envelope, and
  the envelope opens only from the root-owned installation (configuration, executable and
  every ancestor root's, unwritable by others), because any process of the user can run the
  signed binary and a caller-chosen configuration would read the wallet back. A bundle with
  the restricted `keychain-access-groups` entitlement and no provisioning profile is
  killed at launch (exit 137, observed here with an ad hoc signature), so the profile is a
  hard prerequisite, not an option. Not executed: the native Keychain item, which needs
  that profile.
- 2026-11-14: the M4's legacy resident (ad hoc, pid 50314) is locked with `vault.json`
  present and no wallet: its data root `~/.local/share/graphshell/data` holds a credential
  catalog (one profile `default`) and no `identity/`, so adoption is vault and catalog
  only, as on S-PC. SSH fails because that locked resident's agent holds no identities.
- 2026-11-14: macOS launch constraints found while building the installer. A
  `/Library/LaunchAgents` plist loads in every user's session, so the helper reads the
  clients file for its own uid and a session with none (Mayola's) exits successfully and is
  not restarted; the custodian plist still tries to bind markik's socket paths in other
  sessions and fails there, as it always did. `sudo -u` is no Keychain context, so the
  installer moves no data and prints the `adopt` command for the owner's own session.
- 2026-11-14 (D10): the receiving custodian is built from 05183e8 with the new work applied
  (its tracked `Cargo.lock`), not from main: 116 custodian lib tests, 311 castellan tests
  and the envelope test pass there. Main passes 118 custodian and 302 castellan tests
  (the tracked lock was dropped after 05183e8; no resolved-version note exists for it).

## Progress

- 2026-11-16 (D11): Q-PC built the Intel custodian candidate from
  `6f9c718` and passed 118 library tests, six process tests and the Keychain
  envelope fixture. A native Luggage test published and installed a signed
  fixture by its manifest digest. Q-PC has a Developer ID identity. The
  locally available provisioning profile names the earlier synthetic App ID,
  and the signing script rejected it before assembling a production bundle.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-preflight-01.json`.

- 2026-11-16 (D11): Apple issued the Developer ID profile for
  `com.merely.djinn.custodian`. Q-PC decoded it and matched the profile's
  certificate to the signing identity in the intended receiving account's
  login Keychain. Q-PC also built and staged the Intel Djinn consumer from
  `6f542e515`. Production signing and personal adoption are pending a signing
  location outside the receiving account. The live Mac installer and SSH
  enrollment have yet to be qualified.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-signing-preflight-01.json`.

- 2026-11-16 (D11): Moved Q-PC's matching Developer ID signing key to a
  separate standard local login. A test binary signed there satisfied the
  Apple anchor and exact certificate requirement. The receiving login retained
  the public certificate and reported zero valid code-signing identities after
  the source private key was removed. Both temporary transfer copies were
  cleaned up. Production signing and live receiving are pending.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-signing-key-move-01.json`.

- 2026-11-16 (D11): Signed and verified Q-PC's Intel custody bundle, consent
  helper and Djinn resident in `djinn-signing`. The package includes the
  production provisioning profile. Q-PC's protected installation and live
  receiving are pending. After the rollout, remove the `djinnh1` test login
  and the temporary `djinn-signing` login from Q-PC. Before removing the
  signing login, verify that its Developer ID key works from its long-term
  signing location outside the receiving login.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-signed-cohort-01.json`.

- 2026-11-16 (D11): Installed Q-PC's signed Intel cohort under `/Library`.
  Rechecked the installed signatures and hashes as `markik`. The installed
  custodian stored, read back and removed a throwaway Keychain item in the
  owner's GUI session. Signing's restrictive file modes had been preserved by
  the installer. Repaired the live bundle modes and fixed the installer to
  make signed bundles readable and executable while retaining root ownership.
  The legacy Djinn process stayed up. The new LaunchAgents are installed and
  disabled until personal vault adoption and service cutover.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-installed-cohort-01.json`.

- 2026-11-16 (D11): Adopted Q-PC's passphrase vault and verified that it
  reopens to the original identity. Copied the two credential catalog files
  and verified their bytes. The signed Djinn trial unlocked the adopted
  vault, and the protected SSH agent advertised the same fingerprint as the
  legacy agent. The consent helper's Unix connector omitted the configured
  server signing identity, so the first-party status check failed before
  cutover. Fixed the connector, rebuilt the Intel helper, and passed six
  helper tests. Re-signing and an attended, rerunnable consent check remain
  before switching the running resident. The legacy launch file is backed up.

- 2026-11-17 (D11): Signed and installed Q-PC's repaired consent helper.
  Subsequent signed Djinn trials failed before consent because a launchd
  socket could still identify its peer as PID 1 at connect time. Six native
  observations found three connections that first reported PID 1 and then
  the expected custodian on the same connection. Added a bounded wait for the
  expected signature before the custody hello. Ten native `custody-wire`
  tests passed, including the unexpected-server refusal. Cutover is waiting
  for rebuilt signed clients and the attended live consent check. The legacy
  resident is still running.

- 2026-11-17 (D11): Rebuilt Q-PC's Intel consent helper and Djinn resident
  with the launchd peer handoff repair. The resident's lockfile changed
  only the custody-wire source to the patched copy of its existing revision.
  Both unsigned binaries were checked and staged for the same signing
  session. Live consent and the cutover are pending.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-handoff-build-01.json`.

- 2026-11-17 (D11): Signed and installed Q-PC's rebuilt consent helper and
  Djinn resident. The attended live check passed and Q-PC switched to the
  signed resident. A later readback found the same resident PID ready and
  unlocked, both installed hashes matched, and the existing SSH agent
  socket path served the same identity through the custodian. The original
  vault, catalog and launch file are retained for rollback.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-cutover-01.json`.

- 2026-11-17 (D11): Built the macOS Luggage adapter and restricted SSH
  enrollment. Q-PC verified the installed `0.0.1` bundle and its running
  launchd peer. Four native fixture tests passed, including atomic exchange,
  rollback on failed restart, and refusal of replays and invalid packages.
  Q-PC's effective SSH configuration passed in a temporary copy. The live
  enrollment and Developer ID signing of `0.0.2` await the owner.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/q-pc-luggage-preflight-01.json`.

- 2026-11-17 (D11): Enrolled Q-PC's restricted `_djinnupdates` service and
  published the signed Intel `0.0.2` bundle from O-PC. Luggage installed it
  and the new custodian, helper and resident launchd jobs stayed up. After
  the owner's unlock, Djinn reported ready and the preexisting SSH socket
  advertised the original fingerprint. The ordinary SSH key, an altered
  manifest and an install replay were refused. Fixed the adapter's root
  profile check to verify CMS using public system trust roots, and corrected
  the macOS service account setup. Five native adapter tests passed and a
  modified provisioning-profile payload failed signature verification.
  Receipt: `testing/dramatis/fleet-policy/luggage-q-pc/live-publish-upgrade-01.json`.

- 2026-11-17 (D11): Reached iMac-M4 at its newly supplied mesh address
  `192.168.4.28` with the existing host key. Its legacy resident is running
  and locked under `markik`, UID 502. Built the repaired arm64 custodian and
  Luggage receiver on Q-PC and launched both on the M4. Five native updater
  tests passed on the M4. The arm64 resident also built on Q-PC and returned
  its normal help output on the M4. Its receiving
  login holds a different Developer ID identity, so signing separation
  needs the owner's chosen key-transfer route before personal receiving.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-preflight-02.json`.

- 2026-11-17 (D11): The owner authorized moving the M4's specific Developer
  ID key to Q-PC's existing `djinn-signing` login. The attended M4 export
  Terminal is open at its Return gate. Import, exact-certificate signing
  proof and source-key removal are prepared with retries. Source removal
  remains conditional on a verified signature in the destination login.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-signing-key-transfer-01.json`.

- 2026-11-17 (D11): The first M4 export returned a Keychain authorization
  error before showing the transfer-password dialog. No encrypted transfer
  file was created. Opened a retry command that explicitly unlocks the named
  `markik` login Keychain using hidden Terminal input before the exact-identity
  export. The native unlock command is waiting for the owner; the repaired
  export, destination signature and source-key removal remain unverified.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-signing-export-repair-01.json`.

- 2026-11-17 (D11): The explicit M4 Keychain unlock and exact-identity
  export succeeded. Copied the encrypted 3264-byte transfer directly to
  Q-PC through O-PC, verified matching digests and mode 0600, and opened
  Q-PC's native administrator Terminal. The destination signing proof
  and M4 source-key removal remain pending.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-signing-export-accepted-01.json`.

- 2026-11-17 (D11): Verified the imported M4 Developer ID with an exact-
  certificate signature in Q-PC's existing signing login, then removed the
  M4 private-key copy. The unrelated Apple Development identity and public
  Developer ID certificate remain on the M4. Both encrypted transfer files
  and root handoff staging were removed. Q-PC's signing login still has
  neither administrator nor SSH membership.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-signing-key-move-01.json`.

- 2026-11-17 (D11): Q-PC signed the ARM installation cohort and `0.0.2`
  update with the production profile's existing Developer ID. Streamed the
  installation directly to M4, verified its complete digest, bounded exact
  archive entries, native architecture, signatures, timestamps and Keychain
  claims. Removed 111454843 bytes of verified duplicate unsigned delivery
  inputs after signing. Opened M4's native administrator installation step;
  the legacy service, vault adoption and Luggage cutover remain separate.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-signed-cohort-01.json`.

- 2026-11-17 (D11): M4's signed root installation and native Keychain
  envelope round trip passed. Adopted its existing vault to the same master
  and copied both credential catalog files, retaining the originals. The
  attended protected trial and service cutover passed with the original SSH
  fingerprint and old socket path preserved. The signed resident now runs
  as PID 63064. Removed the verified installation delivery copies from both
  hosts after installed-binary readback. Restricted Luggage enrollment is
  prepared and its native administrator Terminal is open.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-cutover-01.json`.

- 2026-11-17 (D10/D11): M4's restricted update service enrolled as hidden
  UID 450. O-PC published the signed ARM release and installed `0.0.2`.
  The ordinary SSH key, an altered manifest and an install replay were
  refused; the invalid publication left the feed empty. The restarted
  resident is ready and unlocked, and the original SSH identity matches.
  Removed duplicate receiver/archive delivery copies after acceptance.
  Receipt: `testing/dramatis/fleet-policy/luggage-m4/live-publish-upgrade-01.json`.

- 2026-11-17 (D11): Corrected a signing-separation oversight. The retained
  Apple Development certificate is a different identity but its subject OU
  is also `HWVZ5S7ACJ`. The installed custody principals match that team and
  app identifiers, so this remaining authority is not excluded. Functional
  receiving and the signed update passed; full H1 signing separation is
  still open. Asked the owner to move this second key into Q-PC's existing
  signing login, or retain it and add certificate-specific peer checks.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-remaining-signing-authority-01.json`.

- 2026-11-17 (D11): The owner asked what the second key is for before
  authorizing a move. Inspection confirmed that it signed Xcode's existing
  `PersonalHopspot.app` build and is referenced by the Retinue pocket NFC
  probe and wildcard iOS provisioning profiles. Moving it would relocate
  future development signing. Revised the recommendation to retain this
  development key and narrow Djinn's accepted signing certificates. The
  second key remains untouched; full signing separation is still open.
  Receipt: `testing/dramatis/fleet-policy/mac-receiving/m4-development-key-usage-01.json`.

- 2026-11-17 (D11): The owner chose to retain the M4 development key for
  Xcode work, including Woodshed and Redshank, and pin Djinn to the specific
  release certificate. Implemented observed leaf-certificate facts in
  Armillary `peer-facts` 0.0.3, both custody admission checks, protected-policy
  pin validation and the coordinated app/helper/resident/policy/adapter
  migration with rollback. Windows tests passed (9 wire, 112 custodian),
  native Intel tests passed (11 wire, 119 custodian), and the native peer
  tests passed on Intel and ARM (5 each). The native adapter and cohort
  transaction suites passed (6 each). Both architecture release builds are
  ready for attended signing; installation and same-team development-key
  negative controls remain pending. Existing 0.0.2 runtimes remain installed.
  This qualifies connection identity only: provisioned Keychain access groups
  are a separate authority, so full H1 isolation is not claimed from these pins.
  Lane: `testing/dramatis/fleet-policy/mac-receiving/certificate-pin-lane-01.json`.

- 2026-11-16 (D10): Y-PC and R-PC enrolled with empty protected feeds. O-PC
  published the same signed release and installed custodian `0.0.2) on both.
  Both hosts refused the ordinary SSH key and an install replay. O-PC
  verified the replacement binaries and each host's existing relay authority
  and identity. Both vaults reported locked after restart. X-PC remained
  unreachable during the rollout.
  Receipts: `testing/dramatis/fleet-policy/luggage-linux-fleet/y-pc-live-publish-upgrade-01.json`
  and `testing/dramatis/fleet-policy/luggage-linux-fleet/r-pc-live-publish-upgrade-01.json`.

- 2026-11-16 (D10): T-PC migrated its digest-only SSH receiver to the
  publish-and-install receiver qualified on S-PC. O-PC verified the signed
  upload reaches the current-version check and the ordinary SSH key is
  refused. The same custodian process continued running `0.0.2`.
  Receipt: `testing/dramatis/fleet-policy/luggage-linux-fleet/t-pc-receiver-migration-01.json`.

- 2026-11-16 (D10): S-PC enrolled with an empty protected feed. O-PC used
  the dedicated SSH update key to publish the signed bundle and then install
  custodian `0.0.2` by its manifest digest. S-PC rejected the ordinary SSH
  key, an invalid manifest signature, and an install replay. The invalid
  upload left the feed empty. O-PC read back the new binary and the existing
  relay authority and identity. The vault was locked after restart.
  Receipt: `testing/dramatis/fleet-policy/luggage-s-pc/live-publish-upgrade-01.json`.

- 2026-11-16 (D10): T-PC accepted a live O-PC request through the dedicated
  Djinn SSH update key and the restricted `djinn-updates` account. Luggage
  verified the fleet publisher's signed release and the Linux adapter
  started custodian `0.0.2`. O-PC read back the new binary and the existing
  relay authority and identity. The ordinary SSH key, a different manifest
  digest and a replay were refused. The vault was locked after restart.
  Receipt: `testing/dramatis/fleet-policy/luggage-t-pc/live-upgrade-01.json`.

- 2026-11-05: completed remaining-fleet inventory and F0 Linux native qualification;
  retained compact results and removed only owned generated delivery executables.
  F1 personal installation/adoption and F2/F3 qualification remain open.
- 2026-11-05: prepared S-PC's read-only receiving review packet. Production
  resident/client hashes and feature/dependency qualification, attended original
  master/profile readback, exact mutation journal and bounded recovery sizing
  remain prerequisites for a runnable ceremony. Personal state is unchanged.
- 2026-11-05: selected production resident/client graphs compile with coherent
  per-process Dramatis dependencies and isolated-custody features. Release delivery
  sizing and the final runtime/rollback packet remain open; the measured compressed
  originals require about 60.5 MB. No personal installation or prompt occurred.
- 2026-11-05: the optimized production resident built successfully. Its candidate
  plus measured rollback allocation requires a brief-specific 160 MB receiving
  peak cap, serial packages and cleanup back below 100 MB. Exact runtime interop,
  final peak accounting and personal receiving remain open.
- 2026-11-05: corrected exact-binary protocol interop passed seven checks; S-PC's
  resident/CLI native checks also passed and delivery copies were removed. The
  reviewed serial receiving reserve fits the explicit cap. Final runnable packet,
  original-master readback, owner application consent and personal receiving remain.
- 2026-11-05: reviewed the frozen S-PC receiving packet and complete staging
  windows. The Enter-triggered original-identity readback launcher is prepared,
  preflighted and running on O-PC for native input. Source readback and personal
  installation have not yet been accepted; their receipts remain separate.
- 2026-11-05: accepted S-PC's original public-identity readback after independent
  live verification. Recorded exact successful-shell attribution and the repaired
  PS5 dispatch. Quiescent recovery and native personal installation remain open;
  the auth-controls chat owns the single foreground handoff.
- 2026-11-05: accepted final receiver/dispatcher source review and qualification;
  preserved immutable controller copies. The auth-controls chat may open the one
  paused S-PC terminal under the existing rollout authorization. Its native
  recovery/adoption/acceptance, cold reopen, fresh SSH and root-trust results
  remain individually recorded gates.
- 2026-11-05: dispatched one independent S-PC Konsole and verified its initial
  Enter gate from unit/process/TTY metadata. At dispatch, the original resident
  and vault were unchanged and receiving/root-start state was absent. Native
  interaction continues in the auth-controls chat, with no competing prompt here.
- 2026-11-05: retained the failed native attempt and public rollback diagnostic.
  Original bytes/metadata/inventory, public identity and unlocked legacy resident
  were verified afterward. Prepared read-only resume inventory; new receiving,
  owner admission and root trust remain pending while Mere's UI repair is qualified.
- 2026-11-05: Mere's checked-confirmation fix passed Linux/Windows source tests
  and required hooks. The clean production replacement passed ten exact-binary
  interoperability/no-wallet checks and was streamed to S-PC within the cap.
  Final resume source/helper review, twelve safety checks and actual PS5
  read-only preflight pass. Native personal acceptance remains open.
- 2026-11-05: opened the single reviewed S-PC resume Konsole and verified the
  initial Enter gate from unit/process/TTY metadata. Original resident remained
  active and owner/root resume state was absent at that snapshot. One native
  readiness/completion handoff is pending in the fleet chat.
- 2026-11-05: the resume passed existing protected-state validation and installed
  hash checks, then rolled back before corrected-resident startup. The added
  loader check wrongly required exit zero for Djinn help, which intentionally
  exits two. All seven originals were verified after restoration; the receiving
  check is being repaired against the exact unchanged binary's measured contract.
- 2026-11-05: corrected the receiving check to require the measured exact exit,
  stdout/stderr lengths and digests. Its real-binary gate passes ten cases and
  fourteen recovery safety cases pass. A distinct resume-loader attempt preserves
  both failed runs and reports a fixed public failure stage. Restaging and actual
  PS5 read-only preflight pass; native acceptance is still pending.
- 2026-11-05: the next native attempt passed vault/CLI admission and original slot
  comparison, then the confined SSH agent crashed during hostname discovery for
  its certificate. Originals were verified after rollback. A seeded synthetic
  regression reproduces it; read-only uname fixes that gate on T-PC while retaining
  confinement denials. Corrected binary and expanded fleet/native receiving remain.
- 2026-11-05: the expanded certificate/signing gate passes on S/Y/R/X; all
  fixture process groups quiesced and generated copies were removed. Corrected
  normal custodian e356 passed ten isolated interoperability/no-wallet checks.
  Reviewed atomic single-copy receiving and actual approved-grant reuse; the
  new native updater remains to be qualified before its human handoff.
- 2026-11-05: frozen v3 receiving source passes ten replacement/grant checks and
  twelve manifest/loader checks; unchanged normal binaries qualify actual approval
  serialization under S-PC's measured umask. All three exact inputs are staged
  within the 156972520-byte peak. Actual PS5 VerifyOnly and wrong-manifest refusal
  pass. One paused native handoff is authorized; personal acceptance remains open
  and the preserved actual application approval will be reused.
- 2026-11-05: S-PC passed native local receiving and reused the prior actual grant.
  The installed weekly policy and original SSH identity were verified. Corrected
  the old agent socket in the four existing SSH aliases and confirmed fresh
  outbound authentication to O-PC, T-PC, iMac-M4 and Q-PC through those aliases.
  Cold reopen, O-PC root setup and live remote consent remain distinct checks.
- 2026-11-05: the S-PC cold reopen and consent-only O-PC pin passed exact-binary
  synthetic and guarded config replacement checks. The reviewed config-only
  follow-up is open at Enter on S-PC. Personal restart and readback are pending.
- 2026-11-05: S-PC passed native cold reopen and preserved its encrypted vault,
  application approval and original identity. O-PC verified the consent pin and
  empty peer ledger over strict SSH. All four S-PC outbound aliases still work
  after restart. Actual remote consent execution remains a separate gate.
- 2026-11-05: the live O-PC to S-PC pilot passed for one per-operation signing
  request. S-PC verified the signature locally, O-PC received the public Done
  acknowledgment and the target authentication helper exited. The installed
  resident stayed active, and the consent pin and generation matched afterward.
  R-PC is next after confirming its vault source.
- 2026-11-05: the owner chose a new R-PC vault. The exact four Linux binaries
  passed loader checks there. The isolated fresh bootstrap and duplicate-init
  checks passed, the compact packet fits both storage caps, and actual PS5
  VerifyOnly passed. The owner started one native R-PC window.
- 2026-11-05: R-PC passed native first unlock with the new local master and
  owner-approved vault client. Both custody sockets and the resident are enabled.
  O-PC verified the consent pin and one-week grant cap over SSH. The fresh agent
  has an empty identity list and the delivery inputs were consumed.
- 2026-11-05: Y-PC's read-only inventory came up empty. The owner chose a fresh
  vault (D1) and a persistent `bin_t` rule for the custody binaries (D2). The
  Fedora/GNOME receiver, donor hash recheck and inert qualification are next.
- 2026-11-05: Zenity qualified both ways (D3; Mere `5e950a51b`). The Y-PC
  receiver adds the GNOME agent check, the D2 label stage, AVC checks and the
  D4 close prompt. Products, fresh-init fixture and packet are staged inert;
  PS5 VerifyOnly passes. The single attended Y-PC window awaits sign-off.
- 2026-11-05: Y-PC passed native first unlock with the new local master and the
  owner-approved vault client through Zenity. Custody executables carry `bin_t`
  and no AVC records appeared during the run. Both custody sockets and the
  resident are enabled. O-PC verified the consent pin, one-week grant cap and
  receipt instance over SSH. The agent is empty and the payloads were consumed.
- 2026-11-05: prepared T-PC's cohort update under D5. A dedicated updater keeps
  config, protected state, root pin, unit, persona drop-in, weekly settings and
  owner settings, swaps e356/c538 in atomically, adds the 23c client, applies
  the D2 rule and keeps xz rollback copies of bb0d and 9f63. Nine sandbox helper
  checks and PS5 VerifyOnly pass. The attended T-PC window awaits sign-off.
- 2026-11-05: T-PC run 01 rolled back cleanly on a false positive in the
  updater's identity check (live Knot sync writes under `personas/`). Run 02
  passed: T-PC now runs e356/c538/23c with its vault, O-PC consent pin, persona
  drop-in, weekly settings and owner settings preserved, and O-PC read the
  state back over SSH. X-PC and the Macs remain.
- 2026-11-05: X-PC's inventory came up empty and it had no dialog backend. With
  zenity 4.2.1 installed (D6) and qualified, its fresh-vault packet (D7) is
  staged inert and PS5 VerifyOnly passes. The attended window awaits sign-off.
- 2026-11-05: X-PC run 01 failed its single post-unlock read on a 3.9 GB host
  and rolled back, keeping the new vault. Run 02 waited for the unlock and
  resumed from that state; O-PC read the consent pin back over SSH. All five
  Linux hosts now run the e356/c538/23c cohort beside O-PC's Windows custody;
  Q-PC and iMac-M4 remain.
- 2026-11-05: inventoried Q-PC and the M4 read-only (M4 now reached at
  192.168.4.50) and listed the M4's code-signing identities. Mac receiving
  waits for the macOS consent channel and envelope (D11); the M4 is a loaned
  machine whose footprint is being measured for cleanup (D9).
- 2026-11-14: built D11's work in Dramatis (`6db13d1` to `6f9c718`): the macOS consent helper, the
  data-protection Keychain envelope behind Castellan's new root-provider seam, a
  rewritten `install-macos.sh` and `build-macos.sh`. Source and synthetic tests pass; no
  native Keychain or dialog run yet. F2's signed receiving, adoption and consent runs
  follow on the M4 (Q-PC the same way); their steps and receipts are in the receipt file.
