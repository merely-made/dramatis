# Fleet custody rollout

**Status, 2026-11-05: in progress.** O-PC/T-PC have qualified personal receiving
and root-trust setup. The other six have saved weekly idle settings. Their
personal custodian deployment remains open. The four remaining Linux hosts
have passed the current synthetic native confinement/unlock gate.

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
| O-PC, T-PC | Personal update/unlock and mutual root/device trust qualified | Preserve baseline; live remote-consent execution remains separate |
| S-PC | Running legacy resident; standard vault/data present; native gate passed | First isolated installation, identity-preserving adoption and compatible resident |
| Y-PC, R-PC, X-PC | No running resident/custodian; no standard-path vault/data found; native gate passed | Locate existing identity state before initial resident/custodian setup |
| Q-PC, iMac-M4 | Running legacy macOS residents; standard vault/data present | Exact signed host/consumer integration and personal receiving |

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

## F1. Linux personal receiving, starting with S-PC

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

S-PC has no checked owner application-settings grant for `personae-vault`.
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

Q-PC and iMac-M4 need their actual OS/architecture receiving cohorts. Protected
mode requires the correct hardened-runtime signatures without get-task-allow,
signed/audit-token peer checks, root-owned installation and the owner's GUI
launchd session. Signing-account separation and native Keychain/presence handling
remain the existing macOS host's responsibilities.

The historical Q-PC signed synthetic lifecycle receipt does not authorize a
current personal-root migration or qualify the Apple Silicon host. The generic
installer's `consent: deny` and absent production data-protection integration
must be resolved through the signed host design, not hidden by replacing a binary.

The checked personal Q-PC resident is unsigned. The M4 resident has an ad hoc
linker signature, without hardened runtime or a Team ID. Neither is a compatible
production signed consumer. Prepare the signed host/consumer cohort before
requesting native receiving; a valid ad hoc integrity check is insufficient.

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
155 MB. Stage custody/helper candidates separately and remove their delivery
copies before the single resident/CLI receiving package. Count every staged
file and backup and verify the full peak before copying; do not overlap receiving
packages from different hosts.
After owned delivery cleanup, retain at most **100000000 bytes** of receipts and
rollback artifacts. Preserve existing receipts and personal state; this cap does
not authorize deleting them. Maintained Cargo artifacts stay in their existing
stable build target. Create no isolated target/home/worktree without an actual
collision or reproducibility need.

Stage and qualify everything possible before human interaction. Use target-local
or foreground Enter-triggered launchers. Human readiness is not a short test
deadline; preserve diagnostics and reuse verified state after an expired prompt.
Avoid overlapping password, Hello and administrator dialogs. A native prompt is
an OS input boundary, not a request to repeat authorization already given in chat.

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

## Progress

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
