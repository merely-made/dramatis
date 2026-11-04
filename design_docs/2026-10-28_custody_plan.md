# Custody: isolation, the vault lock's open work and the parked Secret Service design

**Status:** 2026-10-28: cut from `2026-10-21_custody_isolation_and_security_hardening_plan.md`, `2026-10-05_vault_lock_plan.md` and
`2026-10-08_secret_service_plan.md`, with lane L4 of `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-20_ownership_repair_plan.md` and the resident's custody tiers from
`2026-08-20_device_resident_consolidation_plan.md`, archived in `repos/mere/design_docs/archive_docs/2026-10-28/`. H1 and H2 of custody isolation are
on main: `djinn-custodian` is a separate process behind one authenticated contract (`custody-wire`) with Linux, macOS and
Windows launchers, it holds Castellan's resident host, the wallet, the credential catalog and the SSH agent, and a
production Djinn links no castellan. C04 and C07 are repaired. Gated: Hocket adoption is stopped; no deployment installs a
custodian for daily use until the Linux and signed-macOS receiving runs (wallet at-rest check included) pass, and the
Windows o-pc run is the Windows qualification. The vault lock's L1 to L4 landed; deployment is Mark's step. Open: H1 to H4
remainders, the closing of ruling 44, ruling 91, the Q040 to Q052 repairs, lane L4, and the Secret
Service, parked by SS8.

**Ownership, 2026-11-03:** this plan follows `crates/djinn-custodian` and
`crates/custody-wire` into Dramatis (dramatis_repo D14). Mere retains resident
composition and client integration. Historical sources and receipts retain
their Mere paths. Repository extraction does not qualify deployment on a new OS.
The wallet store and station-grant policy are now Sporran's.

**Update, 2026-11-04:** the one-week policy applies fleet-wide to all already
authorized work. The custodian's configurable absolute unlocked lifetime is
implemented and tested. The portable root/device enrollment and remote-approval
proof gate is implemented; fleet deployment, settings UI and remote approval's
execution/network/backend integration remain open. Platform receiving is separate.

**For:** making the custodian the only production owner of Castellan custody and proving it with enforcement evidence, and
finishing what the lock left. Opened by Mark's request of 2026-10-21 for a security-boundary audit beginning with custody
isolation, his 2026-10-26 ruling that custody isolation is live work and a macOS-only approach is insufficient, and the
lock's origin (2026-10-04, finding that the vault never locks: "we need to be able to lock the vault lmao. Otherwise it's
just a big room").
Not here:
- extraction, receiving cohorts and observation and action gates: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_family_promotion_plan.md`; the pairing
  ceremony, SSH host certificates and the resident's Linux launcher (the rules here must compose with them):
  `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_device_pairing_plan.md`; the Djinn update resident: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_family_update_resident_plan.md`; the
  publication service a confined worker serves: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_site_publication_plan.md`;
- the dramatis repo plan's work (facade, D5, the keeper feature split, PAKE and QR chrome, copy-mode export, sibling repins),
  the chatelaine CXF plan's P4 import and V4 item types, and the pinned threat statement and tier architecture (owning-repo
  follow-up, no competing copy here); the public client `repos/mere/design_docs/dramatis_docs/implementation_strategy/2026-10-11_dramatis_app_plan.md`;
- ownership-repair lanes L1 to L3, L5 and L6 and the audit routing: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_graph_semantics_plan.md` (L1) and
  `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_source_audit_repairs_plan.md`; inference lock behaviour: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_resident_inference_plan.md`.

Receipts from this plan's runs go to `archive_docs/<date>/`, never into this
plan (DOC_POLICY §8). Evidence that matters is a test in the repository or a
line in Findings.

## Constraints

- **Evidence classes.** Every claim is source-confirmed, executed (a retained synthetic diagnostic) or needs testing;
  reproducing unsafe behaviour is not a passing gate. Source review, ordinary suites and this plan alone do not justify
  calling the product hardened; software tests are not physical-sleep, debugger-resistance or power-loss evidence.
  Source: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:25-35,864-878`.
- **The custodian is the only production owner of Castellan custody**, with no new repo or second store. Vault, wallet and
  credential formats and derivation identities survive; each direct opening has one replacement path and no in-process
  fallback when IPC fails. Authentication, operation permission and human consent are three separate decisions; custody
  verifies principal facts itself, never a forwarded app name. Custody keeps vault bootstrap, wallet, credential and
  freshness keys, root operations, SSH policy and native authentication and consent; rendering, model execution, sync
  protocols and document processing stay outside; no general network listener, shell command or arbitrary file-reading API
  in custody. Source: same file `:305-352`.
- **Two separate enforcement controls.** Worker confinement keeps a compromised parser, compute or ingress worker from vault
  or blob-root files and other processes. Custodian protection keeps an unrelated, unsandboxed desktop-account application
  from the storage key, unlocked memory or a substituted launch. A missing mechanism fails activation of the protected
  mode and never selects an unconfined sibling or weaker sealing. Defaults: macOS App Sandbox XPC workers and a launchd
  LaunchAgent in an administrator-owned signed bundle (macOS 14 or later) sealing files under a data-protection Keychain
  envelope with the custodian's own access group; Linux Landlock ABI 6 or newer, seccomp and `no_new_privs` in a launcher,
  and a systemd system service under a dedicated non-login UID with state outside the desktop home; Windows AppContainer
  workers, and an SCM service under a virtual service account with a CNG wrapping key restricted to it. TPM enrollment and
  Secure Enclave backing are separate optional decisions, not completed work. Source: same file `:354-416`.
- **Signing-authority gate (H1-F1).** A protected deployment separates signing and custody-runtime accounts or devices, and
  the receiving account cannot use the signing key unattended to authorize replacement code; a developer account that
  keeps that authority is a development mode and cannot pass H1. Source: same file `:418-435`.
- **Launch, principal and storage rules.** Djinn connects to custody and never spawns it, chooses its executable,
  configuration or key location, supplies its environment or inherits its secret handles; no caller-selected command,
  `DYLD_*` or `LD_*`, DLL search path or writable plugin or configuration; updates are a separate trusted signed path.
  Unattended app authority goes only to an independently identifiable installed service or container principal; PID,
  pathname, AppId or a forwarded label never grants scope. Local sealing covers wallet, credential and epoch material,
  wrappers and every automatic-unlock or recovery copy; migration is transactional (verify the sealed reopen, then retire
  unsealed copies, and test old backups as retained authority); a downgrade, missing Keychain item, key ACL failure or
  outage leaves custody locked. Source: same file `:437-469`.
- **Deny by default, with independent consent.** Policy binds principal, profile or persona, operation, key namespace,
  target, session generation and consent, rechecked at commitment. `AsProfile` and a persona UUID request scope and never
  grant it; the global releasable-salt permission becomes per-principal grants. Only a separately authorized trusted-consent
  channel resolves a pending operation; `confirmed=true` is never consent. Current unlock is a native custody prompt by default;
  a terminal unlock is a documented exception over a separately authorized, mutually authenticated channel with zeroized
  buffers. Continuous key release is a per-consumer exception with exact derivation, lifetime and rotation limits.
  Native message boxes are not a secure attention sequence: where presence is required the custodian validates the OS
  presence result. Source: same file `:486-507,594-597`.
- **Lock, revocation and failure.** Operations, leases and approvals bind to a monotonic generation under a unique custodian
  start; a later Unlocked never revives old authority. Admission closes as lock begins, approvals are invalidated, private
  operations drain or cancel, and secrets are rechecked before delivery. Memory locked, consumers drained and restart
  barrier durable are reported separately; marker persistence failure keeps the memory lock and returns explicit
  degradation. Custodian loss means identity pending, with no fallback or unattended reopen. Source: same file `:509-532`.
- **Budgets and hygiene.** Bound connections, requests, pending decisions, queue bytes, decoded fields, imports,
  derivations, deadlines and holder drain, with a reserved lock and status path; never truncate an operation to meet a
  budget or blindly retry a mutation after an ambiguous disconnect. Fixture limits to measure before production settings:
  1 MiB frame, eight connections (two per principal), sixteen queued operations and 8 MiB queued, one active consent
  prompt, 5 s handshake, 30 s noninteractive deadline, 120 s consent expiry, 5 s drain. Secret-bearing framing uses
  clearing buffers on success, error, cancellation and reallocation. Source: same file `:534-557,585-592`.
- **Three authority tiers.** (1) the independent Castellan custodian; (2) a private-data and blob owner (exact stores, domain
  writer material, leases, document admission) protected like tier 1 with its own service identity; (3) confined workers
  (ingress, compute, publication, import) on one shared launcher, manifest and IPC family, with no vault or blob-root
  paths. Djinn is a coordination client: no vault opening, no launch or update authority, no widening of a worker manifest.
  Order follows exposure: custody and launcher, then configured peer and browser ingress (skippable where proved
  disabled), then compute, then loopback publication; no worker starts merely for having a role. One GPU and library owner
  serves inference and training; the whole `BlobStore` never crosses to a worker. For sync, transport is split from
  domain admission and decryption where the protocol allows opaque bytes; where it needs graph plaintext or signing the
  admitted domain is isolated and its authority stated. Import results are untrusted typed candidates rechecked by
  custody; the SSH signing adapter stays with custody initially. One user-facing resident does not require all authorities
  to share an address space; existing data, identities, store locks and resource ownership survive. Source: same file
  `:599-698`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-08-20_device_resident_consolidation_plan.md:87-96`.
- **Controls to preserve:** empty or master salts and unknown derivations refuse; SSH rechecks lock after approval;
  quarantine consent belongs to the resident; passphrase replacement requires current credentials. Source:
  `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:117-135`.
- **The lock's standing rulings** (vault lock numbering). 7: residents with lock enabled never read `PERSONAE_PASSPHRASE`
  (62: every passphrase-vault resident starts locked; 89: library openers that read it are removed). 15, 81: pandect's wallets
  follow the lock once D8 lands and stay vault-unaware until then. 23, 35, 36: Turnstone, Knot and the graphshell app
  follow the resident's lock, and once the dramatis repo plan's D5 lands "following the resident" means Djinn answers
  Locked. 17, 22: djinn hosts the agent, the standalone `personae-agent` retires after pairing D2, and macOS joins with D2.
  21: other platforms' unlock methods come later behind the same interface. 42: Linux starts locked and prompts (amended
  by 91). 87: Secret Service serving is its own plan. Source:
  `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:287-291,329-333,346-351,367-394,534-543,743-753,942-949,1023-1033,1047-1058`.
- **Lane rules for L4.** Only Mark numbers rulings; a lane stops at forks and brings the copied owner decisions to him with
  code evidence; one worktree per lane and at most three cargo builds at once; a dated successor receipt per lane updates
  register status and the sealed registers are never edited; custody code uses maintained libraries and standards only.
  Source: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-20_ownership_repair_plan.md:57-72,190-196`.

## Decisions

### custody D1. Unlock controls and authorized device approval (2026-11-04)

Mark answered **"Agreed."** to these interface controls:

- Lock after N minutes idle.
- Stay unlocked for N minutes/hours, or until explicitly locked.
- Whether screen lock and sleep also lock the vault.
- Which devices may approve unlocks for this device.

This adopts the preceding clarification: approval may come from another device
authorized under the owner's root identity, scoped to Dramatis custody. The
fleet decision names O-PC as its roster root; that relationship does not prove
every vault key is derived from O-PC or grant unlock authority by itself.
OS-session unlock remains a separate capability.

Links: area custody · plans VL-U · summary Expose configurable vault unlock duration, lock triggers and authorized remote approval.

### custody D2. One-week vault timers and remote grants (2026-11-04)

Mark requested **"We should set the djinn auth expiry and timeout to be a week"**
and clarified **"Both vault timers and remote grants"**. The selected policy is:

- Maximum elapsed unlocked duration: one week, including during active use.
- Idle-lock timeout: one week since activity, distinct from elapsed duration.
- Lifetime for newly issued remote authorization grants: one week from issue.

One week is **604,800 seconds / 10,080 minutes**. Keep all three settings
configurable. Existing independently enabled screen-lock and sleep triggers,
explicit lock and revocation may end access sooner. An existing signed grant
keeps its signed expiry; renewal/reissue requires its authorized issuer and
must not silently extend that grant or confer vault-unlock permission.

Implementation status: the resident's `lock.toml` supports the idle setting.
The custodian now enforces configurable elapsed duration; installed receiving
and remote vault-unlock issuance remain VL-U work. Remote device-grant issuance requires an
explicit `expires_at_ms`; its host needs to apply this selected lifetime.
Production preference does not set test duration: use injected clocks or
explicitly isolated short-lived fixtures for boundary and expiry controls.

Links: area custody · amends custody D1 · plans VL-U · summary Select configurable one-week unlock duration, idle timeout and remote-grant lifetime.

### custody D3. Fleet-wide authorization for existing work (2026-11-04)

Mark clarified **"The week is for all of the tasks, not just this one"** and
wants to renew authorization at the end of a week rather than after keyboard
inactivity. Apply the selected week to the entire configured fleet and all
already approved work, not a relay-specific exception. Existing scopes and
revocation still apply; authorization does not grow merely because it lasts
longer. Short I/O, shutdown and consent-prompt deadlines remain separate.

Treat elapsed authorization as a fixed deadline, not a sliding activity window.
Deploy and verify finite expiry before removing earlier lock triggers that
would otherwise interrupt that work. Distinguish a saved setting, an active
resident reload, a compatible custodian deployment and a tested weekly boundary.
Do not claim unreachable computers were updated. Test fault/expiry controls in
isolated custody fixtures so the battery does not revoke the fleet's real work.

Links: area custody · refines custody D2 · plans VL-U · summary Apply the week to existing authorized work throughout the fleet.

### custody D4. Root-persona approval across networks (2026-11-04)

While coordinating with the remote-controls lane, Mark requested **"we also
want to be able to do these prompts from root personas across networks, and
that's a part of it."** Apply this to the fleet-wide authorization in D3.
Root personas and explicitly enrolled devices may approve custody operations
within their grants. Native OS administrator/presence mechanisms need their
own supported bridge; a signed custody approval does not replace them.

Links: area custody · refines custody D1 · draws on custody D3 · plans VL-U · summary Support root-persona custody approval across networks with separate native OS gates.

## Phases

### H1. Enforced custody boundary and adversarial vertical slice
The portable custodian and its contract are on main with the H1 negative controls in CI-runnable tests; the macOS synthetic
fixture passes in a separate non-admin account and fails in the signing account (the H1-F1 control). Open: receiving runs
on each OS (the custodian README lists the steps); the macOS data-protection Keychain envelope in the portable binary; the
Windows CNG wrapping key; the Windows presence channel (a logon helper, built, never run); the shared confined-worker
launcher and manifest with a hostile-worker fixture, sandboxing active before parsing, and T05, T07 and T10 against
malicious workers and an unrelated same-user app; retiring the source vault and its copies transactionally after `adopt`;
isolating hostile import parsing before it is admitted to the production custody path. Not established by the macOS
fixture: copied or relaunched signed bundles, altered bundle resources, cross-account Keychain API variants,
signed-update replacement; memory residue, crash durability, physical sleep, logout and reboot, resource exhaustion.
- Done when: the installed OS denies worker and unrelated desktop-app extraction, replacement and self-approval while
  authorized operations and sealed cold reopen succeed; W1 and W2's unsafe assertions fail after repair; a socket-only
  implementation cannot pass; a failed platform mechanism blocks that protected deployment.
- Needs: separate signing and runtime accounts (H1-F1); the Linux, signed-macOS and Windows receiving hosts
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:296-303,705-769`

### H2. Complete authority and consumer migration (remainder and production gate)
Implemented 2026-10-26: every Djinn vault use goes through `ResidentCustody`, whose only production implementation is a
client of the custodian; the in-process host lives only under the test feature `in-process-custody`. Open: the tier-2
private-data and blob owner with only the operations its first worker needs, then the shared worker baseline for enabled
ingress, compute and loopback publication, one GPU and library owner, whole-`BlobStore` handoffs removed (corpus-isolation
claims wait on it); qualification of the trusted authentication helpers and the terminal-unlock exception (T01, T02, T04);
publishing each raw-key exception with its peer and rotation consequence. Standing gaps: `publish_grant_carriage` has no
production caller and needs disclosure of roster, grants and wrapped epoch records plus an act in custody first; the
in-process and receipt hosts still read a wallet directly; on macOS the custodian and Djinn share an account, so the wallet
move changes holder, not file access; the Windows wallet is DPAPI-sealed; the Linux credential catalog must move into the
custodian's state directory; consent is polkit once per generation on Linux, absent on macOS (per-use SSH keys refused)
and a same-user helper on Windows, type-checked only; the custodian now links Castellan's keeper and CXF code, the SSH
agent, tokio, pandect and graph-kernel (H4's dependency review); hostile CXF parsing runs inside the custodian, so import
isolation is a custodian-surface item.
- Done when: one authority holds roots and epochs; golden identity, derivation, stored-content and cold-reopen checks
  preserve data and public keys; no broad implicit grant replaces the old global allowlist. Production enablement waits
  on the Linux receiving run (README steps 1 to 8), the signed macOS receiving run, the wallet's at-rest step on Linux
  and the Windows o-pc run (consent helper, DPAPI-to-passphrase adoption, agent pipe).
- Needs: H1 launch identity per OS
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:771-851,897-898,1037-1041`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-08-20_device_resident_consolidation_plan.md:87-96`

### H3. Lifecycle and remaining platform acceptance
- Done when: generation-aware invalidation, bounded drain and durable marker outcomes are executed (T02, T03, T09); native
  macOS lock, suspend and idle sources report truthful coverage and are requalified apart from Linux and Windows (T06);
  H1 enforcement is rerun on each additional platform and signed update or recovery path, verifying exact service accounts,
  entitlements, key ACLs, helper and UI presence, and process and device restrictions (T05, T07); separate OS receipts
  establish the advertised guarantees, and missing platform restrictions stay unqualified.
- Needs: H1 and H2 (the source's phase order)
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:853-866`

### H4. Hostile input and independent review
- Done when: budgets and responsive lock and status are enforced and measured (T08); import, quarantine, authentication,
  replacement, OTP exact-session release and enabled epoch and history behaviours are requalified; dependency, advisory
  and independent protocol and platform review is done on the final bounded custodian, exact features and signed
  artifacts; every finding and test has evidence, an explicit accepted limit or an unqualified deployment.
- Needs: H1 to H3 (the source's phase order)
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:868-878`

### Hocket adoption (stopped)
Hocket seals its identity under the desktop user's OS key, which the custodian's account cannot open, and adopting it in
Djinn would reopen a vault in Djinn. Moving it needs Hocket's identity re-enveloped for custody, an identity-format
change. With a custodian Djinn refuses the adoption (a test build adopts in-process). Hocket's return-to-own-identity path
is intentionally unbuilt, no caller having asked.
- Done when: not set; the re-enveloping is an identity-format change that needs its own ruling.
- Needs: H2
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:5,806`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-07-03_archived_plan_tails_plan.md:765-766`

### VL-44. Close ruling 44: Distillery's transport key
Built 2026-10-09 under rulings 92 to 97: the transport identity is the mesh author key as a `DerivedKeypair`; the
master-taking constructors sit behind a `test-identity` feature turned on only in dev-dependencies; the lookups address
mesh authors with a negative control that a master-bound transport is refused; no rebind while locked. Still to do: the
Fedora gate with the lane on and locked by the real trigger, the push, and knot-editor and Turnstone turning on
`test-identity` in their next repins (a sibling can name the feature only once its pinned mere revision has it).
- Done when: the Fedora gate passes with the lane on and locked by the real trigger; the change is pushed; both siblings
  enable the feature in the repin commit that would otherwise break their tests.
- Needs: -
- Rulings: vault lock 44, 92, 93, 94, 95, 96, 97
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:4-8,550-558,1095-1143,2097-2149`

### VL-91. Linux root in the OS keyring
Ruled 2026-10-09: Linux gets an auto-unlock root held in the desktop's Secret Service, so it unlocks at login like Windows,
replacing ruling 42's ask-once-per-login. Built only after its own assessment of the client library, the persisted lock
and the threat statement's Linux at-rest line. No progress entry exists.
- Done when: the assessment is recorded and the root is built; see the first open question.
- Needs: its own assessment
- Rulings: vault lock 91, 42
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:534-543,1080-1093`

### VL-W. Pandect's wallets (D8)
The lock does not reach pandect's wallet store: wallets stay vault-unaware until the dramatis repo plan's D8 moves wallet
secrets into castellan, and their unattended reopen after a restart is a recorded gap that D8 closes.
- Done when: the lock relocks the wallet stores once D8 lands (ruling 15); the unattended-reopen gap is closed.
- Needs: dramatis repo plan D8 (DR-B)
- Rulings: vault lock 15, 81
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:6-8,329-333,383-386,942-949,2038-2041`

### VL-Q. Repairs not made: Q040 to Q052 and their neighbours
Found by the 2026-10-16 authority audit and left for a separate pass. Each is repaired with a regression or recorded with
the reason it stays.
- Q040: CXF imports a one-byte decoded OTP seed as a normal Vault item and accepts a petition that approval then refuses;
  quarantine review accepts any nonempty seed; share the generator's admission across import, review and exercise,
  preserving unsupported source material. Q041: an SSH import with an invalid comment fails with zero items but has bound
  the destination namespace to a profile; preflight and failure receipts must include ownership records. Q042: deleting
  one of two collections sharing an OTP item leaves the other dangling; decide shared membership against destructive
  collection ownership first.
- Q043: the SSH-agent startup helper and the shared app and browser helper unlink a Unix endpoint after NotFound or
  ConnectionRefused without checking socket type, owner or inode; unify cleanup ownership. Q044: `listening` and `ready`
  are emitted before the app and browser doors bind; add bind-ready acknowledgments. Q045: the identity endpoint's
  `bytes_for` reads through for any hash despite the rule that knowing a hash is insufficient; define one resource
  authorization owner (disclosed dependencies, accepted transfers, cached content, grant retirement) before repairing.
  Q046: a blob over 64 MiB empties the eviction queue and is inserted despite the cache budget; choose refusal or uncached
  serving. Q047: an accepted transfer decision sits in a shared in-memory vector though its comment promises durability;
  distinguish a queued gesture, durable acceptance and completed delivery.
- Q049: daemon shutdown does not clear the route catalog (a strong-reference cycle with the reservoir factory). Q050:
  reopening an existing group session skips the pre-key publish retry; retry on missing durable lane evidence rather than
  minting again. Q052: the Knot residue classifier intersects allocation size classes, subtracts baselines and collapses
  multiplicity, so it has false negatives; prove ownership from more than allocation sizes.
- Neighbours: the resident also writes dial hints, so settings need whole-operation ownership, and `save` deletes the current
  file before a fallible rename; a carriage purge does not recheck a renewed lease and indexes retractions after the
  publications; group-session, bundle and key-transition failure paths need post-commit qualification; bundle export skips
  the full refresh evaluator; enrollment can leave partial writes; removing local certificates issues no signed revocation;
  passphrase format V1 substitutions before upgrade are undetectable; no address-containment evaluator exists
  (`FacePolicy::attenuates` checks principal and action sets only); CXF namespace-binding ordering and Linux D-Bus prompt
  and publication order need qualification; the directory receipt's "about 10 to 18 s" claim is not compared numerically.
- Done when: each item has a regression or a recorded reason; the full-source audit of Castellan, Pandect and Djinn is
  completed and older graph findings are revalidated against the merged design.
- Needs: -
- Rulings: -
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:2156,2176-2190,2209-2236,2250-2406,2416-2448`

### VL-U. Unlock settings and approval from authorized devices (in progress)

Dramatis owns policy and custody enforcement; Djinn presents settings and
requests. Show the four agreed controls per target device, plus its current
lock state and the active unlock deadline or absence of a duration limit.
Keep inactivity and elapsed unlock duration distinct. Configured idle,
screen-lock and sleep triggers continue to apply independently of a duration
limit. Settings changes use the custodian's authorized configuration path;
protected deployments must not acquire a writable-client policy bypass.
The custodian's `max_unlocked_seconds` defaults to 604800; explicit owner-policy
`null` permits indefinite duration. A successful unlock fixes the deadline;
activity, reconnect and duplicate unlock do not renew it. Timer expiry locks,
advances the generation and invalidates cached/pending consent. A calendar
bound also covers suspended time; backwards clock movement fails closed.
The configured I/O ticker and in-flight completion remain bounded separately.
The selected finite duration, idle timeout and new remote-grant lifetime are
one week each (custody D2); display each separately and allow configuration.

Any device explicitly authorized under the owner's root may approve a target
vault unlock after authentication on the approving device. Derivation proofs
or signed delegation establish identity; a revocable permission separately
authorizes the target, vault/profile and operation. Mere pairing, graph-write
permission or a transport key does not authorize custody unlock. Bind each
approval to the target custodian instance, current generation, fresh request
and selected duration; recheck permission and revocation before opening.
Approval travels through an authenticated channel available while the target
vault is locked, without depending on SSH credentials held in that vault.

The target storage backend must explicitly support remote-authorized opening.
A local-presence-only envelope requires a reviewed alternative before this
flow can work; identity association alone cannot decrypt it. Keep unsupported
targets locked and explain the missing capability in the interface.

Implementation slices, in order:

1. **Portable enrollment and proof gate (implemented; source/synthetic).**
   `custody-wire::remote_approval` carries public request/proof records and
   constructs ordinary Insigne delegation statements. A protected root pin
   plus explicit action permission is required; root association alone is
   insufficient. `djinn_custodian::remote_approval::ApprovalGate` validates a
   root's enrollment, direct root-persona approval or an enrolled device's
   one-request approval through Notochord's `validate_chain` and the current
   authoritative revocation ledger. Profile/target, instance/generation,
   petition/digest, nonce, selected duration and request expiry are bound.
   The request uses the existing short consent deadline; it never slides a
   signed weekly grant. An unlock result is capped at the grant's remaining
   lifetime. Verification has no vault/SSH dependency and causes no unlock.
2. **Custody execution and durable enrollment (open).** Persist root pins,
   enrollment and revocations through protected owner storage; fail closed
   on missing/stale state. Restrict approval signing to its exact delegation
   audience in the approving custodian and require its admitted owner action.
   Connect a verified result to the exact active petition or supported unlock
   backend. Recheck requester grants, root/device revocation, target context,
   request deadline and authorization bound at commitment, under custody's
   serialization. Carry the absolute bound into the existing timer; ordinary
   consent never renews it. Backend opening and native OS elevation are
   separate capabilities. A native-only backend remains unsupported remotely.
3. **Locked-state route and O-PC/T-PC receiving (open).** Reuse the resident's
   authenticated channel machinery and Notochord's carrier/subject binding;
   authenticate/pin the target while locked without SSH keys from its vault.
   Relays carry bounded public proofs, never vault keys. Show target/profile,
   operation and requested/effective expiry before signing. First qualify
   O-PC's root enrolling T-PC and T-PC approving one O-PC request, then the
   reverse authorized direction and independent-uplink reconnect. Controls
   cover wrong root, bare pairing, wrong scope, replay, revocation during a
   pending request, restart, fixed expiry and backend refusal. Expand to the
   configured fleet only after this two-device gate. Existing Sporran grant
   storage/validation and the resident channel are seams, not this receipt.

- Done when: all four settings persist through restart and display the policy
  the custodian enforces; finite duration expires during active use; indefinite
  duration does not suppress separately enabled lock triggers; authorized
  approval opens exactly the requested vault for the selected duration.
  Controls refuse an unrelated root, a paired device without unlock permission,
  revoked permission, wrong target/profile, replay, expired request, stale
  generation or a restarted custodian. Exercise lock and revocation during a
  pending approval. Test the one-week boundaries with injected time and verify
  explicitly configured shorter fixture lifetimes. Retain one real two-device receipt and separate receipts
  for each supported storage backend; unsupported backends stay unqualified.
- Needs: root-bound device authorization, a locked-state approval channel,
  backend support and Djinn's settings/approval surface.
  The requested fleet is O-PC, T-PC, Q-PC, S-PC, Y-PC, iMac-M4 and X-PC;
  verify root-bound enrollment before calling remote approval fleet-ready.
- Receipts: focused policy and negative-control results plus the two-device
  and backend summaries in this plan's archived receipt file; 100 MB total
  retained-byte cap. Exploration retains compact summaries only.

### VL-E. Attended steps, deployment and the environment passphrase
Deployment of the lock to the installed resident is Mark's step, as are a real Windows Hello prompt and the native terminal
prompt. Not verified: the wire sign refusal against the real `ssh` binary. `Unlock::from_env()` remains in
`personae-agent`, `personae-vault`, graphshell's `profile.rs` and the web-extension smoke host (ruling 89 removed the
library openers; the two personae binaries were not restated), and those binaries stay out of scope until pairing D2.
macOS has no AutoOs backend. The L1 to L4 receipts are limited by raw key copies, state-only lock watching, marker
persistence failure and missing macOS native event hooks. Lock and unlock follow-through and non-Windows startup unlock
backends are owned here, as are V5 sync (no replicated `IdentityStorage` exists), V3's follow-ons (a passphrase prompt,
`generate`, a ShortTtl relock) and OTP's code presentation, admitted approval surface and credential replication between
persona devices, all unbuilt.
- Done when: the source sets none; each is a recorded receipt or a decision.
- Needs: pairing D2 for the personae binaries and macOS
- Rulings: vault lock 7, 17, 21, 22, 89
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:4-6,13-18,1188,1389-1397,1493,1623-1625,1683-1690`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-07-03_archived_plan_tails_plan.md:1140-1142,1153-1158,1175-1178`

### L4. Custody lifetimes (ownership repair)
Castellan, pandect, cambium and Djinn, after the audit's custody repairs landed; the process boundary is this plan's, the
lifetimes inside it are the lane's (15 findings and 16 candidates). Its acceptance questions: can retrying an acknowledged operation apply it twice or skip it (an interrupted identity adoption moves the
device identity and skips the remaining personas on retry, Q021; Q050; Q047; epoch-revocation idempotence is the repaired
control), and can a permission revoked during deferred work still be used when the effect occurs (the shared host loop
pushes notices before its only authority check, Q060 and A056; a revoke cannot interrupt an in-flight event wait in
Signalman, Q418; a leased result or expired lease still publishes, Q201 and Q219). The lane first reads its slice of the
registers, lists the owner decisions copied today with the single owner each should have, and brings that list to Mark
before code.
- Done when: every finding in the slice is repaired with a test or re-documented with the reason it stays; the duplicated
  implementations in its authority entries are reduced to one owner or recorded as deliberately separate, the owner named
  in the code's documentation; the touched crates pass their gates in the worktree with pins holding; a dated successor
  receipt updates register status and the lane's Progress entry names it.
- Needs: the lane's first register read and question round with Mark
- Rulings: -
- From: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-20_ownership_repair_plan.md:45,57-72,89-91,155-171`

### SS. Secret Service for Djinn (parked by SS8)
Parked: apps keep the platform keyring, Djinn serves no Secret Service, and its own items (chatelaine's keychain, SSH keys,
OTP) stay in its vault under tier invariant 13. SS5 to SS7 stay as the design for when an app needs Djinn's lock. The
design: the resident serves castellan's Secret Service 0.2 on the user's real session bus under a bus name of its own while
gnome-keyring keeps `org.freedesktop.secrets` (SS5); libsecret apps are routed by a `SECRET_SERVICE_BUS_NAME` override in
their `.desktop` file, a reversible step that moves that app's items with a report (SS6); hardcoded clients stay on
gnome-keyring; any same-user caller may act and each item records its creating executable (SS7); the service is served
locked and empty before the first unlock so `Unlock` gets the native Prompt (SS2); a client `Lock` locks the whole vault;
the Flatpak portal backend is out of scope (SS4). A future adapter needs the same custody authorization and OS gates.
Building waits on the pairing plan's D2 launcher. Unowned watch items: Fedora 45 plans to replace gnome-keyring with
`oo7-daemon` (a one-way data migration; the ThinkPad is on Fedora 44 with no oo7); whether gnome-keyring allows its name to
be replaced was never answered; both host seams (`SecretServiceAccessPolicy`, `SecretServiceVault`) are traits with test
implementations only; the ThinkPad's `login` collection read unlocked after `loginctl lock-session` and suspend, which is why
SS8 parked the plan.
- Done when: S1: Djinn enables castellan's `secret-service` feature on Linux, a production `SecretServiceAccessPolicy`
  binds callers, a `SecretServiceVault` sits on Djinn's lock coordinator and native prompt with `prompt_unlock` on a
  blocking thread, the service starts after the first unlock and survives lock and unlock, and a receipt on the real session
  bus under a test name with `secret-tool` leaves gnome-keyring untouched. S2: Djinn serves under its own bus name, routing
  an app is reversible and moves its items, each item records its creating executable, and the check of which process holds
  `org.freedesktop.secrets` reports it. S3: a Djinn user unit starts the resident at logon. S4: on the ThinkPad
  `secret-tool` and a GNOME app store, read, lock and unlock through Djinn, a client `Lock` locks the whole vault, and the
  threat statement and tier architecture name the service.
- Needs: SS8 reversed by an app needing Djinn's lock; `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-28_device_pairing_plan.md` D2 for the Linux launcher
- Rulings: SS1 to SS8; vault lock 10, 66, 67, 68, 69, 87
- From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-08_secret_service_plan.md:4-17,45-65,67-99,134-215`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-07-03_archived_plan_tails_plan.md:1153-1156`

## Open questions

- VL-U: which existing native storage backends can accept remote approval, and
  which require an additional protected opening method? How should an
  authenticated remote work session affect the configurable idle timer?
  These implementation choices remain open; the four controls are agreed.
- How does ruling 91 (a Linux auto-unlock root in the desktop's Secret Service, unlocked by PAM for the session) sit with the
  custodian's Linux design (a dedicated service UID with root-owned configuration and state outside the desktop home,
  passphrase AEAD inside it, polkit consent per generation)? Ruling 91 predates that design and its assessment is unmade.
  From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:1080-1093`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:373,822-825`
- Is ruling 44 landed? The vault lock status says the hard switch landed on 2026-10-09, while the build entry lists the
  Fedora gate, the push and the sibling repins as still to do. From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:4-8,2145-2149`
- Does H2's move of the wallet and credential catalog into the custodian's data root close the gap ruling 81 left for D8, or
  is D8 (castellan taking the wallet's secrets) still needed? From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:942-949`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:807-819`
- Is Q052 repaired? The ownership repair plan records it repaired on the unmerged branch `l6/misleading-success`, while
  the vault lock plan lists it as not repaired. From: `repos/mere/design_docs/mere_docs/implementation_strategy/2026-10-20_ownership_repair_plan.md:427-435`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-05_vault_lock_plan.md:2423-2448`
- Which of V3's follow-ons remain: a passphrase prompt, `generate`, a ShortTtl relock? Later records show a native
  passphrase prompt (the lock's L2 and L3), an in-Djinn Ed25519 generation command and ShortTtl idle expiry in the approval
  broker. From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-07-03_archived_plan_tails_plan.md:1141-1142`
- Where does the Flatpak portal backend gap (`org.freedesktop.impl.portal.Secret`), recorded to be revisited after S4, live
  now that S4 is parked? From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-08_secret_service_plan.md:154-156`
- Which launcher does the Linux resident use? The Secret Service plan says Djinn has no Linux launcher beyond the Windows
  installer, while the pairing plan records a systemd user unit on s-pc and the custodian ships its own system service.
  From: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-08_secret_service_plan.md:56-57`; `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-02_device_pairing_by_key_plan.md:55-62`

## Findings

- 2026-11-04 (source-confirmed): the remote proof gate reuses Insigne's signed
  certificate/attenuation grammar and Notochord's chain/revocation checks.
  `crates/djinn-custodian/src/remote_approval.rs` is not wired to `Core`, the
  driver or a network route. Passing proof tests therefore proves neither
  native presence nor remote vault opening; no fleet enrollment was performed.

- 2026-10-21 (source-confirmed; the sources record a repair for C04 and C07 only): C01 root custody shared Djinn's address
  space; C02 any same-user client can claim an allowed AppId, which routes and does not identify; C03 release policy is a
  global salt and source allowlist, `AsProfile` opens a named profile without an app-to-profile grant, and the
  administrative acts (`ChooseProfile`, `CreateProfile`, `IssueStationGrant`, `RevokeDevice`) lacked a principal policy;
  C05 a released key can be copied and used after lock; C06 `WatchLock` exposes state, not a monotonic generation; C08 macOS
  has no native screen-lock or suspend source and unknown idle locks after the timeout; C09 the hello does not authenticate a
  pinned custodian and terminal unlock sends a passphrase over the control route; C10 the SSH agent supplies no
  authenticated requester facts and Session-tier keys skip per-request approval; C11 accept loops have no shared admission
  budget or handshake deadline and CXF commands read caller-named files before parsing; C12 memory and process protection
  is platform-dependent; C13 secret-bearing IPC uses ordinary buffers, `serde_json` and base64 copies and `PayloadBytes` has
  no clearing `Drop`. Source: `repos/mere/design_docs/archive_docs/2026-10-28/2026-10-21_custody_isolation_and_security_hardening_plan.md:95-115`.
- 2026-10-21: witnesses W1 to W4 assert the current weaknesses on purpose (a released key outlives lock; an admitted
  ordinary client approves a per-use SSH signature; lock reports success without a persistent marker; a delayed observer
  cannot learn of an intervening lock) and must fail at the unsafe assertion after repair while authorized controls
  succeed. Source: same file `:141-142,157-162`.
- 2026-10-21: the experiments owed. T01 a fake custodian is rejected before any secret is sent; T02 delivery held across
  lock, profile switch and revocation; T03 a suspended watcher across lock and restart must reauthorize; T04 SSH pending
  and cached approval across lock, expiry, policy change and forwarding (proposed default: invalidate on lock or generation
  change); T05 wrong user, app, profile, operation, namespace, target and UI role over each real transport; T06 real macOS
  lock, sleep, logout, reboot and crash restart; T07 same-user debugger, memory, root-file and helper-replacement attacks
  and dump policy, with a tracking-allocator positive control for IPC buffers; T08 malformed, oversized and replayed
  frames, floods and stalled holders; T09 crashes at every marker and passphrase-replacement boundary, power loss, old
  backups and freshness-ledger rollback; T10 a malicious-worker fixture cannot read roots, approve itself or restart into
  unattended authority. Source: same file `:164-175`.
- 2026-10-26: the ThinkPad refused SSH, so the custodian README's Linux receiving steps are unverified. Djinn's
  `embedded_reservoir_validation` test `recorded_situation_and_weather_survive_three_owners_and_refuse_tamper` fails the
  same way on plain main. The two broker tests and `custodian_resident` build socket paths from `TMPDIR` and fail on macOS
  with its default (`SUN_LEN`); run them with a short `TMPDIR`. Source: same file `:956-957,995-997,1027-1028,1032-1035`.
- 2026-10-22: a passing macOS primitive fixture authorizes no real-consumer migration; a production deployment preserves
  the signing and runtime account separation and repeats qualification with the actual custodian and consumer packages.
  Source: same file `:289-295`.

## Progress

- 2026-10-28: cut from the custody isolation, vault lock and Secret Service plans, with lane L4 of the ownership repair
  plan and the device resident plan's custody tiers; nothing new landed.

- 2026-11-03: custodian repository extraction is complete (dramatis_repo D14).
  The process, wire client, station-grant policy and native harness have their
  source homes in Dramatis. The Windows suite retains its two baseline
  OS-vault adoption failures; portable independence and Mere integration do
  not close this plan's deployment, signed receiving or operating-system gates.

- 2026-11-04: recorded the agreed unlock interface and root-authorized device
  approval as custody D1 and planned phase VL-U. Documentation only; runtime
  behavior and installed policies have not changed.
- 2026-11-04: custody D2 selects one week for elapsed unlock, idle and new remote
  grants. Applied the supported idle setting to O-PC's active resident; the
  other controls retain their explicit implementation and deployment gates.
- 2026-11-04: custody D3 makes the week fleet-wide for existing approved work.
  Implemented absolute custodian expiry and controls for renewal, sleep/clock
  changes and pending approval. Fleet receiving status is in the receipt.
- 2026-11-04: custody D4 coordinates root-persona prompts across networks.
  Added portable enrollment/approval records and a bounded target verifier
  with fixed-week and adversarial controls. Core execution, protected durable
  enrollment, a locked-state route and real O-PC/T-PC receiving remain open.
