// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Public enrollment and signed revocations in a custodian-owned database.
//! The parent is the existing OS-protected vault directory, never a client
//! path. Redb supplies exclusive opening and transactional commits through
//! Muniment. No key is stored here. This does not defend against an admin
//! restoring the entire protected directory from an old disk snapshot.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use insigne::delegation::{SignedDelegationCertificate, SignedDelegationRevocation};
use muniment::{Backend, RedbBackend};
use notochord::{RevocationLedger, TrustedRoot};
use serde::{Deserialize, Serialize};

use super::{ApprovalGate, ApprovalPolicy, bounded_scope};
use crate::{Refusal, Result};

const FILE: &str = "remote-approval.redb";
const SLOT: &str = "custody/remote-approval/v1";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_ENROLLMENTS: usize = 256;
const MAX_REVOCATIONS: usize = 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pin {
    root: TrustedRoot,
    target: [u8; 32],
    profile: String,
}

impl From<&ApprovalPolicy> for Pin {
    fn from(policy: &ApprovalPolicy) -> Self {
        Self {
            root: policy.root,
            target: policy.target,
            profile: policy.profile.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    pin: Pin,
    revision: u64,
    enrollments: Vec<SignedDelegationCertificate>,
    revocations: Vec<SignedDelegationRevocation>,
}

/// Validated public state, read again before every approval and cache use.
pub(crate) struct Snapshot {
    pub ledger: RevocationLedger,
    pub enrollments: Vec<SignedDelegationCertificate>,
}

/// One exclusive owner of the public authority store. A failed mutation or
/// malformed state disables this handle; it never falls back to an empty ledger.
pub struct EnrollmentStore {
    backend: RedbBackend,
    path: PathBuf,
    policy: ApprovalPolicy,
    revision: u64,
    failed: bool,
}

impl EnrollmentStore {
    /// Explicit owner setup only. Ordinary service startup uses `open` and
    /// refuses absent state. Existing files, including damaged ones, survive.
    ///
    /// # Errors
    /// Refuses invalid policy, unprotected/indirect paths, existing state or
    /// a database/commit failure. The host must establish OS directory protection.
    pub fn initialize(vault: &Path, policy: &ApprovalPolicy) -> Result<()> {
        ApprovalGate::new(policy.clone(), "store-validation".into(), 1)?;
        let path = protected_path(vault)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(
            options
                .open(&path)
                .map_err(|_| Refusal("remote-store-create"))?,
        );
        let backend = RedbBackend::open(&path).map_err(|_| Refusal("remote-store-open"))?;
        let state = State {
            version: 1,
            pin: Pin::from(policy),
            revision: 0,
            enrollments: vec![],
            revocations: vec![],
        };
        let bytes = serde_json::to_vec(&state).map_err(|_| Refusal("remote-store-format"))?;
        pollster::block_on(backend.put(SLOT, &bytes)).map_err(|_| Refusal("remote-store-write"))
    }

    /// Open existing owner state; no creation or reset on missing/corrupt data.
    ///
    /// # Errors
    /// Refuses absent/indirect files, competing owners, corrupt state, a root
    /// pin mismatch, or invalid signed records. Directory ACLs remain host-owned.
    pub fn open(vault: &Path, policy: &ApprovalPolicy) -> Result<Self> {
        ApprovalGate::new(policy.clone(), "store-validation".into(), 1)?;
        let path = protected_path(vault)?;
        check_file(&path)?;
        let backend = RedbBackend::open(&path).map_err(|_| Refusal("remote-store-open"))?;
        let mut store = Self {
            backend,
            path,
            policy: policy.clone(),
            revision: 0,
            failed: false,
        };
        store.load()?;
        Ok(store)
    }

    /// Persist a root-signed device enrollment. Identical retries are idempotent
    /// and never renew its signed expiry; a revoked grant cannot be reinstalled.
    ///
    /// # Errors
    /// Refuses invalid/expired/revoked grants, exhausted budgets and failed commits.
    pub fn enroll(&mut self, grant: SignedDelegationCertificate, now_ms: u64) -> Result<()> {
        let (mut state, ledger) = self.load()?;
        let gate = ApprovalGate::new(self.policy.clone(), "store-validation".into(), 1)?;
        gate.check_enrollment(&grant, &ledger, now_ms)?;
        if let Some(existing) = state
            .enrollments
            .iter()
            .find(|g| g.certificate.id() == grant.certificate.id())
        {
            return if existing == &grant {
                Ok(())
            } else {
                Err(Refusal("remote-enrollment-conflict"))
            };
        }
        if state.enrollments.len() >= MAX_ENROLLMENTS {
            return Err(Refusal("remote-store-capacity"));
        }
        state.enrollments.push(grant);
        self.save(state)
    }

    /// Persist a verified withdrawal of a registered enrollment before ack.
    /// A failed commit poisons this handle instead of continuing on old trust.
    ///
    /// # Errors
    /// Refuses wrong issuer/scope, future or invalid statements,
    /// exhausted budgets and failed commits.
    pub fn revoke(&mut self, revocation: SignedDelegationRevocation, now_ms: u64) -> Result<bool> {
        let (mut state, _) = self.load()?;
        check_revocation(&state, &revocation)?;
        if revocation.revocation.at_ms > now_ms {
            return Err(Refusal("remote-revocation-time"));
        }
        if state
            .revocations
            .iter()
            .any(|r| r.revocation.certificate == revocation.revocation.certificate)
        {
            return Ok(false);
        }
        if state.revocations.len() >= MAX_REVOCATIONS {
            return Err(Refusal("remote-store-capacity"));
        }
        state.revocations.push(revocation);
        self.save(state)?;
        Ok(true)
    }

    pub(crate) fn snapshot(&mut self) -> Result<Snapshot> {
        let (state, ledger) = self.load()?;
        Ok(Snapshot {
            ledger,
            enrollments: state.enrollments,
        })
    }

    fn load(&mut self) -> Result<(State, RevocationLedger)> {
        if self.failed {
            return Err(Refusal("remote-store-unavailable"));
        }
        let result = self.read();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn read(&mut self) -> Result<(State, RevocationLedger)> {
        protected_path(self.path.parent().ok_or(Refusal("remote-store-path"))?)?;
        check_file(&self.path)?;
        let bytes = pollster::block_on(self.backend.get(SLOT))
            .map_err(|_| Refusal("remote-store-read"))?
            .ok_or(Refusal("remote-store-missing"))?;
        if bytes.len() > MAX_BYTES {
            return Err(Refusal("remote-store-capacity"));
        }
        let state: State =
            serde_json::from_slice(&bytes).map_err(|_| Refusal("remote-store-format"))?;
        if state.version != 1
            || state.pin != Pin::from(&self.policy)
            || state.revision < self.revision
        {
            return Err(Refusal("remote-store-binding"));
        }
        if state.enrollments.len() > MAX_ENROLLMENTS || state.revocations.len() > MAX_REVOCATIONS {
            return Err(Refusal("remote-store-capacity"));
        }
        let gate = ApprovalGate::new(self.policy.clone(), "store-validation".into(), 1)?;
        let mut ids = std::collections::BTreeSet::new();
        for grant in &state.enrollments {
            // Expiry does not make a stored record corrupt. Actual use checks
            // the current clock and ledger; here signatures and bounds must hold.
            gate.check_stored_enrollment(grant)?;
            if !ids.insert(grant.certificate.id()) {
                return Err(Refusal("remote-store-format"));
            }
        }
        let mut ledger = RevocationLedger::new();
        for revocation in &state.revocations {
            check_revocation(&state, revocation)?;
            ledger.fold(
                revocation
                    .check()
                    .map_err(|_| Refusal("remote-revocation"))?,
            );
        }
        self.revision = state.revision;
        Ok((state, ledger))
    }

    fn save(&mut self, mut state: State) -> Result<()> {
        state.revision = self
            .revision
            .checked_add(1)
            .ok_or(Refusal("remote-store-revision"))?;
        let bytes = serde_json::to_vec(&state).map_err(|_| Refusal("remote-store-format"))?;
        if bytes.len() > MAX_BYTES {
            return Err(Refusal("remote-store-capacity"));
        }
        if pollster::block_on(self.backend.put(SLOT, &bytes)).is_err() {
            self.failed = true;
            return Err(Refusal("remote-store-write"));
        }
        self.revision = state.revision;
        Ok(())
    }
}

fn check_revocation(state: &State, signed: &SignedDelegationRevocation) -> Result<()> {
    let statement = &signed.revocation;
    if !bounded_scope(&statement.scope)
        || signed.signature().len() != 64
        || signed.signer.signature().len() != 64
    {
        return Err(Refusal("remote-proof-size"));
    }
    let expected = custody_wire::remote_approval::enrollment_scope(
        state.pin.target,
        &state.pin.profile,
        [
            custody_wire::remote_approval::ApprovalAction::Consent,
            custody_wire::remote_approval::ApprovalAction::Unlock,
        ],
    );
    if statement.issuer != state.pin.root.issuer
        || statement.scope.domain != expected.domain
        || statement.scope.resource != expected.resource
        || statement.scope.path_prefix != expected.path_prefix
        || !statement.scope.actions.is_subset(&expected.actions)
    {
        return Err(Refusal("remote-revocation-binding"));
    }
    if state
        .enrollments
        .iter()
        .find(|g| g.certificate.id() == statement.certificate)
        .is_some_and(|grant| statement.scope != grant.certificate.scope)
    {
        return Err(Refusal("remote-revocation-binding"));
    }
    signed.check().map_err(|_| Refusal("remote-revocation"))?;
    Ok(())
}

fn protected_path(vault: &Path) -> Result<PathBuf> {
    if !vault.is_absolute() {
        return Err(Refusal("remote-store-path"));
    }
    let metadata = fs::symlink_metadata(vault).map_err(|_| Refusal("remote-store-path"))?;
    if !metadata.is_dir() || indirect(&metadata) {
        return Err(Refusal("remote-store-path"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != custody_wire::peer::effective_uid()
        {
            return Err(Refusal("remote-store-permissions"));
        }
    }
    Ok(vault.join(FILE))
}

fn check_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal("remote-store-missing"))?;
    if !metadata.is_file() || indirect(&metadata) {
        return Err(Refusal("remote-store-path"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != custody_wire::peer::effective_uid()
        {
            return Err(Refusal("remote-store-permissions"));
        }
    }
    Ok(())
}

fn indirect(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(test)]
mod tests;
