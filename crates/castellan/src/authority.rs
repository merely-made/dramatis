// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Castellan's authority half: the resident Personae host.
//!
//! Custody without ownership. The vault and its truth are `personae`'s; this
//! is the keeper that holds them for the resident, serves the SSH agent,
//! brokers signing approvals, and applies the typed intents the projection
//! offers. Applications (graphshell first) compose it; apps talk to a pipe
//! and never see the key.
//!
//! This host deliberately starts in `StandaloneRetained`: H4 may exercise the
//! shared vault and approval boundary without stealing the user's standard SSH
//! agent endpoint before restart and real-login proofs exist.
//!
//! ## The lock (vault lock plan, rulings 1, 9 to 14, 27, 31)
//!
//! [`PersonaeHost::lock_vault`] locks the vault, then runs every registered
//! [`VaultLockHolder`] before it returns; observers watch
//! [`PersonaeHost::lock_state`]. The agent's `ssh-add -x` engages the same
//! lock. While locked, every secret-reaching surface refuses with
//! [`IdentityIntentError::Locked`], and the snapshot shows the public view kept
//! at lock time. Unlocking takes [`PersonaeHost::unlock_vault`], a native call:
//! no intent carries the credential.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use insigne::DerivedKeyAttestation;
use personae::PersonaId;
use personae::carry::DeviceId;
use personae::signing::{DecisionError, PendingSigningRequest, RememberApproval, SigningDecision};
use personae::{
    CredentialLineage, Ed25519Keypair, Ed25519PublicKey, IdentityError, IdentityProvider,
    ProfileId, ProtocolKey, RetainedKeys, UnlockTier,
};
use sporran::WalletEpochSealer;

use crate::custody::agent::{VaultAgent, VaultLockRequest};
use crate::custody::wallet::{epoch_sealer_for_persona, revoke_remote_auth_device};
use crate::custody::{
    ApprovalBroker, IdentityStorage, IdentityVault, UnlockMethod, roster, ssh_slot,
};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tokio::sync::watch;
use uuid::Uuid;

use crate::lock::VaultLockHolder;

use crate::view::{
    AgentListenerView, CarryView, IdentitySurfaceSnapshot, ProfileView, SshKeyView, VaultLockView,
    VaultProtectionView, VaultView, load_carry_view,
};
#[cfg(test)]
use dramatis::intents::SigningDecisionIntentV1;
use dramatis::intents::{
    CreateProfileIntentV1, DEVICE_REVOKE_INTENT, GenerateSshKeyIntentV1,
    ImportSshKeyNativeIntentV1, LockVaultIntentV1, PROFILE_CREATE_INTENT, PROFILE_SWITCH_INTENT,
    RemoveSshKeyIntentV1, RevokeDeviceIntentV1, SIGNING_APPROVE_IDLE_INTENT,
    SIGNING_APPROVE_ONCE_INTENT, SIGNING_DENY_INTENT, SSH_GENERATE_INTENT,
    SSH_IMPORT_NATIVE_INTENT, SSH_REMOVE_INTENT, SshUnlockPolicyIntentV1, SwitchProfileIntentV1,
    VAULT_LOCK_INTENT, VAULT_UNLOCK_INTENT,
};

const MAX_SHORT_TTL_SECONDS: u32 = 24 * 60 * 60;
#[cfg(windows)]
pub const STANDARD_WINDOWS_AGENT_ENDPOINT: &str = r"\\.\pipe\openssh-ssh-agent";

/// Whether `endpoint` is this user's `SSH_AUTH_SOCK`.
#[cfg(not(windows))]
fn is_standard_unix_agent(endpoint: &str) -> bool {
    same_socket(endpoint, std::env::var_os("SSH_AUTH_SOCK").as_deref())
}

/// The same path, or the same file once links resolve.
#[cfg(any(not(windows), test))]
fn same_socket(endpoint: &str, standard: Option<&std::ffi::OsStr>) -> bool {
    let Some(standard) = standard.filter(|s| !s.is_empty()) else {
        return false;
    };
    let (endpoint, standard) = (
        std::path::Path::new(endpoint),
        std::path::Path::new(standard),
    );
    endpoint == standard
        || matches!(
            (endpoint.canonicalize(), standard.canonicalize()),
            (Ok(a), Ok(b)) if a == b
        )
}

/// Rejected Graphshell identity action.
#[derive(Debug, thiserror::Error)]
pub enum IdentityIntentError {
    #[error("unknown identity intent")]
    UnknownIntent,
    #[error("invalid signing decision payload: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("signing decision rejected: {0}")]
    Decision(#[from] DecisionError),
    #[error("identity vault operation failed: {0}")]
    Identity(IdentityError),
    /// Refused while the vault is locked (ruling 10).
    #[error("the vault is locked")]
    Locked,
    /// Unlock is native: no intent carries the credential (ruling 9).
    #[error("unlocking takes the resident's own surface; no intent carries the credential")]
    UnlockNativeOnly,
    #[error("signing decisions require the resident's independent native confirmation")]
    SigningDecisionNativeOnly,
    #[error("the signing confirmation became stale; ask again")]
    StaleSigningConfirmation,
    #[error("SSH key generation failed")]
    KeyGeneration,
    #[error("SSH public key encoding failed")]
    PublicEncoding,
    #[error("SSH key comment must be at most 256 printable characters")]
    InvalidComment,
    #[error(
        "a persona id must be 1-64 characters of letters, digits, hyphen or underscore, so it \
         survives becoming a filename unchanged"
    )]
    InvalidProfileId,
    #[error("a persona name must be 1-256 printable characters")]
    InvalidProfileName,
    #[error("short idle approval must be between 1 and 86400 seconds")]
    InvalidIdleWindow,
    #[error("SSH key removal requires explicit confirmation")]
    ConfirmationRequired,
    #[error("SSH key fingerprint is not present in the selected profile")]
    KeyNotFound,
    #[error("SSH import requires a native private-key handoff")]
    NativeHandoffRequired,
    #[error("device revocation requires explicit confirmation")]
    DeviceRevocationConfirmationRequired,
    #[error("carry authority is not configured")]
    CarryUnavailable,
    #[error("device revocation failed ({0:?})")]
    DeviceRevocation(std::io::ErrorKind),
    /// Refused at import, with personae's reason (ruling 56).
    #[error("the agent cannot sign this SSH key: {0}")]
    UnsignableKey(String),
    #[error("vault command failed: {0}")]
    /// A terminal vault command was refused or could not complete.
    VaultCommand(String),
}

/// Secret-free result of a terminal vault act.
pub enum VaultCommandOutput {
    /// Public text, keys or certificates.
    Text(String),
    /// Public CA installation material for the terminal to send over SSH.
    Enrollment {
        /// User-selected SSH target.
        target: String,
        /// Shell script carrying only the public CA trust line.
        script: String,
        /// Text shown after the target confirms installation.
        confirmation: String,
    },
}

impl From<IdentityError> for IdentityIntentError {
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::Locked => Self::Locked,
            error => Self::Identity(error),
        }
    }
}

// The intent receipts, at their old paths (dramatis repo plan, ruling D31).
pub use dramatis::receipts::*;

/// Native owner of one shared Personae vault and its SSH adapter.
pub struct PersonaeHost<S: IdentityStorage> {
    vault: Arc<Mutex<IdentityVault<S>>>,
    agent: VaultAgent<S>,
    approval: ApprovalBroker,
    data_root: Option<PathBuf>,
    /// Where the vault lives on disk, when it lives anywhere. A profile
    /// switch writes the family's remembered choice beside it
    /// ([`personae::roster::remember_profile`]); an ephemeral host has no
    /// beside, so `None` switches without remembering.
    vault_dir: Option<PathBuf>,
    protection: VaultProtectionView,
    lock: Arc<ResidentLock<S>>,
    listener: Arc<Mutex<AgentListenerView>>,
    /// Keys the lock leaves in place, one set per purpose (rulings 40, 46).
    retained: Mutex<Vec<Arc<RetainedKeys>>>,
}

/// What stays visible while locked (ruling 11): the profile and SSH key
/// views, kept when the lock is taken. Secret-free by their types.
#[derive(Clone)]
struct KeptView {
    profiles: Vec<ProfileView>,
    ssh_keys: Vec<SshKeyView>,
}

/// Facts shown by the resident's native confirmation surface. A projected
/// request UUID cannot manufacture this context or resolve a broker request.
pub struct NativeSigningContext {
    pending: PendingSigningRequest,
    generation: u64,
}

impl NativeSigningContext {
    pub fn pending(&self) -> &PendingSigningRequest {
        &self.pending
    }
}

/// The resident's lock: the shared vault, the holders that obey it, the
/// state observers watch, and the view kept at lock time.
struct ResidentLock<S: IdentityStorage> {
    vault: Arc<Mutex<IdentityVault<S>>>,
    holders: Mutex<Vec<Arc<dyn VaultLockHolder>>>,
    state: watch::Sender<VaultLockView>,
    kept: Mutex<Option<KeptView>>,
    /// The vault directory whose persisted lock this resident keeps (rulings
    /// 5, 80), when it keeps one.
    persisted: Mutex<Option<PathBuf>>,
    generation: AtomicU64,
}

impl<S: IdentityStorage + 'static> ResidentLock<S> {
    /// The vault first, so a refusal (ruling 27) changes nothing; then
    /// every holder, before anyone is told.
    fn lock(&self) -> Result<(), IdentityError> {
        let mut vault = self.vault.lock().unwrap();
        if !vault.is_locked() {
            let kept = public_views(&vault).ok();
            vault.lock()?;
            self.generation.fetch_add(1, Ordering::SeqCst);
            let holders = self.holders.lock().unwrap().clone();
            for holder in &holders {
                holder.lock();
            }
            *self.kept.lock().unwrap() = kept;
        }
        // Serialize persistence with unlock. A repeated lock retries a failed
        // marker write instead of turning an in-memory lock into false success.
        let persistence = self
            .persisted
            .lock()
            .unwrap()
            .as_deref()
            .map(crate::custody::persist_lock)
            .transpose();
        self.state.send_replace(VaultLockView::Locked);
        if let Err(error) = persistence {
            tracing::error!(%error, "vault memory is locked; durable restart barrier failed");
            return Err(error);
        }
        tracing::info!("vault locked with its configured restart barrier");
        Ok(())
    }

    /// The vault, then every holder re-derives; a holder failing relocks
    /// everything, so nothing is left half unlocked.
    fn unlock(&self, method: UnlockMethod<'_>) -> Result<(), IdentityError> {
        let mut vault = self.vault.lock().unwrap();
        if !vault.is_locked() {
            return Ok(());
        }
        vault.unlock(method)?;
        self.generation.fetch_add(1, Ordering::SeqCst);
        let holders = self.holders.lock().unwrap().clone();
        for holder in &holders {
            let restored = match holder.key_profile() {
                Some(id) => vault.storage().load_profile(id).and_then(|profile| {
                    let provider = personae::InMemoryProvider::from_seed(profile.master.to_seed());
                    holder.unlock(&provider)
                }),
                None => holder.unlock(&*vault),
            };
            if let Err(error) = restored {
                tracing::error!(holder = holder.name(), %error, "holder could not re-derive; relocking");
                for holder in &holders {
                    holder.lock();
                }
                if let Err(relock) = vault.lock() {
                    tracing::error!(%relock, "the vault could not relock");
                }
                return Err(error);
            }
        }
        *self.kept.lock().unwrap() = None;
        if let Some(dir) = self.persisted.lock().unwrap().as_deref() {
            if let Err(error) = crate::custody::clear_persisted_lock(dir) {
                for holder in &holders {
                    holder.lock();
                }
                vault.lock()?;
                self.generation.fetch_add(1, Ordering::SeqCst);
                self.state.send_replace(VaultLockView::Locked);
                if let Err(rollback) = crate::custody::persist_lock(dir) {
                    tracing::error!(%rollback, "unlock failed and the restart barrier could not be restored");
                }
                return Err(error);
            }
        }
        self.state.send_replace(VaultLockView::Unlocked);
        tracing::info!(holders = holders.len(), "vault unlocked");
        Ok(())
    }

    /// A holder joining a locked vault drops its keys at once.
    fn register(&self, holder: Arc<dyn VaultLockHolder>) {
        let vault = self.vault.lock().unwrap();
        if vault.is_locked() {
            holder.lock();
        }
        self.holders.lock().unwrap().push(holder);
    }
}

impl<S: IdentityStorage + 'static> VaultLockRequest for ResidentLock<S> {
    fn lock_vault(&self) -> Result<(), IdentityError> {
        self.lock()
    }
}

/// The secret-free profile and SSH key views of an unlocked vault.
fn public_views<S: IdentityStorage>(vault: &IdentityVault<S>) -> io::Result<KeptView> {
    let profile = vault.current_profile().map_err(io::Error::other)?;
    let current_id = profile.id.0.clone();
    let mut profiles: Vec<_> = vault
        .storage()
        .list_profiles()
        .unwrap_or_default()
        .into_iter()
        .map(|summary| ProfileView {
            selected: summary.id == profile.id,
            id: summary.id.0,
            display_name: summary.display_name,
            slot_count: summary.slot_count,
            master_public_fingerprint: "unknown until profile is selected".to_string(),
        })
        .collect();

    let master_fingerprint = format!(
        "blake3:{}",
        blake3::hash(&profile.master.public_key().to_bytes()).to_hex()
    );
    if let Some(current) = profiles.iter_mut().find(|entry| entry.selected) {
        current.master_public_fingerprint = master_fingerprint.clone();
    } else {
        profiles.push(ProfileView {
            id: current_id.clone(),
            display_name: profile.display_name.clone(),
            selected: true,
            slot_count: profile.slots.len(),
            master_public_fingerprint: master_fingerprint,
        });
    }
    profiles.sort_by(|left, right| left.id.cmp(&right.id));

    let mut ssh_keys = Vec::new();
    for slot in ssh_slot::ssh_slots(profile) {
        let source = profile
            .slots
            .get(&slot.key)
            .expect("ssh_slots only returns profile-owned slots");
        let lineage = source.lineage();
        ssh_keys.push(SshKeyView {
            profile: current_id.clone(),
            fingerprint: slot.fingerprint(),
            comment: slot.private.comment().to_string(),
            public_openssh: slot
                .public()
                .to_openssh()
                .unwrap_or_else(|_| "public key encoding unavailable".to_string()),
            lineage: lineage_label(lineage).to_string(),
            device_loss_note: lineage.device_loss_note().to_string(),
            unlock_policy: unlock_label(source.unlock_tier()),
        });
    }
    ssh_keys.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    Ok(KeptView { profiles, ssh_keys })
}

/// A locked vault with no view kept (never unlocked here): the vault's own
/// public profile, and no keys.
fn bare_view<S: IdentityStorage>(vault: &IdentityVault<S>) -> KeptView {
    let public = vault.public_profile();
    KeptView {
        profiles: vec![ProfileView {
            id: public.id.0.clone(),
            display_name: public.display_name.clone(),
            selected: true,
            slot_count: public.slots.len(),
            master_public_fingerprint: format!(
                "blake3:{}",
                blake3::hash(&public.master_public_key.to_bytes()).to_hex()
            ),
        }],
        ssh_keys: Vec::new(),
    }
}

impl<S: IdentityStorage + 'static> PersonaeHost<S> {
    /// A fresh per-connection SSH agent session over the resident vault.
    pub fn agent_session(&self) -> VaultAgent<S> {
        self.agent.clone()
    }

    /// Revoke one delegated device through pandect's live authority.
    pub fn revoke_device(
        &self,
        request: RevokeDeviceIntentV1,
    ) -> Result<DeviceRevocationReceipt, IdentityIntentError> {
        if !request.confirmed {
            return Err(IdentityIntentError::DeviceRevocationConfirmationRequired);
        }
        self.ensure_unlocked()?;
        let data_root = self
            .data_root
            .as_deref()
            .ok_or(IdentityIntentError::CarryUnavailable)?;
        let outcome = revoke_remote_auth_device(data_root, DeviceId::from_uuid(request.device_id))
            .map_err(|error| IdentityIntentError::DeviceRevocation(error.kind()))?;
        Ok(DeviceRevocationReceipt {
            device_id: outcome.device_id.as_uuid().to_string(),
            already_revoked: outcome.already_revoked,
            rotated_personas: outcome
                .rotated_personas
                .into_iter()
                .map(|persona| persona.as_uuid().to_string())
                .collect(),
            refreshed_devices: outcome
                .refreshed_devices
                .into_iter()
                .map(|device| device.as_uuid().to_string())
                .collect(),
        })
    }

    /// Secret-free Graphshell read model. While locked it reports Locked
    /// with the public view kept at lock time (ruling 11).
    pub fn snapshot(&self) -> std::io::Result<IdentitySurfaceSnapshot> {
        let vault = self.vault.lock().unwrap();
        let (lock, view) = match vault.is_locked() {
            true => (
                VaultLockView::Locked,
                self.lock
                    .kept
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| bare_view(&vault)),
            ),
            false => (VaultLockView::Unlocked, public_views(&vault)?),
        };
        drop(vault);

        let carry = match &self.data_root {
            Some(data_root) => load_carry_view(data_root)?,
            None => CarryView {
                unavailable: vec!["carry data root is not configured".to_string()],
                ..CarryView::default()
            },
        };

        Ok(IdentitySurfaceSnapshot {
            vault: VaultView {
                protection: self.protection,
                lock,
                agent: self.listener.lock().unwrap().clone(),
            },
            profiles: view.profiles,
            ssh_keys: view.ssh_keys,
            carry,
            pending_signing: self.approval.pending(),
            signing_history: self.approval.history(),
        })
    }

    /// Approve exactly one pending operation.
    /// Native composition only; projected intents never call this directly.
    pub fn approve_once(&self, request_id: Uuid) -> Result<(), DecisionError> {
        self.approval.decide(
            request_id,
            SigningDecision::Approve {
                remember: RememberApproval::Once,
            },
        )
    }

    /// Approve under the key's configured short idle window.
    pub fn approve_until_idle(&self, request_id: Uuid) -> Result<(), DecisionError> {
        self.approval.decide(
            request_id,
            SigningDecision::Approve {
                remember: RememberApproval::UntilIdle,
            },
        )
    }

    /// Deny one pending operation.
    pub fn deny(&self, request_id: Uuid) -> Result<(), DecisionError> {
        self.approval.decide(request_id, SigningDecision::Deny)
    }
}

impl<S: IdentityStorage + 'static> IdentityProvider for PersonaeHost<S> {
    fn master_public_key(&self) -> Ed25519PublicKey {
        IdentityProvider::master_public_key(&*self.vault.lock().unwrap())
    }

    fn derive_keypair(&self, salt: &[u8]) -> Result<Ed25519Keypair, IdentityError> {
        self.vault.lock().unwrap().derive_keypair(salt)
    }

    fn attest_derived_key(&self, salt: &[u8]) -> Result<DerivedKeyAttestation, IdentityError> {
        self.vault.lock().unwrap().attest_derived_key(salt)
    }
}

fn validate_comment(comment: &str) -> Result<(), IdentityIntentError> {
    if comment.chars().count() > 256 || comment.chars().any(char::is_control) {
        return Err(IdentityIntentError::InvalidComment);
    }
    Ok(())
}

fn unlock_tier(policy: SshUnlockPolicyIntentV1) -> Result<UnlockTier, IdentityIntentError> {
    match policy {
        SshUnlockPolicyIntentV1::Session => Ok(UnlockTier::Session),
        SshUnlockPolicyIntentV1::ShortTtl { idle_seconds }
            if (1..=MAX_SHORT_TTL_SECONDS).contains(&idle_seconds) =>
        {
            Ok(UnlockTier::ShortTtl { idle_seconds })
        },
        SshUnlockPolicyIntentV1::ShortTtl { .. } => Err(IdentityIntentError::InvalidIdleWindow),
        SshUnlockPolicyIntentV1::PerUse => Ok(UnlockTier::PerUse),
    }
}

fn lineage_label(lineage: CredentialLineage) -> &'static str {
    match lineage {
        CredentialLineage::LocallyDerived => "locally derived",
        CredentialLineage::LocallyGeneratedExternallyRegistered => {
            "locally generated, externally registered"
        },
        CredentialLineage::ExternallyIssued => "externally issued",
        CredentialLineage::ExternallyRootedLocallyHeld => "externally rooted, locally held",
    }
}

fn unlock_label(tier: UnlockTier) -> String {
    match tier {
        UnlockTier::Session => "session".to_string(),
        UnlockTier::ShortTtl { idle_seconds } => format!("{idle_seconds}s idle"),
        UnlockTier::PerUse => "every use".to_string(),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "authority_lock_tests.rs"]
mod lock_tests;

mod credentials;

mod profiles;

mod lifecycle;

mod listeners;
