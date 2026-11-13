// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! SSH agent backend serving the vault's `ssh` slots.
//!
//! V2 of the identity-vault-ssh-agent plan
//! ([`mere/design_docs/mere_docs/implementation_strategy/2026-07-22_identity-vault-ssh-agent_plan.md`](../../../../../design_docs/mere_docs/implementation_strategy/2026-07-22_identity-vault-ssh-agent_plan.md)):
//! a [`ssh_agent_lib::agent::Session`] implementation over an
//! [`IdentityVault`], so stock `ssh` / `ssh-add` use vault-held keys through
//! the standard agent protocol. The `personae-agent` bin is the thin
//! listener around this module.
//!
//! ## Slot shape
//!
//! [`crate::custody::ssh_slot`] owns it: a Direct `ssh` slot keyed by SHA256
//! fingerprint. `ssh-add <file>` is the import path — the OpenSSH client
//! reads the local file and hands the agent the private key, which lands
//! as a vault slot (encrypted at rest by whichever backend the vault
//! opened).
//!
//! ## Honest limits
//!
//! - Ed25519, ECDSA (P-256, P-384) and RSA sign, through [`crate::custody::ssh_sign`]:
//!   RSA by `ring`, `rsa-sha2-256` or `rsa-sha2-512` per the request's flags,
//!   2048 to 4096 bits; a flagless RSA request (`ssh-rsa`, SHA-1) is refused.
//!   `ssh-add` of anything else, P-521 included, is refused with the reason
//!   in the agent's log (the protocol carries none), and re-adding a held key
//!   changes nothing. A P-256 or P-384 key whose scalar `ssh-key` 0.6.7
//!   cannot decode fails inside `ssh-agent-lib`, before this agent sees it.
//! - A standalone agent built with [`VaultAgent::new`] still refuses
//!   [`UnlockTier::PerUse`]. A resident host may provide an
//!   [`ApprovalBroker`] to enforce visible per-use decisions and bounded
//!   short-TTL reuse.
//! - `session-bind@openssh.com` signatures are verified and acknowledged,
//!   and the verified host/session facts scope approval caching. OpenSSH
//!   destination constraints are not yet stored as key policy.
//! - Any local process may connect to the agent endpoint, same as stock
//!   ssh-agent (plan §threat-model note).
//!
//! ## While the vault is locked (vault lock rulings 8 and 9)
//!
//! OpenSSH's behaviour: no identities are listed; sign, add and remove fail,
//! each refusal logged with its reason (the protocol carries none).
//! `ssh-add -x` engages the resident's vault lock through
//! [`VaultLockRequest`]; its lock password is cleared and never used, since
//! hashing it would be our own mechanism. `ssh-add -X` is refused: unlocking
//! happens only on the resident's own surface.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::{QueryResponse, SessionBind};
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::proto::{
    AddIdentity, Extension, PrivateCredential, RemoveIdentity, SignRequest, message,
};
use ssh_key::HashAlg;
use ssh_key::Signature;
use ssh_key::certificate::Certificate;
use ssh_key::private::PrivateKey;
use ssh_key::public::PublicKey;

use crate::custody::broker::ApprovalBroker;
use crate::custody::ssh_face;
use crate::custody::ssh_krl;
use crate::custody::ssh_sign;
use crate::custody::ssh_slot::{self, SshSlot};
use crate::custody::vault::{IdentityStorage, IdentityVault, ProtocolKey, UnlockTier};
use personae::IdentityError;
use personae::enroll;
use personae::signing::{SigningFailureCode, SigningPolicy, SigningRecordResult, SigningRequest};
use personae::ssh_ca::{self, SshCertAuthority, UserCertRequest};

pub use crate::custody::ssh_slot::{SSH_MOD_ID, protocol_key_for};

/// What `ssh-add -x` engages (ruling 9): the resident's whole lock, so every
/// holder of a vault-derived key drops it before the agent answers.
pub trait VaultLockRequest: Send + Sync {
    /// Lock now; a refusal (ruling 27) is an error.
    fn lock_vault(&self) -> Result<(), IdentityError>;
}

/// The reason every locked refusal carries, in the log and the error.
const LOCKED: &str = "refused while the vault is locked";

/// Agent session over a shared vault.
///
/// Cloning shares the vault (one mutation surface, N protocol sessions),
/// which is what `ssh_agent_lib::agent::listen` needs from a session-per-
/// connection agent.
pub struct VaultAgent<S: IdentityStorage> {
    vault: Arc<Mutex<IdentityVault<S>>>,
    approval: Option<ApprovalBroker>,
    adapter: String,
    binding: Option<VerifiedSshBinding>,
    locker: Option<Arc<dyn VaultLockRequest>>,
}

#[derive(Clone)]
struct VerifiedSshBinding {
    target: String,
    session: String,
}

impl<S: IdentityStorage> Clone for VaultAgent<S> {
    fn clone(&self) -> Self {
        Self {
            vault: Arc::clone(&self.vault),
            approval: self.approval.clone(),
            adapter: self.adapter.clone(),
            binding: None,
            locker: self.locker.clone(),
        }
    }
}

impl<S: IdentityStorage> VaultAgent<S> {
    /// Wrap a vault for agent serving.
    pub fn new(vault: IdentityVault<S>) -> Self {
        Self {
            vault: Arc::new(Mutex::new(vault)),
            approval: None,
            adapter: "ssh-agent.local".to_string(),
            binding: None,
            locker: None,
        }
    }

    /// Let `ssh-add -x` engage `locker`. Without one, the lock message is
    /// refused, as before.
    pub fn with_vault_lock(mut self, locker: Arc<dyn VaultLockRequest>) -> Self {
        self.locker = Some(locker);
        self
    }

    fn is_locked(&self) -> bool {
        self.vault.lock().unwrap().is_locked()
    }

    /// The logged refusal for `operation` while locked.
    fn refuse_locked(operation: &str) -> AgentError {
        tracing::warn!(operation, "ssh agent {LOCKED}");
        std::io::Error::other(format!("{operation} {LOCKED}")).into()
    }

    /// Wrap a vault and route tiered signing through a visible approval broker.
    pub fn with_approval_broker(
        vault: IdentityVault<S>,
        approval: ApprovalBroker,
        adapter: impl Into<String>,
    ) -> Self {
        Self {
            vault: Arc::new(Mutex::new(vault)),
            approval: Some(approval),
            adapter: adapter.into(),
            binding: None,
            locker: None,
        }
    }

    /// Build an agent over a vault already shared with its resident host.
    pub fn from_shared_vault(
        vault: Arc<Mutex<IdentityVault<S>>>,
        approval: ApprovalBroker,
        adapter: impl Into<String>,
    ) -> Self {
        Self {
            vault,
            approval: Some(approval),
            adapter: adapter.into(),
            binding: None,
            locker: None,
        }
    }

    /// Share the vault with the resident host's public projection adapter.
    pub fn shared_vault(&self) -> Arc<Mutex<IdentityVault<S>>> {
        Arc::clone(&self.vault)
    }

    /// Approval broker used by this resident agent, when configured.
    pub fn approval_broker(&self) -> Option<&ApprovalBroker> {
        self.approval.as_ref()
    }

    /// Locked lists nothing (the vault answers `Locked`).
    fn ssh_identities(&self) -> Vec<SshSlot> {
        match self.vault.lock().unwrap().current_profile() {
            Ok(profile) => ssh_slot::ssh_slots(profile),
            Err(_) => Vec::new(),
        }
    }

    fn find_by_public(&self, wanted: &PublicKey) -> Option<SshSlot> {
        ssh_slot::find_by_public(self.vault.lock().unwrap().current_profile().ok()?, wanted)
    }

    /// Mint a login certificate for one identity from the vault's own
    /// authority, or `None` if this profile cannot currently issue one.
    ///
    /// Minted per listing rather than cached: it costs one Ed25519
    /// signature, and a certificate that is re-minted on demand can never
    /// be the stale one left over from a policy that has since narrowed.
    ///
    /// The vault is the provider: no copy of the master seed is made.
    fn certificate_for(&self, slot: &SshSlot) -> Option<Certificate> {
        let vault = self.vault.lock().unwrap();
        let profile = vault.current_profile().ok()?;
        let ca = SshCertAuthority::derive(&*vault).ok()?;
        let policy = ssh_face::effective_policy(profile).ok()?;
        let ledger = ssh_krl::load_ledger(profile).ok()?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        let grant = ssh_ca::self_grant(
            &*vault,
            enroll::local_device_id(),
            &policy.action_refs(),
            ssh_ca::MAX_CERT_TTL_MS,
            now_ms,
        )
        .ok()?;
        ca.mint_user_cert(
            &UserCertRequest {
                grant: &grant,
                subject: &PublicKey::from(&slot.private),
                principals: policy.principals.clone(),
                force_command: policy.force_command.clone(),
                source_address: policy.source_address.clone(),
                ledger: &ledger,
            },
            now_ms,
        )
        .ok()
    }
}

#[ssh_agent_lib::async_trait]
impl<S: IdentityStorage + 'static> Session for VaultAgent<S> {
    async fn request_identities(&mut self) -> Result<Vec<message::Identity>, AgentError> {
        // Each key is offered twice when it can be certified: the
        // certificate first, so a host that trusts the authority needs no
        // per-key enrollment, then the bare key, so a host that has only
        // ever seen the key still works. `sign` resolves both to the same
        // slot, because a credential's key_data is the key either way.
        let mut identities = Vec::new();
        if self.is_locked() {
            tracing::debug!("ssh agent lists no identities while the vault is locked");
            return Ok(identities);
        }
        for identity in self.ssh_identities() {
            let public = PublicKey::from(&identity.private);
            let comment = identity.private.comment().to_string();
            if let Some(certificate) = self.certificate_for(&identity) {
                identities.push(message::Identity {
                    credential: PublicCredential::Cert(Box::new(certificate)),
                    comment: format!("{comment} (personae certificate)"),
                });
            }
            identities.push(message::Identity {
                credential: public.key_data().clone().into(),
                comment,
            });
        }
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if self.is_locked() {
            return Err(Self::refuse_locked("sign"));
        }
        let wanted: PublicKey = request.credential.key_data().clone().into();
        let Some(identity) = self.find_by_public(&wanted) else {
            return Err(std::io::Error::other("identity not found in vault").into());
        };
        // Only the slot's public facts wait out an approval; the private key
        // is fetched again afterwards, so a lock meanwhile refuses the sign.
        let (fingerprint, tier, key) = (identity.fingerprint(), identity.tier, identity.key);
        drop(identity.private);
        let authorization = if let Some(approval) = self.approval.clone() {
            let profile = self.vault.lock().unwrap().profile_id().0.clone();
            let mut signing_request = SigningRequest::new(
                profile,
                fingerprint,
                "ssh.sign",
                request.data.as_slice(),
                self.adapter.clone(),
            );
            if let Some(binding) = &self.binding {
                signing_request = signing_request
                    .with_authenticated_target(binding.target.clone())
                    .with_session_binding(binding.session.clone());
            }
            Some(
                approval
                    .authorize(signing_request, SigningPolicy::from(tier))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
            )
        } else if tier == UnlockTier::PerUse {
            tracing::warn!(?key, "per-use slot refused: no confirmation UI yet");
            return Err(std::io::Error::other(
                "per-use slot refused: the agent has no confirmation UI yet",
            )
            .into());
        } else {
            None
        };
        let identity = match self.is_locked() {
            true => Err(Self::refuse_locked("sign")),
            false => self
                .find_by_public(&wanted)
                .ok_or_else(|| std::io::Error::other("identity not found in vault").into()),
        };
        let identity = match identity {
            Ok(identity) => identity,
            Err(error) => {
                if let (Some(approval), Some(authorization)) = (&self.approval, authorization) {
                    approval.complete(
                        authorization,
                        SigningRecordResult::Failed {
                            code: SigningFailureCode::AdapterFailure,
                        },
                    );
                }
                return Err(error);
            },
        };
        tracing::info!(?key, flags = request.flags, "signing request");
        let signed = ssh_sign::sign(
            identity.private.key_data(),
            request.data.as_slice(),
            request.flags,
        )
        .map_err(AgentError::other);
        if let Ok(signature) = &signed {
            tracing::info!(?key, algorithm = %signature.algorithm(), "signed");
        }
        if let (Some(approval), Some(authorization)) = (&self.approval, authorization) {
            let result = match &signed {
                Ok(signature) => SigningRecordResult::Signed {
                    signature_ref: format!(
                        "blake3:{}",
                        blake3::hash(signature.as_bytes()).to_hex()
                    ),
                },
                Err(_) => SigningRecordResult::Failed {
                    code: SigningFailureCode::AdapterFailure,
                },
            };
            approval.complete(authorization, result);
        }
        signed
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if self.is_locked() {
            return Err(Self::refuse_locked("add identity"));
        }
        let PrivateCredential::Key { privkey, comment } = identity.credential else {
            return Err(std::io::Error::other("unsupported credential type").into());
        };
        let mut private = PrivateKey::try_from(privkey).map_err(AgentError::other)?;
        if private.comment().is_empty() && !comment.is_empty() {
            private.set_comment(comment.as_str());
        }
        let key = ssh_slot::protocol_key_for(&private);
        let mut vault = self.vault.lock().unwrap();
        // Ruling 54: a held key is never rewritten, its tier included.
        if vault
            .current_profile()
            .map_err(AgentError::other)?
            .slots
            .contains_key(&key)
        {
            tracing::info!(?key, "ssh identity already held; left untouched");
            return Ok(());
        }
        // Ruling 56: only keys the agent can sign are taken in.
        if let Err(refused) = ssh_sign::check_signable(private.key_data()) {
            tracing::warn!(?key, %refused, "ssh identity refused");
            return Err(AgentError::other(refused));
        }
        let slot = ssh_slot::slot_for(&private, UnlockTier::Session).map_err(AgentError::other)?;
        tracing::info!(?key, "adding ssh identity to vault");
        vault.add_slot(key, slot).map_err(AgentError::other)
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        if self.is_locked() {
            return Err(Self::refuse_locked("remove identity"));
        }
        let wanted: PublicKey = identity.credential.key_data().clone().into();
        let Some(found) = self.find_by_public(&wanted) else {
            return Err(std::io::Error::other("identity not found in vault").into());
        };
        tracing::info!(key = ?found.key, "removing ssh identity from vault");
        self.vault
            .lock()
            .unwrap()
            .remove_slot(&found.key)
            .map_err(AgentError::other)?;
        Ok(())
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        match extension.name.as_str() {
            "query" => {
                let response = Extension::new_message(QueryResponse {
                    extensions: vec!["query".into(), "session-bind@openssh.com".into()],
                })?;
                Ok(Some(response))
            },
            // Modern OpenSSH binds each connection to a host session. v1
            // verifies the binding signature and acknowledges; per-session
            // key restrictions (the constraint half) are not enforced yet.
            "session-bind@openssh.com" => match extension.parse_message::<SessionBind>()? {
                Some(bind) => {
                    bind.verify_signature()
                        .map_err(|_| AgentError::ExtensionFailure)?;
                    self.binding = Some(VerifiedSshBinding {
                        target: format!(
                            "ssh-host-key:{}",
                            bind.host_key.fingerprint(HashAlg::Sha256)
                        ),
                        session: format!(
                            "blake3:{};forwarding={}",
                            blake3::hash(&bind.session_id).to_hex(),
                            bind.is_forwarding
                        ),
                    });
                    tracing::debug!("session-bind acknowledged");
                    Ok(None)
                },
                None => Err(AgentError::Failure),
            },
            other => {
                tracing::debug!(extension = other, "unsupported extension");
                Err(AgentError::ExtensionFailure)
            },
        }
    }

    /// `ssh-add -x`: engage the resident's vault lock. The password is
    /// cleared unread. Locking a locked agent fails, as OpenSSH's does.
    async fn lock(&mut self, mut password: String) -> Result<(), AgentError> {
        zeroize::Zeroize::zeroize(&mut password);
        let Some(locker) = self.locker.clone() else {
            tracing::warn!("ssh agent lock refused: this agent has no vault lock to engage");
            return Err(std::io::Error::other("this agent has no vault lock to engage").into());
        };
        if self.is_locked() {
            tracing::warn!("ssh agent lock refused: the vault is already locked");
            return Err(std::io::Error::other("the vault is already locked").into());
        }
        match locker.lock_vault() {
            Ok(()) => {
                tracing::info!("vault locked over the ssh agent protocol");
                Ok(())
            },
            Err(error) => {
                tracing::warn!(%error, "ssh agent lock refused");
                Err(AgentError::other(error))
            },
        }
    }

    /// `ssh-add -X` is refused over the wire (ruling 9): unlocking happens
    /// only on the resident's own surface.
    async fn unlock(&mut self, mut password: String) -> Result<(), AgentError> {
        zeroize::Zeroize::zeroize(&mut password);
        tracing::warn!("ssh agent unlock refused: unlock on the resident's own surface");
        Err(std::io::Error::other("unlock over the agent protocol is refused").into())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        if self.is_locked() {
            return Err(Self::refuse_locked("remove all identities"));
        }
        let keys: Vec<ProtocolKey> = self
            .ssh_identities()
            .into_iter()
            .map(|identity| identity.key)
            .collect();
        tracing::info!(count = keys.len(), "removing all ssh identities from vault");
        let mut vault = self.vault.lock().unwrap();
        for key in keys {
            vault.remove_slot(&key).map_err(AgentError::other)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
