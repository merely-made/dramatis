// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<S: IdentityStorage + 'static> PersonaeHost<S> {
    /// Generate an Ed25519 key entirely inside the resident authority.
    pub fn generate_ssh_key(
        &self,
        request: GenerateSshKeyIntentV1,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        validate_comment(&request.comment)?;
        let tier = unlock_tier(request.unlock_policy)?;
        let mut private = PrivateKey::random(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .map_err(|_| IdentityIntentError::KeyGeneration)?;
        private.set_comment(request.comment.as_str());
        self.store_ssh_private(private, tier, SshKeyMutationKind::Generated)
    }

    /// Store a key received directly from a native file picker.
    ///
    /// Callers pass the parsed key object, not serialized key bytes. This API
    /// is intentionally separate from `apply_intent`.
    pub fn import_ssh_private(
        &self,
        private: PrivateKey,
        options: ImportSshKeyNativeIntentV1,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        validate_comment(
            private
                .comment()
                .as_str()
                .map_err(|_| IdentityIntentError::InvalidComment)?,
        )?;
        let tier = unlock_tier(options.unlock_policy)?;
        self.store_ssh_private(private, tier, SshKeyMutationKind::Imported)
    }

    /// Import into a named CXF destination without changing the selected
    /// persona. Uses the native import's validation and held-key no-op.
    #[cfg(feature = "cxf")]
    pub fn import_ssh_private_for(
        &self,
        profile: &ProfileId,
        private: PrivateKey,
        options: ImportSshKeyNativeIntentV1,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        validate_comment(
            private
                .comment()
                .as_str()
                .map_err(|_| IdentityIntentError::InvalidComment)?,
        )?;
        let tier = unlock_tier(options.unlock_policy)?;
        self.store_ssh_private_in(Some(profile), private, tier, SshKeyMutationKind::Imported)
    }

    pub(super) fn store_ssh_private(
        &self,
        private: PrivateKey,
        tier: UnlockTier,
        operation: SshKeyMutationKind,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        self.store_ssh_private_in(None, private, tier, operation)
    }

    pub(super) fn store_ssh_private_in(
        &self,
        destination: Option<&ProfileId>,
        private: PrivateKey,
        tier: UnlockTier,
        operation: SshKeyMutationKind,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        let mut vault = self.vault.lock().unwrap();
        Self::store_ssh_private_held(&mut vault, destination, private, tier, operation)
    }

    #[cfg(feature = "cxf")]
    pub(crate) fn with_cxf_vault<R>(
        &self,
        act: impl FnOnce(&mut IdentityVault<S>) -> R,
    ) -> Result<R, IdentityError> {
        let mut vault = self.vault.lock().unwrap();
        vault.current_profile()?;
        Ok(act(&mut vault))
    }

    #[cfg(feature = "cxf")]
    pub(crate) fn import_ssh_private_for_held_vault(
        vault: &mut IdentityVault<S>,
        profile: &ProfileId,
        private: PrivateKey,
        options: ImportSshKeyNativeIntentV1,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        validate_comment(
            private
                .comment()
                .as_str()
                .map_err(|_| IdentityIntentError::InvalidComment)?,
        )?;
        let tier = unlock_tier(options.unlock_policy)?;
        Self::store_ssh_private_held(
            vault,
            Some(profile),
            private,
            tier,
            SshKeyMutationKind::Imported,
        )
    }

    pub(super) fn store_ssh_private_held(
        vault: &mut IdentityVault<S>,
        destination: Option<&ProfileId>,
        private: PrivateKey,
        tier: UnlockTier,
        operation: SshKeyMutationKind,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        let key = ssh_slot::protocol_key_for(&private);
        let public = PublicKey::from(&private);
        let fingerprint = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let public_openssh = public
            .to_openssh()
            .map_err(|_| IdentityIntentError::PublicEncoding)?;
        vault.current_profile()?;
        let destination = destination
            .cloned()
            .unwrap_or_else(|| vault.profile_id().clone());
        let mut other_profile = if &destination == vault.profile_id() {
            None
        } else {
            Some(vault.storage().load_profile(&destination)?)
        };
        // Ruling 54: a held key is never rewritten; the receipt describes the
        // slot as held, comment and tier included.
        let profile = other_profile.as_ref().unwrap_or(vault.current_profile()?);
        if let Some(held) = profile.slots.get(&key) {
            let held_private = ssh_slot::private_key_from_slot(held)?;
            return Ok(SshKeyMutationReceipt {
                operation,
                fingerprint,
                comment: held_private.comment().to_string(),
                public_openssh,
                unlock_policy: unlock_label(held.unlock_tier()),
                replaced_existing: true,
            });
        }
        // Ruling 56: only keys the agent can sign are taken in.
        crate::custody::ssh_sign::check_signable(private.key_data())
            .map_err(|refused| IdentityIntentError::UnsignableKey(refused.to_string()))?;
        let slot = ssh_slot::slot_for(&private, tier)?;
        let comment = private.comment().to_string();
        if &destination == vault.profile_id() {
            vault.add_slot(key, slot)?;
        } else {
            let profile = other_profile.as_mut().expect("named non-selected profile");
            profile.slots.insert(key, slot);
            vault.storage().save_profile(profile)?;
        }
        Ok(SshKeyMutationReceipt {
            operation,
            fingerprint,
            comment,
            public_openssh,
            unlock_policy: unlock_label(tier),
            replaced_existing: false,
        })
    }

    /// Remove one SSH slot only after the local UI confirms its fingerprint.
    pub fn remove_ssh_key(
        &self,
        request: RemoveSshKeyIntentV1,
    ) -> Result<SshKeyMutationReceipt, IdentityIntentError> {
        if !request.confirmed {
            return Err(IdentityIntentError::ConfirmationRequired);
        }
        let key = ProtocolKey::new(ssh_slot::SSH_MOD_ID, Some(request.fingerprint.clone()));
        let mut vault = self.vault.lock().unwrap();
        let Some(slot) = vault.current_profile()?.slots.get(&key) else {
            return Err(IdentityIntentError::KeyNotFound);
        };
        let private = ssh_slot::private_key_from_slot(slot)?;
        let public = PublicKey::from(&private);
        let receipt = SshKeyMutationReceipt {
            operation: SshKeyMutationKind::Removed,
            fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            comment: private.comment().to_string(),
            public_openssh: public
                .to_openssh()
                .map_err(|_| IdentityIntentError::PublicEncoding)?,
            unlock_policy: unlock_label(slot.unlock_tier()),
            replaced_existing: false,
        };
        vault.remove_slot(&key)?;
        Ok(receipt)
    }

    /// The private-lane payload sealer for one persona.
    ///
    /// Eidetic sits below the wallet and owns no keys, so its seal seam stays
    /// inert until a host supplies a `PayloadSealer`; its own header says
    /// landing the seam "changes no runtime behavior" for exactly that reason.
    /// This is the supply point. The keeper already holds the carry root, which
    /// is the only thing beyond the persona that building one needs, so no
    /// other component has to learn where the wallet lives.
    ///
    /// `None` twice over, and deliberately not an error either time: a host
    /// with no carry root has no wallet to seal under, and a persona with no
    /// staged epoch has nothing to seal with. Eidetic's own posture is that "a
    /// keyless host stays in the cleartext lane, which is a host policy
    /// decision, not this seam's to enforce", so the decision is returned to
    /// the caller rather than taken here. A caller that requires sealing
    /// refuses on `None`; one that does not writes cleartext, which is what
    /// every caller does today.
    pub fn payload_sealer(&self, persona: PersonaId) -> io::Result<Option<WalletEpochSealer>> {
        if self.is_locked() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the vault is locked",
            ));
        }
        let Some(data_root) = self.data_root.as_deref() else {
            return Ok(None);
        };
        epoch_sealer_for_persona(data_root, persona)
    }

    /// Capture authoritative request facts before displaying a native dialog.
    pub fn begin_native_signing(
        &self,
        request_id: Uuid,
    ) -> Result<NativeSigningContext, IdentityIntentError> {
        let vault = self.vault.lock().unwrap();
        if vault.is_locked() {
            return Err(IdentityIntentError::Locked);
        }
        let pending = self
            .approval
            .pending()
            .into_iter()
            .find(|p| p.request.request_id == request_id)
            .ok_or(DecisionError::NotPending)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        if pending.request.profile != vault.current_profile()?.id.0 || pending.expires_at_ms <= now
        {
            return Err(IdentityIntentError::StaleSigningConfirmation);
        }
        Ok(NativeSigningContext {
            pending,
            generation: self.lock.generation.load(Ordering::SeqCst),
        })
    }

    /// Called only after the resident-owned UI confirms the captured facts.
    /// Lock/profile transitions and expiry invalidate the confirmation.
    pub fn complete_native_signing(
        &self,
        context: NativeSigningContext,
        decision: SigningDecision,
    ) -> Result<(), IdentityIntentError> {
        let vault = self.vault.lock().unwrap();
        if vault.is_locked() {
            return Err(IdentityIntentError::Locked);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        if self.lock.generation.load(Ordering::SeqCst) != context.generation
            || context.pending.expires_at_ms <= now
            || vault.current_profile()?.id.0 != context.pending.request.profile
            || !self
                .approval
                .pending()
                .iter()
                .any(|p| p == &context.pending)
        {
            return Err(IdentityIntentError::StaleSigningConfirmation);
        }
        self.approval
            .decide(context.pending.request.request_id, decision)?;
        Ok(())
    }
}
