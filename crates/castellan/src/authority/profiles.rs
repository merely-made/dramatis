// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<S: IdentityStorage + 'static> PersonaeHost<S> {
    /// Switch the resident vault to another persona, live.
    ///
    /// Everything sharing the vault follows from its next operation — the SSH
    /// agent holds the same `Arc<Mutex<IdentityVault>>`, so the next signing
    /// request is served from the new persona's slots with no restart
    /// anywhere. The choice is then remembered beside the vault so the rest
    /// of the family opens on it too; a host with no on-disk vault switches
    /// without remembering, and the receipt says which happened.
    pub fn switch_profile(
        &self,
        payload: SwitchProfileIntentV1,
    ) -> Result<ProfileSwitchReceipt, IdentityIntentError> {
        let id = ProfileId(payload.profile);
        {
            let mut vault = self.vault.lock().unwrap();
            vault.switch_profile(&id)?;
            self.lock.generation.fetch_add(1, Ordering::SeqCst);
        }
        // The kept sets follow the persona now speaking.
        let salts: Vec<Vec<Vec<u8>>> = self
            .retained
            .lock()
            .unwrap()
            .iter()
            .map(|kept| kept.salts())
            .collect();
        for set in salts {
            if let Err(error) = self.retained_keys(&set) {
                tracing::warn!(%error, "kept keys not recaptured after the switch");
            }
        }
        let remembered = match &self.vault_dir {
            Some(dir) => match roster::remember_profile(dir, &id) {
                Ok(()) => true,
                // The switch itself succeeded; a choice that could not be
                // written is worth saying, not worth unwinding.
                Err(error) => {
                    tracing::warn!(%error, profile = %id.0, "switched without remembering");
                    false
                },
            },
            None => false,
        };
        Ok(ProfileSwitchReceipt {
            profile: id.0,
            remembered,
        })
    }

    /// Mint a persona in the vault.
    ///
    /// **Does not switch to it.** Creating an identity and becoming it are
    /// separate decisions: a persona minted for another device or another
    /// purpose is not one the user is necessarily adopting, and the new card
    /// carries the ordinary switch action for when they are.
    ///
    /// The id is constrained rather than sanitized. It reaches a filename in
    /// `owner_settings::settings_path`, which replaces anything unsafe with
    /// `_`; accepting `a/b` here would mean it and `a_b` silently share one
    /// settings file. Refusing at the point of creation is the only place that
    /// cannot be worked around later.
    pub fn create_profile(
        &self,
        payload: CreateProfileIntentV1,
    ) -> Result<ProfileCreatedReceipt, IdentityIntentError> {
        let id = payload.id.trim();
        if id.is_empty()
            || id.chars().count() > 64
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(IdentityIntentError::InvalidProfileId);
        }
        let display_name = payload.display_name.trim();
        if display_name.is_empty()
            || display_name.chars().count() > 256
            || display_name.chars().any(char::is_control)
        {
            return Err(IdentityIntentError::InvalidProfileName);
        }
        // `roster::create_profile` refuses a taken id, which is the guard that
        // matters: minting over a persona would replace its master key and
        // every certificate rooted on it.
        let vault = self.vault.lock().unwrap();
        let profile =
            roster::create_profile(vault.storage(), &ProfileId(id.to_string()), display_name)?;
        Ok(ProfileCreatedReceipt {
            id: profile.id.0,
            display_name: profile.display_name,
            master_public_fingerprint: format!(
                "blake3:{}",
                blake3::hash(&profile.master.public_key().to_bytes()).to_hex()
            ),
        })
    }

    /// Execute a resident act while profile authority and vault lock are stable.
    /// The callback must never prompt or wait for user input.
    pub fn with_profile_authority<R>(
        &self,
        profile: &ProfileId,
        act: impl FnOnce() -> R,
    ) -> Result<R, IdentityError> {
        let vault = self.vault.lock().unwrap();
        vault.current_profile()?;
        vault.storage().load_profile(profile)?;
        Ok(act())
    }

    /// A bounded content operation admitted to the currently selected profile.
    /// Lock and profile switching wait for the operation to finish. The callback
    /// must not call back into this host, prompt, or perform network operations.
    pub fn with_current_profile_authority<R>(
        &self,
        profile: &ProfileId,
        expected_master: &[u8; 32],
        act: impl FnOnce() -> R,
    ) -> Result<R, IdentityError> {
        let vault = self.vault.lock().unwrap();
        let current = vault.current_profile()?;
        if vault.profile_id() != profile
            || current.master.public_key().to_bytes() != *expected_master
        {
            return Err(IdentityError::Backend(
                "retained-content profile changed".into(),
            ));
        }
        Ok(act())
    }

    /// The wallet and carry data root this host was composed with.
    pub fn data_root(&self) -> Option<&std::path::Path> {
        self.data_root.as_deref()
    }

    /// Sign `message` with the open persona's master under the host's lock.
    /// Only the independent custodian calls this, after its own consent; no
    /// master seed is returned.
    pub fn sign_with_master(&self, message: &[u8]) -> Result<([u8; 32], [u8; 64]), IdentityError> {
        let vault = self.vault.lock().unwrap();
        let master = &vault.current_profile()?.master;
        Ok((
            master.public_key().to_bytes(),
            master.sign(message).to_bytes(),
        ))
    }

    /// The persona currently spoken as.
    pub fn current_profile_id(&self) -> ProfileId {
        self.vault.lock().unwrap().profile_id().clone()
    }

    /// Whether the vault holds a persona `id`.
    pub fn has_profile(&self, id: &ProfileId) -> Result<bool, IdentityError> {
        let vault = self.vault.lock().unwrap();
        Ok(vault
            .storage()
            .list_profiles()?
            .iter()
            .any(|summary| &summary.id == id))
    }

    /// The persona whose master is `master`, if any. Refused while Locked.
    pub fn profile_holding(
        &self,
        master: &Ed25519PublicKey,
    ) -> Result<Option<ProfileId>, IdentityError> {
        if self.is_locked() {
            return Err(IdentityError::Locked);
        }
        let vault = self.vault.lock().unwrap();
        for summary in vault.storage().list_profiles()? {
            if vault
                .storage()
                .load_profile(&summary.id)?
                .master
                .public_key()
                == *master
            {
                return Ok(Some(summary.id));
            }
        }
        Ok(None)
    }

    /// Place an existing master in the vault as persona `id`, key unchanged,
    /// without switching to it: an application's own identity adopted into
    /// custody (dramatis D13). Refuses a taken id, as `create_profile` does.
    pub fn import_profile(
        &self,
        id: &ProfileId,
        display_name: &str,
        master: Ed25519Keypair,
    ) -> Result<(), IdentityError> {
        if self.is_locked() {
            return Err(IdentityError::Locked);
        }
        let vault = self.vault.lock().unwrap();
        roster::import_profile(vault.storage(), id, display_name, master).map(|_| ())
    }

    /// Run the terminal vault command inside the same lock boundary as the agent.
    /// No storage is reopened and no secret is returned to the application.
    pub fn vault_command(
        &self,
        profile: &ProfileId,
        command: &str,
        args: &[String],
    ) -> Result<VaultCommandOutput, IdentityIntentError> {
        let mut vault = self.vault.lock().unwrap();
        if vault.is_locked() {
            return Err(IdentityIntentError::Locked);
        }
        let valid_id = |id: &str| {
            !id.is_empty()
                && id.chars().count() <= 64
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        // New names follow the native create intent. Existing profile ids
        // remain addressable, including names created by older CLI versions.
        if command == "new-profile" && args.first().is_some_and(|id| !valid_id(id)) {
            return Err(IdentityIntentError::InvalidProfileId);
        }
        let mut output = Vec::new();
        let result = crate::custody::vault_commands::execute(
            vault.storage(),
            profile,
            &format!("{:?}", self.protection),
            command,
            args,
            &mut output,
        );
        // Slot changes must be visible to the live agent, not just the next restart.
        let selected = vault.profile_id().clone();
        vault.switch_profile(&selected)?;
        match result.map_err(IdentityIntentError::VaultCommand)? {
            Some(enrollment) => Ok(VaultCommandOutput::Enrollment {
                target: enrollment.target,
                script: enrollment.script,
                confirmation: enrollment.confirmation,
            }),
            None => String::from_utf8(output)
                .map(VaultCommandOutput::Text)
                .map_err(|error| IdentityIntentError::VaultCommand(error.to_string())),
        }
    }

    /// A provider for persona `id` without switching to it, for an
    /// application that speaks as a persona of its own (D13). Refused while
    /// Locked; it lives only as long as the caller's act.
    pub fn profile_provider(
        &self,
        id: &ProfileId,
    ) -> Result<personae::InMemoryProvider, IdentityError> {
        if self.is_locked() {
            return Err(IdentityError::Locked);
        }
        let vault = self.vault.lock().unwrap();
        let profile = vault.storage().load_profile(id)?;
        Ok(personae::InMemoryProvider::from_seed(
            profile.master.to_seed(),
        ))
    }

    /// Apply one typed action a card offered (graphshell's
    /// `identity_projection`, names in [`dramatis::intents`]).
    pub fn apply_intent(
        &self,
        intent: &str,
        payload: &[u8],
    ) -> Result<IdentityIntentOutcome, IdentityIntentError> {
        match intent {
            SIGNING_APPROVE_ONCE_INTENT | SIGNING_APPROVE_IDLE_INTENT | SIGNING_DENY_INTENT => {
                Err(IdentityIntentError::SigningDecisionNativeOnly)
            },
            SSH_GENERATE_INTENT => {
                let payload: GenerateSshKeyIntentV1 = serde_json::from_slice(payload)?;
                self.generate_ssh_key(payload)
                    .map(IdentityIntentOutcome::SshKeyMutation)
            },
            SSH_REMOVE_INTENT => {
                let payload: RemoveSshKeyIntentV1 = serde_json::from_slice(payload)?;
                self.remove_ssh_key(payload)
                    .map(IdentityIntentOutcome::SshKeyMutation)
            },
            SSH_IMPORT_NATIVE_INTENT => {
                let _: ImportSshKeyNativeIntentV1 = serde_json::from_slice(payload)?;
                Err(IdentityIntentError::NativeHandoffRequired)
            },
            DEVICE_REVOKE_INTENT => {
                let payload: RevokeDeviceIntentV1 = serde_json::from_slice(payload)?;
                self.revoke_device(payload)
                    .map(IdentityIntentOutcome::DeviceRevocation)
            },
            PROFILE_SWITCH_INTENT => {
                let payload: SwitchProfileIntentV1 = serde_json::from_slice(payload)?;
                self.switch_profile(payload)
                    .map(IdentityIntentOutcome::ProfileSwitch)
            },
            PROFILE_CREATE_INTENT => {
                let payload: CreateProfileIntentV1 = serde_json::from_slice(payload)?;
                self.create_profile(payload)
                    .map(IdentityIntentOutcome::ProfileCreated)
            },
            VAULT_LOCK_INTENT => {
                let _: LockVaultIntentV1 = serde_json::from_slice(payload)?;
                self.lock_vault()?;
                Ok(IdentityIntentOutcome::VaultLocked)
            },
            VAULT_UNLOCK_INTENT => Err(IdentityIntentError::UnlockNativeOnly),
            _ => Err(IdentityIntentError::UnknownIntent),
        }
    }
}
