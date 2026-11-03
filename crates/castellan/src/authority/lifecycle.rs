// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<S: IdentityStorage + 'static> PersonaeHost<S> {
    /// Compose a resident host without taking over the standard agent endpoint.
    pub fn new(
        vault: IdentityVault<S>,
        data_root: Option<PathBuf>,
        protection: VaultProtectionView,
    ) -> Self {
        Self::with_decision_timeout(vault, data_root, protection, Duration::from_secs(120))
    }

    /// Constructor with a bounded timeout for tests and configured hosts.
    pub fn with_decision_timeout(
        vault: IdentityVault<S>,
        data_root: Option<PathBuf>,
        protection: VaultProtectionView,
        decision_timeout: Duration,
    ) -> Self {
        let initial = match vault.is_locked() {
            true => VaultLockView::Locked,
            false => VaultLockView::Unlocked,
        };
        let vault = Arc::new(Mutex::new(vault));
        let lock = Arc::new(ResidentLock {
            vault: Arc::clone(&vault),
            holders: Mutex::new(Vec::new()),
            state: watch::channel(initial).0,
            kept: Mutex::new(None),
            persisted: Mutex::new(None),
            generation: AtomicU64::new(0),
        });
        let approval = ApprovalBroker::new(decision_timeout);
        let agent =
            VaultAgent::from_shared_vault(Arc::clone(&vault), approval.clone(), "graphshell.ssh")
                .with_vault_lock(Arc::clone(&lock) as Arc<dyn VaultLockRequest>);
        Self {
            vault,
            agent,
            approval,
            data_root,
            protection,
            lock,
            listener: Arc::new(Mutex::new(AgentListenerView::StandaloneRetained)),
            retained: Mutex::new(Vec::new()),
            vault_dir: None,
        }
    }

    /// Name where the vault lives, so a profile switch also remembers the
    /// choice for the rest of the family.
    pub fn with_vault_dir(mut self, dir: PathBuf) -> Self {
        self.vault_dir = Some(dir);
        self
    }

    /// Keep the persisted lock in `dir`: every lock writes its marker and
    /// every unlock clears it, so a restart under a lock waits for a user act
    /// (rulings 5, 76, 80). Only the resident sets this; a host without it
    /// leaves nothing on disk.
    pub fn with_persisted_lock(self, dir: PathBuf) -> Self {
        *self.lock.persisted.lock().unwrap() = Some(dir);
        self
    }

    /// Lock the vault and every registered holder (ruling 1): when this
    /// returns, no holder keeps a vault-derived key. Refused while no unlock
    /// method is available (ruling 27). Any surface may ask.
    pub fn lock_vault(&self) -> Result<(), IdentityIntentError> {
        Ok(self.lock.lock()?)
    }

    /// Unlock by a user act on this resident's own surface; never reachable
    /// through an intent or the agent protocol (ruling 9). A wrong credential
    /// leaves everything locked.
    pub fn unlock_vault(&self, method: UnlockMethod<'_>) -> Result<(), IdentityIntentError> {
        Ok(self.lock.unlock(method)?)
    }

    /// The vault mutex serializes replacement with signing, writes and lock transitions.
    pub fn change_passphrase(
        &self,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), crate::custody::PassphraseChangeError> {
        self.vault.lock().unwrap().change_passphrase(old, new)
    }

    /// Whether the vault is locked.
    pub fn is_locked(&self) -> bool {
        self.vault.lock().unwrap().is_locked()
    }

    /// The lock state, for observers (ruling 31): a UI, the status route.
    pub fn lock_state(&self) -> watch::Receiver<VaultLockView> {
        self.lock.state.subscribe()
    }

    /// Have `holder` drop its keys with every lock and re-derive them with
    /// every unlock. Registered while locked, it locks at once.
    pub fn register_lock_holder(&self, holder: Arc<dyn VaultLockHolder>) {
        self.lock.register(holder);
    }

    /// A restricted provider for exactly `salts` that the lock leaves in
    /// place (rulings 40, 46): captured from the vault the first time it is
    /// asked for while unlocked, then served as kept, locked or not. It
    /// derives nothing else. Locked with nothing kept, it is `Locked`.
    pub fn retained_keys(&self, salts: &[Vec<u8>]) -> Result<Arc<RetainedKeys>, IdentityError> {
        let vault = self.vault.lock().unwrap();
        let master = IdentityProvider::master_public_key(&*vault);
        let mut retained = self.retained.lock().unwrap();
        if let Some(kept) = retained
            .iter()
            .find(|kept| kept.master_public_key() == master && kept.holds(salts))
        {
            return Ok(Arc::clone(kept));
        }
        let captured = Arc::new(RetainedKeys::capture(&*vault, salts)?);
        retained.retain(|kept| kept.master_public_key() == master);
        retained.push(Arc::clone(&captured));
        Ok(captured)
    }

    pub(super) fn ensure_unlocked(&self) -> Result<(), IdentityIntentError> {
        match self.is_locked() {
            true => Err(IdentityIntentError::Locked),
            false => Ok(()),
        }
    }
}
