// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The envelope's at-rest claim, with an in-memory root provider standing in
//! for the Keychain (a process of its own: the provider is process-wide).
//! A legacy wallet's raw identity seed is sealed on its first read under the
//! provider's root, reads back the same, and without the provider is locked,
//! never raw. The native Keychain provider is qualified on the signed host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use castellan::custody::wallet::load_identity_seed;
use castellan::custody::{
    AutoUnlockRootProvider, install_auto_unlock_provider, remove_auto_unlock_provider,
};
use personae::IdentityError;
use zeroize::Zeroizing;

#[derive(Default)]
struct Memory(Mutex<HashMap<String, [u8; 32]>>);

impl AutoUnlockRootProvider for Memory {
    fn backend(&self) -> &'static str {
        "memory"
    }
    fn create(&self, account: &str, root: &[u8; 32]) -> Result<(), IdentityError> {
        self.0.lock().unwrap().insert(account.into(), *root);
        Ok(())
    }
    fn load(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, IdentityError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .map(|root| Zeroizing::new(*root)))
    }
    fn discard(&self, account: &str) {
        self.0.lock().unwrap().remove(account);
    }
}

#[test]
fn an_adopted_raw_seed_is_sealed_under_the_envelope_and_locked_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let seed = [0x42u8; 32];
    let path = sporran::wallet_store::identity_seed_path(root);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, seed).unwrap();

    // No envelope: the legacy raw seed reads as it always did.
    assert_eq!(load_identity_seed(root).unwrap(), Some(seed));
    assert_eq!(std::fs::read(&path).unwrap(), seed);

    let memory = Arc::new(Memory::default());
    install_auto_unlock_provider(memory.clone());
    assert_eq!(
        load_identity_seed(root).unwrap(),
        Some(seed),
        "first read under the envelope"
    );
    let at_rest = std::fs::read(&path).unwrap();
    assert_ne!(at_rest.len(), 32, "the seed is no longer 32 raw bytes");
    assert!(
        !at_rest.windows(32).any(|w| w == seed),
        "and its bytes are not in the file"
    );
    assert_eq!(
        load_identity_seed(root).unwrap(),
        Some(seed),
        "cold reopen from the sealed record"
    );
    assert_eq!(
        memory.0.lock().unwrap().len(),
        1,
        "one root, kept in the provider only"
    );

    // A process without the envelope (another user process, an unsigned copy)
    // reads nothing: the record is sealed and there is no raw fallback.
    remove_auto_unlock_provider();
    assert_eq!(load_identity_seed(root).unwrap(), None);

    // The provider losing the item is a refusal, never a fresh root over the seed.
    install_auto_unlock_provider(memory.clone());
    memory.0.lock().unwrap().clear();
    assert!(load_identity_seed(root).is_err());
    assert!(
        memory.0.lock().unwrap().is_empty(),
        "nothing was minted to replace the item"
    );
    remove_auto_unlock_provider();
}
