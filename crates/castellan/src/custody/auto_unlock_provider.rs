// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A host-installed protected home for the local auto-unlock root.
//!
//! Windows wraps the root with DPAPI in `startup_unlock`. Where the OS offers
//! no such call to this crate (macOS), the process that owns custody installs
//! a provider that keeps the 32-byte root somewhere only that process can
//! read: the signed custodian's data-protection Keychain item, under its own
//! access group. The root file beside the wallet then holds no secret. It
//! names the backend and the item, so a missing item, a different backend or
//! a copied file is a refusal and never a silent new root: a downgrade, a
//! missing item or an access failure leaves the wallet locked.
//!
//! With no provider installed the answer stays `Ok(None)`, as before.

// Windows keeps its root through DPAPI and never asks a provider.
#![cfg_attr(windows, allow(dead_code))]

use std::path::Path;
use std::sync::{Arc, RwLock};

use personae::IdentityError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MARKER_VERSION: u8 = 1;

/// Where a platform keeps the auto-unlock root. Every failure, including a
/// missing item or a refused access, is an `Err`: the caller never falls back
/// to an unprotected root.
pub trait AutoUnlockRootProvider: Send + Sync {
    /// Recorded in the root file; a file written by another backend is refused.
    fn backend(&self) -> &'static str;
    /// Store a new root under `account`. Never replaces an existing item.
    fn create(&self, account: &str, root: &[u8; 32]) -> Result<(), IdentityError>;
    /// The root under `account`, `None` when the item does not exist.
    fn load(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, IdentityError>;
    /// Remove an item this process just created and could not record.
    fn discard(&self, account: &str);
}

static PROVIDER: RwLock<Option<Arc<dyn AutoUnlockRootProvider>>> = RwLock::new(None);

/// Install the process's provider. The custodian does this before it opens
/// anything; other castellan users never do, and keep the plain answer.
pub fn install_auto_unlock_provider(provider: Arc<dyn AutoUnlockRootProvider>) {
    *PROVIDER.write().unwrap_or_else(|e| e.into_inner()) = Some(provider);
}

/// Remove the provider (tests).
pub fn remove_auto_unlock_provider() {
    *PROVIDER.write().unwrap_or_else(|e| e.into_inner()) = None;
}

pub(super) fn installed() -> Option<Arc<dyn AutoUnlockRootProvider>> {
    PROVIDER.read().unwrap_or_else(|e| e.into_inner()).clone()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    backend: String,
    account: String,
}

fn backend_error(text: impl std::fmt::Display) -> IdentityError {
    IdentityError::Backend(text.to_string())
}

/// The root named by the file at `path`, created with its item when the file
/// is absent and `create` is set.
pub(super) fn load(path: &Path, create: bool) -> Result<Option<[u8; 32]>, IdentityError> {
    let Some(provider) = installed() else {
        return Ok(None);
    };
    if path.exists() {
        return existing(&*provider, path).map(Some);
    }
    if !create {
        return Ok(None);
    }
    let mut root = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *root).map_err(|_| backend_error("auto-unlock randomness unavailable"))?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| backend_error("auto-unlock randomness unavailable"))?;
    let account = blake3::hash(&id).to_hex().to_string();
    provider.create(&account, &root)?;
    let marker = Marker {
        version: MARKER_VERSION,
        backend: provider.backend().to_string(),
        account: account.clone(),
    };
    if let Err(error) = write_marker(path, &marker) {
        provider.discard(&account);
        return Err(error);
    }
    Ok(Some(*root))
}

fn existing(provider: &dyn AutoUnlockRootProvider, path: &Path) -> Result<[u8; 32], IdentityError> {
    let bytes = std::fs::read(path)
        .map_err(|e| backend_error(format!("read auto-unlock root {path:?}: {e}")))?;
    let marker: Marker = serde_json::from_slice(&bytes)
        .map_err(|e| backend_error(format!("parse auto-unlock root {path:?}: {e}")))?;
    if marker.version != MARKER_VERSION {
        return Err(backend_error(format!(
            "unsupported auto-unlock root version {} at {path:?}",
            marker.version
        )));
    }
    if marker.backend != provider.backend() {
        return Err(backend_error(format!(
            "auto-unlock root {path:?} names backend {}, not {}",
            marker.backend,
            provider.backend()
        )));
    }
    match provider.load(&marker.account)? {
        Some(root) => Ok(*root),
        None => Err(backend_error(format!(
            "the protected item for auto-unlock root {path:?} is missing"
        ))),
    }
}

fn write_marker(path: &Path, marker: &Marker) -> Result<(), IdentityError> {
    use std::io::Write;
    let bytes = serde_json::to_vec(marker).map_err(backend_error)?;
    let parent = path
        .parent()
        .ok_or_else(|| backend_error("auto-unlock path has no parent"))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| backend_error(format!("create {parent:?}: {e}")))?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| backend_error("auto-unlock randomness unavailable"))?;
    let temporary = parent.join(format!(
        ".auto-unlock-{}.tmp",
        blake3::hash(&nonce).to_hex()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(backend_error(format!(
            "write auto-unlock root {path:?}: {error}"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Serializes the tests that touch the process-wide provider.
    pub(crate) static SERIAL: Mutex<()> = Mutex::new(());

    #[derive(Default)]
    pub(crate) struct Memory {
        items: Mutex<HashMap<String, [u8; 32]>>,
        refuse: Mutex<bool>,
    }

    impl AutoUnlockRootProvider for Memory {
        fn backend(&self) -> &'static str {
            "memory"
        }
        fn create(&self, account: &str, root: &[u8; 32]) -> Result<(), IdentityError> {
            let mut items = self.items.lock().unwrap();
            if items.contains_key(account) {
                return Err(backend_error("duplicate item"));
            }
            items.insert(account.into(), *root);
            Ok(())
        }
        fn load(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, IdentityError> {
            if *self.refuse.lock().unwrap() {
                return Err(backend_error("access refused"));
            }
            Ok(self
                .items
                .lock()
                .unwrap()
                .get(account)
                .map(|root| Zeroizing::new(*root)))
        }
        fn discard(&self, account: &str) {
            self.items.lock().unwrap().remove(account);
        }
    }

    fn installed_memory() -> (Arc<Memory>, std::sync::MutexGuard<'static, ()>) {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let memory = Arc::new(Memory::default());
        install_auto_unlock_provider(memory.clone());
        (memory, guard)
    }

    #[test]
    fn the_root_lives_in_the_provider_and_the_file_holds_no_secret() {
        let (memory, _guard) = installed_memory();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-root.auto.json");
        assert_eq!(
            super::super::load_existing_auto_unlock_root(&path).unwrap(),
            None,
            "reading never creates"
        );
        assert!(!path.exists());
        let root = super::super::load_or_create_auto_unlock_root(&path)
            .unwrap()
            .unwrap();
        assert_ne!(root, [0u8; 32]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&root.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        assert_eq!(
            super::super::load_or_create_auto_unlock_root(&path).unwrap(),
            Some(root)
        );
        assert_eq!(
            super::super::load_existing_auto_unlock_root(&path).unwrap(),
            Some(root)
        );
        assert_eq!(
            memory.items.lock().unwrap().len(),
            1,
            "one item, not one per call"
        );
        assert!(super::super::auto_unlock_backend_available());
        remove_auto_unlock_provider();
    }

    #[test]
    fn a_missing_item_is_a_refusal_and_never_a_new_root() {
        let (memory, _guard) = installed_memory();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-root.auto.json");
        super::super::load_or_create_auto_unlock_root(&path)
            .unwrap()
            .unwrap();
        memory.items.lock().unwrap().clear();
        assert!(super::super::load_or_create_auto_unlock_root(&path).is_err());
        assert!(super::super::load_existing_auto_unlock_root(&path).is_err());
        assert!(
            memory.items.lock().unwrap().is_empty(),
            "nothing was minted to replace it"
        );
        remove_auto_unlock_provider();
    }

    #[test]
    fn an_access_failure_a_foreign_backend_and_a_changed_file_all_refuse() {
        let (memory, _guard) = installed_memory();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-root.auto.json");
        super::super::load_or_create_auto_unlock_root(&path)
            .unwrap()
            .unwrap();
        *memory.refuse.lock().unwrap() = true;
        assert!(super::super::load_existing_auto_unlock_root(&path).is_err());
        *memory.refuse.lock().unwrap() = false;
        let good = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, good.replace("memory", "dpapi")).unwrap();
        assert!(
            super::super::load_existing_auto_unlock_root(&path).is_err(),
            "another backend's file"
        );
        std::fs::write(
            &path,
            br#"{"version":1,"backend":"memory","account":"other"}"#,
        )
        .unwrap();
        assert!(
            super::super::load_existing_auto_unlock_root(&path).is_err(),
            "an item that is not there"
        );
        std::fs::write(&path, br#"{"version":2,"backend":"memory","account":"x"}"#).unwrap();
        assert!(super::super::load_existing_auto_unlock_root(&path).is_err());
        std::fs::write(
            &path,
            b"{\"version\":1,\"backend\":\"memory\",\"account\":\"x\",\"extra\":1}",
        )
        .unwrap();
        assert!(super::super::load_existing_auto_unlock_root(&path).is_err());
        remove_auto_unlock_provider();
    }

    #[test]
    fn a_marker_that_cannot_be_written_leaves_no_item() {
        let (memory, _guard) = installed_memory();
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::write(&blocked, b"a file where the directory should be").unwrap();
        assert!(super::super::load_or_create_auto_unlock_root(blocked.join("root.json")).is_err());
        assert!(memory.items.lock().unwrap().is_empty());
        remove_auto_unlock_provider();
    }

    #[test]
    fn the_persisted_lock_still_refuses_before_the_provider_is_asked() {
        let (_memory, _guard) = installed_memory();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-root.auto.json");
        super::super::load_or_create_auto_unlock_root(&path)
            .unwrap()
            .unwrap();
        super::super::persist_lock(dir.path()).unwrap();
        assert!(matches!(
            super::super::load_existing_auto_unlock_root(&path),
            Err(IdentityError::Locked)
        ));
        remove_auto_unlock_provider();
    }
}
