// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Where a padlock KEK slot's key lives (padlock profile §3.6, custody D8).
//!
//! An [`OsKekStore`] mints a random 32-byte KEK for a new slot and gives it
//! back when the slot is opened. Windows keeps it as a user-scope DPAPI blob
//! inside the slot. Elsewhere it is an item of the host-installed
//! [`AutoUnlockRootProvider`] (the macOS custodian's Keychain envelope), named
//! by the slot's id. A store installed for one data root overrides both, which
//! is how tests and hosts without an OS store supply one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use personae::IdentityError;
use zeroize::Zeroizing;

use super::auto_unlock_provider::{self, AutoUnlockRootProvider};

/// A new slot's KEK and the opaque blob to keep in the slot.
pub type Minted = (Zeroizing<[u8; 32]>, Option<Vec<u8>>);

/// An OS-held home for padlock KEKs. Every failure is an `Err`; a missing
/// item is never a new key.
pub trait OsKekStore: Send + Sync {
    /// The slot's `kid` method: `dpapi`, `keychain` or `secsvc`.
    fn method(&self) -> &'static str;
    /// A new random KEK for slot `id`, and the opaque blob to keep in the slot.
    ///
    /// # Errors
    /// The store refused or is unavailable.
    fn create(&self, id: &str) -> Result<Minted, IdentityError>;
    /// The KEK of slot `id`.
    ///
    /// # Errors
    /// The item is missing, locked or refused.
    fn open(&self, id: &str, blob: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>, IdentityError>;
    /// Remove slot `id`'s item, if the store keeps one.
    fn discard(&self, id: &str);
}

fn error(text: impl std::fmt::Display) -> IdentityError {
    IdentityError::Backend(text.to_string())
}

fn random_kek() -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut kek = Zeroizing::new([0u8; 32]);
    getrandom::fill(kek.as_mut()).map_err(|_| error("KEK randomness unavailable"))?;
    Ok(kek)
}

/// A fresh slot id: 16 random hex digits.
///
/// # Errors
/// The OS random number generator failed.
pub fn new_slot_id() -> Result<String, IdentityError> {
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).map_err(|_| error("slot id randomness unavailable"))?;
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn to_kek(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut kek = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err(error("the stored KEK is not 32 bytes"));
    }
    kek.copy_from_slice(bytes);
    Ok(kek)
}

/// User-scope DPAPI (OP 11): the KEK's DPAPI blob is the slot's `pl-os-blob`.
#[cfg(windows)]
pub struct Dpapi;

#[cfg(windows)]
impl OsKekStore for Dpapi {
    fn method(&self) -> &'static str {
        "dpapi"
    }
    fn create(&self, _id: &str) -> Result<Minted, IdentityError> {
        let kek = random_kek()?;
        let blob = super::startup_unlock::dpapi_protect(kek.as_ref())?;
        Ok((kek, Some(blob)))
    }
    fn open(&self, _id: &str, blob: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let blob = blob.ok_or_else(|| error("the DPAPI slot carries no blob"))?;
        to_kek(&super::startup_unlock::dpapi_unprotect(blob)?)
    }
    fn discard(&self, _id: &str) {}
}

/// A host-installed provider's items, one per slot id.
pub struct Provider(pub Arc<dyn AutoUnlockRootProvider>);

impl OsKekStore for Provider {
    fn method(&self) -> &'static str {
        self.0.slot_method()
    }
    fn create(&self, id: &str) -> Result<Minted, IdentityError> {
        let kek = random_kek()?;
        self.0.create(id, &kek)?;
        Ok((kek, None))
    }
    fn open(&self, id: &str, _blob: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        self.0
            .load(id)?
            .ok_or_else(|| error(format!("the protected item for slot {id} is missing")))
    }
    fn discard(&self, id: &str) {
        self.0.discard(id);
    }
}

fn overrides() -> &'static Mutex<HashMap<PathBuf, Arc<dyn OsKekStore>>> {
    static STORES: OnceLock<Mutex<HashMap<PathBuf, Arc<dyn OsKekStore>>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Use `store` for the wallet under `data_root` in this process, in place of
/// the platform's. For tests and for hosts that supply their own OS store.
pub fn install_os_kek_store(data_root: &Path, store: Arc<dyn OsKekStore>) {
    if let Ok(mut stores) = overrides().lock() {
        stores.insert(data_root.to_path_buf(), store);
    }
}

/// Drop the store installed for `data_root`.
pub fn remove_os_kek_store(data_root: &Path) {
    if let Ok(mut stores) = overrides().lock() {
        stores.remove(data_root);
    }
}

/// The store for `data_root`: an installed one, else the platform's.
#[must_use]
pub fn os_kek_store(data_root: &Path) -> Option<Arc<dyn OsKekStore>> {
    let installed = overrides()
        .lock()
        .ok()
        .and_then(|stores| stores.get(data_root).cloned());
    installed.or_else(platform_default)
}

// Windows returns DPAPI; the provider line after it is type-checked here too,
// so the code other platforms run is compiled on every platform.
#[cfg_attr(windows, allow(unreachable_code))]
fn platform_default() -> Option<Arc<dyn OsKekStore>> {
    #[cfg(windows)]
    return Some(Arc::new(Dpapi));
    auto_unlock_provider::installed().map(|p| Arc::new(Provider(p)) as Arc<dyn OsKekStore>)
}

/// An in-memory store, for tests and examples that need no OS store. A test
/// installs it for its data root with [`install_os_kek_store`]. It does not
/// reach a child process.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub struct MemoryOsKek {
    items: Mutex<HashMap<String, [u8; 32]>>,
}

#[cfg(any(test, feature = "test-support"))]
impl OsKekStore for MemoryOsKek {
    fn method(&self) -> &'static str {
        "keychain"
    }
    fn create(&self, id: &str) -> Result<Minted, IdentityError> {
        let kek = random_kek()?;
        let mut items = self.items.lock().map_err(|_| error("poisoned"))?;
        if items.contains_key(id) {
            return Err(error("duplicate item"));
        }
        items.insert(id.to_string(), *kek);
        Ok((kek, None))
    }
    fn open(&self, id: &str, _blob: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let items = self.items.lock().map_err(|_| error("poisoned"))?;
        items
            .get(id)
            .map(|kek| Zeroizing::new(*kek))
            .ok_or_else(|| error(format!("the item for slot {id} is missing")))
    }
    fn discard(&self, id: &str) {
        if let Ok(mut items) = self.items.lock() {
            items.remove(id);
        }
    }
}
