// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The wallet's local root under the padlock (custody D8, D9 step one).
//!
//! The 32-byte root that keys the wallet's local sealed store is the
//! padlock's root, at `<data_root>/identity/wallet-root.padlock`. `AutoOs`
//! tries the padlock's OS slot at start; `Prompt` and `Locked` open nothing
//! until the user unlocks, and then the root is held for the session. A
//! candidate root is accepted only if it opens the wallet's existing sealed
//! records ("Existing sealed records must open"). A wallet with a legacy
//! auto-unlock root and no padlock keeps using it until the explicit
//! [`migrate_wallet_root_to_padlock`].
//!
//! The padlock's passphrase is its own: until step two it is not the vault's.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use personae::{SealedRecordStorage, StartupUnlockMode};
use serde::de::IgnoredAny;
use sporran::wallet_store::{
    identity_auto_unlock_root_path, identity_dir, identity_seed_path, local_device_identity_path,
};
use zeroize::Zeroizing;

use super::padlock_file::{padlock_error, read_padlock, remove_padlock, write_padlock};
use super::secrets::{io_backend_error, looks_like_sealed_record, wallet_startup_unlock_mode};
use crate::custody::os_kek::{OsKekStore, new_slot_id, os_kek_store};
use crate::custody::padlock::{Argon2Params, NewSlot, Padlock, SlotInfo, SlotInput, SlotKind};
use crate::custody::startup_unlock::refuse_if_persisted;
use crate::custody::{auto_unlock_provider, load_existing_auto_unlock_root};

/// The padlock file's name in the wallet's identity directory (OP 15).
pub const WALLET_PADLOCK_FILENAME: &str = "wallet-root.padlock";

type Root = Zeroizing<[u8; 32]>;

/// `<data_root>/identity/wallet-root.padlock`.
#[must_use]
pub fn wallet_padlock_path(data_root: &Path) -> PathBuf {
    identity_dir(data_root).join(WALLET_PADLOCK_FILENAME)
}

fn sessions() -> &'static Mutex<HashMap<PathBuf, Root>> {
    static SESSIONS: OnceLock<Mutex<HashMap<PathBuf, Root>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn session_active(data_root: &Path) -> bool {
    sessions()
        .lock()
        .map(|s| s.contains_key(data_root))
        .unwrap_or(false)
}

pub(super) fn set_session(data_root: &Path, root: Root) {
    if let Ok(mut s) = sessions().lock() {
        s.insert(data_root.to_path_buf(), root);
    }
}

pub(super) fn clear_session(data_root: &Path) {
    if let Ok(mut s) = sessions().lock() {
        s.remove(data_root);
    }
}

/// How the owner opens the padlock for an operation.
pub enum WalletUnlock<'a> {
    /// The padlock's OS slot for this platform's store.
    Os,
    /// One of its passphrase slots (normalised to NFC). Not the vault's
    /// passphrase: step two of custody D9 unifies them.
    Passphrase(&'a str),
}

/// The binding check: `root` opens the wallet's existing sealed records. A
/// wallet with none yet has nothing to check.
pub(super) fn records_open(data_root: &Path, root: &[u8; 32]) -> bool {
    let store = SealedRecordStorage::open_with_key(data_root, *root);
    for path in [
        identity_seed_path(data_root),
        local_device_identity_path(data_root),
    ] {
        if path.is_file() && looks_like_sealed_record(&path) {
            let Ok(relative) = path.strip_prefix(data_root) else {
                return false;
            };
            return matches!(store.load_record::<IgnoredAny>(relative), Ok(Some(_)));
        }
    }
    true
}

fn split_kid(kid: &str) -> (&str, &str) {
    kid.split_once('/').unwrap_or((kid, ""))
}

fn os_slots<'a>(
    padlock: &'a Padlock,
    store: &'a dyn OsKekStore,
) -> impl Iterator<Item = SlotInfo> + 'a {
    padlock
        .slots()
        .into_iter()
        .filter(move |s| s.kind == SlotKind::Kek && split_kid(&s.kid).0 == store.method())
}

/// Open `padlock` with `how`; `None` when it has no slot of that kind.
fn open(data_root: &Path, padlock: &Padlock, how: &WalletUnlock<'_>) -> io::Result<Option<Root>> {
    let verify = |root: &[u8; 32]| records_open(data_root, root);
    match how {
        WalletUnlock::Passphrase(phrase) => {
            match padlock.unlock(&SlotInput::Passphrase(phrase), verify) {
                Ok(root) => Ok(Some(root)),
                Err(crate::custody::padlock::PadlockError::NoMatchingSlot) => Ok(None),
                Err(error) => Err(padlock_error(error)),
            }
        },
        WalletUnlock::Os => {
            let Some(store) = os_kek_store(data_root) else {
                return Ok(None);
            };
            let mut last = None;
            for slot in os_slots(padlock, &*store) {
                let kek = store
                    .open(split_kid(&slot.kid).1, slot.os_blob.as_deref())
                    .map_err(io_backend_error)?;
                let input = SlotInput::Kek {
                    kid: &slot.kid,
                    kek: &kek,
                };
                match padlock.unlock(&input, verify) {
                    Ok(root) => return Ok(Some(root)),
                    Err(error) => last = Some(padlock_error(error)),
                }
            }
            last.map_or(Ok(None), Err)
        },
    }
}

/// Whether a wallet root may be created when none exists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    Create,
    Existing,
}

/// The root that keys the wallet's local sealed store this launch, if any.
pub(super) fn local_root(data_root: &Path, access: Access) -> io::Result<Option<Root>> {
    if let Some(root) = sessions()
        .lock()
        .ok()
        .and_then(|s| s.get(data_root).cloned())
    {
        return Ok(Some(root));
    }
    match wallet_startup_unlock_mode(data_root) {
        StartupUnlockMode::AutoOs => auto_root(data_root, access),
        StartupUnlockMode::Prompt | StartupUnlockMode::Locked => Ok(None),
    }
}

/// The unattended root: the padlock's OS slot, else a legacy auto-unlock
/// root as before, else (when allowed) a new padlock with one OS slot.
pub(super) fn auto_root(data_root: &Path, access: Access) -> io::Result<Option<Root>> {
    let path = wallet_padlock_path(data_root);
    refuse_if_persisted(&path).map_err(io_backend_error)?;
    if let Some(padlock) = read_padlock(&path)? {
        return open(data_root, &padlock, &WalletUnlock::Os);
    }
    let legacy = identity_auto_unlock_root_path(data_root);
    if legacy.exists() {
        return load_existing_auto_unlock_root(legacy)
            .map(|root| root.map(Zeroizing::new))
            .map_err(io_backend_error);
    }
    if access == Access::Existing {
        return Ok(None);
    }
    let Some(store) = os_kek_store(data_root) else {
        return Ok(None);
    };
    let root = random_root()?;
    create_padlock(data_root, &root, Some(&*store), None)?;
    Ok(Some(root))
}

fn random_root() -> io::Result<Root> {
    let mut root = Zeroizing::new([0u8; 32]);
    getrandom::fill(root.as_mut()).map_err(|_| io::Error::other("root randomness unavailable"))?;
    Ok(root)
}

fn next_pass_kid(padlock: Option<&Padlock>) -> String {
    let taken: Vec<String> = padlock
        .map(|p| p.slots().into_iter().map(|s| s.kid).collect())
        .unwrap_or_default();
    (1..)
        .map(|n| format!("pass/{n}"))
        .find(|kid| !taken.contains(kid))
        .unwrap_or_default()
}

/// A new padlock around `root` with an OS slot, a passphrase slot or both,
/// written and verified; a minted OS item is discarded if the write fails.
fn create_padlock(
    data_root: &Path,
    root: &[u8; 32],
    store: Option<&dyn OsKekStore>,
    passphrase: Option<&str>,
) -> io::Result<()> {
    let id = new_slot_id().map_err(io_backend_error)?;
    let os = store
        .map(|store| store.create(&id).map(|minted| (store, minted)))
        .transpose()
        .map_err(io_backend_error)?;
    let result = (|| {
        let kid = os
            .as_ref()
            .map(|(store, _)| format!("{}/{id}", store.method()));
        let pass_kid = next_pass_kid(None);
        let mut padlock = match (&os, &kid) {
            (Some((_, (kek, blob))), Some(kid)) => {
                let first = NewSlot::Kek {
                    kid,
                    kek,
                    os_blob: blob.as_deref(),
                };
                Padlock::create(root, &first).map_err(padlock_error)?
            },
            _ => {
                let phrase =
                    passphrase.ok_or_else(|| io::Error::other("a padlock needs a slot"))?;
                let first = NewSlot::Passphrase {
                    kid: &pass_kid,
                    passphrase: phrase,
                    params: Argon2Params::DEFAULT,
                };
                Padlock::create(root, &first).map_err(padlock_error)?
            },
        };
        if let (Some(phrase), Some((_, (kek, _))), Some(kid)) = (passphrase, &os, &kid) {
            let with = SlotInput::Kek { kid, kek };
            let new = NewSlot::Passphrase {
                kid: &pass_kid,
                passphrase: phrase,
                params: Argon2Params::DEFAULT,
            };
            padlock
                .add_slot(&with, |r| r == root, &new)
                .map_err(padlock_error)?;
        }
        write_padlock(&wallet_padlock_path(data_root), &padlock, |staged| {
            let opened = match (&os, &kid) {
                (Some((_, (kek, _))), Some(kid)) => {
                    staged.unlock(&SlotInput::Kek { kid, kek }, |r| r == root)
                },
                _ => staged.unlock(
                    &SlotInput::Passphrase(passphrase.unwrap_or_default()),
                    |r| r == root,
                ),
            };
            opened.map(drop).map_err(padlock_error)
        })
    })();
    if result.is_err()
        && let Some((store, _)) = &os
    {
        store.discard(&id);
    }
    result
}

/// First run in `Prompt` or `Locked`: a new padlock whose one slot is
/// `passphrase`, held open for this session. Refused if the wallet already
/// has a root. The passphrase is the padlock's, not the vault's.
///
/// # Errors
/// A root exists already, or the padlock could not be written.
pub fn create_wallet_padlock_with_passphrase(data_root: &Path, passphrase: &str) -> io::Result<()> {
    if wallet_padlock_path(data_root).exists() || identity_auto_unlock_root_path(data_root).exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the wallet already has a root",
        ));
    }
    let root = random_root()?;
    create_padlock(data_root, &root, None, Some(passphrase))?;
    set_session(data_root, root);
    Ok(())
}

/// Unlock the wallet for this session with one of the padlock's passphrase
/// slots. `Ok(false)` when there is no padlock or no passphrase slot.
///
/// # Errors
/// A wrong passphrase (`PermissionDenied`), a damaged padlock, or a root that
/// does not open the wallet's records.
pub fn unlock_wallet_with_passphrase(data_root: &Path, passphrase: &str) -> io::Result<bool> {
    let Some(padlock) = read_padlock(&wallet_padlock_path(data_root))? else {
        return Ok(false);
    };
    let Some(root) = open(data_root, &padlock, &WalletUnlock::Passphrase(passphrase))? else {
        return Ok(false);
    };
    set_session(data_root, root);
    Ok(true)
}

fn existing_padlock(data_root: &Path) -> io::Result<Padlock> {
    read_padlock(&wallet_padlock_path(data_root))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the wallet has no padlock"))
}

/// The padlock's slots: `kid` and kind, no secrets.
///
/// # Errors
/// No padlock, or a padlock the strict reader refuses.
pub fn wallet_padlock_slots(data_root: &Path) -> io::Result<Vec<SlotInfo>> {
    Ok(existing_padlock(data_root)?.slots())
}

/// The input that opened the padlock, re-derived for the slot it named.
fn opened(
    data_root: &Path,
    padlock: &Padlock,
    how: &WalletUnlock<'_>,
) -> io::Result<(Root, String, Option<Root>)> {
    let root = open(data_root, padlock, how)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no slot of that kind"))?;
    match how {
        WalletUnlock::Passphrase(phrase) => {
            let kid = padlock
                .opening_kid(&SlotInput::Passphrase(phrase))
                .map_err(padlock_error)?;
            Ok((root, kid, None))
        },
        WalletUnlock::Os => {
            let store = os_kek_store(data_root).ok_or_else(|| io::Error::other("no OS store"))?;
            for slot in os_slots(padlock, &*store) {
                let kek = store
                    .open(split_kid(&slot.kid).1, slot.os_blob.as_deref())
                    .map_err(io_backend_error)?;
                if padlock
                    .opening_kid(&SlotInput::Kek {
                        kid: &slot.kid,
                        kek: &kek,
                    })
                    .is_ok()
                {
                    return Ok((root, slot.kid, Some(kek)));
                }
            }
            Err(io::Error::other("the OS slot did not reopen"))
        },
    }
}

fn input<'a>(
    how: &'a WalletUnlock<'_>,
    kid: &'a str,
    kek: Option<&'a Root>,
) -> io::Result<SlotInput<'a>> {
    match (how, kek) {
        (WalletUnlock::Passphrase(phrase), _) => Ok(SlotInput::Passphrase(phrase)),
        (WalletUnlock::Os, Some(kek)) => Ok(SlotInput::Kek { kid, kek }),
        (WalletUnlock::Os, None) => Err(io::Error::other("the OS slot's key is not in hand")),
    }
}

/// Add a passphrase slot, opening the padlock with `with`. Returns its `kid`.
///
/// # Errors
/// The padlock does not open with `with`, or the write fails.
pub fn add_wallet_passphrase_slot(
    data_root: &Path,
    with: &WalletUnlock<'_>,
    passphrase: &str,
) -> io::Result<String> {
    let mut padlock = existing_padlock(data_root)?;
    let (root, kid, kek) = opened(data_root, &padlock, with)?;
    let new_kid = next_pass_kid(Some(&padlock));
    let new = NewSlot::Passphrase {
        kid: &new_kid,
        passphrase,
        params: Argon2Params::DEFAULT,
    };
    padlock
        .add_slot(&input(with, &kid, kek.as_ref())?, |r| r == &*root, &new)
        .map_err(padlock_error)?;
    write_padlock(&wallet_padlock_path(data_root), &padlock, |staged| {
        staged
            .unlock(&SlotInput::Passphrase(passphrase), |r| r == &*root)
            .map(drop)
            .map_err(padlock_error)
    })?;
    Ok(new_kid)
}

/// Add an OS slot for this platform's store. Returns its `kid`.
///
/// # Errors
/// No OS store, the padlock does not open with `with`, or the write fails.
pub fn add_wallet_os_slot(data_root: &Path, with: &WalletUnlock<'_>) -> io::Result<String> {
    let store = os_kek_store(data_root)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no OS store here"))?;
    let mut padlock = existing_padlock(data_root)?;
    let (root, kid, kek) = opened(data_root, &padlock, with)?;
    let id = new_slot_id().map_err(io_backend_error)?;
    let new_kid = format!("{}/{id}", store.method());
    let (new_kek, blob) = store.create(&id).map_err(io_backend_error)?;
    let result = (|| {
        let new = NewSlot::Kek {
            kid: &new_kid,
            kek: &new_kek,
            os_blob: blob.as_deref(),
        };
        padlock
            .add_slot(&input(with, &kid, kek.as_ref())?, |r| r == &*root, &new)
            .map_err(padlock_error)?;
        write_padlock(&wallet_padlock_path(data_root), &padlock, |staged| {
            let open = SlotInput::Kek {
                kid: &new_kid,
                kek: &new_kek,
            };
            staged
                .unlock(&open, |r| r == &*root)
                .map(drop)
                .map_err(padlock_error)
        })
    })();
    if let Err(error) = result {
        store.discard(&id);
        return Err(error);
    }
    Ok(new_kid)
}

/// Replace the passphrase slot `old` opens with one for `new`, in one write.
///
/// # Errors
/// `old` opens no slot, or the write fails.
pub fn change_wallet_passphrase(data_root: &Path, old: &str, new: &str) -> io::Result<()> {
    let mut padlock = existing_padlock(data_root)?;
    let with = WalletUnlock::Passphrase(old);
    let (root, old_kid, _) = opened(data_root, &padlock, &with)?;
    let new_kid = next_pass_kid(Some(&padlock));
    let slot = NewSlot::Passphrase {
        kid: &new_kid,
        passphrase: new,
        params: Argon2Params::DEFAULT,
    };
    padlock
        .add_slot(&SlotInput::Passphrase(old), |r| r == &*root, &slot)
        .map_err(padlock_error)?;
    padlock.remove_slot(&old_kid).map_err(padlock_error)?;
    write_padlock(&wallet_padlock_path(data_root), &padlock, |staged| {
        staged
            .unlock(&SlotInput::Passphrase(new), |r| r == &*root)
            .map(drop)
            .map_err(padlock_error)
    })
}

/// Remove the slot `kid`, then its OS item. This is not revocation: a copy of
/// the padlock file taken before still opens with the removed method.
///
/// # Errors
/// No such slot, it is the last one this reader can open, or the write fails.
pub fn remove_wallet_padlock_slot(data_root: &Path, kid: &str) -> io::Result<()> {
    let mut padlock = existing_padlock(data_root)?;
    let removed = padlock.slots().into_iter().find(|s| s.kid == kid);
    padlock.remove_slot(kid).map_err(padlock_error)?;
    write_padlock(&wallet_padlock_path(data_root), &padlock, |_| Ok(()))?;
    if let (Some(slot), Some(store)) = (removed, os_kek_store(data_root))
        && slot.kind == SlotKind::Kek
        && split_kid(&slot.kid).0 == store.method()
    {
        store.discard(split_kid(&slot.kid).1);
    }
    Ok(())
}

/// The explicit migration (OP 15): the legacy auto-unlock root goes under a
/// new padlock with this platform's OS slot (and `passphrase`'s slot, if
/// given); the padlock is verified to open and the wallet's records to open
/// under it; only then is the legacy root retired. Any failure leaves the
/// legacy root as it was and no padlock.
///
/// # Errors
/// A padlock exists already, there is no legacy root or no OS store, the root
/// does not open the records, or a write fails.
pub fn migrate_wallet_root_to_padlock(
    data_root: &Path,
    passphrase: Option<&str>,
) -> io::Result<()> {
    let path = wallet_padlock_path(data_root);
    if read_padlock(&path)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the wallet already has a padlock",
        ));
    }
    let legacy = identity_auto_unlock_root_path(data_root);
    if !legacy.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the wallet has no legacy root",
        ));
    }
    let store = os_kek_store(data_root)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no OS store here"))?;
    let root = load_existing_auto_unlock_root(&legacy)
        .map_err(io_backend_error)?
        .map(Zeroizing::new)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "the legacy root cannot be opened here",
            )
        })?;
    if !records_open(data_root, &root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the legacy root does not open the wallet's records",
        ));
    }
    create_padlock(data_root, &root, Some(&*store), passphrase)?;
    // Through the new padlock, as a reader will open it.
    let check = auto_reopen(data_root, &root);
    let retired = check.and_then(|()| retire_legacy_root(&legacy));
    if let Err(error) = retired {
        if let Ok(Some(padlock)) = read_padlock(&path) {
            for slot in os_slots(&padlock, &*store) {
                store.discard(split_kid(&slot.kid).1);
            }
        }
        remove_padlock(&path)?;
        return Err(error);
    }
    Ok(())
}

fn auto_reopen(data_root: &Path, root: &[u8; 32]) -> io::Result<()> {
    let padlock = existing_padlock(data_root)?;
    match open(data_root, &padlock, &WalletUnlock::Os)? {
        Some(opened) if *opened == *root => Ok(()),
        _ => Err(io::Error::other(
            "the new padlock did not reopen to the legacy root",
        )),
    }
}

/// Remove the legacy root file, and the provider item its marker names.
fn retire_legacy_root(legacy: &Path) -> io::Result<()> {
    #[derive(serde::Deserialize)]
    struct Marker {
        account: String,
    }
    let account = std::fs::read(legacy)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Marker>(&bytes).ok())
        .map(|marker| marker.account);
    std::fs::remove_file(legacy)?;
    if let (Some(account), Some(provider)) = (account, auto_unlock_provider::installed()) {
        provider.discard(&account);
    }
    Ok(())
}

#[cfg(test)]
#[path = "root_tests.rs"]
mod tests;
