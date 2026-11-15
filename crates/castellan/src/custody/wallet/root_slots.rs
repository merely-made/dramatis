// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The owner's acts on the padlock's slots (padlock profile §4.3 to §4.6):
//! list, add a passphrase or OS slot, change the passphrase, remove a slot.

use std::io;
use std::path::Path;

use super::super::padlock_file::{padlock_error, write_padlock};
use super::super::secrets::io_backend_error;
use super::{
    Root, WalletUnlock, existing_padlock, next_pass_kid, open, os_slots, split_kid,
    wallet_padlock_path,
};
use crate::custody::os_kek::{new_slot_id, os_kek_store};
use crate::custody::padlock::{Argon2Params, NewSlot, Padlock, SlotInfo, SlotInput, SlotKind};

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
