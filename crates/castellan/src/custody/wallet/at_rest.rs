// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Wallet secrets at rest (custody D5, 2026-11-14: "Refuse; never write or
//! read raw"). A secret is saved only into a sealed store and read only from
//! one. A raw legacy file is refused, never read, until the explicit
//! [`migrate_legacy_wallet_secrets`] seals it under a store that exists.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use personae::{PersonaId, SealedRecordStorage};
use sporran::PERSONAS_DIR;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::secrets::{
    io_backend_error, looks_like_sealed_record, wallet_local_secret_store,
    wallet_persona_secret_store, wallet_secret_store,
};
use super::{LocalDeviceIdentity, PersonaEpochBridge, RemoteAuthWrappingKeyBridge};
use sporran::wallet_store::{
    identity_seed_path, local_device_identity_path, persona_epoch_bridge_path,
    remote_auth_wrapping_keys_path, save_bytes_atomic,
};

/// Why a wallet secret was refused at rest. Carried inside the `io::Error`
/// the wallet functions return; [`WalletSecretRefusal::of`] reads it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletSecretRefusal {
    /// No sealed store is open for this secret, so nothing was written.
    NoSealedStore {
        /// Which secret was refused.
        secret: &'static str,
    },
    /// The file is a raw legacy secret, which is never read as one.
    LegacyRaw {
        /// The raw file, left as it was.
        path: PathBuf,
    },
}

impl WalletSecretRefusal {
    /// The refusal inside `error`, if it carries one.
    pub fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

impl fmt::Display for WalletSecretRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSealedStore { secret } => write!(
                f,
                "no sealed store is open for the wallet's {secret}; it is never written raw"
            ),
            Self::LegacyRaw { path } => write!(
                f,
                "{path:?} holds a raw legacy wallet secret, which is never read raw; \
                 run migrate_legacy_wallet_secrets once a sealed store exists"
            ),
        }
    }
}

impl std::error::Error for WalletSecretRefusal {}

impl From<WalletSecretRefusal> for io::Error {
    fn from(refusal: WalletSecretRefusal) -> Self {
        let kind = match refusal {
            WalletSecretRefusal::NoSealedStore { .. } => io::ErrorKind::PermissionDenied,
            WalletSecretRefusal::LegacyRaw { .. } => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, refusal)
    }
}

pub(super) fn no_sealed_store(secret: &'static str) -> io::Error {
    WalletSecretRefusal::NoSealedStore { secret }.into()
}

/// Refuse an existing file that is not a sealed record.
pub(super) fn refuse_raw(path: &Path) -> io::Result<()> {
    if looks_like_sealed_record(path) {
        return Ok(());
    }
    Err(WalletSecretRefusal::LegacyRaw {
        path: path.to_path_buf(),
    }
    .into())
}

fn is_raw(path: &Path) -> bool {
    path.is_file() && !looks_like_sealed_record(path)
}

/// Seal every raw legacy wallet secret under `data_root`, returning the
/// files sealed. The explicit migration custody D5 allows, and the only one.
///
/// In order: the identity seed and the delegated-device identity under the
/// local store, then each persona's private-epoch bridge and the remote-auth
/// wrapping keys under the seed's store. Each raw file is read, sealed in
/// place, and read back; only an equal read-back leaves the sealed record,
/// otherwise the raw bytes are put back and the error returned. A secret whose
/// store does not exist is refused with nothing changed.
pub fn migrate_legacy_wallet_secrets(data_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut sealed = Vec::new();
    let seed_path = identity_seed_path(data_root);
    if is_raw(&seed_path) {
        let store = wallet_local_secret_store(data_root)?
            .ok_or_else(|| no_sealed_store("identity seed"))?;
        let raw = Zeroizing::new(std::fs::read(&seed_path)?);
        let seed = Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy identity seed at {seed_path:?} is not 32 raw bytes"),
            )
        })?);
        seal_verified(&store, data_root, &seed_path, &raw, &*seed)?;
        sealed.push(seed_path);
    }
    let device_path = local_device_identity_path(data_root);
    if is_raw(&device_path) {
        let store = wallet_local_secret_store(data_root)?
            .ok_or_else(|| no_sealed_store("delegated-device identity"))?;
        migrate_json::<LocalDeviceIdentity>(&store, data_root, &device_path)?;
        sealed.push(device_path);
    }
    for persona in persona_dirs(data_root)? {
        let path = persona_epoch_bridge_path(data_root, persona);
        if is_raw(&path) {
            let store = wallet_persona_secret_store(data_root)?
                .ok_or_else(|| no_sealed_store("private-epoch bridge"))?;
            migrate_json::<PersonaEpochBridge>(&store, data_root, &path)?;
            sealed.push(path);
        }
    }
    let keys_path = remote_auth_wrapping_keys_path(data_root);
    if is_raw(&keys_path) {
        let store =
            wallet_secret_store(data_root)?.ok_or_else(|| no_sealed_store("remote-auth wrapping keys"))?;
        migrate_json::<RemoteAuthWrappingKeyBridge>(&store, data_root, &keys_path)?;
        sealed.push(keys_path);
    }
    Ok(sealed)
}

/// Every raw legacy wallet secret under `data_root`: each file of a kind
/// [`migrate_legacy_wallet_secrets`] handles that is not a sealed record.
///
/// # Errors
/// The persona directory cannot be read.
pub fn raw_legacy_wallet_secrets(data_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = vec![identity_seed_path(data_root), local_device_identity_path(data_root)];
    for persona in persona_dirs(data_root)? {
        paths.push(persona_epoch_bridge_path(data_root, persona));
    }
    paths.push(remote_auth_wrapping_keys_path(data_root));
    Ok(paths.into_iter().filter(|path| is_raw(path)).collect())
}

/// Whether `path` holds a sealed record (not a raw legacy secret).
#[must_use]
pub fn is_sealed_wallet_record(path: &Path) -> bool {
    looks_like_sealed_record(path)
}

/// Whether the sealed secret at `path` under `data_root` holds what the raw
/// legacy bytes `raw` held. Its store must be open (for example inside
/// `with_wallet_unlocked`).
///
/// # Errors
/// The sealed record cannot be read, or `raw` does not parse as its kind.
pub fn sealed_secret_matches_raw(data_root: &Path, path: &Path, raw: &[u8]) -> io::Result<bool> {
    fn parse<T: DeserializeOwned>(raw: &[u8]) -> io::Result<T> {
        serde_json::from_slice(raw).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
    if path == identity_seed_path(data_root) {
        return Ok(super::secrets::load_identity_seed(data_root)?.is_some_and(|seed| seed.as_slice() == raw));
    }
    if path == local_device_identity_path(data_root) {
        let sealed = super::devices::load_local_device_identity(data_root)?;
        return Ok(sealed == Some(parse::<LocalDeviceIdentity>(raw)?));
    }
    if path == remote_auth_wrapping_keys_path(data_root) {
        let sealed = super::devices::load_remote_auth_wrapping_key_bridge(data_root)?;
        return Ok(sealed == Some(parse::<RemoteAuthWrappingKeyBridge>(raw)?));
    }
    for persona in persona_dirs(data_root)? {
        if path == persona_epoch_bridge_path(data_root, persona) {
            let sealed = super::epochs::load_persona_epoch_bridge(data_root, persona)?;
            return Ok(sealed == Some(parse::<PersonaEpochBridge>(raw)?));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{path:?} is not a wallet secret")))
}

/// Every persona directory, with or without a manifest: a bridge can
/// outlive or precede its persona's `wallet.json`.
fn persona_dirs(data_root: &Path) -> io::Result<Vec<PersonaId>> {
    let entries = match std::fs::read_dir(data_root.join(PERSONAS_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut personas = Vec::new();
    for entry in entries {
        if let Ok(uuid) = entry?.file_name().to_string_lossy().parse::<uuid::Uuid>() {
            personas.push(PersonaId::from_uuid(uuid));
        }
    }
    Ok(personas)
}

fn migrate_json<T>(store: &SealedRecordStorage, data_root: &Path, path: &Path) -> io::Result<()>
where
    T: Serialize + DeserializeOwned + PartialEq,
{
    let raw = Zeroizing::new(std::fs::read(path)?);
    let value: T = serde_json::from_slice(&raw).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy wallet secret at {path:?} does not parse: {err}"),
        )
    })?;
    seal_verified(store, data_root, path, &raw, &value)
}

fn seal_verified<T>(
    store: &SealedRecordStorage,
    data_root: &Path,
    path: &Path,
    raw: &[u8],
    value: &T,
) -> io::Result<()>
where
    T: Serialize + DeserializeOwned + PartialEq,
{
    let relative = path
        .strip_prefix(data_root)
        .expect("wallet path under data root");
    let outcome = store
        .save_record(relative, value)
        .and_then(|()| store.load_record::<T>(relative))
        .map_err(io_backend_error)
        .and_then(|back| match back {
            Some(back) if back == *value => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the sealed record at {path:?} did not read back equal"),
            )),
        });
    if let Err(error) = outcome {
        // The raw file was replaced in place; put it back before refusing.
        save_bytes_atomic(path, raw)?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[path = "at_rest_tests.rs"]
mod tests;
