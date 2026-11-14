// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The device fabric's secret pieces: this host's delegated-device identity
//! and the retained remote-auth wrapping keys. Moved from pandect's
//! `wallet_store::devices` (DR-B), which keeps the opaque grant bytes.

use std::io;
use std::path::Path;

use personae::InMemoryProvider;

use super::at_rest::{no_sealed_store, refuse_raw};
use super::secrets::{
    io_backend_error, looks_like_sealed_record, wallet_local_secret_store, wallet_secret_store,
};
use super::{DeviceId, LocalDeviceIdentity, RemoteAuthWrappingKeyBridge};
use sporran::wallet_store::{local_device_identity_path, remote_auth_wrapping_keys_path};

/// Load the local delegated-device identity, or `None` when absent.
pub fn load_local_device_identity(data_root: &Path) -> io::Result<Option<LocalDeviceIdentity>> {
    let path = local_device_identity_path(data_root);
    if !path.is_file() {
        return Ok(None);
    }
    let relative = path
        .strip_prefix(data_root)
        .expect("wallet path under data root");
    // Custody D5: a raw legacy identity is refused, a sealed-read failure returned.
    refuse_raw(&path)?;
    let Some(store) = wallet_local_secret_store(data_root)? else {
        return Ok(None);
    };
    store.load_record(relative).map_err(io_backend_error)
}

pub(super) fn local_device_identity_locked_at_startup(data_root: &Path) -> bool {
    let path = local_device_identity_path(data_root);
    path.is_file()
        && looks_like_sealed_record(&path)
        && load_local_device_identity(data_root)
            .ok()
            .flatten()
            .is_none()
}

/// Save the local delegated-device identity as a sealed record; with no
/// sealed store this is refused and nothing is written.
pub fn save_local_device_identity(
    data_root: &Path,
    identity: &LocalDeviceIdentity,
) -> io::Result<()> {
    let path = local_device_identity_path(data_root);
    let store = wallet_local_secret_store(data_root)?
        .ok_or_else(|| no_sealed_store("delegated-device identity"))?;
    store
        .save_record(
            path.strip_prefix(data_root)
                .expect("wallet path under data root"),
            identity,
        )
        .map_err(io_backend_error)
}

/// Load the retained remote-auth wrapping-key bridge, or `None` when absent.
pub fn load_remote_auth_wrapping_key_bridge(
    data_root: &Path,
) -> io::Result<Option<RemoteAuthWrappingKeyBridge>> {
    let path = remote_auth_wrapping_keys_path(data_root);
    if !path.is_file() {
        return Ok(None);
    }
    // Custody D5: a raw legacy bridge is refused, a sealed-read failure returned.
    refuse_raw(&path)?;
    let Some(store) = wallet_secret_store(data_root)? else {
        return Ok(None);
    };
    store
        .load_record(
            path.strip_prefix(data_root)
                .expect("wallet path under data root"),
        )
        .map_err(io_backend_error)
}

/// Save the retained remote-auth wrapping-key bridge atomically.
pub fn save_remote_auth_wrapping_key_bridge(
    data_root: &Path,
    bridge: &RemoteAuthWrappingKeyBridge,
) -> io::Result<()> {
    let store = wallet_secret_store(data_root)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "identity seed missing; cannot seal remote-auth wrapping keys",
        )
    })?;
    let path = remote_auth_wrapping_keys_path(data_root);
    store
        .save_record(
            path.strip_prefix(data_root)
                .expect("wallet path under data root"),
            bridge,
        )
        .map_err(io_backend_error)
}

/// Ensure a stable delegated-device identity exists for this data root.
pub fn ensure_local_device_identity(
    data_root: &Path,
    device_label: &str,
) -> io::Result<LocalDeviceIdentity> {
    if let Some(identity) = load_local_device_identity(data_root)? {
        return Ok(identity);
    }
    let seed = InMemoryProvider::random().master_keypair().to_seed();
    let identity = LocalDeviceIdentity::new(DeviceId::new(), seed, device_label.to_string());
    save_local_device_identity(data_root, &identity)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::super::RemoteAuthWrappingKeyRecord;
    use super::super::secrets::save_identity_seed;
    use super::super::store_test_support::*;
    use super::super::*;
    use super::*;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn local_device_identity_round_trips() {
        let root = temp_data_root("local-device");
        let identity = LocalDeviceIdentity::new(fixture_device(), [0x33; 32], "Tablet".into());
        save_local_device_identity(&root, &identity).unwrap();
        let restored = load_local_device_identity(&root).unwrap().unwrap();
        assert_eq!(restored, identity);
        assert_eq!(
            restored.public_key(),
            DevicePublicKey::from(restored.keypair().public_key())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn a_legacy_local_device_identity_is_refused_until_the_explicit_migration() {
        let root = temp_data_root("local-device-migrate");
        let identity = LocalDeviceIdentity::new(fixture_device(), [0x33; 32], "Tablet".into());
        save_json_atomic(&local_device_identity_path(&root), &identity).unwrap();

        let error = load_local_device_identity(&root).unwrap_err();
        assert!(matches!(
            WalletSecretRefusal::of(&error),
            Some(WalletSecretRefusal::LegacyRaw { .. })
        ));
        migrate_legacy_wallet_secrets(&root).unwrap();

        let restored = load_local_device_identity(&root).unwrap().unwrap();
        assert_eq!(restored, identity);
        assert!(identity_auto_unlock_root_path(&root).is_file());

        let text = fs::read_to_string(local_device_identity_path(&root)).unwrap();
        assert!(!text.contains("\"label\": \"Tablet\""));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remote_auth_wrapping_key_bridge_round_trips_as_a_sealed_record() {
        let root = temp_data_root("wrapping-keys");
        save_identity_seed(&root, [0x66; 32]).unwrap();
        let bridge = RemoteAuthWrappingKeyBridge {
            schema_version: WALLET_SCHEMA_VERSION,
            keys: vec![RemoteAuthWrappingKeyRecord {
                device_id: fixture_device(),
                ticket_id: Some(Uuid::from_u128(0xfeed)),
                wrapping_key: [0x5a; 32],
            }],
        };

        save_remote_auth_wrapping_key_bridge(&root, &bridge).unwrap();
        let restored = load_remote_auth_wrapping_key_bridge(&root)
            .unwrap()
            .unwrap();
        assert_eq!(restored, bridge);

        let text = fs::read_to_string(remote_auth_wrapping_keys_path(&root)).unwrap();
        assert!(!text.contains("\"wrapping_key\""));
        assert!(!text.contains("feed"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_local_device_identity_is_idempotent() {
        let root = temp_data_root("ensure-local-device");
        let first = ensure_local_device_identity(&root, "Phone").unwrap();
        let second = ensure_local_device_identity(&root, "Other Label").unwrap();
        assert_eq!(first, second);
        assert_eq!(second.label, "Phone");
        let _ = fs::remove_dir_all(&root);
    }
}
