// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Custody D5: no raw write, no raw read, migration only on request.
//! `Prompt` startup stands for "no sealed store" on every platform; the
//! store-backed cases need Windows' DPAPI root.

use std::fs;
use std::path::Path;

use personae::StartupUnlockMode;
use sporran::device_settings_store::{DeviceSettings, save_device_settings};

use super::super::store_test_support::*;
use super::super::*;
use super::*;

fn without_store(root: &Path) {
    save_device_settings(
        root,
        &DeviceSettings {
            startup_unlock_mode: StartupUnlockMode::Prompt,
            mesh_lending: None,
        },
    )
    .unwrap();
}

fn refusal(error: &io::Error) -> WalletSecretRefusal {
    WalletSecretRefusal::of(error)
        .cloned()
        .unwrap_or_else(|| panic!("not a wallet-secret refusal: {error}"))
}

fn bridge(secret: &[u8]) -> PersonaEpochBridge {
    PersonaEpochBridge {
        schema_version: WALLET_SCHEMA_VERSION,
        persona_id: fixture_persona(),
        epochs: vec![PrivateEpochRecord {
            epoch_id: fixture_epoch(),
            epoch_secret: secret.to_vec(),
        }],
    }
}

#[test]
fn saving_without_a_sealed_store_errors_and_writes_nothing() {
    let root = temp_data_root("at-rest-no-store-save");
    without_store(&root);

    let error = save_identity_seed(&root, [0x21; 32]).unwrap_err();
    assert_eq!(
        refusal(&error),
        WalletSecretRefusal::NoSealedStore {
            secret: "identity seed"
        }
    );
    assert!(!identity_seed_path(&root).exists());

    let error = save_persona_epoch_bridge(&root, &bridge(b"epoch")).unwrap_err();
    assert!(matches!(
        refusal(&error),
        WalletSecretRefusal::NoSealedStore { .. }
    ));
    assert!(!persona_epoch_bridge_path(&root, fixture_persona()).exists());

    let error = ensure_local_device_identity(&root, "Tablet").unwrap_err();
    assert!(matches!(
        refusal(&error),
        WalletSecretRefusal::NoSealedStore { .. }
    ));
    assert!(!local_device_identity_path(&root).exists());

    let error = ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap_err();
    assert!(matches!(
        refusal(&error),
        WalletSecretRefusal::NoSealedStore { .. }
    ));
    assert!(!identity_seed_path(&root).exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_raw_legacy_seed_is_refused_with_the_migration_error_and_left_as_it_was() {
    let root = temp_data_root("at-rest-raw-seed");
    let path = identity_seed_path(&root);
    save_bytes_atomic(&path, &[0x22; 32]).unwrap();

    for error in [
        load_identity_seed(&root).unwrap_err(),
        load_identity_seed_read_only(&root).unwrap_err(),
    ] {
        assert_eq!(
            refusal(&error),
            WalletSecretRefusal::LegacyRaw { path: path.clone() }
        );
        assert!(error.to_string().contains("migrate_legacy_wallet_secrets"));
    }
    assert_eq!(fs::read(&path).unwrap(), [0x22; 32]);
    assert!(!identity_auto_unlock_root_path(&root).exists());
    assert!(!wallet_padlock_path(&root).exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_raw_legacy_epoch_bridge_is_refused_with_the_migration_error() {
    let root = temp_data_root("at-rest-raw-bridge");
    let path = persona_epoch_bridge_path(&root, fixture_persona());
    save_json_atomic(&path, &bridge(b"plain")).unwrap();
    let before = fs::read(&path).unwrap();

    let error = load_persona_epoch_bridge(&root, fixture_persona()).unwrap_err();
    assert_eq!(refusal(&error), WalletSecretRefusal::LegacyRaw { path: path.clone() });
    assert_eq!(fs::read(&path).unwrap(), before);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn migration_refuses_without_a_sealed_store_and_changes_nothing() {
    let root = temp_data_root("at-rest-migrate-no-store");
    without_store(&root);
    let seed_path = identity_seed_path(&root);
    save_bytes_atomic(&seed_path, &[0x23; 32]).unwrap();
    let bridge_path = persona_epoch_bridge_path(&root, fixture_persona());
    save_json_atomic(&bridge_path, &bridge(b"plain")).unwrap();
    let bridge_before = fs::read(&bridge_path).unwrap();

    let error = migrate_legacy_wallet_secrets(&root).unwrap_err();
    assert!(matches!(
        refusal(&error),
        WalletSecretRefusal::NoSealedStore { .. }
    ));
    assert_eq!(fs::read(&seed_path).unwrap(), [0x23; 32]);
    assert_eq!(fs::read(&bridge_path).unwrap(), bridge_before);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn migration_refuses_a_raw_file_that_is_not_a_seed_and_leaves_it() {
    let root = temp_data_root("at-rest-migrate-short");
    let path = identity_seed_path(&root);
    save_bytes_atomic(&path, &[0x24; 31]).unwrap();

    assert!(migrate_legacy_wallet_secrets(&root).is_err());
    assert_eq!(fs::read(&path).unwrap(), [0x24; 31]);

    let _ = fs::remove_dir_all(&root);
}

/// A raw seed, a raw epoch bridge and a raw device identity: migrate, then
/// read everything back from the sealed records.
#[cfg(windows)]
#[test]
fn migration_seals_every_raw_secret_and_reads_back_equal() {
    let root = temp_data_root("at-rest-migrate");
    let seed = [0x25; 32];
    let seed_path = identity_seed_path(&root);
    save_bytes_atomic(&seed_path, &seed).unwrap();
    let bridge_path = persona_epoch_bridge_path(&root, fixture_persona());
    save_json_atomic(&bridge_path, &bridge(b"known-private-epoch")).unwrap();
    let device = LocalDeviceIdentity::new(fixture_device(), [0x26; 32], "Tablet".into());
    let device_path = local_device_identity_path(&root);
    save_json_atomic(&device_path, &device).unwrap();

    let mut sealed = migrate_legacy_wallet_secrets(&root).unwrap();
    sealed.sort();
    let mut expected = vec![seed_path.clone(), device_path.clone(), bridge_path.clone()];
    expected.sort();
    assert_eq!(sealed, expected);

    for path in [&seed_path, &bridge_path, &device_path] {
        assert!(looks_like_sealed_record(path), "{path:?} is sealed");
    }
    assert!(!fs::read(&seed_path).unwrap().windows(32).any(|w| w == seed));
    assert!(!fs::read_to_string(&bridge_path).unwrap().contains("known-private-epoch"));
    assert_eq!(load_identity_seed(&root).unwrap(), Some(seed));
    assert_eq!(
        load_persona_epoch_bridge(&root, fixture_persona()).unwrap(),
        Some(bridge(b"known-private-epoch"))
    );
    assert_eq!(load_local_device_identity(&root).unwrap(), Some(device));
    assert!(migrate_legacy_wallet_secrets(&root).unwrap().is_empty(), "idempotent");

    let _ = fs::remove_dir_all(&root);
}

fn corrupt_ciphertext(path: &Path) {
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let byte = &mut record["ciphertext"][0];
    *byte = serde_json::json!((byte.as_u64().unwrap() + 1) % 256);
    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
}

#[cfg(windows)]
#[test]
fn a_sealed_read_failure_is_returned_never_swallowed() {
    let root = temp_data_root("at-rest-sealed-failure");
    save_identity_seed(&root, [0x27; 32]).unwrap();
    save_persona_epoch_bridge(&root, &bridge(b"sealed-epoch")).unwrap();
    let bridge_path = persona_epoch_bridge_path(&root, fixture_persona());
    corrupt_ciphertext(&bridge_path);
    let error = load_persona_epoch_bridge(&root, fixture_persona()).unwrap_err();
    assert!(WalletSecretRefusal::of(&error).is_none(), "{error}");

    let seed_path = identity_seed_path(&root);
    corrupt_ciphertext(&seed_path);
    let error = load_identity_seed(&root).unwrap_err();
    assert!(WalletSecretRefusal::of(&error).is_none(), "{error}");
    assert!(looks_like_sealed_record(&seed_path), "nothing rewrote the record");

    let _ = fs::remove_dir_all(&root);
}
