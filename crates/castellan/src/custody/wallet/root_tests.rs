// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The wallet's root under the padlock: the whole flow on a real OS store
//! (DPAPI, Windows), and the same flow through the in-memory store seam.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use personae::StartupUnlockMode;
use sporran::device_settings_store::{DeviceSettings, save_device_settings};

use super::super::store_test_support::*;
use super::super::*;
use super::*;
use crate::custody::os_kek::{MemoryOsKek, Provider, install_os_kek_store, remove_os_kek_store};
#[cfg(windows)]
use crate::custody::os_kek::Dpapi;
#[cfg(windows)]
use crate::custody::padlock::MAX_OS_BLOB_BYTES;

fn mode(root: &Path, startup_unlock_mode: StartupUnlockMode) {
    save_device_settings(
        root,
        &DeviceSettings {
            startup_unlock_mode,
            mesh_lending: None,
        },
    )
    .unwrap();
}

fn kinds(root: &Path) -> Vec<(String, SlotKind)> {
    wallet_padlock_slots(root)
        .unwrap()
        .into_iter()
        .map(|s| (split_kid(&s.kid).0.to_string(), s.kind))
        .collect()
}

/// The flow every store must pass: create under AutoOs, add a passphrase,
/// Prompt unlock, wrong passphrase, change it, remove a slot, last slot kept.
fn whole_flow(root: &Path, method: &str) {
    ensure_wallet_state(root, fixture_persona(), "Studio PC").unwrap();
    let seed = load_identity_seed(root)
        .unwrap()
        .expect("AutoOs opens the OS slot");
    assert!(wallet_padlock_path(root).is_file());
    assert!(
        !identity_auto_unlock_root_path(root).exists(),
        "no legacy root for a new wallet"
    );
    assert_eq!(kinds(root), [(method.to_string(), SlotKind::Kek)]);

    let kid = add_wallet_passphrase_slot(root, &WalletUnlock::Os, "first phrase").unwrap();
    assert_eq!(kid, "pass/1");
    mode(root, StartupUnlockMode::Prompt);
    assert_eq!(
        load_identity_seed(root).unwrap(),
        None,
        "Prompt opens nothing at start"
    );
    let wrong = unlock_wallet_with_passphrase(root, "wrong phrase").unwrap_err();
    assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(load_identity_seed(root).unwrap(), None);
    assert!(unlock_wallet_with_passphrase(root, "first phrase").unwrap());
    assert_eq!(load_identity_seed(root).unwrap(), Some(seed));
    relock_wallet_after_manual_unlock(root);
    assert_eq!(load_identity_seed(root).unwrap(), None);

    change_wallet_passphrase(root, "first phrase", "second phrase").unwrap();
    assert!(unlock_wallet_with_passphrase(root, "first phrase").is_err());
    assert!(unlock_wallet_with_passphrase(root, "second phrase").unwrap());
    relock_wallet_after_manual_unlock(root);

    let os_kid = wallet_padlock_slots(root).unwrap()[0].kid.clone();
    remove_wallet_padlock_slot(root, &os_kid).unwrap();
    assert_eq!(kinds(root), [("pass".to_string(), SlotKind::Passphrase)]);
    let last = remove_wallet_padlock_slot(root, "pass/2").unwrap_err();
    assert_eq!(
        last.kind(),
        io::ErrorKind::InvalidData,
        "the last openable slot stays"
    );
    mode(root, StartupUnlockMode::AutoOs);
    assert_eq!(
        load_identity_seed(root).unwrap(),
        None,
        "no OS slot is left to try"
    );
    assert!(unlock_wallet_with_passphrase(root, "second phrase").unwrap());
    assert_eq!(load_identity_seed(root).unwrap(), Some(seed));
    relock_wallet_after_manual_unlock(root);
}

#[cfg(windows)]
#[test]
fn dpapi_slot_whole_flow() {
    let root = temp_data_root("padlock-dpapi-flow");
    install_os_kek_store(&root, Arc::new(Dpapi));
    whole_flow(&root, "dpapi");
    let _ = fs::remove_dir_all(&root);
}

#[cfg(windows)]
#[test]
fn a_real_dpapi_blob_fits_the_bound() {
    let root = temp_data_root("padlock-dpapi-blob");
    install_os_kek_store(&root, Arc::new(Dpapi));
    ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap();
    let slot = &wallet_padlock_slots(&root).unwrap()[0];
    let blob = slot.os_blob.as_ref().expect("a DPAPI slot keeps its blob");
    eprintln!("DPAPI blob for a 32-byte KEK: {} bytes", blob.len());
    assert!(blob.len() <= MAX_OS_BLOB_BYTES);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn memory_store_whole_flow() {
    let root = temp_data_root("padlock-memory-flow");
    install_os_kek_store(&root, Arc::new(MemoryOsKek::default()));
    whole_flow(&root, "keychain");
    remove_os_kek_store(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn provider_store_holds_a_kek_per_slot() {
    let root = temp_data_root("padlock-provider");
    let memory = Arc::new(crate::custody::auto_unlock_provider::tests::Memory::default());
    install_os_kek_store(&root, Arc::new(Provider(memory)));
    ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap();
    assert!(load_identity_seed(&root).unwrap().is_some());
    assert_eq!(kinds(&root), [("keychain".to_string(), SlotKind::Kek)]);
    assert_eq!(wallet_padlock_slots(&root).unwrap()[0].os_blob, None);
    remove_os_kek_store(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn prompt_first_run_creates_a_passphrase_padlock() {
    let root = temp_data_root("padlock-prompt-first-run");
    mode(&root, StartupUnlockMode::Prompt);
    let refused = ensure_wallet_state(&root, fixture_persona(), "Studio PC");
    assert!(
        refused.is_err(),
        "no sealed store before the padlock exists"
    );
    create_wallet_padlock_with_passphrase(&root, "owner phrase").unwrap();
    ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap();
    let seed = load_identity_seed(&root).unwrap();
    assert!(seed.is_some());
    assert_eq!(kinds(&root), [("pass".to_string(), SlotKind::Passphrase)]);
    let again = create_wallet_padlock_with_passphrase(&root, "other").unwrap_err();
    assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    relock_wallet_after_manual_unlock(&root);
    assert_eq!(load_identity_seed(&root).unwrap(), None);
    assert!(unlock_wallet_with_passphrase(&root, "owner phrase").unwrap());
    assert_eq!(load_identity_seed(&root).unwrap(), seed);
    relock_wallet_after_manual_unlock(&root);
    let _ = fs::remove_dir_all(&root);
}

fn memory_wallet(tag: &str) -> std::path::PathBuf {
    let root = temp_data_root(tag);
    install_os_kek_store(&root, Arc::new(MemoryOsKek::default()));
    ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap();
    root
}

#[test]
fn a_tampered_padlock_is_refused_and_no_new_root_is_made() {
    let root = memory_wallet("padlock-tampered");
    let path = wallet_padlock_path(&root);
    let mut bytes = fs::read(&path).unwrap();
    let at = bytes.len() - 45;
    bytes[at] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(load_identity_seed(&root).is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "the file is left as it was"
    );
    remove_os_kek_store(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_padlock_around_a_foreign_root_fails_the_binding_check() {
    let root = memory_wallet("padlock-foreign-root");
    let seed_before = fs::read(identity_seed_path(&root)).unwrap();
    let path = wallet_padlock_path(&root);
    fs::remove_file(&path).unwrap();
    // A writer mints a padlock around a root of its choosing.
    create_padlock(&root, &[0x42; 32], os_kek_store(&root).as_deref(), None).unwrap();
    let error = load_identity_seed(&root).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(identity_seed_path(&root)).unwrap(), seed_before);
    remove_os_kek_store(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_interrupted_replacement_leaves_an_openable_padlock() {
    let root = memory_wallet("padlock-interrupted");
    let path = wallet_padlock_path(&root);
    let before = fs::read(&path).unwrap();
    super::super::padlock_file::fail_point::arm();
    assert!(add_wallet_passphrase_slot(&root, &WalletUnlock::Os, "phrase").is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(load_identity_seed(&root).unwrap().is_some());
    // A crash inside the house's replace leaves only the moved-aside copy.
    let mut aside = path.file_name().unwrap().to_os_string();
    aside.push(".previous");
    fs::rename(&path, path.with_file_name(aside)).unwrap();
    assert!(load_identity_seed(&root).unwrap().is_some());
    remove_os_kek_store(&root);
    let _ = fs::remove_dir_all(&root);
}

#[cfg(windows)]
fn legacy_wallet(tag: &str) -> std::path::PathBuf {
    let root = temp_data_root(tag);
    install_os_kek_store(&root, Arc::new(Dpapi));
    // A wallet made before the padlock: a DPAPI auto-unlock root file.
    crate::custody::load_or_create_auto_unlock_root(identity_auto_unlock_root_path(&root))
        .unwrap()
        .unwrap();
    ensure_wallet_state(&root, fixture_persona(), "Studio PC").unwrap();
    assert!(
        !wallet_padlock_path(&root).exists(),
        "a legacy root keeps working as before"
    );
    root
}

#[cfg(windows)]
#[test]
fn migration_from_a_legacy_dpapi_root() {
    let root = legacy_wallet("padlock-migrate");
    let seed = load_identity_seed(&root).unwrap().unwrap();
    migrate_wallet_root_to_padlock(&root, Some("owner phrase")).unwrap();
    assert!(
        !identity_auto_unlock_root_path(&root).exists(),
        "the legacy root is retired"
    );
    let mut methods: Vec<_> = kinds(&root).into_iter().map(|(m, _)| m).collect();
    methods.sort();
    assert_eq!(methods, ["dpapi", "pass"]);
    assert_eq!(
        load_identity_seed(&root).unwrap(),
        Some(seed),
        "same root, same records"
    );
    mode(&root, StartupUnlockMode::Prompt);
    assert!(unlock_wallet_with_passphrase(&root, "owner phrase").unwrap());
    assert_eq!(load_identity_seed(&root).unwrap(), Some(seed));
    relock_wallet_after_manual_unlock(&root);
    let again = migrate_wallet_root_to_padlock(&root, None).unwrap_err();
    assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    let _ = fs::remove_dir_all(&root);
}

#[cfg(windows)]
#[test]
fn a_refused_migration_from_a_legacy_dpapi_root_changes_nothing() {
    let root = legacy_wallet("padlock-migrate-refused");
    let legacy = fs::read(identity_auto_unlock_root_path(&root)).unwrap();
    // The seed record is replaced by one sealed under another root.
    let seed_path = identity_seed_path(&root);
    let foreign = SealedRecordStorage::open_with_key(&root, [0x13; 32]);
    foreign
        .save_record(seed_path.strip_prefix(&root).unwrap(), &[0u8; 32])
        .unwrap();
    let seed_record = fs::read(&seed_path).unwrap();
    let error = migrate_wallet_root_to_padlock(&root, None).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        fs::read(identity_auto_unlock_root_path(&root)).unwrap(),
        legacy
    );
    assert_eq!(fs::read(&seed_path).unwrap(), seed_record);
    assert!(!wallet_padlock_path(&root).exists());
    let _ = fs::remove_dir_all(&root);
}
