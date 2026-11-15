// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! "Adopt with a passphrase, or refuse": the four cases of adopting a wallet,
//! the states a kill leaves and their reruns, and the command route out for
//! raw secrets already adopted. Every store comes through the test seam, so
//! these run the same on every platform.

use std::fs;
use std::path::{Path, PathBuf};

use castellan::custody::os_kek::{install_memory_os_kek, install_os_kek_store, os_kek_store};
use castellan::custody::wallet::{
    WalletUnlock, create_wallet_padlock_with_passphrase, ensure_wallet_state,
    is_sealed_wallet_record, load_identity_seed, relock_wallet_after_manual_unlock,
    unlock_wallet_with_passphrase, wallet_padlock_slots, with_wallet_unlocked,
};
use sporran::wallet_store::identity_seed_path;

use crate::wallet::{PASSPHRASE_FLAG, adopt_wallet, carry_files, wallet_files};

const PHRASE: &str = "owner phrase";

/// A copy of the raw legacy wallet main's `ensure_wallet_state` wrote with no
/// sealed store (`tests/fixtures/raw_legacy_wallet`): a raw 32-byte seed.
pub(super) fn raw_wallet() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/raw_legacy_wallet"),
        dir.path(),
    );
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else if entry.file_name() != ".gitattributes" {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Every file under `root`, with its bytes.
fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = wallet_files(root)
        .unwrap()
        .into_iter()
        .map(|rel| (rel.clone(), fs::read(root.join(rel)).unwrap()))
        .collect();
    files.sort();
    files
}

fn raw_seed(root: &Path) -> Vec<u8> {
    fs::read(identity_seed_path(root)).unwrap()
}

fn kids(root: &Path) -> Vec<String> {
    wallet_padlock_slots(root)
        .unwrap()
        .into_iter()
        .map(|s| s.kid)
        .collect()
}

#[test]
fn without_a_store_or_passphrase_a_raw_wallet_is_refused_and_nothing_changes() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    let before = snapshot(source.path());
    let error = adopt_wallet(source.path(), dest.path(), None).unwrap_err();
    assert!(error.contains(PASSPHRASE_FLAG), "{error}");
    assert_eq!(
        snapshot(source.path()),
        before,
        "the source is untouched byte for byte"
    );
    assert!(
        wallet_files(dest.path()).unwrap().is_empty(),
        "the custodian holds no wallet file"
    );
}

#[test]
fn with_a_passphrase_the_raw_seed_is_sealed_under_a_new_padlock_before_the_source_goes() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    let seed = raw_seed(source.path());
    let adopted = adopt_wallet(source.path(), dest.path(), Some(PHRASE)).unwrap();
    assert!(adopted.left.is_empty(), "{:?}", adopted.left);
    let sealed = identity_seed_path(dest.path());
    assert!(is_sealed_wallet_record(&sealed));
    assert!(
        !fs::read(&sealed).unwrap().windows(32).any(|w| w == seed),
        "the seed bytes are not in the file"
    );
    assert_eq!(kids(dest.path()), ["pass/1"]);
    assert!(wallet_files(source.path()).unwrap().is_empty());
    assert!(unlock_wallet_with_passphrase(dest.path(), PHRASE).unwrap());
    assert_eq!(
        load_identity_seed(dest.path()).unwrap().unwrap().to_vec(),
        seed
    );
    relock_wallet_after_manual_unlock(dest.path());
    assert!(
        adopt_wallet(source.path(), dest.path(), Some(PHRASE))
            .unwrap_err()
            .contains("no wallet")
    );
}

#[test]
fn with_an_os_store_the_raw_seed_is_sealed_under_it() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    install_memory_os_kek(dest.path());
    let seed = raw_seed(source.path());
    adopt_wallet(source.path(), dest.path(), None).unwrap();
    assert_eq!(kids(dest.path()).len(), 1);
    assert!(kids(dest.path())[0].starts_with("keychain/"));
    assert_eq!(
        load_identity_seed(dest.path()).unwrap().unwrap().to_vec(),
        seed,
        "AutoOs opens it"
    );
}

#[test]
fn a_wallet_already_sealed_moves_as_it_is() {
    let source = tempfile::tempdir().unwrap();
    install_memory_os_kek(source.path());
    ensure_wallet_state(source.path(), personae::PersonaId::new(), "fixture").unwrap();
    let before = snapshot(source.path());
    let dest = tempfile::tempdir().unwrap();
    install_os_kek_store(dest.path(), os_kek_store(source.path()).unwrap());
    adopt_wallet(source.path(), dest.path(), None).unwrap();
    assert_eq!(
        snapshot(dest.path()),
        before,
        "the same files, the same bytes"
    );
    assert!(load_identity_seed(dest.path()).unwrap().is_some());
}

#[test]
fn a_kill_after_the_copy_is_restarted_from_the_untouched_source() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    let seed = raw_seed(source.path());
    carry_files(source.path(), dest.path()).unwrap();
    // Killed again after the padlock was made and the seed sealed.
    create_wallet_padlock_with_passphrase(dest.path(), PHRASE).unwrap();
    castellan::custody::wallet::migrate_legacy_wallet_secrets(dest.path()).unwrap();
    relock_wallet_after_manual_unlock(dest.path());
    adopt_wallet(source.path(), dest.path(), Some(PHRASE)).unwrap();
    assert!(wallet_files(source.path()).unwrap().is_empty());
    assert!(unlock_wallet_with_passphrase(dest.path(), PHRASE).unwrap());
    assert_eq!(
        load_identity_seed(dest.path()).unwrap().unwrap().to_vec(),
        seed
    );
    relock_wallet_after_manual_unlock(dest.path());
}

#[test]
fn a_kill_while_the_source_was_retired_is_finished_not_restarted() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    let seed = raw_seed(source.path());
    carry_files(source.path(), dest.path()).unwrap();
    create_wallet_padlock_with_passphrase(dest.path(), PHRASE).unwrap();
    castellan::custody::wallet::migrate_legacy_wallet_secrets(dest.path()).unwrap();
    relock_wallet_after_manual_unlock(dest.path());
    // The retirement had removed one file when the process died.
    fs::remove_file(source.path().join("identity/device-roster.json")).unwrap();
    let held = snapshot(dest.path());
    adopt_wallet(source.path(), dest.path(), Some(PHRASE)).unwrap();
    assert_eq!(
        snapshot(dest.path()),
        held,
        "the custodian's sealed wallet is not redone"
    );
    assert!(wallet_files(source.path()).unwrap().is_empty());
    assert!(unlock_wallet_with_passphrase(dest.path(), PHRASE).unwrap());
    assert_eq!(
        load_identity_seed(dest.path()).unwrap().unwrap().to_vec(),
        seed
    );
    relock_wallet_after_manual_unlock(dest.path());
}

#[test]
fn a_rerun_with_the_wrong_passphrase_refuses_and_keeps_the_source() {
    let (source, dest) = (raw_wallet(), tempfile::tempdir().unwrap());
    carry_files(source.path(), dest.path()).unwrap();
    create_wallet_padlock_with_passphrase(dest.path(), PHRASE).unwrap();
    castellan::custody::wallet::migrate_legacy_wallet_secrets(dest.path()).unwrap();
    relock_wallet_after_manual_unlock(dest.path());
    let before = snapshot(source.path());
    assert!(adopt_wallet(source.path(), dest.path(), Some("not it")).is_err());
    assert_eq!(snapshot(source.path()), before);
}

#[test]
fn another_wallet_in_the_custodians_root_is_never_cleared() {
    let source = raw_wallet();
    let dest = tempfile::tempdir().unwrap();
    install_memory_os_kek(dest.path());
    ensure_wallet_state(dest.path(), personae::PersonaId::new(), "theirs").unwrap();
    let theirs = snapshot(dest.path());
    assert!(
        adopt_wallet(source.path(), dest.path(), Some(PHRASE))
            .unwrap_err()
            .contains("already holds")
    );
    assert_eq!(snapshot(dest.path()), theirs);
}

#[test]
fn raw_secrets_already_adopted_have_a_command_route_out() {
    // A wallet adopted by the old command on a store-less custodian: a raw seed.
    let dest = raw_wallet();
    let seed = raw_seed(dest.path());
    create_wallet_padlock_with_passphrase(dest.path(), PHRASE).unwrap();
    relock_wallet_after_manual_unlock(dest.path());
    let request = crate::wallet::root_admin::Request {
        action: "seal-legacy",
        kid: None,
        with: Some("passphrase"),
        passphrase: None,
    };
    let mut out = Vec::new();
    crate::wallet::root_admin::run(
        dest.path(),
        &request,
        &mut format!("{PHRASE}\n").as_bytes(),
        &mut out,
    )
    .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("sealed 1"));
    assert!(is_sealed_wallet_record(&identity_seed_path(dest.path())));
    let opened = with_wallet_unlocked(dest.path(), &WalletUnlock::Passphrase(PHRASE), || {
        load_identity_seed(dest.path())
    });
    assert_eq!(opened.unwrap().unwrap().to_vec(), seed);
}
