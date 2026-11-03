// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::custody::vault::{
    CredentialLineage, IdentitySlot, IdentityVault, ProtocolKey, SecretBytes, UnlockTier,
};
use tempfile::tempdir;

#[test]
fn changing_a_legacy_file_authenticates_and_upgrades_every_profile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.json");
    let storage = PassphraseEncryptedStorage::open(&path, b"old").unwrap();
    for (id, byte) in [("one", 41), ("two", 42)] {
        storage
            .save_profile(&Profile::new(
                ProfileId(id.into()),
                id,
                Ed25519Keypair::from_seed([byte; 32]),
            ))
            .unwrap();
    }
    let mut file = storage.load_file().unwrap();
    storage
        .with_cipher(|cipher| {
            for (id, entry) in &mut file.profiles {
                let plain = decrypt_profile(cipher, FILE_VERSION, id, entry).unwrap();
                let nonce = random_bytes(NONCE_LEN);
                entry.ciphertext = cipher
                    .encrypt(
                        <&Nonce>::try_from(nonce.as_slice()).unwrap(),
                        Payload {
                            msg: &plain,
                            aad: &profile_aad(1, id),
                        },
                    )
                    .unwrap();
                entry.nonce = nonce;
            }
        })
        .unwrap();
    file.version = 1;
    storage.save_file(&file).unwrap();
    storage.change_passphrase(b"old", b"new").unwrap();
    drop(storage);
    assert!(PassphraseEncryptedStorage::open(&path, b"old").is_err());
    let storage = PassphraseEncryptedStorage::open(&path, b"new").unwrap();
    assert_eq!(storage.load_file().unwrap().version, FILE_VERSION);
    for (id, byte) in [("one", 41), ("two", 42)] {
        assert_eq!(
            storage
                .load_profile(&ProfileId(id.into()))
                .unwrap()
                .master
                .to_seed(),
            [byte; 32]
        );
    }
}

#[test]
fn saving_a_legacy_vault_upgrades_every_profile_without_changing_keys() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let salt = random_bytes(ARGON2_SALT_LEN);
    let kek = derive_kek(b"legacy fixture", &salt).unwrap();
    let cipher = ChaCha20Poly1305::new(<&Key>::try_from(kek.as_slice()).unwrap());
    let mut profiles = HashMap::new();
    for (id, seed) in [("first", [0x71; 32]), ("second", [0x72; 32])] {
        let plain = PlaintextProfile {
            display_name: id.into(),
            master_seed: seed,
            slots: Vec::new(),
        };
        let bytes = personae::zeroizing_json::to_vec(&plain).unwrap();
        let nonce = random_bytes(NONCE_LEN);
        let ciphertext = cipher
            .encrypt(
                <&Nonce>::try_from(nonce.as_slice()).unwrap(),
                bytes.as_slice(),
            )
            .unwrap();
        profiles.insert(id.into(), EncryptedProfile { nonce, ciphertext });
    }
    std::fs::write(
        &path,
        serde_json::to_vec(&EncryptedFile {
            version: 1,
            salt,
            profiles,
        })
        .unwrap(),
    )
    .unwrap();
    let storage = PassphraseEncryptedStorage::open(&path, b"legacy fixture").unwrap();
    let mut first = storage.load_profile(&ProfileId("first".into())).unwrap();
    first.display_name = "Renamed".into();
    storage.save_profile(&first).unwrap();
    assert_eq!(storage.load_file().unwrap().version, FILE_VERSION);
    let reopened = PassphraseEncryptedStorage::open(&path, b"legacy fixture").unwrap();
    assert_eq!(
        reopened
            .load_profile(&first.id)
            .unwrap()
            .master
            .public_key(),
        first.master.public_key()
    );
    assert_eq!(
        reopened
            .load_profile(&ProfileId("second".into()))
            .unwrap()
            .master
            .public_key(),
        Ed25519Keypair::from_seed([0x72; 32]).public_key()
    );
}

fn nostr_slot() -> IdentitySlot {
    IdentitySlot::Direct {
        kind: "nostr".to_string(),
        payload: SecretBytes::new(vec![0x42; 32]),
        lineage: CredentialLineage::LocallyGeneratedExternallyRegistered,
        unlock_tier: UnlockTier::Session,
    }
}

fn matrix_slot() -> IdentitySlot {
    IdentitySlot::Bootstrap {
        kind: "matrix".to_string(),
        bootstrap: SecretBytes::new(b"login-flow-seed".to_vec()),
        state_dir: PathBuf::from("/tmp/matrix-state"),
        lineage: CredentialLineage::LocallyGeneratedExternallyRegistered,
        unlock_tier: UnlockTier::ShortTtl { idle_seconds: 900 },
    }
}

#[test]
fn save_and_load_round_trips_through_passphrase_encrypt() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let storage = PassphraseEncryptedStorage::open(&path, b"correct horse battery staple").unwrap();

    let id = ProfileId("personal".to_string());
    let mut profile = Profile::new(id.clone(), "personal", Ed25519Keypair::from_seed([7; 32]));
    profile
        .slots
        .insert(ProtocolKey::new("nostr", None), nostr_slot());
    profile.slots.insert(
        ProtocolKey::new("matrix", Some("homeserver-1".into())),
        matrix_slot(),
    );

    storage.save_profile(&profile).unwrap();

    let loaded = storage.load_profile(&id).unwrap();
    assert_eq!(loaded.display_name, "personal");
    assert_eq!(
        loaded.master.public_key().to_bytes(),
        profile.master.public_key().to_bytes()
    );
    assert_eq!(loaded.slots.len(), 2);
    assert!(loaded.has_slot(&ProtocolKey::new("nostr", None)));
    assert!(loaded.has_slot(&ProtocolKey::new("matrix", Some("homeserver-1".into()))));
}

#[test]
fn wrong_passphrase_on_existing_file_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");

    // First open + save with the right passphrase.
    let storage = PassphraseEncryptedStorage::open(&path, b"right").unwrap();
    let mut profile = Profile::new(
        ProfileId("p".into()),
        "p",
        Ed25519Keypair::from_seed([5; 32]),
    );
    profile
        .slots
        .insert(ProtocolKey::new("nostr", None), nostr_slot());
    storage.save_profile(&profile).unwrap();
    drop(storage);

    // Reopen with wrong passphrase — must error during open, not
    // silently produce a different KEK.
    let res = PassphraseEncryptedStorage::open(&path, b"wrong");
    match res {
        Err(IdentityError::Backend(msg)) => {
            assert!(msg.contains("incorrect passphrase"), "got: {msg}");
        },
        Err(e) => panic!("unexpected error variant: {e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn correct_passphrase_on_existing_file_succeeds() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");

    let storage = PassphraseEncryptedStorage::open(&path, b"hunter2").unwrap();
    let mut profile = Profile::new(
        ProfileId("p".into()),
        "p",
        Ed25519Keypair::from_seed([5; 32]),
    );
    profile
        .slots
        .insert(ProtocolKey::new("nostr", None), nostr_slot());
    storage.save_profile(&profile).unwrap();
    drop(storage);

    let storage2 = PassphraseEncryptedStorage::open(&path, b"hunter2").unwrap();
    let loaded = storage2.load_profile(&ProfileId("p".into())).unwrap();
    assert_eq!(loaded.display_name, "p");
}

#[test]
fn delete_profile_removes_from_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let storage = PassphraseEncryptedStorage::open(&path, b"pp").unwrap();
    let id = ProfileId("p".into());
    storage
        .save_profile(&Profile::new(
            id.clone(),
            "p",
            Ed25519Keypair::from_seed([1; 32]),
        ))
        .unwrap();
    storage.delete_profile(&id).unwrap();
    let summary = storage.list_profiles().unwrap();
    assert_eq!(summary.len(), 0);
}

#[test]
fn vault_works_against_passphrase_storage() {
    // End-to-end: IdentityVault wraps PassphraseEncryptedStorage and
    // round-trips slots through the encrypted file.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let storage = PassphraseEncryptedStorage::open(&path, b"pp").unwrap();

    let profile = Profile::new(
        ProfileId("p".into()),
        "p",
        Ed25519Keypair::from_seed([9; 32]),
    );
    let mut vault = IdentityVault::with_profile(storage, profile);
    vault
        .add_slot(ProtocolKey::new("nostr", None), nostr_slot())
        .unwrap();

    // Re-open from the same file.
    let storage2 = PassphraseEncryptedStorage::open(&path, b"pp").unwrap();
    let loaded = storage2.load_profile(&ProfileId("p".into())).unwrap();
    assert!(loaded.has_slot(&ProtocolKey::new("nostr", None)));
}

#[test]
fn ciphertext_bytes_do_not_contain_plaintext_secrets() {
    // Light-touch sanity check: the on-disk file should not
    // contain the plaintext slot bytes.
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let storage = PassphraseEncryptedStorage::open(&path, b"pp").unwrap();
    let mut profile = Profile::new(
        ProfileId("p".into()),
        "test-display-name-not-secret",
        Ed25519Keypair::from_seed([3; 32]),
    );
    // Use a distinctive marker as the slot payload.
    profile.slots.insert(
        ProtocolKey::new("test", None),
        IdentitySlot::Direct {
            kind: "test".to_string(),
            payload: SecretBytes::new(b"DISTINCTIVE_SECRET_MARKER".to_vec()),
            lineage: CredentialLineage::LocallyDerived,
            unlock_tier: UnlockTier::Session,
        },
    );
    storage.save_profile(&profile).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    // Display name is plaintext-encoded inside the ciphertext, so
    // it should NOT appear directly. Same for the secret marker.
    assert!(
        !bytes
            .windows(b"DISTINCTIVE_SECRET_MARKER".len())
            .any(|w| w == b"DISTINCTIVE_SECRET_MARKER")
    );
    assert!(
        !bytes
            .windows(b"test-display-name-not-secret".len())
            .any(|w| w == b"test-display-name-not-secret")
    );
}
