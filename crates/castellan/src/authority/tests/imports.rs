// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// personae's test-only `ssh-keygen` fixtures.
fn fixture(name: &str) -> PrivateKey {
    let text = match name {
        "ed25519" => {
            include_str!("../../../tests/fixtures/ssh/ed25519")
        },
        "rsa2048" => {
            include_str!("../../../tests/fixtures/ssh/rsa2048")
        },
        "rsa4096" => {
            include_str!("../../../tests/fixtures/ssh/rsa4096")
        },
        "ecdsa256" => {
            include_str!("../../../tests/fixtures/ssh/ecdsa256")
        },
        "ecdsa384" => {
            include_str!("../../../tests/fixtures/ssh/ecdsa384")
        },
        "ecdsa521" => {
            include_str!("../../../tests/fixtures/ssh/ecdsa521")
        },
        "rsa1024" => {
            include_str!("../../../tests/fixtures/ssh/rsa1024")
        },
        "rsa2560" => {
            include_str!("../../../tests/fixtures/ssh/rsa2560")
        },
        "rsa8192" => {
            include_str!("../../../tests/fixtures/ssh/rsa8192")
        },
        "rsa2048e3" => {
            include_str!("../../../tests/fixtures/ssh/rsa2048e3")
        },
        "dsa" => include_str!("../../../tests/fixtures/ssh/dsa"),
        other => panic!("no fixture {other}"),
    };
    PrivateKey::from_openssh(text).unwrap()
}

const P4A_KEYS: [&str; 4] = ["rsa2048", "rsa4096", "ecdsa256", "ecdsa384"];

/// Ruling 54: re-importing a held key, even asking for another tier and
/// carrying another comment, rewrites nothing and says it is held.
#[test]
fn reimporting_a_held_key_rewrites_nothing() {
    let host = PersonaeHost::new(
        IdentityVault::with_profile(
            InMemoryStorage::new(),
            Profile::new(
                ProfileId("research".to_string()),
                "Research",
                Ed25519Keypair::from_seed([0x4c; 32]),
            ),
        ),
        None,
        VaultProtectionView::Ephemeral,
    );
    for name in ["ed25519", "rsa2048", "ecdsa256"] {
        let mut first = fixture(name);
        first.set_comment("as first imported");
        let key = protocol_key_for(&first);
        let per_use = ImportSshKeyNativeIntentV1 {
            unlock_policy: SshUnlockPolicyIntentV1::PerUse,
        };
        let imported = host.import_ssh_private(first, per_use).unwrap();
        assert!(!imported.replaced_existing, "{name}");
        let before = slot_parts(&host, &key);

        let mut again = fixture(name);
        again.set_comment("a different comment");
        let receipt = host.import_ssh_private(again, session_import()).unwrap();
        assert!(receipt.replaced_existing, "{name}: reported as held");
        assert_eq!(receipt.comment, "as first imported", "{name}");
        assert_eq!(receipt.unlock_policy, imported.unlock_policy, "{name}");
        assert_eq!(slot_parts(&host, &key), before, "{name}: byte for byte");
        assert_eq!(slot_parts(&host, &key).3, UnlockTier::PerUse, "{name}");
    }
}

/// Rulings 55 and 56: import refuses what the agent cannot sign, naming
/// why, and stores nothing.
#[test]
fn native_import_refuses_unsignable_keys_with_the_reason() {
    let host = PersonaeHost::new(
        IdentityVault::with_profile(
            InMemoryStorage::new(),
            Profile::new(
                ProfileId("research".to_string()),
                "Research",
                Ed25519Keypair::from_seed([0x4d; 32]),
            ),
        ),
        None,
        VaultProtectionView::Ephemeral,
    );
    for name in [
        "rsa1024",
        "rsa2560",
        "rsa8192",
        "rsa2048e3",
        "dsa",
        "ecdsa521",
    ] {
        let error = host
            .import_ssh_private(fixture(name), session_import())
            .unwrap_err();
        let IdentityIntentError::UnsignableKey(reason) = &error else {
            panic!("{name}: {error}");
        };
        assert!(
            reason.contains("2048 to 4096 bits")
                || reason.contains("ssh-dss")
                || reason.contains("P-521"),
            "{name}: {reason}"
        );
    }
    assert!(host.snapshot().unwrap().ssh_keys.is_empty());
}

fn slot_parts(
    host: &PersonaeHost<InMemoryStorage>,
    key: &ProtocolKey,
) -> (String, Vec<u8>, CredentialLineage, UnlockTier) {
    let vault = host.vault.lock().unwrap();
    match vault
        .current_profile()
        .unwrap()
        .slots
        .get(key)
        .expect("slot held")
    {
        crate::custody::IdentitySlot::Direct {
            kind,
            payload,
            lineage,
            unlock_tier,
        } => (
            kind.clone(),
            payload.as_slice().to_vec(),
            *lineage,
            *unlock_tier,
        ),
        _ => panic!("ssh slots are Direct"),
    }
}

fn session_import() -> ImportSshKeyNativeIntentV1 {
    ImportSshKeyNativeIntentV1 {
        unlock_policy: SshUnlockPolicyIntentV1::Session,
    }
}

/// P4a, ruling 20: RSA and ECDSA keys land in new fingerprint-keyed slots
/// and the Ed25519 slot already held is untouched, byte for byte.
#[test]
fn native_import_holds_rsa_and_ecdsa_beside_an_untouched_ed25519_slot() {
    let ed25519 = fixture("ed25519");
    let ed_key = protocol_key_for(&ed25519);
    let mut profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x4a; 32]),
    );
    profile.slots.insert(
        ed_key.clone(),
        slot_for(&ed25519, UnlockTier::PerUse).unwrap(),
    );
    let host = PersonaeHost::new(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        None,
        VaultProtectionView::Ephemeral,
    );
    let before = slot_parts(&host, &ed_key);

    for name in P4A_KEYS {
        let key = fixture(name);
        let public = PublicKey::from(&key);
        let fingerprint = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let receipt = host.import_ssh_private(key, session_import()).unwrap();
        assert_eq!(receipt.fingerprint, fingerprint, "{name}");
        assert!(!receipt.replaced_existing, "{name} is a new slot");
        let held = slot_parts(
            &host,
            &ProtocolKey::new(ssh_slot::SSH_MOD_ID, Some(fingerprint)),
        );
        assert_eq!(held.0, ssh_slot::SSH_MOD_ID, "{name}");
        let stored = PrivateKey::from_openssh(&held.1).unwrap();
        assert_eq!(
            PublicKey::from(&stored).key_data(),
            public.key_data(),
            "{name}"
        );
    }

    assert_eq!(slot_parts(&host, &ed_key), before, "the Ed25519 slot");
    assert_eq!(host.snapshot().unwrap().ssh_keys.len(), 1 + P4A_KEYS.len());
}

/// The resident's agent signs each imported key over the named-pipe wire,
/// RSA as the request's flags ask, and refuses a flagless RSA request.
#[cfg(windows)]
#[tokio::test]
async fn imported_rsa_and_ecdsa_keys_sign_over_the_named_pipe_wire() {
    use ssh_agent_lib::client::Client;
    use ssh_key::{EcdsaCurve, HashAlg};
    use tokio::net::windows::named_pipe::ClientOptions;

    let host = PersonaeHost::with_decision_timeout(
        IdentityVault::with_profile(
            InMemoryStorage::new(),
            Profile::new(
                ProfileId("research".to_string()),
                "Research",
                Ed25519Keypair::from_seed([0x4b; 32]),
            ),
        ),
        None,
        VaultProtectionView::Ephemeral,
        Duration::from_secs(2),
    );
    for name in P4A_KEYS {
        host.import_ssh_private(fixture(name), session_import())
            .unwrap();
    }
    let endpoint = format!(r"\\.\pipe\castellan-p4a-receipt-{}", Uuid::new_v4());
    let listener = host.bind_receipt_listener(&endpoint).unwrap();
    let server = tokio::spawn(ssh_agent_lib::agent::listen(listener, host.agent_session()));
    let mut client = Client::new(ClientOptions::new().open(&endpoint).unwrap());
    assert_eq!(
        client.request_identities().await.unwrap().len(),
        2 * P4A_KEYS.len()
    );

    let rsa = |hash| Algorithm::Rsa { hash: Some(hash) };
    let ecdsa = |curve| Algorithm::Ecdsa { curve };
    for (name, flags, expected) in [
        ("rsa2048", 0x02, rsa(HashAlg::Sha256)),
        ("rsa2048", 0x04, rsa(HashAlg::Sha512)),
        ("rsa4096", 0x02, rsa(HashAlg::Sha256)),
        ("rsa4096", 0x04, rsa(HashAlg::Sha512)),
        ("ecdsa256", 0, ecdsa(EcdsaCurve::NistP256)),
        ("ecdsa384", 0, ecdsa(EcdsaCurve::NistP384)),
    ] {
        let public = PublicKey::from(&fixture(name));
        let signature = client
            .sign(SignRequest {
                credential: public.key_data().clone().into(),
                data: b"castellan-p4a-wire".to_vec(),
                flags,
            })
            .await
            .unwrap();
        assert_eq!(signature.algorithm(), expected, "{name} flags {flags}");
        public
            .key_data()
            .verify(b"castellan-p4a-wire", &signature)
            .unwrap();
    }
    let flagless = client
        .sign(SignRequest {
            credential: PublicKey::from(&fixture("rsa2048"))
                .key_data()
                .clone()
                .into(),
            data: b"castellan-p4a-wire".to_vec(),
            flags: 0,
        })
        .await;
    assert!(flagless.is_err(), "ssh-rsa (SHA-1) is never signed");

    server.abort();
    let _ = server.await;
}

#[test]
fn typed_generation_and_confirmed_removal_mutate_the_shared_vault() {
    let profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x19; 32]),
    );
    let host = PersonaeHost::new(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        None,
        VaultProtectionView::Ephemeral,
    );
    let generate = serde_json::to_vec(&GenerateSshKeyIntentV1 {
        comment: "generated in Graphshell".to_string(),
        unlock_policy: SshUnlockPolicyIntentV1::ShortTtl { idle_seconds: 45 },
    })
    .unwrap();
    let generated = host.apply_intent(SSH_GENERATE_INTENT, &generate).unwrap();
    let IdentityIntentOutcome::SshKeyMutation(generated) = generated else {
        panic!("expected SSH key mutation");
    };
    assert_eq!(generated.operation, SshKeyMutationKind::Generated);
    assert_eq!(generated.unlock_policy, "45s idle");
    assert!(generated.public_openssh.starts_with("ssh-ed25519 "));
    assert_eq!(host.snapshot().unwrap().ssh_keys.len(), 1);

    let unconfirmed = serde_json::to_vec(&RemoveSshKeyIntentV1 {
        fingerprint: generated.fingerprint.clone(),
        confirmed: false,
    })
    .unwrap();
    assert!(matches!(
        host.apply_intent(SSH_REMOVE_INTENT, &unconfirmed),
        Err(IdentityIntentError::ConfirmationRequired)
    ));
    assert_eq!(host.snapshot().unwrap().ssh_keys.len(), 1);

    let confirmed = serde_json::to_vec(&RemoveSshKeyIntentV1 {
        fingerprint: generated.fingerprint,
        confirmed: true,
    })
    .unwrap();
    let removed = host.apply_intent(SSH_REMOVE_INTENT, &confirmed).unwrap();
    assert!(matches!(
        removed,
        IdentityIntentOutcome::SshKeyMutation(SshKeyMutationReceipt {
            operation: SshKeyMutationKind::Removed,
            ..
        })
    ));
    assert!(host.snapshot().unwrap().ssh_keys.is_empty());
}

#[test]
fn native_import_never_accepts_private_key_bytes_as_an_intent() {
    let profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x29; 32]),
    );
    let host = PersonaeHost::new(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        None,
        VaultProtectionView::Ephemeral,
    );
    let mut private =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
    private.set_comment("native import");
    let private_openssh = private.to_openssh(LineEnding::LF).unwrap().to_string();
    let receipt = host
        .import_ssh_private(
            private,
            ImportSshKeyNativeIntentV1 {
                unlock_policy: SshUnlockPolicyIntentV1::PerUse,
            },
        )
        .unwrap();
    let public_json = serde_json::to_string(&receipt).unwrap();
    assert_eq!(receipt.operation, SshKeyMutationKind::Imported);
    assert!(!public_json.contains(&private_openssh));
    assert!(!public_json.contains("BEGIN OPENSSH PRIVATE KEY"));

    let options = serde_json::to_vec(&ImportSshKeyNativeIntentV1 {
        unlock_policy: SshUnlockPolicyIntentV1::Session,
    })
    .unwrap();
    assert!(matches!(
        host.apply_intent(SSH_IMPORT_NATIVE_INTENT, &options),
        Err(IdentityIntentError::NativeHandoffRequired)
    ));
    assert_eq!(host.snapshot().unwrap().ssh_keys.len(), 1);
}
