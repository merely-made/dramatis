// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::custody::ssh_sign::tests::fixture;
use crate::custody::vault::{InMemoryStorage, Profile, ProfileId};
use personae::Ed25519Keypair;
use personae::signing::{ApprovalSource, RememberApproval, SigningDecision, SigningRecordResult};
use signature::Verifier;
use ssh_key::Algorithm;
use std::time::Duration;

fn test_agent() -> VaultAgent<InMemoryStorage> {
    let profile = Profile::new(
        ProfileId("test".into()),
        "test",
        Ed25519Keypair::from_seed([7; 32]),
    );
    VaultAgent::new(IdentityVault::with_profile(InMemoryStorage::new(), profile))
}

fn random_key(comment: &str) -> PrivateKey {
    let mut key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
    key.set_comment(comment);
    key
}

fn vault_slot_count(agent: &VaultAgent<InMemoryStorage>) -> usize {
    agent
        .vault
        .lock()
        .unwrap()
        .current_profile()
        .unwrap()
        .slots
        .len()
}

#[tokio::test]
async fn added_identity_is_listed_and_stored() {
    let mut agent = test_agent();
    let key = random_key("laptop");
    let stored_key = protocol_key_for(&key);
    agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: key.key_data().clone(),
                comment: "laptop".into(),
            },
        })
        .await
        .unwrap();

    // One key, two credentials: the personae certificate first so a
    // host trusting the authority needs no per-key enrollment, then the
    // bare key for hosts that only know the key. Both carry the same
    // key data, which is why `sign` can resolve either to one slot.
    let listed = agent.request_identities().await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(matches!(listed[0].credential, PublicCredential::Cert(_)));
    assert_eq!(listed[0].comment, "laptop (personae certificate)");
    assert!(matches!(listed[1].credential, PublicCredential::Key(_)));
    assert_eq!(listed[1].comment, "laptop");
    assert_eq!(
        listed[0].credential.key_data(),
        listed[1].credential.key_data()
    );
    assert!(
        agent
            .vault
            .lock()
            .unwrap()
            .slot(&stored_key)
            .unwrap()
            .is_some()
    );
}

/// Signing must work when the client picks the certificate, since that
/// is the credential `ssh` prefers once one is offered.
#[tokio::test]
async fn a_certificate_credential_signs_with_its_underlying_key() {
    let mut agent = test_agent();
    let key = random_key("certified");
    agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: key.key_data().clone(),
                comment: "certified".into(),
            },
        })
        .await
        .unwrap();

    let listed = agent.request_identities().await.unwrap();
    let certificate = listed
        .iter()
        .find(|identity| matches!(identity.credential, PublicCredential::Cert(_)))
        .expect("a certificate is offered");
    let signature = agent
        .sign(SignRequest {
            credential: certificate.credential.clone(),
            data: b"over the certificate".to_vec(),
            flags: 0,
        })
        .await
        .expect("signing through the certificate credential");
    assert!(
        PublicKey::from(&key)
            .key_data()
            .verify(b"over the certificate", &signature)
            .is_ok(),
        "the signature must verify against the underlying key"
    );
}

#[tokio::test]
async fn sign_round_trips_and_verifies() {
    let mut agent = test_agent();
    let key = random_key("signer");
    let public = PublicKey::from(&key);
    agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: key.key_data().clone(),
                comment: String::new(),
            },
        })
        .await
        .unwrap();

    let data = b"session-blob-to-sign".to_vec();
    let sig = agent
        .sign(SignRequest {
            credential: public.key_data().clone().into(),
            data: data.clone(),
            flags: 0,
        })
        .await
        .unwrap();
    public.key_data().verify(&data, &sig).unwrap();
}

#[tokio::test]
async fn per_use_slot_refuses_to_sign() {
    let mut agent = test_agent();
    let key = random_key("guarded");
    let public = PublicKey::from(&key);
    agent
        .vault
        .lock()
        .unwrap()
        .add_slot(
            ssh_slot::protocol_key_for(&key),
            ssh_slot::slot_for(&key, UnlockTier::PerUse).unwrap(),
        )
        .unwrap();

    let err = agent
        .sign(SignRequest {
            credential: public.key_data().clone().into(),
            data: b"blob".to_vec(),
            flags: 0,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("per-use"), "got: {err}");
}

#[tokio::test]
async fn per_use_slot_signs_only_after_broker_approval() {
    let key = random_key("guarded");
    let public = PublicKey::from(&key);
    let mut profile = Profile::new(
        ProfileId("research".into()),
        "Research",
        Ed25519Keypair::from_seed([7; 32]),
    );
    profile.slots.insert(
        ssh_slot::protocol_key_for(&key),
        ssh_slot::slot_for(&key, UnlockTier::PerUse).unwrap(),
    );
    let broker = ApprovalBroker::new(Duration::from_secs(1));
    let mut agent = VaultAgent::with_approval_broker(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        broker.clone(),
        "ssh-agent.test",
    );
    let data = b"approval-bound-payload".to_vec();
    let verify_data = data.clone();
    let signing = tokio::spawn(async move {
        agent
            .sign(SignRequest {
                credential: public.key_data().clone().into(),
                data,
                flags: 0,
            })
            .await
    });

    let pending = loop {
        if let Some(pending) = broker.pending().into_iter().next() {
            break pending;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(pending.request.profile, "research");
    assert_eq!(pending.request.operation, "ssh.sign");
    broker
        .decide(
            pending.request.request_id,
            SigningDecision::Approve {
                remember: RememberApproval::Once,
            },
        )
        .unwrap();

    let signature = signing.await.unwrap().unwrap();
    PublicKey::from(&key)
        .key_data()
        .verify(&verify_data, &signature)
        .unwrap();
    let history = broker.history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].approval_source, Some(ApprovalSource::UserOnce));
    assert!(matches!(
        history[0].result,
        SigningRecordResult::Signed { .. }
    ));
}

#[tokio::test]
async fn per_use_slot_denial_returns_to_the_ssh_adapter() {
    let key = random_key("guarded");
    let public = PublicKey::from(&key);
    let mut profile = Profile::new(
        ProfileId("research".into()),
        "Research",
        Ed25519Keypair::from_seed([7; 32]),
    );
    profile.slots.insert(
        ssh_slot::protocol_key_for(&key),
        ssh_slot::slot_for(&key, UnlockTier::PerUse).unwrap(),
    );
    let broker = ApprovalBroker::new(Duration::from_secs(1));
    let mut agent = VaultAgent::with_approval_broker(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        broker.clone(),
        "ssh-agent.test",
    );
    let signing = tokio::spawn(async move {
        agent
            .sign(SignRequest {
                credential: public.key_data().clone().into(),
                data: b"denied-payload".to_vec(),
                flags: 0,
            })
            .await
    });

    let pending = loop {
        if let Some(pending) = broker.pending().into_iter().next() {
            break pending;
        }
        tokio::task::yield_now().await;
    };
    broker
        .decide(pending.request.request_id, SigningDecision::Deny)
        .unwrap();
    let error = signing.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("denied"), "got: {error}");
    assert_eq!(broker.history().len(), 1);
    assert_eq!(broker.history()[0].result, SigningRecordResult::Denied);
}

#[tokio::test]
async fn unknown_key_is_refused() {
    let mut agent = test_agent();
    let stranger = PublicKey::from(&random_key("stranger"));
    let err = agent
        .sign(SignRequest {
            credential: stranger.key_data().clone().into(),
            data: b"blob".to_vec(),
            flags: 0,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "got: {err}");
}

#[tokio::test]
async fn remove_and_remove_all_clear_slots() {
    let mut agent = test_agent();
    let a = random_key("a");
    let b = random_key("b");
    for key in [&a, &b] {
        agent
            .add_identity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey: key.key_data().clone(),
                    comment: String::new(),
                },
            })
            .await
            .unwrap();
    }
    assert_eq!(vault_slot_count(&agent), 2);

    agent
        .remove_identity(RemoveIdentity {
            credential: PublicKey::from(&a).key_data().clone().into(),
        })
        .await
        .unwrap();
    assert_eq!(vault_slot_count(&agent), 1);

    agent.remove_all_identities().await.unwrap();
    assert_eq!(vault_slot_count(&agent), 0);
}

async fn add(agent: &mut VaultAgent<InMemoryStorage>, key: &PrivateKey) {
    agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: key.key_data().clone(),
                comment: key.comment().to_string(),
            },
        })
        .await
        .unwrap();
}

async fn sign_with<S: IdentityStorage + 'static>(
    agent: &mut VaultAgent<S>,
    credential: PublicCredential,
    data: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    agent
        .sign(SignRequest {
            credential,
            data: data.to_vec(),
            flags,
        })
        .await
}

#[tokio::test]
async fn rsa_signs_through_the_agent_as_its_flags_ask() {
    use crate::custody::ssh_sign::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};
    use ssh_key::HashAlg;
    let mut agent = test_agent();
    let key = fixture("rsa3072");
    add(&mut agent, &key).await;
    let public = PublicKey::from(&key);
    for (flags, hash) in [
        (SSH_AGENT_RSA_SHA2_256, HashAlg::Sha256),
        (SSH_AGENT_RSA_SHA2_512, HashAlg::Sha512),
    ] {
        let signature = sign_with(&mut agent, public.key_data().clone().into(), b"blob", flags)
            .await
            .unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
        public.key_data().verify(b"blob", &signature).unwrap();
    }
    let refused = sign_with(&mut agent, public.key_data().clone().into(), b"blob", 0)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("SHA-1"), "got: {refused}");
}

/// `ssh` prefers the personae certificate; an RSA one signs per flags too.
#[tokio::test]
async fn an_rsa_certificate_credential_signs_with_its_underlying_key() {
    use crate::custody::ssh_sign::SSH_AGENT_RSA_SHA2_512;
    let mut agent = test_agent();
    let key = fixture("rsa2048");
    add(&mut agent, &key).await;
    let certificate = agent
        .request_identities()
        .await
        .unwrap()
        .into_iter()
        .find(|identity| matches!(identity.credential, PublicCredential::Cert(_)))
        .expect("a certificate is offered");
    let signature = sign_with(
        &mut agent,
        certificate.credential,
        b"cert",
        SSH_AGENT_RSA_SHA2_512,
    )
    .await
    .unwrap();
    PublicKey::from(&key)
        .key_data()
        .verify(b"cert", &signature)
        .unwrap();
}

#[tokio::test]
async fn ecdsa_signs_through_the_agent_on_p256_and_p384() {
    let mut agent = test_agent();
    for name in ["ecdsa256", "ecdsa384"] {
        let key = fixture(name);
        add(&mut agent, &key).await;
        let public = PublicKey::from(&key);
        let signature = sign_with(&mut agent, public.key_data().clone().into(), b"blob", 0)
            .await
            .unwrap();
        assert_eq!(signature.algorithm(), public.algorithm(), "{name}");
        public.key_data().verify(b"blob", &signature).unwrap();
    }
}

/// The pre-P4a Ed25519 slot, captured at `d0d8372b` as its serialized
/// `PlaintextSlot`, stays byte-identical while RSA and ECDSA keys are
/// added, listed, re-added and used beside it, and signs as before.
#[tokio::test]
async fn an_existing_ed25519_slot_is_byte_identical_and_signs_as_before() {
    use crate::custody::profile_wire::slot_to_plaintext;
    use crate::custody::ssh_sign::tests::{BASELINE_MESSAGE, BASELINE_SIGNATURE};
    const BASELINE_WIRE: &[u8] = include_bytes!("../../../tests/fixtures/ssh/ed25519.slot.json");

    let ed25519 = fixture("ed25519");
    let ed_key = protocol_key_for(&ed25519);
    let wire = |agent: &VaultAgent<InMemoryStorage>| {
        let vault = agent.vault.lock().unwrap();
        let slot = vault
            .current_profile()
            .unwrap()
            .slots
            .get(&ed_key)
            .expect("slot held");
        serde_json::to_vec(&slot_to_plaintext(&ed_key, slot)).unwrap()
    };
    let mut agent = test_agent();
    agent
        .vault
        .lock()
        .unwrap()
        .add_slot(
            ed_key.clone(),
            ssh_slot::slot_for(&ed25519, UnlockTier::Session).unwrap(),
        )
        .unwrap();
    assert_eq!(
        wire(&agent),
        BASELINE_WIRE,
        "the slot as pre-P4a code wrote it"
    );

    let others: Vec<PrivateKey> = ["rsa2048", "rsa4096", "ecdsa256", "ecdsa384"]
        .into_iter()
        .map(fixture)
        .collect();
    for key in &others {
        add(&mut agent, key).await;
    }
    add(&mut agent, &others[0]).await;
    add(&mut agent, &ed25519).await;
    let listed = agent.request_identities().await.unwrap();
    assert_eq!(
        listed.len(),
        2 * (1 + others.len()),
        "a certificate and a key each"
    );
    for key in &others {
        let flags = crate::custody::ssh_sign::SSH_AGENT_RSA_SHA2_256;
        let public = PublicKey::from(key);
        let signature = sign_with(&mut agent, public.key_data().clone().into(), b"x", flags)
            .await
            .unwrap();
        public.key_data().verify(b"x", &signature).unwrap();
    }

    let public = PublicKey::from(&ed25519);
    let signature = sign_with(
        &mut agent,
        public.key_data().clone().into(),
        BASELINE_MESSAGE,
        0,
    )
    .await
    .unwrap();
    assert_eq!(hex::encode(signature.as_bytes()), BASELINE_SIGNATURE);
    public
        .key_data()
        .verify(BASELINE_MESSAGE, &signature)
        .unwrap();
    assert_eq!(wire(&agent), BASELINE_WIRE, "untouched afterwards");
    assert_eq!(vault_slot_count(&agent), 1 + others.len());
}

#[tokio::test]
async fn readding_the_same_key_is_idempotent() {
    let mut agent = test_agent();
    let key = random_key("dup");
    for _ in 0..2 {
        agent
            .add_identity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey: key.key_data().clone(),
                    comment: "dup".into(),
                },
            })
            .await
            .unwrap();
    }
    assert_eq!(vault_slot_count(&agent), 1);
}

/// Ruling 54: `ssh-add` of a held PerUse key keeps it PerUse, byte for
/// byte, whatever comment the client sends.
#[tokio::test]
async fn readding_a_held_key_rewrites_nothing_its_tier_included() {
    use crate::custody::profile_wire::slot_to_plaintext;
    let mut agent = test_agent();
    let key = fixture("rsa2048");
    let stored = protocol_key_for(&key);
    agent
        .vault
        .lock()
        .unwrap()
        .add_slot(
            stored.clone(),
            ssh_slot::slot_for(&key, UnlockTier::PerUse).unwrap(),
        )
        .unwrap();
    let wire = |agent: &VaultAgent<InMemoryStorage>| {
        let vault = agent.vault.lock().unwrap();
        let slot = vault.current_profile().unwrap().slots.get(&stored).unwrap();
        serde_json::to_vec(&slot_to_plaintext(&stored, slot)).unwrap()
    };
    let before = wire(&agent);
    agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: key.key_data().clone(),
                comment: "a different comment".into(),
            },
        })
        .await
        .unwrap();
    assert_eq!(wire(&agent), before);
    let tier = agent.vault.lock().unwrap().current_profile().unwrap().slots[&stored].unlock_tier();
    assert_eq!(tier, UnlockTier::PerUse);
}

// ─── Vault lock rulings 8 and 9 ───────────────────────────────────────

use crate::custody::SealedProfileStorage;
use crate::custody::sealed_profile_storage::PASSPHRASE_ROOT_FILE;
use crate::custody::unlock::UnlockMethod;

mod locking;
