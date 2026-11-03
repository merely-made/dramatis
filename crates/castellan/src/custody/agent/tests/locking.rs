// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

const LOCK_PASSPHRASE: &[u8] = b"agent lock";

/// Locks the shared vault directly: the resident's broadcast is
/// castellan's, and this agent only needs something to engage.
struct DirectLock(Arc<Mutex<IdentityVault<SealedProfileStorage>>>);

impl VaultLockRequest for DirectLock {
    fn lock_vault(&self) -> Result<(), IdentityError> {
        self.0.lock().unwrap().lock()
    }
}

/// A lockable agent over a temp vault holding one Ed25519 key.
fn lockable_agent(dir: &std::path::Path) -> (VaultAgent<SealedProfileStorage>, PrivateKey) {
    let root = [0x6e; 32];
    crate::custody::save_passphrase_root(dir.join(PASSPHRASE_ROOT_FILE), &root, LOCK_PASSPHRASE)
        .unwrap();
    let storage = SealedProfileStorage::open_with_key(dir, root);
    let key = random_key("locked");
    let mut profile = Profile::new(
        ProfileId("test".into()),
        "test",
        Ed25519Keypair::from_seed([7; 32]),
    );
    profile.slots.insert(
        protocol_key_for(&key),
        ssh_slot::slot_for(&key, UnlockTier::Session).unwrap(),
    );
    storage.save_profile(&profile).unwrap();
    let vault = Arc::new(Mutex::new(IdentityVault::with_profile(storage, profile)));
    let agent = VaultAgent::from_shared_vault(
        Arc::clone(&vault),
        ApprovalBroker::new(Duration::from_secs(1)),
        "ssh-agent.test",
    )
    .with_vault_lock(Arc::new(DirectLock(vault)));
    (agent, key)
}

fn credential(key: &PrivateKey) -> PublicCredential {
    PublicKey::from(key).key_data().clone().into()
}

#[tokio::test]
async fn a_locked_agent_lists_nothing_and_refuses_sign_add_and_remove_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, key) = lockable_agent(dir.path());
    let before = agent.request_identities().await.unwrap();
    assert_eq!(before.len(), 2, "certificate and key");
    agent.lock(String::from("ignored")).await.unwrap();

    assert!(agent.request_identities().await.unwrap().is_empty());
    let sign = sign_with(&mut agent, credential(&key), b"x", 0).await;
    assert!(sign.unwrap_err().to_string().contains(LOCKED));
    let other = random_key("newcomer");
    let add = agent
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: other.key_data().clone(),
                comment: String::new(),
            },
        })
        .await;
    assert!(add.unwrap_err().to_string().contains(LOCKED));
    let remove = agent
        .remove_identity(RemoveIdentity {
            credential: credential(&key),
        })
        .await;
    assert!(remove.unwrap_err().to_string().contains(LOCKED));
    let remove_all = agent.remove_all_identities().await;
    assert!(remove_all.unwrap_err().to_string().contains(LOCKED));

    // Unlocked on the resident's own surface: the same identities, signing.
    agent
        .vault
        .lock()
        .unwrap()
        .unlock(UnlockMethod::Passphrase(LOCK_PASSPHRASE))
        .unwrap();
    let after = agent.request_identities().await.unwrap();
    assert_eq!(
        after
            .iter()
            .map(|i| i.credential.key_data())
            .collect::<Vec<_>>(),
        before
            .iter()
            .map(|i| i.credential.key_data())
            .collect::<Vec<_>>()
    );
    let signature = sign_with(&mut agent, credential(&key), b"x", 0)
        .await
        .unwrap();
    PublicKey::from(&key)
        .key_data()
        .verify(b"x", &signature)
        .unwrap();
    assert_eq!(vault_slot_count_of(&agent), 1, "nothing added or removed");
}

fn vault_slot_count_of(agent: &VaultAgent<SealedProfileStorage>) -> usize {
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
async fn the_lock_message_engages_the_vault_lock_and_unlock_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, _key) = lockable_agent(dir.path());
    agent.lock(String::from("pw")).await.unwrap();
    assert!(agent.vault.lock().unwrap().is_locked());
    assert!(agent.vault.lock().unwrap().storage().is_locked());
    // OpenSSH fails a second lock.
    assert!(agent.lock(String::from("pw")).await.is_err());
    // `-X` never unlocks, whatever the password.
    let refused = agent.unlock(String::from("pw")).await.unwrap_err();
    assert!(refused.to_string().contains("refused"), "{refused}");
    let passphrase = String::from_utf8(LOCK_PASSPHRASE.to_vec()).unwrap();
    assert!(agent.unlock(passphrase).await.is_err());
    assert!(agent.vault.lock().unwrap().is_locked());
}

#[tokio::test]
async fn without_a_vault_lock_the_lock_message_is_refused() {
    let mut agent = test_agent();
    assert!(agent.lock(String::from("pw")).await.is_err());
    assert!(!agent.vault.lock().unwrap().is_locked());
}

/// A lock while a sign waits for approval: the key is fetched again
/// after the approval, so the sign is refused and recorded failed.
#[tokio::test]
async fn a_lock_during_an_approval_refuses_the_sign() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _) = lockable_agent(dir.path());
    let key = random_key("guarded");
    agent
        .vault
        .lock()
        .unwrap()
        .add_slot(
            protocol_key_for(&key),
            ssh_slot::slot_for(&key, UnlockTier::PerUse).unwrap(),
        )
        .unwrap();
    let broker = agent.approval_broker().unwrap().clone();
    let mut signer = agent.clone();
    let wanted = credential(&key);
    let signing = tokio::spawn(async move { sign_with_any(&mut signer, wanted).await });
    let pending = loop {
        if let Some(pending) = broker.pending().into_iter().next() {
            break pending;
        }
        tokio::task::yield_now().await;
    };
    agent.vault.lock().unwrap().lock().unwrap();
    broker
        .decide(
            pending.request.request_id,
            SigningDecision::Approve {
                remember: RememberApproval::Once,
            },
        )
        .unwrap();
    let error = signing.await.unwrap().unwrap_err();
    assert!(error.to_string().contains(LOCKED), "{error}");
    assert!(matches!(
        broker.history()[0].result,
        SigningRecordResult::Failed { .. }
    ));
}

async fn sign_with_any<S: IdentityStorage + 'static>(
    agent: &mut VaultAgent<S>,
    credential: PublicCredential,
) -> Result<Signature, AgentError> {
    agent
        .sign(SignRequest {
            credential,
            data: b"held".to_vec(),
            flags: 0,
        })
        .await
}

/// Rulings 55 and 56: `ssh-add` refuses what the agent cannot sign, the
/// reason in the error, and stores nothing.
#[tokio::test]
async fn ssh_add_refuses_unsignable_keys_with_the_reason() {
    let mut agent = test_agent();
    let mut refused: Vec<(String, ssh_key::private::KeypairData)> = [
        "rsa1024",
        "rsa2560",
        "rsa8192",
        "rsa2048e3",
        "dsa",
        "ecdsa521",
    ]
    .into_iter()
    .map(|name| (name.to_string(), fixture(name).key_data().clone()))
    .collect();
    for key in crate::custody::ssh_sign::tests::security_keys() {
        refused.push(("security key".into(), key));
    }
    for (name, privkey) in refused {
        let error = agent
            .add_identity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey,
                    comment: String::new(),
                },
            })
            .await
            .unwrap_err();
        let reason = error.to_string();
        assert!(
            reason.contains("2048 to 4096 bits")
                || reason.contains("does not sign")
                || reason.contains("P-521"),
            "{name}: {reason}"
        );
    }
    assert_eq!(vault_slot_count(&agent), 0);
}
