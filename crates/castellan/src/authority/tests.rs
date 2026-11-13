// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use crate::custody::ssh_slot::{protocol_key_for, slot_for};
use crate::custody::{InMemoryStorage, Profile};
use personae::{Ed25519Keypair, ProfileId};
use signature::Verifier;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::proto::SignRequest;
use ssh_key::{Algorithm, LineEnding};

use super::*;

/// The Unix receipt wall: the user's `SSH_AUTH_SOCK`, by path or by a
/// link to it, is the standard endpoint; any other socket is not.
#[test]
fn the_users_agent_socket_is_the_standard_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("agent.sock");
    std::fs::write(&sock, b"").unwrap();
    let standard = Some(sock.as_os_str());
    assert!(same_socket(&sock.display().to_string(), standard));
    assert!(!same_socket(
        &dir.path().join("receipt.sock").display().to_string(),
        standard
    ));
    assert!(!same_socket(&sock.display().to_string(), None));
    let dotted = dir.path().join(".").join("agent.sock");
    assert!(same_socket(&dotted.display().to_string(), standard));
}

#[test]
fn snapshot_discloses_public_ssh_material_but_not_the_private_slot() {
    let mut private = ssh_key::PrivateKey::random(
        &mut rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    private.set_comment("workstation");
    let private_openssh = private.to_openssh(LineEnding::LF).unwrap().to_string();
    let mut profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x5a; 32]),
    );
    profile.slots.insert(
        protocol_key_for(&private),
        slot_for(&private, UnlockTier::PerUse).unwrap(),
    );
    let storage = InMemoryStorage::new();
    storage.save_profile(&profile).unwrap();
    let host = PersonaeHost::new(
        IdentityVault::with_profile(storage, profile),
        None,
        VaultProtectionView::Ephemeral,
    );

    let snapshot = host.snapshot().unwrap();
    let json = snapshot.to_public_json().unwrap();
    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(snapshot.ssh_keys.len(), 1);
    assert_eq!(snapshot.ssh_keys[0].comment, "workstation");
    assert_eq!(snapshot.ssh_keys[0].unlock_policy, "every use");
    assert!(
        snapshot.ssh_keys[0]
            .public_openssh
            .starts_with("ssh-ed25519 ")
    );
    assert!(!json.contains(&private_openssh));
    assert!(!json.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(!json.contains("5a5a5a5a5a5a5a5a"));
    assert_eq!(snapshot.vault.agent, AgentListenerView::StandaloneRetained);
}

#[test]
fn a_created_persona_joins_the_vault_and_the_host_stays_where_it_was() {
    // Creating and becoming are separate decisions: a persona minted for
    // another device is not one the user is adopting.
    let storage = InMemoryStorage::new();
    let work = Profile::new(
        ProfileId("work".into()),
        "Work",
        Ed25519Keypair::from_seed([0x31; 32]),
    );
    storage.save_profile(&work).unwrap();
    let host = PersonaeHost::new(
        IdentityVault::with_profile(storage, work),
        None,
        VaultProtectionView::Ephemeral,
    );
    let before = IdentityProvider::master_public_key(&host).to_bytes();

    let outcome = host
        .apply_intent(
            PROFILE_CREATE_INTENT,
            &serde_json::to_vec(&CreateProfileIntentV1 {
                id: "alt".into(),
                display_name: "Late Night Alt".into(),
            })
            .unwrap(),
        )
        .unwrap();

    match outcome {
        IdentityIntentOutcome::ProfileCreated(receipt) => {
            assert_eq!(receipt.id, "alt");
            assert_eq!(receipt.display_name, "Late Night Alt");
            assert!(receipt.master_public_fingerprint.starts_with("blake3:"));
        },
        other => panic!("expected a creation receipt, got {other:?}"),
    }

    let snapshot = host.snapshot().unwrap();
    let mut ids: Vec<&str> = snapshot.profiles.iter().map(|p| p.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["alt", "work"], "the new persona is in the roster");
    assert_eq!(
        snapshot
            .profiles
            .iter()
            .filter(|p| p.selected)
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        ["work"],
        "creating does not switch"
    );
    assert_eq!(
        IdentityProvider::master_public_key(&host).to_bytes(),
        before,
        "and the host still speaks as the persona it had"
    );
}

#[test]
fn an_id_that_would_not_survive_becoming_a_filename_is_refused() {
    // `owner_settings::settings_path` replaces anything unsafe with `_`,
    // so accepting `a/b` here would mean it and `a_b` silently share one
    // settings file. Refusing at creation is the only place that cannot be
    // worked around later.
    let host = PersonaeHost::new(
        IdentityVault::with_profile(
            InMemoryStorage::new(),
            Profile::new(
                ProfileId("work".into()),
                "Work",
                Ed25519Keypair::from_seed([0x32; 32]),
            ),
        ),
        None,
        VaultProtectionView::Ephemeral,
    );
    for bad in ["../../evil", "a/b", "with space", "", "   "] {
        assert!(
            matches!(
                host.create_profile(CreateProfileIntentV1 {
                    id: bad.into(),
                    display_name: "Whatever".into(),
                }),
                Err(IdentityIntentError::InvalidProfileId)
            ),
            "{bad:?} must be refused"
        );
    }
    assert!(
        host.create_profile(CreateProfileIntentV1 {
            id: "a".repeat(65),
            display_name: "Long".into(),
        })
        .is_err()
    );
    // And a name that is only whitespace, or carries control characters.
    for bad in ["", "   ", "two\nlines"] {
        assert!(
            matches!(
                host.create_profile(CreateProfileIntentV1 {
                    id: "fine".into(),
                    display_name: bad.into(),
                }),
                Err(IdentityIntentError::InvalidProfileName)
            ),
            "{bad:?} must be refused as a name"
        );
    }
    assert_eq!(
        host.snapshot().unwrap().profiles.len(),
        1,
        "nothing was minted by any of the refusals"
    );
}

#[test]
fn creating_over_an_existing_persona_is_refused() {
    // The guard that matters: minting over a persona replaces its master
    // key and every certificate rooted on it.
    let storage = InMemoryStorage::new();
    let work = Profile::new(
        ProfileId("work".into()),
        "Work",
        Ed25519Keypair::from_seed([0x33; 32]),
    );
    storage.save_profile(&work).unwrap();
    let before = work.master.public_key().to_bytes();
    let host = PersonaeHost::new(
        IdentityVault::with_profile(storage, work),
        None,
        VaultProtectionView::Ephemeral,
    );

    assert!(
        host.create_profile(CreateProfileIntentV1 {
            id: "work".into(),
            display_name: "Impostor".into(),
        })
        .is_err()
    );
    assert_eq!(
        IdentityProvider::master_public_key(&host).to_bytes(),
        before,
        "the existing persona keeps its key"
    );
}

#[test]
fn a_projected_switch_is_live_and_remembered_for_the_family() {
    // The gap this closes: the projection could show which persona the
    // host speaks as, and nothing could change it.
    let storage = InMemoryStorage::new();
    let work = Profile::new(
        ProfileId("work".into()),
        "Work",
        Ed25519Keypair::from_seed([0x11; 32]),
    );
    let personal = Profile::new(
        ProfileId("personal".into()),
        "Personal",
        Ed25519Keypair::from_seed([0x12; 32]),
    );
    storage.save_profile(&work).unwrap();
    storage.save_profile(&personal).unwrap();
    let vault_dir =
        std::env::temp_dir().join(format!("graphshell-switch-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&vault_dir);
    let host = PersonaeHost::new(
        IdentityVault::with_profile(storage, work),
        None,
        VaultProtectionView::Ephemeral,
    )
    .with_vault_dir(vault_dir.clone());

    let before = IdentityProvider::master_public_key(&host).to_bytes();
    let outcome = host
        .apply_intent(
            PROFILE_SWITCH_INTENT,
            &serde_json::to_vec(&SwitchProfileIntentV1 {
                profile: "personal".into(),
            })
            .unwrap(),
        )
        .unwrap();

    // Live: the host's own identity — the one the shared SSH agent
    // serves — is the new persona, and the snapshot marks it selected.
    assert_ne!(
        IdentityProvider::master_public_key(&host).to_bytes(),
        before
    );
    let snapshot = host.snapshot().unwrap();
    let selected: Vec<&str> = snapshot
        .profiles
        .iter()
        .filter(|profile| profile.selected)
        .map(|profile| profile.id.as_str())
        .collect();
    assert_eq!(selected, ["personal"]);

    // Remembered: the family's choice file now names the new persona.
    match outcome {
        IdentityIntentOutcome::ProfileSwitch(receipt) => {
            assert_eq!(receipt.profile, "personal");
            assert!(receipt.remembered);
        },
        other => panic!("expected a profile switch receipt, got {other:?}"),
    }
    assert_eq!(
        roster::chosen_profile(&vault_dir),
        Some(ProfileId("personal".into()))
    );

    // A persona that does not exist is an error, and the host still
    // speaks as the one it had.
    assert!(
        host.switch_profile(SwitchProfileIntentV1 {
            profile: "absent".into(),
        })
        .is_err()
    );
    assert_eq!(
        host.snapshot()
            .unwrap()
            .profiles
            .iter()
            .find(|p| p.selected)
            .unwrap()
            .id,
        "personal"
    );
    let _ = std::fs::remove_dir_all(&vault_dir);
}

#[tokio::test]
async fn projected_decisions_cannot_release_the_real_ssh_adapter_without_native_confirmation() {
    let mut private = ssh_key::PrivateKey::random(
        &mut rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    private.set_comment("approval-key");
    let public = ssh_key::PublicKey::from(&private);
    let mut profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x2a; 32]),
    );
    profile.slots.insert(
        protocol_key_for(&private),
        slot_for(&private, UnlockTier::PerUse).unwrap(),
    );
    let host = PersonaeHost::with_decision_timeout(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        None,
        VaultProtectionView::Ephemeral,
        Duration::from_secs(2),
    );
    let mut agent = host.agent_session();
    let signing = tokio::spawn(async move {
        agent
            .sign(SignRequest {
                credential: public.key_data().clone().into(),
                data: b"native-host-approval".to_vec(),
                flags: 0,
            })
            .await
    });

    let pending = loop {
        if let Some(pending) = host.snapshot().unwrap().pending_signing.into_iter().next() {
            break pending;
        }
        tokio::task::yield_now().await;
    };
    let payload = serde_json::to_vec(&SigningDecisionIntentV1 {
        request_id: pending.request.request_id,
    })
    .unwrap();
    for intent in [
        SIGNING_APPROVE_ONCE_INTENT,
        SIGNING_APPROVE_IDLE_INTENT,
        SIGNING_DENY_INTENT,
    ] {
        assert!(matches!(
            host.apply_intent(intent, &payload),
            Err(IdentityIntentError::SigningDecisionNativeOnly)
        ));
    }
    assert!(
        !signing.is_finished(),
        "the projected client cannot resolve its request"
    );
    let context = host
        .begin_native_signing(pending.request.request_id)
        .unwrap();
    host.complete_native_signing(
        context,
        SigningDecision::Approve {
            remember: RememberApproval::Once,
        },
    )
    .unwrap();

    let signature = signing.await.unwrap().unwrap();
    assert!(!signature.as_bytes().is_empty());
    let completed = host.snapshot().unwrap();
    assert!(completed.pending_signing.is_empty());
    assert_eq!(completed.signing_history.len(), 1);
    assert!(matches!(
        completed.signing_history[0].result,
        personae::signing::SigningRecordResult::Signed { .. }
    ));
}

#[cfg(windows)]
#[tokio::test]
async fn isolated_named_pipe_lists_and_signs_through_the_ssh_wire_protocol() {
    use ssh_agent_lib::client::Client;
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut private = ssh_key::PrivateKey::random(
        &mut rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    private.set_comment("wire-receipt");
    let public = ssh_key::PublicKey::from(&private);
    let mut profile = Profile::new(
        ProfileId("research".to_string()),
        "Research",
        Ed25519Keypair::from_seed([0x3a; 32]),
    );
    profile.slots.insert(
        protocol_key_for(&private),
        slot_for(&private, UnlockTier::PerUse).unwrap(),
    );
    let host = PersonaeHost::with_decision_timeout(
        IdentityVault::with_profile(InMemoryStorage::new(), profile),
        None,
        VaultProtectionView::Ephemeral,
        Duration::from_secs(2),
    );
    assert_eq!(
        host.bind_receipt_listener(r"\\.\pipe\openssh-ssh-agent")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        host.bind_standard_listener(r"\\.\pipe\graphshell-not-standard")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let endpoint = format!(r"\\.\pipe\graphshell-h4-receipt-{}", Uuid::new_v4());
    let listener = host.bind_receipt_listener(&endpoint).unwrap();
    let server = tokio::spawn(ssh_agent_lib::agent::listen(listener, host.agent_session()));

    let pipe = ClientOptions::new().open(&endpoint).unwrap();
    let mut client = Client::new(pipe);
    // One slot, two offers. A certifiable key is offered as its
    // certificate first, so a host that trusts the authority needs no
    // per-key enrollment, and then bare, so a host that has only ever seen
    // the key still works. Both resolve to the same slot when signing,
    // because a credential's key data is the key either way.
    let identities = client.request_identities().await.unwrap();
    assert_eq!(
        identities
            .iter()
            .map(|identity| identity.comment.as_str())
            .collect::<Vec<_>>(),
        ["wire-receipt (personae certificate)", "wire-receipt"],
        "the wire offers the certificate before the bare key"
    );
    assert_eq!(
        host.snapshot().unwrap().vault.agent,
        AgentListenerView::ReceiptEndpoint {
            endpoint: endpoint.clone()
        }
    );

    let data = b"graphshell-isolated-wire-receipt".to_vec();
    let verify_data = data.clone();
    let credential = identities[0].credential.clone();
    let signing = tokio::spawn(async move {
        client
            .sign(SignRequest {
                credential,
                data,
                flags: 0,
            })
            .await
    });

    let pending = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(pending) = host.snapshot().unwrap().pending_signing.into_iter().next() {
                break pending;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    host.approve_once(pending.request.request_id).unwrap();

    let signature = signing.await.unwrap().unwrap();
    public.key_data().verify(&verify_data, &signature).unwrap();
    assert!(matches!(
        host.snapshot().unwrap().signing_history[0].result,
        personae::signing::SigningRecordResult::Signed { .. }
    ));

    server.abort();
    let _ = server.await;
}

mod imports;
