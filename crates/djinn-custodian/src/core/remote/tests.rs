// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::remote_approval::{ApprovalPolicy, storage::EnrollmentStore};
use crate::tests::{Harness, djinn, outcome_for};
use custody_wire::remote_approval::{ApprovalAction, enrollment_scope};
use insigne::delegation::{DelegationCertificate, DelegationParent, DelegationRevocation};
use notochord::TrustedRoot;
use personae::delegation::Issue;
use personae::{IdentityProvider, InMemoryProvider};

mod route_tests;

struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    h: Harness,
    session: u64,
    root: InMemoryProvider,
    device: InMemoryProvider,
    grant: SignedDelegationCertificate,
}

impl Fixture {
    fn new(consent: &str) -> Self {
        let (directory, target) = crate::tests::vault();
        let root = InMemoryProvider::from_seed([0x41; 32]);
        let device = InMemoryProvider::from_seed([0x42; 32]);
        let issuer = root.master_public_key().to_bytes();
        let policy = ApprovalPolicy::weekly(
            TrustedRoot {
                authority: issuer,
                issuer,
            },
            target,
            "work".into(),
            [ApprovalAction::Consent],
        );
        let config = Config::parse(&serde_json::to_vec(&serde_json::json!({
            "vault":{"directory":directory.path(),"profile":"work"},
            "owner":{"unix_uid":1000},"consent":"channel","remote_approval":policy,
            "principals":[{"name":"djinn","match":{"unix-uid":1000},"grants":[
                {"operation":"status"},{"operation":"lock"},{"operation":"unlock"},
                {"operation":"release","profile":{"named":"work"},"salts":[{"exact":"mesh-author"}],"consent":consent}
            ]}]
        })).unwrap()).unwrap();
        EnrollmentStore::initialize(directory.path(), &policy).unwrap();
        let mut h = Harness::new(config.clone());
        let session = h.open(djinn());
        h.unlock(session);
        let at = wall_ms().unwrap();
        let grant = SignedDelegationCertificate::issue(
            &root,
            DelegationCertificate::new(
                DelegationParent::Root(issuer),
                issuer,
                device.master_public_key().to_bytes(),
                enrollment_scope(target, "work", [ApprovalAction::Consent]),
                at,
                at,
                Some(at + 604_800_000),
                1,
                [4; 32],
            ),
        )
        .unwrap();
        h.core.enroll_remote_device(grant.clone()).unwrap();
        Self {
            _directory: directory,
            config,
            h,
            session,
            root,
            device,
            grant,
        }
    }
    fn release() -> Operation {
        Operation::Release {
            profile: "work".into(),
            salts: vec![Bytes(b"mesh-author".to_vec())],
        }
    }
    fn challenge(&mut self) -> (u64, ApprovalRequest) {
        let (id, effects) = self.h.request(self.session, Self::release());
        assert!(outcome_for(&effects, self.session, id).is_none());
        let petition = self.h.core.remote_petition().unwrap();
        let (result, _) = self
            .h
            .core
            .request_remote_consent(id, &petition.digest, self.h.now);
        (id, result.unwrap())
    }
    fn proof(&self, request: &ApprovalRequest) -> ApprovalProof {
        ApprovalProof {
            chain: vec![
                self.grant.clone(),
                SignedDelegationCertificate::issue(
                    &self.device,
                    request.approval_for_device(&self.grant, wall_ms().unwrap()),
                )
                .unwrap(),
            ],
        }
    }
    fn revoke(&self) -> SignedDelegationRevocation {
        SignedDelegationRevocation::issue(
            &self.root,
            DelegationRevocation::new(
                self.grant.certificate.id(),
                self.grant.certificate.issuer,
                self.grant.certificate.scope.clone(),
                wall_ms().unwrap(),
                [5; 32],
            ),
        )
        .unwrap()
    }
}

#[test]
fn an_enrolled_device_completes_a_real_custody_petition_without_a_local_helper() {
    let mut f = Fixture::new("per-operation");
    let (id, request) = f.challenge();
    let proof = f.proof(&request);
    let (result, effects) =
        f.h.core
            .approve_remote_consent(request.nonce, &proof, f.h.now);
    result.unwrap();
    assert!(matches!(
        outcome_for(&effects, f.session, id),
        Some(Outcome::Success {
            answer: Answer::Released { .. }
        })
    ));
    assert!(
        f.h.core
            .approve_remote_consent(request.nonce, &proof, f.h.now)
            .0
            .is_err()
    );
    assert!(f.h.core.request_remote_unlock().is_err());
    assert!(
        !f.h.core.status().locked,
        "ordinary consent does not change the vault lock"
    );
    assert!(
        f.h.core.consented.is_empty(),
        "remote proof never becomes an untracked local consent bit"
    );
}

#[test]
fn per_generation_remote_consent_is_cached_until_revoked_without_sliding_the_timer() {
    let mut f = Fixture::new("per-generation");
    let original_deadline = f.h.core.next_deadline();
    let (_, request) = f.challenge();
    let proof = f.proof(&request);
    f.h.core
        .approve_remote_consent(request.nonce, &proof, f.h.now)
        .0
        .unwrap();
    let (id, effects) = f.h.request(f.session, Fixture::release());
    assert!(matches!(
        outcome_for(&effects, f.session, id),
        Some(Outcome::Success { .. })
    ));
    assert_eq!(f.h.core.next_deadline(), original_deadline);
    let revocation = f.revoke();
    f.h.core.revoke_remote_device(revocation.clone()).0.unwrap();
    let generation = f.h.core.generation();
    f.h.core.revoke_remote_device(revocation).0.unwrap();
    assert_eq!(
        f.h.core.generation(),
        generation,
        "revocation replay cannot repeatedly invalidate work"
    );
    let (_, challenge) = f.challenge();
    let proof = f.proof(&challenge);
    assert!(
        f.h.core
            .approve_remote_consent(challenge.nonce, &proof, f.h.now)
            .0
            .is_err()
    );
}

#[test]
fn per_operation_remote_consent_does_not_authorize_the_next_operation() {
    let mut f = Fixture::new("per-operation");
    let (_, request) = f.challenge();
    let proof = f.proof(&request);
    f.h.core
        .approve_remote_consent(request.nonce, &proof, f.h.now)
        .0
        .unwrap();
    let (_, next) = f.challenge();
    assert_ne!(request.nonce, next.nonce);
}

#[test]
fn a_pinned_root_persona_can_complete_the_real_petition_directly() {
    let mut f = Fixture::new("per-operation");
    let (id, request) = f.challenge();
    let issuer = f.root.master_public_key().to_bytes();
    let proof = ApprovalProof {
        chain: vec![
            SignedDelegationCertificate::issue(
                &f.root,
                request.approval_statement(
                    DelegationParent::Root(issuer),
                    issuer,
                    wall_ms().unwrap(),
                ),
            )
            .unwrap(),
        ],
    };
    let (result, effects) =
        f.h.core
            .approve_remote_consent(request.nonce, &proof, f.h.now);
    result.unwrap();
    assert!(matches!(
        outcome_for(&effects, f.session, id),
        Some(Outcome::Success { .. })
    ));
}

#[test]
fn deny_policy_stays_deny_even_with_a_root_pin_and_enrolled_devices() {
    let mut f = Fixture::new("per-generation");
    f.h.core.config.consent = ConsentMode::Deny;
    let (id, effects) = f.h.request(f.session, Fixture::release());
    assert!(matches!(
        outcome_for(&effects, f.session, id),
        Some(Outcome::Refused { .. })
    ));
    assert!(f.h.core.remote_petition().is_none());
}

#[test]
fn permission_is_rechecked_at_commit_and_a_closed_requester_cannot_be_approved() {
    for close in [false, true] {
        let mut f = Fixture::new("per-operation");
        let (id, request) = f.challenge();
        let proof = f.proof(&request);
        if close {
            f.h.core.close(f.session);
        } else {
            f.h.core.config.principals[0].grants.pop();
        }
        let (result, effects) =
            f.h.core
                .approve_remote_consent(request.nonce, &proof, f.h.now);
        assert!(result.is_err());
        assert!(!matches!(
            outcome_for(&effects, f.session, id),
            Some(Outcome::Success { .. })
        ));
    }
}

#[test]
fn lock_revocation_and_expiry_between_challenge_and_commit_refuse_execution() {
    for cause in [0, 1, 2] {
        let mut f = Fixture::new("per-generation");
        let (_, request) = f.challenge();
        let proof = f.proof(&request);
        match cause {
            0 => {
                f.h.core.lock_now();
            },
            1 => {
                let revoke = f.revoke();
                f.h.core.revoke_remote_device(revoke).0.unwrap();
            },
            _ => {
                f.h.now += limits::CONSENT;
            },
        }
        assert!(
            f.h.core
                .approve_remote_consent(request.nonce, &proof, f.h.now)
                .0
                .is_err()
        );
    }
}

#[test]
fn restart_keeps_enrollment_and_revocation_but_drops_live_approval_and_cached_consent() {
    let mut f = Fixture::new("per-generation");
    let (_, request) = f.challenge();
    let proof = f.proof(&request);
    let revocation = f.revoke();
    f.h.core.revoke_remote_device(revocation).0.unwrap();
    let config = f.config.clone();
    drop(f.h);
    let mut h = Harness::new(config);
    let session = h.open(djinn());
    h.unlock(session);
    assert!(
        h.core
            .approve_remote_consent(request.nonce, &proof, h.now)
            .0
            .is_err()
    );
    assert!(h.core.enroll_remote_device(f.grant).is_err());
}

#[test]
fn explicit_remote_configuration_requires_existing_storage_and_a_matching_profile() {
    let f = Fixture::new("per-operation");
    let mut config = f.config.clone();
    let policy = config.remote_approval.clone().unwrap();
    drop(f.h);
    config.remote_approval.as_mut().unwrap().profile = "different".into();
    assert!(
        Core::start(config).is_err(),
        "the stored root/target/profile pin must match"
    );
    let (empty, _) = crate::tests::vault();
    let mut config = crate::tests::config(empty.path(), "channel", "per-operation");
    config.vault.profile = Some("work".into());
    config.remote_approval = Some(policy);
    assert!(Core::start(config).is_err());
    assert!(!empty.path().join("remote-approval.redb").exists());
}

#[test]
fn a_valid_but_unregistered_device_grant_is_not_an_enrollment() {
    let mut f = Fixture::new("per-operation");
    let (_, request) = f.challenge();
    let mut certificate = f.grant.certificate.clone();
    certificate.nonce = [8; 32];
    let new = SignedDelegationCertificate::issue(&f.root, certificate).unwrap();
    let proof = ApprovalProof {
        chain: vec![
            new.clone(),
            SignedDelegationCertificate::issue(
                &f.device,
                request.approval_for_device(&new, wall_ms().unwrap()),
            )
            .unwrap(),
        ],
    };
    assert_eq!(
        f.h.core
            .approve_remote_consent(request.nonce, &proof, f.h.now)
            .0
            .err(),
        Some(Refusal("remote-enrollment-missing"))
    );
    f.h.core.enroll_remote_device(new).unwrap();
    f.h.core
        .approve_remote_consent(request.nonce, &proof, f.h.now)
        .0
        .unwrap();
}

#[test]
fn an_approval_cannot_move_to_another_petition_reusing_the_same_client_request_id() {
    let mut f = Fixture::new("per-operation");
    let (id, first) = f.challenge();
    let petition = f.h.core.remote_petition().unwrap();
    let second =
        f.h.core
            .request_remote_consent(id, &petition.digest, f.h.now)
            .0
            .unwrap();
    let second_proof = f.proof(&second);
    let _ = f.h.core.handle(
        f.session,
        ClientMessage::Request {
            id,
            instance: f.h.core.instance().into(),
            generation: f.h.core.generation(),
            operation: Fixture::release(),
        },
        f.h.now,
    );
    let proof = f.proof(&first);
    f.h.core
        .approve_remote_consent(first.nonce, &proof, f.h.now)
        .0
        .unwrap();
    let next = f.h.core.remote_petition().unwrap();
    assert_ne!(next.digest, petition.digest);
    assert!(
        f.h.core
            .approve_remote_consent(second.nonce, &second_proof, f.h.now)
            .0
            .is_err()
    );
    assert_eq!(f.h.core.remote_petition().unwrap().digest, next.digest);
}

#[test]
fn remote_consent_completes_a_real_per_use_ssh_signature() {
    use ssh_agent_lib::agent::Session;
    let mut f = Fixture::new("per-operation");
    let private =
        ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[0x52; 32]));
    // Trusted fixture setup, not an added client import permission.
    f.h.core
        .custody()
        .import_ssh_key(
            private
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
            None,
            br#"{"unlock_policy":{"kind":"per_use"}}"#,
        )
        .unwrap();
    let public = private.public_key().key_data().clone();
    let verify = personae::Ed25519PublicKey::from_bytes(&public.ed25519().unwrap().0).unwrap();
    let mut agent = f.h.core.custody().agent_session().unwrap();
    let signer = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(agent.sign(ssh_agent_lib::proto::SignRequest {
            credential: public.into(),
            data: b"remote signing receipt".to_vec(),
            flags: 0,
        }))
    });
    let until = Instant::now() + Duration::from_secs(10);
    let petition = loop {
        f.h.core.petition_signing(f.h.now);
        if let Some(petition) = f.h.core.remote_petition() {
            break petition;
        }
        assert!(Instant::now() < until, "signing petition did not arrive");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(petition.operation, "ssh-sign");
    let request =
        f.h.core
            .request_remote_consent(petition.request, &petition.digest, f.h.now)
            .0
            .unwrap();
    let proof = f.proof(&request);
    f.h.core
        .approve_remote_consent(request.nonce, &proof, f.h.now)
        .0
        .unwrap();
    let signature = signer.join().unwrap().unwrap();
    let bytes: [u8; 64] = signature.as_bytes().try_into().unwrap();
    assert!(verify.verify(
        b"remote signing receipt",
        &personae::Ed25519Signature::from_bytes(&bytes)
    ));
}
