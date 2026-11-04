// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use custody_wire::remote_approval::ApprovalOperation::{Consent, Unlock};
use insigne::delegation::{
    DelegationCertificate, DelegationParent, DelegationRevocation, SignedDelegationCertificate,
    SignedDelegationRevocation,
};
use personae::delegation::Issue;
use personae::{IdentityProvider, InMemoryProvider};

const NOW: u64 = 1_790_000_000_000;
const WEEK_MS: u64 = WEEK_SECONDS * 1000;

struct Pair {
    root: InMemoryProvider,
    approver: InMemoryProvider,
    target: [u8; 32],
    gate: ApprovalGate,
    ledger: RevocationLedger,
    now: Instant,
}

impl Pair {
    fn new() -> Self {
        let root = InMemoryProvider::from_seed([1; 32]);
        let approver = InMemoryProvider::from_seed([2; 32]);
        let target = InMemoryProvider::from_seed([3; 32])
            .master_public_key()
            .to_bytes();
        let policy = ApprovalPolicy::weekly(
            TrustedRoot {
                authority: root.master_public_key().to_bytes(),
                issuer: root.master_public_key().to_bytes(),
            },
            target,
            "work".into(),
            [ApprovalAction::Unlock, ApprovalAction::Consent],
        );
        Self {
            root,
            approver,
            target,
            gate: ApprovalGate::new(policy, "instance-a".into(), 1).unwrap(),
            ledger: RevocationLedger::new(),
            now: Instant::now(),
        }
    }

    fn begin(&mut self, operation: ApprovalOperation) -> ApprovalRequest {
        self.gate.begin(operation, NOW, self.now).unwrap()
    }

    fn grant(&self) -> SignedDelegationCertificate {
        let root = self.root.master_public_key().to_bytes();
        SignedDelegationCertificate::issue(
            &self.root,
            DelegationCertificate::new(
                DelegationParent::Root(root),
                root,
                self.approver.master_public_key().to_bytes(),
                enrollment_scope(
                    self.target,
                    "work",
                    [ApprovalAction::Unlock, ApprovalAction::Consent],
                ),
                NOW,
                NOW,
                Some(NOW + WEEK_MS),
                1,
                [4; 32],
            ),
        )
        .unwrap()
    }

    fn proof(&self, request: &ApprovalRequest) -> ApprovalProof {
        self.proof_with_grant(request, self.grant())
    }

    fn proof_with_grant(
        &self,
        request: &ApprovalRequest,
        grant: SignedDelegationCertificate,
    ) -> ApprovalProof {
        let approval = SignedDelegationCertificate::issue(
            &self.approver,
            request.approval_for_device(&grant, NOW),
        )
        .unwrap();
        ApprovalProof {
            chain: vec![grant, approval],
        }
    }

    fn accept(&mut self, nonce: [u8; 32], proof: &ApprovalProof) -> Result<VerifiedApproval> {
        self.gate.accept(nonce, proof, &self.ledger, NOW, self.now)
    }
}

#[test]
fn root_enrolls_a_device_and_its_approval_is_single_use_without_target_secrets() {
    let mut pair = Pair::new();
    // This gate has no vault object, target private key or SSH credential.
    let request = pair.begin(Unlock {
        seconds: WEEK_SECONDS,
    });
    let grant = pair.grant();
    let enrolled = pair
        .gate
        .check_enrollment(&grant, &pair.ledger, NOW)
        .unwrap();
    assert_eq!(
        enrolled.device(),
        pair.approver.master_public_key().to_bytes()
    );
    assert_eq!(enrolled.certificate(), grant.certificate.id());
    assert_eq!(enrolled.expires_at_ms(), NOW + WEEK_MS);
    let proof: ApprovalProof =
        serde_json::from_slice(&serde_json::to_vec(&pair.proof(&request)).unwrap()).unwrap();
    let receipt = pair.accept(request.nonce, &proof).unwrap();
    assert_eq!(receipt.request(), &request);
    assert_eq!(
        receipt.approver(),
        pair.approver.master_public_key().to_bytes()
    );
    assert_eq!(receipt.unlock_until_ms(), Some(NOW + WEEK_MS));
    assert_eq!(
        pair.accept(request.nonce, &proof).err(),
        Some(Refusal("remote-not-pending"))
    );
}

#[test]
fn an_explicitly_authorized_root_persona_can_approve_directly() {
    let mut pair = Pair::new();
    let request = pair.begin(Consent {
        request: 37,
        digest: [9; 32],
    });
    let root = pair.root.master_public_key().to_bytes();
    let proof = ApprovalProof {
        chain: vec![
            SignedDelegationCertificate::issue(
                &pair.root,
                request.approval_statement(DelegationParent::Root(root), root, NOW),
            )
            .unwrap(),
        ],
    };
    let receipt = pair.accept(request.nonce, &proof).unwrap();
    assert_eq!(receipt.approver(), root);
    assert_eq!(
        receipt.unlock_until_ms(),
        None,
        "consent never renews existing authorization"
    );
}

#[test]
fn a_direct_root_approval_has_a_short_request_window_and_a_separate_unlock_bound() {
    let mut pair = Pair::new();
    let request = pair.begin(Unlock {
        seconds: WEEK_SECONDS,
    });
    let root = pair.root.master_public_key().to_bytes();
    let proof = ApprovalProof {
        chain: vec![
            SignedDelegationCertificate::issue(
                &pair.root,
                request.approval_statement(DelegationParent::Root(root), root, NOW),
            )
            .unwrap(),
        ],
    };
    let receipt = pair.accept(request.nonce, &proof).unwrap();
    assert_eq!(receipt.unlock_until_ms(), Some(NOW + WEEK_MS));
    assert_eq!(receipt.request().expires_at_ms, NOW + 120_000);
}

#[test]
fn owner_limits_can_be_shorter_and_overflow_is_refused() {
    let mut pair = Pair::new();
    pair.gate.policy.max_unlock_seconds = 30;
    assert_eq!(
        pair.gate.begin(Unlock { seconds: 31 }, NOW, pair.now).err(),
        Some(Refusal("remote-duration"))
    );
    let request = pair.begin(Unlock { seconds: 30 });
    let proof = pair.proof(&request);
    assert_eq!(
        pair.accept(request.nonce, &proof)
            .unwrap()
            .unlock_until_ms(),
        Some(NOW + 30_000)
    );
    let mut pair = Pair::new();
    assert_eq!(
        pair.gate
            .begin(Unlock { seconds: 1 }, u64::MAX, pair.now)
            .err(),
        Some(Refusal("remote-time"))
    );
    let mut policy = pair.gate.policy.clone();
    policy.max_grant_seconds = u64::MAX;
    assert!(ApprovalGate::new(policy, "instance".into(), 1).is_err());
}

#[test]
fn association_alone_and_an_unrelated_root_do_not_grant_unlock_permission() {
    let mut pair = Pair::new();
    pair.gate.policy.actions.clear();
    assert_eq!(
        pair.gate.begin(Unlock { seconds: 60 }, NOW, pair.now).err(),
        Some(Refusal("remote-action"))
    );
    pair.gate.policy.actions.insert(ApprovalAction::Unlock);
    pair.gate.policy.actions.insert(ApprovalAction::Consent);
    let request = pair.begin(Unlock { seconds: 60 });
    let mut grant = pair.grant().certificate;
    let stranger = InMemoryProvider::from_seed([8; 32]);
    grant.issuer = stranger.master_public_key().to_bytes();
    grant.parent = DelegationParent::Root(grant.issuer);
    let proof = pair.proof_with_grant(
        &request,
        SignedDelegationCertificate::issue(&stranger, grant).unwrap(),
    );
    assert!(pair.accept(request.nonce, &proof).is_err());
    let proof = pair.proof(&request);
    assert!(
        pair.accept(request.nonce, &proof).is_ok(),
        "a bad proof cannot consume the owner's request"
    );
}

#[test]
fn every_target_request_field_is_bound_even_when_the_approver_resigns_it() {
    let changes: [fn(&mut ApprovalRequest); 8] = [
        |r| r.target = [7; 32],
        |r| r.profile = "work/adjacent".into(),
        |r| r.instance = "other-instance".into(),
        |r| r.generation += 1,
        |r| r.nonce = [6; 32],
        |r| r.operation = Unlock { seconds: 61 },
        |r| r.issued_at_ms -= 1,
        |r| r.expires_at_ms -= 1,
    ];
    for change in changes {
        let mut pair = Pair::new();
        let request = pair.begin(Unlock { seconds: 60 });
        let mut changed = request.clone();
        change(&mut changed);
        let proof = pair.proof(&changed);
        assert!(
            pair.accept(request.nonce, &proof).is_err(),
            "accepted {changed:?}"
        );
    }
}

#[test]
fn changing_a_petition_or_its_digest_does_not_approve_the_original() {
    for operation in [
        Consent {
            request: 38,
            digest: [9; 32],
        },
        Consent {
            request: 37,
            digest: [8; 32],
        },
        Unlock { seconds: 60 },
    ] {
        let mut pair = Pair::new();
        let request = pair.begin(Consent {
            request: 37,
            digest: [9; 32],
        });
        let mut changed = request.clone();
        changed.operation = operation;
        let proof = pair.proof(&changed);
        assert!(pair.accept(request.nonce, &proof).is_err());
    }
}

#[test]
fn a_signed_device_grant_must_specifically_allow_the_requested_action_and_profile() {
    for (profile, action) in [
        ("work", ApprovalAction::Consent),
        ("work-other", ApprovalAction::Unlock),
    ] {
        let mut pair = Pair::new();
        let request = pair.begin(Unlock { seconds: 60 });
        let mut grant = pair.grant().certificate;
        grant.scope = enrollment_scope(pair.target, profile, [action]);
        let proof = pair.proof_with_grant(
            &request,
            SignedDelegationCertificate::issue(&pair.root, grant).unwrap(),
        );
        assert!(pair.accept(request.nonce, &proof).is_err());
    }
}

#[test]
fn revocation_is_rechecked_at_acceptance_and_survives_a_serialized_ledger() {
    let mut pair = Pair::new();
    let request = pair.begin(Unlock { seconds: 60 });
    let proof = pair.proof(&request);
    let grant = &proof.chain[0].certificate;
    let revoke = SignedDelegationRevocation::issue(
        &pair.root,
        DelegationRevocation::new(grant.id(), grant.issuer, grant.scope.clone(), NOW, [5; 32]),
    )
    .unwrap();
    pair.ledger.fold(revoke.check().unwrap());
    pair.ledger = serde_json::from_slice(&serde_json::to_vec(&pair.ledger).unwrap()).unwrap();
    assert!(pair.accept(request.nonce, &proof).is_err());
    let new_request = pair.begin(Unlock { seconds: 60 });
    let proof = pair.proof(&new_request);
    assert!(
        pair.accept(new_request.nonce, &proof).is_err(),
        "reconnecting cannot revive a revoked enrollment"
    );
}

#[test]
fn lock_generation_restart_and_withdrawal_invalidate_pending_approvals() {
    for (instance, generation) in [("instance-a", 2), ("instance-b", 1)] {
        let mut pair = Pair::new();
        let request = pair.begin(Unlock { seconds: 60 });
        let proof = pair.proof(&request);
        pair.gate.synchronize(instance, generation).unwrap();
        assert!(pair.accept(request.nonce, &proof).is_err());
    }
    let mut pair = Pair::new();
    assert!(pair.gate.synchronize("instance-a", 0).is_err());
    let request = pair.begin(Unlock { seconds: 60 });
    let proof = pair.proof(&request);
    pair.gate.cancel(request.nonce);
    assert!(pair.accept(request.nonce, &proof).is_err());
}

#[test]
fn expiry_sleep_and_clock_rollback_cannot_renew_a_pending_approval() {
    for (wall_delta, instant_delta) in [(120_000, 0), (0, 120_000), (119_999, 119_999)] {
        let mut pair = Pair::new();
        let request = pair.begin(Unlock { seconds: 60 });
        let proof = pair.proof(&request);
        let result = pair.gate.accept(
            request.nonce,
            &proof,
            &pair.ledger,
            NOW + wall_delta,
            pair.now + Duration::from_millis(instant_delta),
        );
        assert_eq!(
            result.is_ok(),
            wall_delta < 120_000 && instant_delta < 120_000
        );
    }
    let mut pair = Pair::new();
    let request = pair.begin(Unlock { seconds: 60 });
    let proof = pair.proof(&request);
    assert_eq!(
        pair.gate
            .accept(request.nonce, &proof, &pair.ledger, NOW - 1, pair.now)
            .err(),
        Some(Refusal("remote-clock"))
    );
    assert!(pair.accept(request.nonce, &proof).is_err());
}

#[test]
fn one_week_is_fixed_and_new_approval_is_capped_by_the_grants_remaining_life() {
    let mut pair = Pair::new();
    let request = pair.begin(Unlock {
        seconds: WEEK_SECONDS,
    });
    let proof = pair.proof(&request);
    let receipt = pair
        .gate
        .accept(
            request.nonce,
            &proof,
            &pair.ledger,
            NOW + 1000,
            pair.now + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(receipt.unlock_until_ms(), Some(NOW + WEEK_MS));
    for expiry in [None, Some(NOW + WEEK_MS + 1)] {
        let mut pair = Pair::new();
        let request = pair.begin(Unlock { seconds: 60 });
        let mut grant = pair.grant().certificate;
        grant.expires_at_ms = expiry;
        let proof = pair.proof_with_grant(
            &request,
            SignedDelegationCertificate::issue(&pair.root, grant).unwrap(),
        );
        assert_eq!(
            pair.accept(request.nonce, &proof).err(),
            Some(Refusal("remote-grant-duration"))
        );
    }
    for seconds in [0, WEEK_SECONDS + 1] {
        assert_eq!(
            pair.gate
                .begin(
                    Unlock { seconds },
                    NOW + 1000,
                    pair.now + Duration::from_secs(1)
                )
                .err(),
            Some(Refusal("remote-duration"))
        );
    }
}

#[test]
fn grant_expiry_does_not_become_a_new_week_on_reconnect() {
    for elapsed in [WEEK_MS - 1, WEEK_MS] {
        let mut pair = Pair::new();
        let grant = pair.grant();
        let request = pair
            .gate
            .begin(Unlock { seconds: 60 }, NOW + WEEK_MS - 60_000, pair.now)
            .unwrap();
        let leaf = SignedDelegationCertificate::issue(
            &pair.approver,
            request.approval_for_device(&grant, request.issued_at_ms),
        )
        .unwrap();
        let proof = ApprovalProof {
            chain: vec![grant, leaf],
        };
        let result = pair.gate.accept(
            request.nonce,
            &proof,
            &pair.ledger,
            NOW + elapsed,
            pair.now + Duration::from_millis(elapsed - (WEEK_MS - 60_000)),
        );
        if elapsed < WEEK_MS {
            assert_eq!(result.unwrap().unlock_until_ms(), Some(NOW + WEEK_MS));
        } else {
            assert!(
                result.is_err(),
                "an expired grant cannot be renewed by reconnecting"
            );
        }
    }
}

#[test]
fn requests_and_proof_work_are_bounded_and_a_tampered_signature_is_refused() {
    let mut pair = Pair::new();
    let request = pair.begin(Unlock { seconds: 60 });
    let mut proof = pair.proof(&request);
    proof.chain[1].certificate.subject = [7; 32];
    assert!(pair.accept(request.nonce, &proof).is_err());
    proof = pair.proof(&request);
    proof.chain[0].certificate.scope.path_prefix = "x".repeat(2049);
    assert_eq!(
        pair.accept(request.nonce, &proof).err(),
        Some(Refusal("remote-proof-size"))
    );
    proof.chain.push(proof.chain[0].clone());
    assert_eq!(
        pair.accept(request.nonce, &proof).err(),
        Some(Refusal("remote-chain"))
    );
    for _ in 1..MAX_PENDING {
        pair.begin(Unlock { seconds: 60 });
    }
    assert_eq!(
        pair.gate.begin(Unlock { seconds: 60 }, NOW, pair.now).err(),
        Some(Refusal("remote-capacity"))
    );
    assert!(
        pair.gate
            .begin(
                Unlock { seconds: 60 },
                NOW + 120_000,
                pair.now + Duration::from_secs(120)
            )
            .is_ok()
    );
}
