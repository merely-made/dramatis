// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use custody_wire::remote_approval::route::{RemoteCommand, RemoteReply};

fn route(f: &mut Fixture, session: u64, command: RemoteCommand) -> (RemoteReply, Effects) {
    let (id, effects) = f.h.request(
        session,
        Operation::RemoteApproval {
            command: Box::new(command),
        },
    );
    let Some(Outcome::Success {
        answer: Answer::Value { value },
    }) = outcome_for(&effects, session, id)
    else {
        panic!("missing public route answer");
    };
    (serde_json::from_value(value).unwrap(), effects)
}

fn grant_bridge(f: &mut Fixture, session: u64) {
    f.h.core
        .sessions
        .get_mut(&session)
        .unwrap()
        .principal
        .grants
        .push(Grant::RemoteApprovalBridge);
}

#[test]
fn bridge_is_separately_granted_and_has_public_locked_state_only() {
    let mut f = Fixture::new("per-operation");
    let session = f.session;
    assert!(matches!(
        f.h.outcome(
            session,
            Operation::RemoteApproval {
                command: Box::new(RemoteCommand::State {}),
            }
        ),
        Outcome::Refused { .. }
    ));
    grant_bridge(&mut f, session);
    let _ = f.h.outcome(session, Operation::Lock {});
    let (reply, _) = route(&mut f, session, RemoteCommand::State {});
    let RemoteReply::State { state } = reply else {
        panic!("missing state");
    };
    assert!(state.locked);
    assert_eq!(state.enrollments, vec![f.grant.clone()]);
    assert!(matches!(route(&mut f, session, RemoteCommand::Unlock {}).0,
        RemoteReply::Refused { code } if code == "remote-unlock-backend-unsupported"));
    assert!(f.h.core.status().locked);
}

#[test]
fn approval_over_the_wire_releases_only_to_the_original_requester_and_is_one_use() {
    let mut f = Fixture::new("per-operation");
    let bridge = f.h.open(djinn());
    // This connection carries proofs only, even though the owner's other
    // admitted session can request a scoped release.
    f.h.core.sessions.get_mut(&bridge).unwrap().principal.grants =
        vec![Grant::RemoteApprovalBridge];
    let (original, _) = f.h.request(f.session, Fixture::release());
    let (reply, _) = route(&mut f, bridge, RemoteCommand::Challenge {});
    let RemoteReply::Challenge { petition, request } = reply else {
        panic!("no challenge");
    };
    assert_eq!(petition.request, original);
    let proof = f.proof(&request);
    let command = RemoteCommand::Approve {
        nonce: request.nonce,
        proof,
    };
    let (reply, effects) = route(&mut f, bridge, command.clone());
    assert_eq!(reply, RemoteReply::Done {});
    assert!(matches!(
        outcome_for(&effects, f.session, original),
        Some(Outcome::Success {
            answer: Answer::Released { .. }
        })
    ));
    assert!(
        effects
            .messages
            .iter()
            .filter(|(session, _)| *session == bridge)
            .all(|(_, message)| {
                matches!(
                    message,
                    ServerMessage::Outcome {
                        outcome: Outcome::Success {
                            answer: Answer::Value { .. }
                        },
                        ..
                    }
                )
            })
    );
    assert!(matches!(
        route(&mut f, bridge, command).0,
        RemoteReply::Refused { .. }
    ));
    assert!(matches!(
        f.h.outcome(bridge, Fixture::release()),
        Outcome::Refused { .. }
    ));
}

#[test]
fn wire_withdrawal_is_durable_and_bad_root_enrollment_is_refused() {
    let mut f = Fixture::new("per-operation");
    let session = f.session;
    grant_bridge(&mut f, session);
    let mut invalid = f.grant.clone();
    invalid.certificate.issuer = [0; 32];
    assert!(matches!(
        route(&mut f, session, RemoteCommand::Enroll { grant: invalid }).0,
        RemoteReply::Refused { .. }
    ));
    let revocation = f.revoke();
    assert_eq!(
        route(&mut f, session, RemoteCommand::Revoke { revocation }).0,
        RemoteReply::Done {}
    );
    let (reply, _) = route(&mut f, session, RemoteCommand::State {});
    assert!(matches!(reply, RemoteReply::State { state } if state.enrollments.is_empty()));
    let grant = f.grant.clone();
    assert!(matches!(
        route(&mut f, session, RemoteCommand::Enroll { grant }).0,
        RemoteReply::Refused { .. }
    ));
}

#[test]
fn root_and_approval_authority_signatures_require_the_native_consent_path() {
    use crate::policy::{Matcher, PrincipalRule, ProfileScope, PurposeRule};
    use custody_wire::remote_approval::DOMAIN;
    use insigne::delegation::delegation_signing_salt;

    for root_signature in [false, true] {
        let mut f = Fixture::new("per-operation");
        let master = f.h.core.vault.master_public_key().unwrap();
        let certificate = DelegationCertificate::new(
            DelegationParent::Root(master),
            master,
            f.grant.certificate.subject,
            enrollment_scope(master, "work", [ApprovalAction::Consent]),
            1000,
            1000,
            Some(2000),
            1,
            [7; 32],
        );
        let (purpose, salt, message, rule) = if root_signature {
            (
                Purpose::Root {},
                vec![],
                b"root statement".to_vec(),
                PurposeRule::Root,
            )
        } else {
            (
                Purpose::Delegation {
                    audience: DOMAIN.into(),
                },
                delegation_signing_salt(&certificate.scope),
                certificate.signing_bytes(),
                PurposeRule::Delegation {
                    audience: DOMAIN.into(),
                },
            )
        };
        let grant = Grant::Sign {
            profile: ProfileScope::Named("work".into()),
            purpose: rule,
            consent: Consent::PerOperation,
        };
        f.h.core.config.principals[0].grants.push(grant.clone());
        f.h.core
            .sessions
            .get_mut(&f.session)
            .unwrap()
            .principal
            .grants
            .push(grant);
        let operation = Operation::Sign {
            profile: "work".into(),
            purpose,
            salt: Bytes(salt),
            message: Bytes(message),
        };
        assert!(
            matches!(
                f.h.outcome(f.session, operation.clone()),
                Outcome::Refused { .. }
            ),
            "an absent native helper must not fall back to remote approval"
        );

        f.h.core.config.principals.push(PrincipalRule {
            name: "native-helper".into(),
            matcher: Matcher::UnixUid(2000),
            grants: vec![Grant::Status],
            consent_channel: true,
        });
        let helper = f.h.open(Peer::Unix {
            uid: 2000,
            gid: 2000,
            pid: Some(2000),
        });
        let (id, effects) = f.h.request(f.session, operation);
        assert!(outcome_for(&effects, f.session, id).is_none());
        let petition = f.h.core.queue.back().unwrap().summary.clone();
        assert!(f.h.core.remote_petition().is_none());
        assert!(
            f.h.core
                .request_remote_consent(id, &petition.digest, f.h.now)
                .0
                .is_err()
        );
        let (result, effects) = f.h.core.decide(
            super::super::Decider::Session(helper),
            id,
            &petition.digest,
            petition.generation,
            true,
            f.h.now,
        );
        result.unwrap();
        assert!(matches!(
            outcome_for(&effects, f.session, id),
            Some(Outcome::Success {
                answer: Answer::Signature { .. }
            })
        ));
    }
}

#[test]
fn cached_device_consent_does_not_authorize_root_or_approval_authority_signatures() {
    let mut f = Fixture::new("per-generation");
    let (_, request) = f.challenge();
    let grant_index = f.h.core.queue.back().unwrap().grant;
    let proof = f.proof(&request);
    f.h.core
        .approve_remote_consent(request.nonce, &proof, f.h.now)
        .0
        .unwrap();
    for namespace in [
        "root".to_string(),
        format!("delegation:{}", custody_wire::remote_approval::DOMAIN),
    ] {
        assert!(
            !f.h.core
                .remote_cached_consent("djinn", grant_index, "work", &namespace, f.h.now)
                .unwrap()
        );
    }
    assert!(
        f.h.core
            .remote_cached_consent("djinn", grant_index, "work", "derived-keys", f.h.now)
            .unwrap()
    );
}
