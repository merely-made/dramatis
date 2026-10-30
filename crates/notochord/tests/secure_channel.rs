// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! N1: a secure session binds independent carrier, channel and subject facts.

use notochord::{
    CarrierKind, DenyReason, LocalNetworkPolicy, NetworkId, ProfileRef, ProofBinding,
    RequestedAction, RevocationLedger, SecureChannelFacts, SecureIdentityPolicy, ServiceAccess,
    ServiceRule, SessionFacts, SessionHello, TrafficClass, admit_secure, respond,
};
use personae::{IdentityProvider, InMemoryProvider};

const NETWORK: NetworkId = NetworkId([3; 32]);
const PROTOCOL: &[u8] = b"mere/murm/v1";
const SERVICE: &str = "/services/murm";

fn subject() -> InMemoryProvider {
    InMemoryProvider::from_seed([4; 32])
}
fn subject_key() -> [u8; 32] {
    subject().master_public_key().to_bytes()
}
fn responder_key() -> [u8; 32] {
    InMemoryProvider::from_seed([8; 32])
        .master_public_key()
        .to_bytes()
}
fn action() -> RequestedAction {
    RequestedAction {
        domain: "mere.network".into(),
        path: SERVICE.into(),
        action: "connect".into(),
    }
}
fn profile() -> ProfileRef {
    ProfileRef {
        id: "mere.base".into(),
        revision: 2,
    }
}
fn policy(require_transport: bool) -> LocalNetworkPolicy {
    let mut p = LocalNetworkPolicy::closed(NETWORK);
    p.accepted_profiles.push(profile());
    p.services.insert(
        SERVICE.into(),
        ServiceRule::new(
            ServiceAccess::Public,
            "mere.network",
            ["connect"],
            require_transport,
            None,
        ),
    );
    p
}
fn carrier() -> SessionFacts {
    SessionFacts::new(PROTOCOL, CarrierKind::Reticulum).with_ingress(Some(3), Some([9; 16]))
}
fn channel() -> SecureChannelFacts {
    SecureChannelFacts::new(
        b"mere/noise/XX_25519_ChaChaPoly_BLAKE2b".to_vec(),
        1,
        vec![6; 64],
        subject_key(),
        responder_key(),
        PROTOCOL,
    )
}
fn hello(facts: &SessionFacts, channel: &SecureChannelFacts) -> SessionHello {
    SessionHello::issue_secure(
        &subject(),
        NETWORK,
        profile(),
        action(),
        TrafficClass::Interactive,
        [42; 32],
        &facts.secure_proof_binding(channel),
        vec![],
    )
    .unwrap()
}
fn admit(
    hello: &SessionHello,
    facts: &SessionFacts,
    channel: &SecureChannelFacts,
    rule: SecureIdentityPolicy,
) -> Result<notochord::AdmittedPrincipal, DenyReason> {
    let p = policy(false);
    admit_secure(
        &p,
        &RevocationLedger::new(),
        &hello.encode(&p.limits).unwrap(),
        facts,
        channel,
        rule,
        50,
        0,
    )
    .1
}

#[test]
fn a_secure_subject_is_admitted_without_inventing_carrier_authentication() {
    let facts = carrier();
    let original = facts.clone();
    let channel = channel();
    let hello = hello(&facts, &channel);
    let principal = admit(
        &hello,
        &facts,
        &channel,
        SecureIdentityPolicy::MatchCarrierWhenPresent,
    )
    .unwrap();
    assert_eq!(principal.subject, subject_key());
    assert_eq!(
        principal.session_id,
        hello.secure_session_id(&facts.secure_proof_binding(&channel))
    );
    assert_eq!(facts, original);
    assert_eq!(facts.authenticated_initiator, None);
}

#[test]
fn a_captured_proof_cannot_move_between_channels_roles_profiles_protocols_or_links() {
    let facts = carrier();
    let base = channel();
    let hello = hello(&facts, &base);
    for changed in [
        {
            let mut c = base.clone();
            c.handshake_hash[0] ^= 1;
            c
        },
        {
            let mut c = base.clone();
            std::mem::swap(&mut c.initiator, &mut c.responder);
            c
        },
        {
            let mut c = base.clone();
            c.profile.push(b'x');
            c
        },
        {
            let mut c = base.clone();
            c.version += 1;
            c
        },
        {
            let mut c = base.clone();
            c.protocol = b"other/inner/v1".to_vec();
            c
        },
    ] {
        assert_eq!(
            admit(
                &hello,
                &facts,
                &changed,
                SecureIdentityPolicy::MatchCarrierWhenPresent
            ),
            Err(DenyReason::SessionProofInvalid)
        );
    }
    let mut other_link = facts.clone();
    other_link.ingress.shared_link = Some([10; 16]);
    assert_eq!(
        admit(
            &hello,
            &other_link,
            &base,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        ),
        Err(DenyReason::SessionProofInvalid)
    );
    let mut other_outer = facts.clone();
    other_outer.protocol = b"other/outer/v1".to_vec();
    assert_eq!(
        admit(
            &hello,
            &other_outer,
            &base,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        ),
        Err(DenyReason::SessionProofInvalid)
    );
    let mut other_carrier_key = facts.clone();
    other_carrier_key.authenticated_initiator = Some([5; 32]);
    assert_eq!(
        admit(
            &hello,
            &other_carrier_key,
            &base,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        ),
        Err(DenyReason::SessionProofInvalid)
    );
    let mut other_interface = facts.clone();
    other_interface.ingress.local_interface = Some(999);
    assert!(
        admit(
            &hello,
            &other_interface,
            &base,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        )
        .is_ok()
    );
}

#[test]
fn an_opaque_outer_protocol_can_carry_an_independently_bound_inner_protocol() {
    let mut facts = carrier();
    facts.protocol = b"mere/opaque-tunnel/v1".to_vec();
    let channel = channel();
    let hello = hello(&facts, &channel);
    assert!(
        admit(
            &hello,
            &facts,
            &channel,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        )
        .is_ok()
    );
}

#[test]
fn explicit_policy_controls_distinct_carrier_and_application_keys() {
    let facts = SessionFacts::authenticated(PROTOCOL, CarrierKind::P2panda, [11; 32]);
    let channel = channel();
    let hello = hello(&facts, &channel);
    assert_eq!(
        admit(
            &hello,
            &facts,
            &channel,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        ),
        Err(DenyReason::SecureChannelIdentityMismatch)
    );
    assert!(
        admit(
            &hello,
            &facts,
            &channel,
            SecureIdentityPolicy::AttestedApplication
        )
        .is_ok()
    );

    // Two independently valid handshakes do not prove that an unrelated channel
    // key belongs to the hello's subject.
    let mut unrelated = channel.clone();
    unrelated.initiator = [12; 32];
    let unrelated_hello = hello_with_channel(&facts, &unrelated);
    assert_eq!(
        admit(
            &unrelated_hello,
            &facts,
            &unrelated,
            SecureIdentityPolicy::AttestedApplication
        ),
        Err(DenyReason::SubjectNotSecurePeer)
    );
}
fn hello_with_channel(facts: &SessionFacts, channel: &SecureChannelFacts) -> SessionHello {
    hello(facts, channel)
}

#[test]
fn an_explicit_bound_proof_can_use_an_independent_native_endpoint_identity() {
    let endpoint = InMemoryProvider::from_seed([21; 32])
        .master_public_key()
        .to_bytes();
    let remote_endpoint = InMemoryProvider::from_seed([22; 32])
        .master_public_key()
        .to_bytes();
    let facts = SessionFacts::authenticated(PROTOCOL, CarrierKind::P2panda, endpoint);
    let channel = SecureChannelFacts::new(
        b"mere/iroh-tls-exporter-bistream".to_vec(),
        1,
        vec![23; 32],
        endpoint,
        remote_endpoint,
        PROTOCOL,
    );
    let hello = hello(&facts, &channel);
    assert_ne!(endpoint, subject_key());
    assert_ne!(endpoint, *hello.session_signer.derived());
    assert_ne!(remote_endpoint, subject_key());
    for strict in [
        SecureIdentityPolicy::MatchCarrierWhenPresent,
        SecureIdentityPolicy::AttestedApplication,
    ] {
        assert_eq!(
            admit(&hello, &facts, &channel, strict),
            Err(DenyReason::SubjectNotSecurePeer)
        );
    }
    let accepted = admit(
        &hello,
        &facts,
        &channel,
        SecureIdentityPolicy::BoundChannelApplicationProof,
    )
    .unwrap();
    assert_eq!(accepted.subject, subject_key());
    assert_eq!(facts.authenticated_initiator, Some(endpoint));
    assert_eq!(channel.initiator, endpoint);

    // The new association policy still binds every observed channel component.
    for changed in [
        {
            let mut c = channel.clone();
            c.handshake_hash[0] ^= 1;
            c
        },
        {
            let mut c = channel.clone();
            c.initiator = responder_key();
            c
        },
        {
            let mut c = channel.clone();
            c.responder = responder_key();
            c
        },
        {
            let mut c = channel.clone();
            std::mem::swap(&mut c.initiator, &mut c.responder);
            c
        },
        {
            let mut c = channel.clone();
            c.protocol = b"wrong/service".to_vec();
            c
        },
    ] {
        assert_eq!(
            admit(
                &hello,
                &facts,
                &changed,
                SecureIdentityPolicy::BoundChannelApplicationProof
            ),
            Err(DenyReason::SessionProofInvalid)
        );
    }
    let mut changed_facts = facts.clone();
    changed_facts.authenticated_initiator = Some(responder_key());
    assert_eq!(
        admit(
            &hello,
            &changed_facts,
            &channel,
            SecureIdentityPolicy::BoundChannelApplicationProof
        ),
        Err(DenyReason::SessionProofInvalid)
    );
    for changed in [
        {
            let mut h = hello.clone();
            h.subject = responder_key();
            h
        },
        {
            let mut h = hello.clone();
            h.action.path = "/other".into();
            h
        },
        {
            let mut h = hello.clone();
            h.network = NetworkId([24; 32]);
            h
        },
    ] {
        assert_eq!(
            admit(
                &changed,
                &facts,
                &channel,
                SecureIdentityPolicy::BoundChannelApplicationProof
            ),
            Err(DenyReason::SessionProofInvalid)
        );
    }
    let mut closed = policy(true);
    closed.services.get_mut(SERVICE).unwrap().access = ServiceAccess::MemberOnly;
    let outcome = admit_secure(
        &closed,
        &RevocationLedger::new(),
        &hello.encode(&closed.limits).unwrap(),
        &facts,
        &channel,
        SecureIdentityPolicy::BoundChannelApplicationProof,
        50,
        0,
    )
    .1;
    assert!(
        matches!(outcome, Err(DenyReason::Delegation(_))),
        "a bound channel grants no membership: {outcome:?}"
    );
}

#[test]
fn an_attested_session_signer_can_be_the_secure_peer_without_becoming_the_subject() {
    let facts = SessionFacts::authenticated(PROTOCOL, CarrierKind::P2panda, [11; 32]);
    let mut channel = channel();
    channel.initiator = subject()
        .derive_keypair(&notochord::network_session_signing_salt(&NETWORK))
        .unwrap()
        .public_key()
        .to_bytes();
    let binding = facts.secure_proof_binding(&channel);
    let hello = SessionHello::issue_secure_network_bound(
        &subject(),
        NETWORK,
        profile(),
        action(),
        TrafficClass::Interactive,
        [42; 32],
        &binding,
        vec![],
    )
    .unwrap();
    let principal = admit(
        &hello,
        &facts,
        &channel,
        SecureIdentityPolicy::AttestedApplication,
    )
    .unwrap();
    assert_eq!(principal.subject, subject_key());
    assert_ne!(principal.subject, channel.initiator);
}

#[test]
fn a_carrier_identity_requirement_still_means_the_carrier_authenticated_it() {
    let p = policy(true);
    let facts = carrier();
    let channel = channel();
    let hello = hello(&facts, &channel);
    let (_, outcome) = admit_secure(
        &p,
        &RevocationLedger::new(),
        &hello.encode(&p.limits).unwrap(),
        &facts,
        &channel,
        SecureIdentityPolicy::MatchCarrierWhenPresent,
        50,
        0,
    );
    assert_eq!(outcome, Err(DenyReason::TransportIdentityRequired));
    assert!(
        admit(
            &hello,
            &facts,
            &channel,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        )
        .is_ok()
    );
}

#[test]
fn secure_admission_never_falls_back_to_a_legacy_transcript() {
    let p = policy(false);
    let facts = carrier();
    let channel = channel();
    let legacy = SessionHello::issue(
        &subject(),
        NETWORK,
        profile(),
        action(),
        TrafficClass::Interactive,
        [42; 32],
        &facts.proof_binding(),
        vec![],
    )
    .unwrap();
    assert!(matches!(
        admit(
            &legacy,
            &facts,
            &channel,
            SecureIdentityPolicy::MatchCarrierWhenPresent
        ),
        Err(DenyReason::UnsupportedWireVersion {
            requested: 1,
            supported: 2
        })
    ));
    let secure = hello(&facts, &channel);
    assert!(
        !respond(
            &p,
            &RevocationLedger::new(),
            &secure.encode(&p.limits).unwrap(),
            &facts,
            50,
            0
        )
        .1
        .is_accept()
    );
}

#[test]
fn malformed_local_channel_facts_are_refused_before_signing_or_admission() {
    let facts = carrier();
    let channel = channel();
    let good = hello(&facts, &channel);
    for bad in [
        {
            let mut c = channel.clone();
            c.profile.clear();
            c
        },
        {
            let mut c = channel.clone();
            c.profile = vec![1; 129];
            c
        },
        {
            let mut c = channel.clone();
            c.version = 0;
            c
        },
        {
            let mut c = channel.clone();
            c.handshake_hash = vec![1; 1];
            c
        },
        {
            let mut c = channel.clone();
            c.protocol = vec![1; 256];
            c
        },
    ] {
        assert!(matches!(
            SessionHello::issue_secure(
                &subject(),
                NETWORK,
                profile(),
                action(),
                TrafficClass::Interactive,
                [42; 32],
                &facts.secure_proof_binding(&bad),
                vec![]
            ),
            Err(notochord::HandshakeError::InvalidBinding)
        ));
        assert_eq!(
            admit(
                &good,
                &facts,
                &bad,
                SecureIdentityPolicy::MatchCarrierWhenPresent
            ),
            Err(DenyReason::InvalidSecureChannel)
        );
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn admitted_secure_session_retains_the_original_carrier_record() {
    let (mut client, server) = tokio::io::duplex(8192);
    let facts = carrier();
    let channel = channel();
    let hello = hello(&facts, &channel);
    let task = tokio::spawn(async move {
        notochord::initiate_session(&mut client, &hello, &Default::default())
            .await
            .unwrap()
    });
    let admitted = notochord::admit_session_secure(
        server,
        &policy(false),
        &RevocationLedger::new(),
        &facts,
        &channel,
        SecureIdentityPolicy::MatchCarrierWhenPresent,
        50,
        0,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(admitted.session.facts, facts);
    assert_eq!(admitted.secure_channel, channel);
    assert!(task.await.unwrap().is_accept());
}

#[test]
fn the_legacy_v1_transcript_and_signature_match_the_pre_n1_implementation() {
    // Captured by running this fixture against the pre-N1 source, rather than
    // deriving an expectation with the new signing/verification implementation.
    let binding = ProofBinding::initiator(PROTOCOL, Some(subject_key()), None);
    let hello = SessionHello::issue(
        &subject(),
        NETWORK,
        profile(),
        action(),
        TrafficClass::Interactive,
        [42; 32],
        &binding,
        vec![],
    )
    .unwrap();
    assert_eq!(
        hello.session_id(&binding),
        [
            165, 34, 92, 119, 216, 202, 127, 155, 41, 205, 5, 221, 51, 213, 41, 178, 238, 179, 131,
            237, 16, 240, 15, 123, 76, 56, 230, 98, 128, 56, 130, 53
        ]
    );
    assert_eq!(
        hello.transcript_signature,
        [
            189, 171, 96, 227, 174, 182, 39, 228, 40, 164, 250, 89, 70, 80, 175, 110, 188, 79, 107,
            200, 153, 204, 220, 50, 191, 96, 122, 232, 57, 26, 226, 170, 54, 38, 216, 231, 161,
            234, 155, 136, 188, 164, 54, 182, 249, 238, 190, 47, 26, 56, 155, 184, 229, 218, 100,
            46, 52, 222, 16, 39, 26, 8, 26, 3
        ]
    );
    assert!(hello.verify_proof(&binding));
}
