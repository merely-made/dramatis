// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

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
