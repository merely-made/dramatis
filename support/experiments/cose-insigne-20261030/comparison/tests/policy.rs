use cose_insigne_codec::{Body, Certificate, Kind, Revocation, Scope, payload, sign, verify};
use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationId, DelegationParent, delegation_signing_salt,
};
use personae::{IdentityProvider, InMemoryProvider};

fn scope() -> Scope {
    Scope {
        domain: "mesh".into(),
        resource: vec![7],
        path_prefix: "/docs".into(),
        actions: vec!["read".into(), "write".into()],
    }
}
fn legacy_scope(s: &Scope) -> CapabilityScope {
    CapabilityScope {
        domain: s.domain.clone(),
        resource: s.resource.clone(),
        path_prefix: s.path_prefix.clone(),
        actions: s.actions.iter().cloned().collect(),
    }
}
fn legacy(c: &Certificate, parent: DelegationParent) -> DelegationCertificate {
    DelegationCertificate::new(
        parent,
        c.issuer,
        c.subject,
        legacy_scope(&c.scope),
        c.issued_at,
        c.not_before,
        c.expiry,
        c.remaining_depth,
        c.nonce,
    )
}
fn signed(body: &Body, provider: &InMemoryProvider) -> (Vec<u8>, insigne::DerivedKeyAttestation) {
    let scope = match body {
        Body::Certificate(c) => &c.scope,
        Body::Revocation(r) => &r.scope,
    };
    let salt = delegation_signing_salt(&legacy_scope(scope));
    let att = provider.attest_derived_key(&salt).unwrap();
    let key = provider.derive_keypair(&salt).unwrap();
    (
        sign(body, att.derived(), |msg| key.sign(msg).to_bytes()).unwrap(),
        att,
    )
}
fn authenticated(
    wire: &[u8],
    kind: Kind,
    att: &insigne::DerivedKeyAttestation,
    expected_scope: &Scope,
    issuer: &[u8; 32],
) -> Result<Body, ()> {
    let checked = att
        .check(&delegation_signing_salt(&legacy_scope(expected_scope)))
        .map_err(|_| ())?;
    if checked.master() != issuer {
        return Err(());
    }
    let body = verify(wire, kind, checked.derived(), |msg, sig| {
        let key = ed25519_dalek::VerifyingKey::from_bytes(checked.derived()).unwrap();
        ed25519_dalek::Signature::from_slice(sig).is_ok_and(|s| key.verify_strict(msg, &s).is_ok())
    })
    .map_err(|_| ())?;
    let (actual_scope, actual_issuer) = match &body {
        Body::Certificate(c) => (&c.scope, &c.issuer),
        Body::Revocation(r) => (&r.scope, &r.issuer),
    };
    if actual_scope != expected_scope || actual_issuer != issuer {
        return Err(());
    }
    Ok(body)
}
#[test]
fn derived_attestation_binds_candidate_issuer_scope_and_key() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let issuer = provider.master_public_key().to_bytes();
    let body = Body::Certificate(Certificate {
        parent_kind: 0,
        parent_id: [7; 32],
        issuer,
        subject: [2; 32],
        scope: scope(),
        issued_at: 5,
        not_before: 10,
        expiry: Some(100),
        remaining_depth: 2,
        nonce: [3; 32],
    });
    let (wire, att) = signed(&body, &provider);
    assert_eq!(
        authenticated(&wire, Kind::Certificate, &att, &scope(), &issuer),
        Ok(body.clone())
    );
    assert!(authenticated(&wire, Kind::Certificate, &att, &scope(), &[9; 32]).is_err());
    let mut other = scope();
    other.resource = vec![8];
    assert!(authenticated(&wire, Kind::Certificate, &att, &other, &issuer).is_err());
    let outsider = InMemoryProvider::from_seed([9; 32]);
    let (_, other_att) = signed(&body, &outsider);
    assert!(authenticated(&wire, Kind::Certificate, &other_att, &scope(), &issuer).is_err());
}
#[test]
fn authenticated_body_uses_existing_scope_time_and_depth_policy_and_has_new_id() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let issuer = provider.master_public_key().to_bytes();
    let parent = Certificate {
        parent_kind: 0,
        parent_id: [7; 32],
        issuer,
        subject: [2; 32],
        scope: scope(),
        issued_at: 5,
        not_before: 10,
        expiry: Some(100),
        remaining_depth: 2,
        nonce: [3; 32],
    };
    let body = Body::Certificate(parent.clone());
    let (wire, att) = signed(&body, &provider);
    let Body::Certificate(checked) =
        authenticated(&wire, Kind::Certificate, &att, &scope(), &issuer).unwrap()
    else {
        panic!()
    };
    let legacy_parent = legacy(&checked, DelegationParent::Root([7; 32]));
    let candidate_id = *blake3::hash(&payload(&body).unwrap()).as_bytes();
    assert_ne!(candidate_id, legacy_parent.id().0);
    assert!(legacy_parent.covers("/docs/a", "read", 10));
    assert!(!legacy_parent.covers("/docs-private", "read", 10));
    assert!(!legacy_parent.covers("/docs/a", "read", 101));
    let mut child = parent.clone();
    child.parent_kind = 1;
    child.parent_id = candidate_id;
    child.issuer = parent.subject;
    child.subject = [4; 32];
    child.scope.path_prefix = "/docs/a".into();
    child.scope.actions = vec!["read".into()];
    child.remaining_depth = 1;
    // Oracle translation is explicitly test-only: it changes the ID reference, not a checked proof.
    let mut oracle = legacy(&child, DelegationParent::Certificate(legacy_parent.id()));
    assert!(oracle.attenuates(&legacy_parent));
    oracle.remaining_delegation_depth = 2;
    assert!(!oracle.attenuates(&legacy_parent));
    oracle.remaining_delegation_depth = 1;
    oracle.expires_at_ms = None;
    assert!(!oracle.attenuates(&legacy_parent));
    oracle.expires_at_ms = Some(100);
    oracle.scope.path_prefix = "/".into();
    assert!(!oracle.attenuates(&legacy_parent));
    assert_ne!(DelegationId(child.parent_id), legacy_parent.id());
}
#[test]
fn authenticated_revocation_commits_target_issuer_scope_and_time() {
    let provider = InMemoryProvider::from_seed([1; 32]);
    let issuer = provider.master_public_key().to_bytes();
    let rev = Body::Revocation(Revocation {
        certificate_id: [7; 32],
        issuer,
        scope: scope(),
        at_ms: 50,
        nonce: [5; 32],
    });
    let (wire, att) = signed(&rev, &provider);
    assert_eq!(
        authenticated(&wire, Kind::Revocation, &att, &scope(), &issuer),
        Ok(rev)
    );
    let mut tampered = wire;
    let n = tampered.len();
    tampered[n - 1] ^= 1;
    assert!(authenticated(&tampered, Kind::Revocation, &att, &scope(), &issuer).is_err());
}

#[test]
fn paired_candidate_revocation_matches_legacy_ledger_oracle_after_id_translation() {
    use insigne::delegation::{DelegationRevocation, SignedDelegationRevocation};
    use personae::delegation::Issue;
    let provider = InMemoryProvider::from_seed([1; 32]);
    let issuer = provider.master_public_key().to_bytes();
    let certificate = Certificate {
        parent_kind: 0,
        parent_id: [7; 32],
        issuer,
        subject: [2; 32],
        scope: scope(),
        issued_at: 5,
        not_before: 10,
        expiry: Some(100),
        remaining_depth: 2,
        nonce: [3; 32],
    };
    let body = Body::Certificate(certificate.clone());
    let (cert_wire, cert_att) = signed(&body, &provider);
    let checked_cert =
        authenticated(&cert_wire, Kind::Certificate, &cert_att, &scope(), &issuer).unwrap();
    let candidate_id = *blake3::hash(&payload(&checked_cert).unwrap()).as_bytes();
    let revocation = Body::Revocation(Revocation {
        certificate_id: candidate_id,
        issuer,
        scope: scope(),
        at_ms: 50,
        nonce: [5; 32],
    });
    let (rev_wire, rev_att) = signed(&revocation, &provider);
    let Body::Revocation(checked_rev) =
        authenticated(&rev_wire, Kind::Revocation, &rev_att, &scope(), &issuer).unwrap()
    else {
        panic!()
    };
    // This is a test-only translation and separately issued legacy proof. The
    // candidate cannot be folded as Notochord's private CheckedRevocation.
    let legacy_cert = legacy(&certificate, DelegationParent::Root([7; 32]));
    let legacy_rev = SignedDelegationRevocation::issue(
        &provider,
        DelegationRevocation::new(
            legacy_cert.id(),
            checked_rev.issuer,
            legacy_scope(&checked_rev.scope),
            checked_rev.at_ms,
            checked_rev.nonce,
        ),
    )
    .unwrap();
    let mut ledger = notochord::RevocationLedger::new();
    ledger.fold(legacy_rev.check().unwrap());
    assert!(checked_rev.certificate_id == candidate_id && checked_rev.issuer == certificate.issuer);
    assert!(ledger.revokes(&legacy_cert));
    let other = InMemoryProvider::from_seed([9; 32]);
    let other_issuer = other.master_public_key().to_bytes();
    let wrong_rev = SignedDelegationRevocation::issue(
        &other,
        DelegationRevocation::new(
            legacy_cert.id(),
            other_issuer,
            legacy_scope(&scope()),
            50,
            [5; 32],
        ),
    )
    .unwrap();
    let mut wrong_ledger = notochord::RevocationLedger::new();
    wrong_ledger.fold(wrong_rev.check().unwrap());
    assert!(!wrong_ledger.revokes(&legacy_cert));
    assert_ne!(other_issuer, certificate.issuer);
    assert_ne!(checked_rev.certificate_id, legacy_cert.id().0);
}
