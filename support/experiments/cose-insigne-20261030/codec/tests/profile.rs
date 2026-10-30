use cose_insigne_codec::{Body, Certificate, Kind, Revocation, Scope, payload, sign, verify};

fn scope() -> Scope {
    Scope {
        domain: "mesh".into(),
        resource: vec![7],
        path_prefix: "/docs".into(),
        actions: vec!["read".into(), "write".into()],
    }
}
fn cert() -> Body {
    Body::Certificate(Certificate {
        parent_kind: 0,
        parent_id: [1; 32],
        issuer: [2; 32],
        subject: [3; 32],
        scope: scope(),
        issued_at: 10,
        not_before: 11,
        expiry: Some(20),
        remaining_depth: 2,
        nonce: [4; 32],
    })
}
fn revocation() -> Body {
    Body::Revocation(Revocation {
        certificate_id: [5; 32],
        issuer: [2; 32],
        scope: scope(),
        at_ms: 12,
        nonce: [6; 32],
    })
}
// Deterministic test-only signature callback binds every byte of the Sig_structure.
fn signature(bytes: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        let n = i % 64;
        out[n] = out[n].wrapping_add(*b).rotate_left(1);
    }
    out
}
fn check(bytes: &[u8], sig: &[u8]) -> bool {
    signature(bytes) == sig
}
#[test]
fn cert_and_revocation_round_trip() {
    for (body, kind) in [
        (cert(), Kind::Certificate),
        (revocation(), Kind::Revocation),
    ] {
        let msg = sign(&body, &[9; 32], signature).unwrap();
        assert_eq!(verify(&msg, kind, &[9; 32], check), Ok(body));
    }
}
#[test]
fn rejects_tampering_wrong_key_and_kind() {
    let msg = sign(&cert(), &[9; 32], signature).unwrap();
    assert!(verify(&msg, Kind::Revocation, &[9; 32], check).is_err());
    assert!(verify(&msg, Kind::Certificate, &[8; 32], check).is_err());
    let mut modified = msg.clone();
    let n = modified.len();
    modified[n - 1] ^= 1;
    assert!(verify(&modified, Kind::Certificate, &[9; 32], check).is_err());
}
#[test]
fn rejects_unsorted_or_duplicate_actions() {
    let mut body = cert();
    if let Body::Certificate(ref mut c) = body {
        c.scope.actions = vec!["write".into(), "read".into()];
    }
    assert!(payload(&body).is_err());
    if let Body::Certificate(ref mut c) = body {
        c.scope.actions = vec!["read".into(), "read".into()];
    }
    assert!(payload(&body).is_err());
}
#[test]
fn rejects_input_over_limit_and_trailing_bytes() {
    assert!(verify(&vec![0; 1024 * 1024], Kind::Certificate, &[9; 32], check).is_err());
    let mut msg = sign(&cert(), &[9; 32], signature).unwrap();
    msg.push(0);
    assert!(verify(&msg, Kind::Certificate, &[9; 32], check).is_err());
}

#[test]
fn rejects_unprotected_extra_headers_and_absent_payload() {
    use coset::{CoseSign1, Label, TaggedCborSerializable, cbor::value::Value};
    let msg = sign(&cert(), &[9; 32], signature).unwrap();
    let parsed = CoseSign1::from_tagged_slice(&msg).unwrap();
    let mut unprotected = parsed.clone();
    unprotected
        .unprotected
        .rest
        .push((Label::Int(999), Value::Bool(true)));
    assert!(
        verify(
            &unprotected.to_tagged_vec().unwrap(),
            Kind::Certificate,
            &[9; 32],
            check
        )
        .is_err()
    );
    let mut missing = parsed;
    missing.payload = None;
    assert!(
        verify(
            &missing.to_tagged_vec().unwrap(),
            Kind::Certificate,
            &[9; 32],
            check
        )
        .is_err()
    );
}

#[test]
fn rejects_a_signature_using_another_external_aad() {
    use coset::{CoseSign1, TaggedCborSerializable};
    let msg = sign(&cert(), &[9; 32], signature).unwrap();
    let mut parsed = CoseSign1::from_tagged_slice(&msg).unwrap();
    parsed.signature = signature(&parsed.tbs_data(b"different aad")).to_vec();
    assert!(
        verify(
            &parsed.to_tagged_vec().unwrap(),
            Kind::Certificate,
            &[9; 32],
            check
        )
        .is_err()
    );
}

#[test]
fn rejects_validly_signed_payload_with_wrong_field_type() {
    use coset::{
        CoseSign1, TaggedCborSerializable,
        cbor::{self, value::Value},
    };
    let mut msg =
        CoseSign1::from_tagged_slice(&sign(&cert(), &[9; 32], signature).unwrap()).unwrap();
    let mut body: Value = cbor::de::from_reader(msg.payload.as_ref().unwrap().as_slice()).unwrap();
    let Value::Array(ref mut fields) = body else {
        panic!()
    };
    fields[3] = Value::Text("not a 32-byte issuer".into());
    let mut bytes = Vec::new();
    cbor::ser::into_writer(&body, &mut bytes).unwrap();
    msg.payload = Some(bytes);
    msg.signature = signature(&msg.tbs_data(b"merely/insigne/cose-comparison/v1")).to_vec();
    assert!(
        verify(
            &msg.to_tagged_vec().unwrap(),
            Kind::Certificate,
            &[9; 32],
            check
        )
        .is_err()
    );
}

fn raw_message(
    protected_extra: Option<(i64, coset::cbor::value::Value)>,
    unprotected_extra: Option<(i64, coset::cbor::value::Value)>,
) -> Vec<u8> {
    use coset::cbor::{self, value::Value};
    fn enc(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        cbor::ser::into_writer(v, &mut b).unwrap();
        b
    }
    let mut headers = vec![
        (Value::Integer(1.into()), Value::Integer((-19).into())),
        (
            Value::Integer(3.into()),
            Value::Text("application/vnd.merely.delegation-certificate+cbor".into()),
        ),
        (Value::Integer(4.into()), Value::Bytes(vec![9; 32])),
    ];
    if let Some((k, v)) = protected_extra {
        headers.push((Value::Integer(k.into()), v));
    }
    let protected = enc(&Value::Map(headers));
    let body = payload(&cert()).unwrap();
    let tbs = enc(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.clone()),
        Value::Bytes(b"merely/insigne/cose-comparison/v1".to_vec()),
        Value::Bytes(body.clone()),
    ]));
    let unprotected = unprotected_extra
        .into_iter()
        .map(|(k, v)| (Value::Integer(k.into()), v))
        .collect();
    enc(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(body),
            Value::Bytes(signature(&tbs).to_vec()),
        ])),
    ))
}
#[test]
fn rejects_explicit_empty_iv_in_protected_header() {
    use coset::cbor::value::Value;
    let wire = raw_message(Some((5, Value::Bytes(vec![]))), None);
    assert!(verify(&wire, Kind::Certificate, &[9; 32], check).is_err());
}
#[test]
fn rejects_explicit_empty_crit_in_protected_header() {
    use coset::cbor::value::Value;
    let wire = raw_message(Some((2, Value::Array(vec![]))), None);
    assert!(verify(&wire, Kind::Certificate, &[9; 32], check).is_err());
}
#[test]
fn rejects_explicit_empty_iv_in_unprotected_header() {
    use coset::cbor::value::Value;
    let wire = raw_message(None, Some((5, Value::Bytes(vec![]))));
    assert!(verify(&wire, Kind::Certificate, &[9; 32], check).is_err());
}

#[test]
fn accepts_raw_profile_control() {
    let wire = raw_message(None, None);
    assert_eq!(
        verify(&wire, Kind::Certificate, &[9; 32], check),
        Ok(cert())
    );
}
