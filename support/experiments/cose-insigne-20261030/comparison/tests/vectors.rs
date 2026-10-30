use cose_insigne_codec::{Kind, verify};
use ed25519_dalek::{Signature, VerifyingKey};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independently_signed_vectors_obey_profile() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/vectors.json")).unwrap();
    for v in file["vectors"].as_array().unwrap() {
        let key: [u8; 32] = hex(v["public_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key).unwrap();
        let wire = hex(v["wire_hex"].as_str().unwrap());
        let kind = if v["kind"] == "certificate" {
            Kind::Certificate
        } else {
            Kind::Revocation
        };
        let result = verify(&wire, kind, &key, |message, signature| {
            Signature::from_slice(signature)
                .is_ok_and(|sig| verifying_key.verify_strict(message, &sig).is_ok())
        });
        assert_eq!(
            result.is_ok(),
            v["profile_valid"].as_bool().unwrap(),
            "{}",
            v["name"]
        );
        if v["name"] == "certificate_valid" {
            let payload = hex(v["payload_hex"].as_str().unwrap());
            let offset = wire
                .windows(payload.len())
                .position(|w| w == payload.as_slice())
                .unwrap();
            let mut tampered = wire.clone();
            tampered[offset + payload.len() - 1] ^= 1;
            assert!(
                verify(&tampered, kind, &key, |message, signature| {
                    Signature::from_slice(signature)
                        .is_ok_and(|sig| verifying_key.verify_strict(message, &sig).is_ok())
                })
                .is_err()
            );
        }
        if let Ok(body) = result {
            assert_eq!(
                cose_insigne_codec::payload(&body).unwrap(),
                hex(v["payload_hex"].as_str().unwrap())
            );
            let expected = &v["expected_fields"];
            match body {
                cose_insigne_codec::Body::Certificate(c) => {
                    assert_eq!(
                        c.parent_id.as_slice(),
                        hex(expected["parent_id_hex"].as_str().unwrap())
                    );
                    assert_eq!(
                        c.issuer.as_slice(),
                        hex(expected["issuer_hex"].as_str().unwrap())
                    );
                    assert_eq!(
                        c.subject.as_slice(),
                        hex(expected["subject_hex"].as_str().unwrap())
                    );
                    check_scope(&c.scope, &expected["scope"]);
                    assert_eq!(
                        c.parent_kind as u64,
                        expected["parent_kind"].as_u64().unwrap()
                    );
                    assert_eq!(c.issued_at, expected["issued_at_ms"].as_u64().unwrap());
                    assert_eq!(c.not_before, expected["not_before_ms"].as_u64().unwrap());
                    assert_eq!(c.expiry, expected["expiry_ms"].as_u64());
                    assert_eq!(
                        c.remaining_depth as u64,
                        expected["remaining_depth"].as_u64().unwrap()
                    );
                    assert_eq!(
                        c.nonce.as_slice(),
                        hex(expected["nonce_hex"].as_str().unwrap())
                    );
                },
                cose_insigne_codec::Body::Revocation(r) => {
                    assert_eq!(
                        r.certificate_id.as_slice(),
                        hex(expected["certificate_id_hex"].as_str().unwrap())
                    );
                    assert_eq!(
                        r.issuer.as_slice(),
                        hex(expected["issuer_hex"].as_str().unwrap())
                    );
                    check_scope(&r.scope, &expected["scope"]);
                    assert_eq!(r.at_ms, expected["at_ms"].as_u64().unwrap());
                    assert_eq!(
                        r.nonce.as_slice(),
                        hex(expected["nonce_hex"].as_str().unwrap())
                    );
                },
            }
        }
    }
}

fn check_scope(scope: &cose_insigne_codec::Scope, expected: &serde_json::Value) {
    assert_eq!(scope.domain, expected["domain"].as_str().unwrap());
    assert_eq!(
        scope.resource,
        hex(expected["resource_hex"].as_str().unwrap())
    );
    assert_eq!(scope.path_prefix, expected["path_prefix"].as_str().unwrap());
    assert_eq!(
        scope.actions,
        expected["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
}
