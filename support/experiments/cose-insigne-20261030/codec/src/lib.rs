#![no_std]
extern crate alloc;
use alloc::{string::String, vec, vec::Vec};
use coset::{
    Algorithm, ContentType, CoseSign1, Header, ProtectedHeader, RegisteredLabelWithPrivate,
    TaggedCborSerializable,
    cbor::{self, value::Value},
    iana,
};

/// Chosen profile limit, including the COSE envelope.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const AAD: &[u8] = b"merely/insigne/cose-comparison/v1";
const CERT_TYPE: &str = "application/vnd.merely.delegation-certificate+cbor";
const REV_TYPE: &str = "application/vnd.merely.delegation-revocation+cbor";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub domain: String,
    pub resource: Vec<u8>,
    pub path_prefix: String,
    pub actions: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub parent_kind: u8,
    pub parent_id: [u8; 32],
    pub issuer: [u8; 32],
    pub subject: [u8; 32],
    pub scope: Scope,
    pub issued_at: u64,
    pub not_before: u64,
    pub expiry: Option<u64>,
    pub remaining_depth: u16,
    pub nonce: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub certificate_id: [u8; 32],
    pub issuer: [u8; 32],
    pub scope: Scope,
    pub at_ms: u64,
    pub nonce: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Revocation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Certificate(Certificate),
    Revocation(Revocation),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

fn text(kind: Kind) -> &'static str {
    match kind {
        Kind::Certificate => CERT_TYPE,
        Kind::Revocation => REV_TYPE,
    }
}
fn scope_valid(s: &Scope) -> bool {
    !s.domain.is_empty()
        && !s.resource.is_empty()
        && !s.path_prefix.is_empty()
        && !s.actions.is_empty()
        && s.actions.iter().all(|a| !a.is_empty())
        && s.actions.windows(2).all(|w| w[0] < w[1])
}
fn scope_value(s: &Scope) -> Value {
    Value::Array(vec![
        Value::Text(s.domain.clone()),
        Value::Bytes(s.resource.clone()),
        Value::Text(s.path_prefix.clone()),
        Value::Array(s.actions.iter().map(|x| Value::Text(x.clone())).collect()),
    ])
}
fn n(v: u64) -> Value {
    Value::Integer(v.into())
}
fn bytes(v: &[u8; 32]) -> Value {
    Value::Bytes(v.to_vec())
}
fn serialize(v: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    cbor::ser::into_writer(v, &mut out).map_err(|_| Error)?;
    if out.len() > MAX_MESSAGE_BYTES {
        return Err(Error);
    }
    Ok(out)
}
/// Encode the versioned CBOR payload, with preferred integer encodings.
pub fn payload(body: &Body) -> Result<Vec<u8>, Error> {
    let value = match body {
        Body::Certificate(c) => {
            if c.parent_kind > 1
                || c.issuer == [0; 32]
                || c.subject == [0; 32]
                || !scope_valid(&c.scope)
                || c.issued_at > c.not_before
                || c.expiry.is_some_and(|v| v < c.not_before)
            {
                return Err(Error);
            }
            Value::Array(vec![
                n(1),
                n(c.parent_kind.into()),
                bytes(&c.parent_id),
                bytes(&c.issuer),
                bytes(&c.subject),
                scope_value(&c.scope),
                n(c.issued_at),
                n(c.not_before),
                c.expiry.map_or(Value::Null, n),
                n(c.remaining_depth.into()),
                bytes(&c.nonce),
            ])
        },
        Body::Revocation(r) => {
            if !scope_valid(&r.scope) {
                return Err(Error);
            }
            Value::Array(vec![
                n(1),
                bytes(&r.certificate_id),
                bytes(&r.issuer),
                scope_value(&r.scope),
                n(r.at_ms),
                bytes(&r.nonce),
            ])
        },
    };
    serialize(&value)
}
fn array(v: Value, len: usize) -> Result<Vec<Value>, Error> {
    match v {
        Value::Array(a) if a.len() == len => Ok(a),
        _ => Err(Error),
    }
}
fn integer(v: Value) -> Result<u64, Error> {
    match v {
        Value::Integer(i) => u64::try_from(i).map_err(|_| Error),
        _ => Err(Error),
    }
}
fn b32(v: Value) -> Result<[u8; 32], Error> {
    match v {
        Value::Bytes(b) => b.try_into().map_err(|_| Error),
        _ => Err(Error),
    }
}
fn string(v: Value) -> Result<String, Error> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(Error),
    }
}
fn decode_scope(v: Value) -> Result<Scope, Error> {
    let mut a = array(v, 4)?.into_iter();
    let domain = string(a.next().ok_or(Error)?)?;
    let resource = match a.next().ok_or(Error)? {
        Value::Bytes(b) => b,
        _ => return Err(Error),
    };
    let path_prefix = string(a.next().ok_or(Error)?)?;
    let actions = match a.next().ok_or(Error)? {
        Value::Array(a) => a.into_iter().map(string).collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Error),
    };
    let scope = Scope {
        domain,
        resource,
        path_prefix,
        actions,
    };
    if !scope_valid(&scope) {
        return Err(Error);
    }
    Ok(scope)
}
fn decode(data: &[u8], kind: Kind) -> Result<Body, Error> {
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(Error);
    }
    let mut rest = data;
    let value: Value = cbor::de::from_reader(&mut rest).map_err(|_| Error)?;
    if !rest.is_empty() {
        return Err(Error);
    }
    let mut a = array(
        value,
        match kind {
            Kind::Certificate => 11,
            Kind::Revocation => 6,
        },
    )?
    .into_iter();
    if integer(a.next().ok_or(Error)?)? != 1 {
        return Err(Error);
    }
    let body = match kind {
        Kind::Certificate => {
            let parent_kind = u8::try_from(integer(a.next().ok_or(Error)?)?).map_err(|_| Error)?;
            let parent_id = b32(a.next().ok_or(Error)?)?;
            let issuer = b32(a.next().ok_or(Error)?)?;
            let subject = b32(a.next().ok_or(Error)?)?;
            let scope = decode_scope(a.next().ok_or(Error)?)?;
            let issued_at = integer(a.next().ok_or(Error)?)?;
            let not_before = integer(a.next().ok_or(Error)?)?;
            let expiry = match a.next().ok_or(Error)? {
                Value::Null => None,
                v => Some(integer(v)?),
            };
            let remaining_depth =
                u16::try_from(integer(a.next().ok_or(Error)?)?).map_err(|_| Error)?;
            let nonce = b32(a.next().ok_or(Error)?)?;
            Body::Certificate(Certificate {
                parent_kind,
                parent_id,
                issuer,
                subject,
                scope,
                issued_at,
                not_before,
                expiry,
                remaining_depth,
                nonce,
            })
        },
        Kind::Revocation => Body::Revocation(Revocation {
            certificate_id: b32(a.next().ok_or(Error)?)?,
            issuer: b32(a.next().ok_or(Error)?)?,
            scope: decode_scope(a.next().ok_or(Error)?)?,
            at_ms: integer(a.next().ok_or(Error)?)?,
            nonce: b32(a.next().ok_or(Error)?)?,
        }),
    };
    // One byte representation per statement is required for content identity.
    if payload(&body)?.as_slice() != data {
        return Err(Error);
    }
    Ok(body)
}
/// Sign with a caller-supplied Ed25519 signer; the key is fixed by the caller.
pub fn sign(
    body: &Body,
    key: &[u8; 32],
    signer: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<Vec<u8>, Error> {
    let kind = match body {
        Body::Certificate(_) => Kind::Certificate,
        Body::Revocation(_) => Kind::Revocation,
    };
    let header = Header {
        alg: Some(Algorithm::Assigned(iana::Algorithm::Ed25519)),
        content_type: Some(ContentType::Text(text(kind).into())),
        key_id: key.to_vec(),
        ..Header::default()
    };
    let mut message = CoseSign1 {
        protected: ProtectedHeader {
            original_data: None,
            header,
        },
        unprotected: Header::default(),
        payload: Some(payload(body)?),
        signature: Vec::new(),
    };
    message.signature = signer(&message.tbs_data(AAD)).to_vec();
    let wire = message.to_tagged_vec().map_err(|_| Error)?;
    if wire.len() > MAX_MESSAGE_BYTES {
        return Err(Error);
    }
    Ok(wire)
}
/// Verify using a caller-supplied strict verifier and fixed expected kind and key.
pub fn verify(
    wire: &[u8],
    kind: Kind,
    key: &[u8; 32],
    verifier: impl FnOnce(&[u8], &[u8]) -> bool,
) -> Result<Body, Error> {
    if wire.len() > MAX_MESSAGE_BYTES {
        return Err(Error);
    }
    let msg = CoseSign1::from_tagged_slice(wire).map_err(|_| Error)?;
    let h = &msg.protected.header;
    if h.alg
        != Some(RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::Ed25519,
        ))
        || h.content_type != Some(ContentType::Text(text(kind).into()))
        || h.key_id.as_slice() != key
        || !h.crit.is_empty()
        || !h.iv.is_empty()
        || !h.partial_iv.is_empty()
        || !h.counter_signatures.is_empty()
        || !h.rest.is_empty()
        || !msg.unprotected.is_empty()
        || msg.signature.len() != 64
        || msg.payload.is_none()
    {
        return Err(Error);
    }
    if !verifier(&msg.tbs_data(AAD), &msg.signature) {
        return Err(Error);
    }
    decode(msg.payload.as_ref().ok_or(Error)?, kind)
}
