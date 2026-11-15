// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The strict reader (profile §5): rules R1 to R17, all before any KDF runs.

use std::cmp::Ordering;

use coset::cbor::value::Value;
use coset::{
    AsCborValue, CborSerializable, ContentType, CoseEncrypt, CoseError, Header, Label,
    RegisteredLabelWithPrivate, TaggedCborSerializable, iana,
};

use super::slot::{self, Slot};
use super::{BODY_PROTECTED, CONTENT_TYPE, MAX_FILE_BYTES, MAX_SLOTS, PadlockError, SlotKind};

/// Parses `bytes` under every rule of profile §5.1; the body comes back with
/// its recipients moved into the slot list.
pub(super) fn parse(bytes: &[u8]) -> Result<(CoseEncrypt, Vec<Slot>), PadlockError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(PadlockError::TooLarge);
    }
    let value = Value::from_slice(bytes).map_err(|e| match e {
        CoseError::ExtraneousData => PadlockError::TrailingBytes,
        _ => PadlockError::Malformed,
    })?;
    if encode(&value) != bytes {
        return Err(PadlockError::NotDeterministic);
    }
    canonical(&value)?;
    protected_bstrs(&value)?;
    let Value::Tag(96, inner) = value else {
        return Err(PadlockError::NotTagged);
    };
    let mut cose = CoseEncrypt::from_cbor_value(*inner).map_err(|e| match e {
        CoseError::DuplicateMapKey => PadlockError::DuplicateLabel,
        _ => PadlockError::Structure,
    })?;
    // coset re-emits what it parsed; equality means every slot, foreign ones
    // included, is written back byte for byte.
    if cose.clone().to_tagged_vec().ok().as_deref() != Some(bytes) {
        return Err(PadlockError::NotDeterministic);
    }
    check_body(&cose)?;
    let recipients = std::mem::take(&mut cose.recipients);
    if recipients.is_empty() {
        return Err(PadlockError::NoSlots);
    }
    if recipients.len() > MAX_SLOTS {
        return Err(PadlockError::TooManySlots);
    }
    let mut kids = Vec::with_capacity(recipients.len());
    for r in &recipients {
        headers_generic(&r.protected.header, &r.unprotected)?;
        let kid = &r.unprotected.key_id;
        slot::kid_method(kid)?;
        if kids.contains(&kid) {
            return Err(PadlockError::DuplicateKid);
        }
        kids.push(kid);
    }
    let slots = recipients
        .into_iter()
        .map(classify)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((cose, slots))
}

/// A256KW with no nested recipients and a method this reader implements is a
/// profile slot; anything else is foreign, skipped and kept (profile §5.4).
fn classify(r: coset::CoseRecipient) -> Result<Slot, PadlockError> {
    let a256kw = RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A256KW);
    let alg = r
        .unprotected
        .alg
        .as_ref()
        .or(r.protected.header.alg.as_ref());
    // kid_method already passed for every slot.
    let kid = String::from_utf8(r.unprotected.key_id.clone()).map_err(|_| PadlockError::Kid)?;
    let kind = slot::kid_method(kid.as_bytes())
        .ok()
        .and_then(slot::kind_for_method);
    match kind {
        Some(kind) if alg == Some(&a256kw) && r.recipients.is_empty() => {
            slot::validate(r, kind, kid)
        },
        _ => Ok(Slot {
            recipient: r,
            kind: SlotKind::Foreign,
            kid,
            kdf: None,
            os_blob: None,
        }),
    }
}

/// R6, R7 and R10 to R11 for the body.
fn check_body(cose: &CoseEncrypt) -> Result<(), PadlockError> {
    let protected = &cose.protected.header;
    headers_generic(protected, &cose.unprotected)?;
    if protected.content_type != Some(ContentType::Text(CONTENT_TYPE.to_string())) {
        return Err(PadlockError::Version);
    }
    if protected.alg
        != Some(RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ChaCha20Poly1305,
        ))
    {
        return Err(PadlockError::WrongAlg);
    }
    if labels(protected) != [Label::Int(1), Label::Int(3)]
        || cose.protected.original_data.as_deref() != Some(BODY_PROTECTED)
        || labels(&cose.unprotected) != [Label::Int(5)]
    {
        return Err(PadlockError::BodyHeader);
    }
    if cose.unprotected.iv.len() != 12 {
        return Err(PadlockError::IvLength);
    }
    if cose.ciphertext.as_ref().map(Vec::len) != Some(48) {
        return Err(PadlockError::CiphertextLength);
    }
    Ok(())
}

/// R7 (no `crit`) and R6 (no label in both buckets) for one layer.
fn headers_generic(protected: &Header, unprotected: &Header) -> Result<(), PadlockError> {
    if !protected.crit.is_empty() || !unprotected.crit.is_empty() {
        return Err(PadlockError::Critical);
    }
    let u = labels(unprotected);
    if labels(protected).iter().any(|l| u.contains(l)) {
        return Err(PadlockError::LabelInBothBuckets);
    }
    Ok(())
}

/// The labels present in a header, in coset's emission order.
fn labels(h: &Header) -> Vec<Label> {
    let present = [
        h.alg.is_some(),
        !h.crit.is_empty(),
        h.content_type.is_some(),
        !h.key_id.is_empty(),
        !h.iv.is_empty(),
        !h.partial_iv.is_empty(),
        !h.counter_signatures.is_empty(),
    ];
    (1..)
        .zip(present)
        .filter(|(_, p)| *p)
        .map(|(l, _)| Label::Int(l))
        .chain(h.rest.iter().map(|(l, _)| l.clone()))
        .collect()
}

fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Encoding an in-memory Value into a Vec cannot fail.
    let _ = coset::cbor::ser::into_writer(v, &mut out);
    out
}

/// R4 and R5 for every map: keys in bytewise order of their encodings
/// (RFC 8949 §4.2.1), none twice.
fn canonical(v: &Value) -> Result<(), PadlockError> {
    match v {
        Value::Array(items) => items.iter().try_for_each(canonical),
        Value::Tag(_, inner) => canonical(inner),
        Value::Map(entries) => {
            let mut previous: Option<Vec<u8>> = None;
            for (k, val) in entries {
                let key = encode(k);
                match previous.as_ref().map(|p| p.cmp(&key)) {
                    Some(Ordering::Equal) => return Err(PadlockError::DuplicateLabel),
                    Some(Ordering::Greater) => return Err(PadlockError::NotDeterministic),
                    _ => {},
                }
                canonical(k)?;
                canonical(val)?;
                previous = Some(key);
            }
            Ok(())
        },
        _ => Ok(()),
    }
}

/// R2, R4 and R5 inside each protected-header bstr, body and slots.
fn protected_bstrs(v: &Value) -> Result<(), PadlockError> {
    let Value::Tag(_, inner) = v else {
        return Ok(());
    };
    layer(inner)
}

fn layer(v: &Value) -> Result<(), PadlockError> {
    let Value::Array(items) = v else {
        return Ok(());
    };
    if let Some(Value::Bytes(b)) = items.first()
        && !b.is_empty()
    {
        let inner = Value::from_slice(b).map_err(|_| PadlockError::Malformed)?;
        if encode(&inner) != *b {
            return Err(PadlockError::NotDeterministic);
        }
        canonical(&inner)?;
    }
    match items.get(3) {
        Some(Value::Array(recipients)) => recipients.iter().try_for_each(layer),
        _ => Ok(()),
    }
}
