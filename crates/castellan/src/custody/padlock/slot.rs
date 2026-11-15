// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Slots: their kinds, labels and keys (profile §3.4 to §3.6). Every primitive
//! is a library call: icu_normalizer (NFC), argon2 (Argon2id), aes-kw (A256KW).

use aes_kw::{KeyInit, KwAes256};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use coset::cbor::value::Value;
use coset::{CoseRecipient, HeaderBuilder, Label, iana};
use icu_normalizer::ComposingNormalizerBorrowed;
use zeroize::Zeroizing;

use super::{
    Argon2Params, LABEL_KDF, LABEL_KDF_M, LABEL_KDF_P, LABEL_KDF_SALT, LABEL_KDF_T, LABEL_KDF_V,
    LABEL_OS_BLOB, MAX_OS_BLOB_BYTES, NewSlot, PadlockError, SlotKind,
};

/// Argon2id's type value, RFC 9106 §3.1 (y = 2).
const KDF_ARGON2ID: i64 = 2;
/// Argon2's version, RFC 9106 §3.1 (v = 0x13).
const KDF_VERSION: i64 = 0x13;
const SALT_LEN: usize = 16;
const WRAPPED_LEN: usize = 40;

/// A slot as the reader validated it; the recipient keeps its bytes.
#[derive(Clone)]
pub(super) struct Slot {
    pub(super) recipient: CoseRecipient,
    pub(super) kind: SlotKind,
    pub(super) kid: String,
    pub(super) kdf: Option<([u8; SALT_LEN], Argon2Params)>,
    pub(super) os_blob: Option<Vec<u8>>,
}

/// The kind a `kid` method names; `None` is a method this reader does not
/// implement, so the slot is foreign (profile §3.4, §5.4).
pub(super) fn kind_for_method(method: &str) -> Option<SlotKind> {
    match method {
        "pass" => Some(SlotKind::Passphrase),
        "dpapi" | "keychain" | "secsvc" => Some(SlotKind::Kek),
        _ => None,
    }
}

/// `<method>/<id>`, 3 to 64 bytes; method `[a-z0-9]+`, id printable ASCII
/// without `/` or space (profile §3.4). Returns the method.
pub(super) fn kid_method(kid: &[u8]) -> Result<&str, PadlockError> {
    let text = std::str::from_utf8(kid).map_err(|_| PadlockError::Kid)?;
    let (method, id) = text.split_once('/').ok_or(PadlockError::Kid)?;
    let method_ok = !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let id_ok = !id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
    if (3..=64).contains(&kid.len()) && method_ok && id_ok {
        Ok(method)
    } else {
        Err(PadlockError::Kid)
    }
}

/// Validates a profile slot's labels and values (rules R12, R13, R15).
pub(super) fn validate(
    recipient: CoseRecipient,
    kind: SlotKind,
    kid: String,
) -> Result<Slot, PadlockError> {
    let empty = recipient
        .protected
        .original_data
        .as_deref()
        .unwrap_or_default();
    if !empty.is_empty() || !recipient.protected.header.is_empty() {
        return Err(PadlockError::SlotProtected);
    }
    let h = &recipient.unprotected;
    if h.content_type.is_some()
        || !h.iv.is_empty()
        || !h.partial_iv.is_empty()
        || !h.counter_signatures.is_empty()
    {
        return Err(PadlockError::SlotLabel);
    }
    if recipient.ciphertext.as_ref().map(Vec::len) != Some(WRAPPED_LEN) {
        return Err(PadlockError::WrappedKeyLength);
    }
    let rest = |label: i64| {
        h.rest
            .iter()
            .find(|(l, _)| *l == Label::Int(label))
            .map(|(_, v)| v)
    };
    let allowed: &[i64] = match kind {
        SlotKind::Passphrase => &[
            LABEL_KDF,
            LABEL_KDF_SALT,
            LABEL_KDF_M,
            LABEL_KDF_T,
            LABEL_KDF_P,
            LABEL_KDF_V,
        ],
        _ => &[LABEL_OS_BLOB],
    };
    if h.rest
        .iter()
        .any(|(l, _)| !matches!(l, Label::Int(i) if allowed.contains(i)))
    {
        return Err(PadlockError::SlotLabel);
    }
    let (mut kdf, mut os_blob) = (None, None);
    if kind == SlotKind::Passphrase {
        if h.rest.len() != allowed.len() {
            return Err(PadlockError::KdfLabels);
        }
        let int = |label| match rest(label) {
            Some(Value::Integer(i)) => i64::try_from(i128::from(*i)).ok(),
            _ => None,
        };
        let salt: [u8; SALT_LEN] = match rest(LABEL_KDF_SALT) {
            Some(Value::Bytes(b)) => b
                .as_slice()
                .try_into()
                .map_err(|_| PadlockError::SaltLength)?,
            _ => return Err(PadlockError::SaltLength),
        };
        let u32_of = |label| int(label).and_then(|i| u32::try_from(i).ok());
        let params = match (
            u32_of(LABEL_KDF_M),
            u32_of(LABEL_KDF_T),
            u32_of(LABEL_KDF_P),
        ) {
            (Some(m_kib), Some(t), Some(p)) => Argon2Params { m_kib, t, p },
            _ => return Err(PadlockError::KdfBounds),
        };
        if int(LABEL_KDF) != Some(KDF_ARGON2ID) || int(LABEL_KDF_V) != Some(KDF_VERSION) {
            return Err(PadlockError::KdfBounds);
        }
        params.check()?;
        kdf = Some((salt, params));
    } else if let Some(v) = rest(LABEL_OS_BLOB) {
        match v {
            Value::Bytes(b) if b.len() <= MAX_OS_BLOB_BYTES => os_blob = Some(b.clone()),
            _ => return Err(PadlockError::OsBlob),
        }
    }
    Ok(Slot {
        recipient,
        kind,
        kid,
        kdf,
        os_blob,
    })
}

/// RFC 8265 §4.2.2's normalisation step only: Unicode NFC.
fn nfc(passphrase: &str) -> Zeroizing<String> {
    // NFC grows UTF-8 by at most 3x (UAX #15 §9), so the buffer never
    // reallocates and leaves no uncleared copy behind.
    let mut out = Zeroizing::new(String::with_capacity(passphrase.len() * 3));
    // Writing into a String cannot fail.
    let _ = ComposingNormalizerBorrowed::new_nfc().normalize_to(passphrase, &mut *out);
    out
}

/// KEK = Argon2id(NFC(passphrase), salt, m, t, p, T = 32, v = 0x13), no K or X
/// (RFC 9106 §3.1; profile §3.5).
pub(super) fn passphrase_kek(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, PadlockError> {
    params.check()?;
    let normal = nfc(passphrase);
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| PadlockError::KdfBounds)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; 32]);
    // The working memory is ours so it is cleared on drop (vault lock ruling 33).
    let mut blocks = Zeroizing::new(vec![Block::default(); argon.params().block_count()]);
    argon
        .hash_password_into_with_memory(normal.as_bytes(), salt, kek.as_mut(), &mut blocks[..])
        .map_err(|_| PadlockError::Kdf)?;
    Ok(kek)
}

/// AES-KW wrap of the CEK, RFC 3394 §2.2.1 (A256KW, RFC 9053 §6.2.1).
pub(super) fn wrap(kek: &[u8; 32], cek: &[u8; 32]) -> Result<Vec<u8>, PadlockError> {
    let kw = KwAes256::new_from_slice(kek).map_err(|_| PadlockError::Kdf)?;
    let mut out = vec![0u8; WRAPPED_LEN];
    kw.wrap_key(cek, &mut out).map_err(|_| PadlockError::Kdf)?;
    Ok(out)
}

/// AES-KW unwrap; a failed integrity check returns no key data (RFC 3394 §2.2.3.1).
pub(super) fn unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let kw = KwAes256::new_from_slice(kek).ok()?;
    let mut cek = Zeroizing::new([0u8; 32]);
    kw.unwrap_key(wrapped, cek.as_mut()).ok()?;
    Some(cek)
}

/// Builds the recipient for `new` around `cek`, checking that it unwraps.
pub(super) fn build(
    new: &NewSlot<'_>,
    cek: &[u8; 32],
    salt: [u8; SALT_LEN],
) -> Result<Slot, PadlockError> {
    let (kid, kind) = match new {
        NewSlot::Passphrase { kid, .. } => (*kid, SlotKind::Passphrase),
        NewSlot::Kek { kid, .. } => (*kid, SlotKind::Kek),
    };
    if kind_for_method(kid_method(kid.as_bytes())?) != Some(kind) {
        return Err(PadlockError::Kid);
    }
    let mut header = HeaderBuilder::new()
        .algorithm(iana::Algorithm::A256KW)
        .key_id(kid.as_bytes().to_vec());
    let kek = match new {
        NewSlot::Passphrase {
            passphrase, params, ..
        } => {
            header = header
                .value(LABEL_KDF, Value::from(KDF_ARGON2ID))
                .value(LABEL_KDF_SALT, Value::Bytes(salt.to_vec()))
                .value(LABEL_KDF_M, Value::from(params.m_kib))
                .value(LABEL_KDF_T, Value::from(params.t))
                .value(LABEL_KDF_P, Value::from(params.p))
                .value(LABEL_KDF_V, Value::from(KDF_VERSION));
            passphrase_kek(passphrase, &salt, *params)?
        },
        NewSlot::Kek { kek, os_blob, .. } => {
            if let Some(blob) = os_blob {
                if blob.len() > MAX_OS_BLOB_BYTES {
                    return Err(PadlockError::OsBlob);
                }
                header = header.value(LABEL_OS_BLOB, Value::Bytes(blob.to_vec()));
            }
            Zeroizing::new(**kek)
        },
    };
    let wrapped = wrap(&kek, cek)?;
    if unwrap(&kek, &wrapped).as_deref() != Some(cek) {
        return Err(PadlockError::WrongSecret);
    }
    let recipient = CoseRecipient {
        unprotected: header.build(),
        ciphertext: Some(wrapped),
        ..Default::default()
    };
    validate(recipient, kind, kid.to_string())
}
