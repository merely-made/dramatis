// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The profile's own vectors (profile §6.2, §6.3), from
//! `tests/fixtures/padlock/vectors.json`, which `crosscheck.py` produces
//! independently. Every positive entry is rebuilt here from the fixed inputs.

use coset::{CoseEncrypt, TaggedCborSerializable};
use serde_json::Value as Json;

use super::{
    Argon2Params, BODY_PROTECTED, NewSlot, Padlock, PadlockError, SlotInput, SlotKind, slot,
};

const VECTORS: &str = include_str!("../../../tests/fixtures/padlock/vectors.json");
const PASSPHRASE: &str = "correct horse battery staple";
const NFC_COMPOSED: &str = "\u{00c5}ngstr\u{00f6}m caf\u{00e9}";
const NFC_DECOMPOSED: &str = "A\u{030a}ngstro\u{0308}m cafe\u{0301}";

fn json() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

fn get(section: &str, key: &str) -> Vec<u8> {
    hex::decode(json()[section][key].as_str().unwrap()).unwrap()
}

fn input<const N: usize>(key: &str) -> [u8; N] {
    get("inputs", key).try_into().unwrap()
}

fn container(key: &str) -> Vec<u8> {
    get("containers", key)
}

fn pass_slot<'a>(kid: &'a str, passphrase: &'a str) -> NewSlot<'a> {
    NewSlot::Passphrase {
        kid,
        passphrase,
        params: Argon2Params::DEFAULT,
    }
}

fn kek_input(kek: &[u8; 32]) -> SlotInput<'_> {
    SlotInput::Kek {
        kid: "keychain/test",
        kek,
    }
}

/// The body's three fields, which no slot change may touch (profile §3.3).
fn body_of(bytes: &[u8]) -> (Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>) {
    let cose = CoseEncrypt::from_tagged_slice(bytes).unwrap();
    (
        cose.protected.original_data,
        cose.unprotected.iv,
        cose.ciphertext,
    )
}

#[test]
fn inputs_match_the_profile() {
    let inputs = &json()["inputs"];
    assert_eq!(inputs["passphrase"], PASSPHRASE);
    assert_eq!(inputs["nfc_composed_utf8"], hex::encode(NFC_COMPOSED));
    assert_eq!(inputs["nfc_decomposed_utf8"], hex::encode(NFC_DECOMPOSED));
    let a = &inputs["argon2"];
    let d = Argon2Params::DEFAULT;
    assert_eq!(
        (a["m_kib"].as_u64(), a["t"].as_u64(), a["p"].as_u64()),
        (
            Some(u64::from(d.m_kib)),
            Some(u64::from(d.t)),
            Some(u64::from(d.p))
        )
    );
    assert_eq!(get("steps", "body_protected"), BODY_PROTECTED);
}

#[test]
fn v1_v2_keks_and_wraps() {
    let kek = slot::passphrase_kek(PASSPHRASE, &input("salt"), Argon2Params::DEFAULT).unwrap();
    assert_eq!(kek.to_vec(), get("steps", "kek_pass"));
    let cek = input::<32>("cek");
    assert_eq!(slot::wrap(&kek, &cek).unwrap(), get("steps", "wrap_pass"));
    assert_eq!(
        slot::wrap(&input("os_kek"), &cek).unwrap(),
        get("steps", "wrap_os")
    );
    assert_eq!(
        slot::wrap(&input("os_kek2"), &cek).unwrap(),
        get("steps", "wrap_blob")
    );
}

#[test]
fn nfc_composed_and_decomposed_give_one_kek() {
    let salt = input("salt_nfc");
    let a = slot::passphrase_kek(NFC_COMPOSED, &salt, Argon2Params::DEFAULT).unwrap();
    let b = slot::passphrase_kek(NFC_DECOMPOSED, &salt, Argon2Params::DEFAULT).unwrap();
    assert_eq!(a.to_vec(), get("steps", "kek_nfc"));
    assert_eq!(a, b);
}

#[test]
fn v3_v4_one_slot_container_and_unlock() {
    let first = pass_slot("pass/1", PASSPHRASE);
    let lock = Padlock::create_with(
        &input("root"),
        &input("cek"),
        input("iv"),
        &first,
        input("salt"),
    )
    .unwrap();
    let bytes = lock.to_bytes().unwrap();
    assert_eq!(bytes, container("one_slot"));
    assert_eq!(body_of(&bytes).2, Some(get("steps", "ciphertext")));
    let mut seen = None;
    let root = lock
        .unlock(&SlotInput::Passphrase(PASSPHRASE), |r| {
            seen = Some(*r);
            true
        })
        .unwrap();
    assert_eq!(*root, input::<32>("root"));
    assert_eq!(seen, Some(input::<32>("root")));
}

#[test]
fn v5_add_slot_keeps_body_and_first_slot() {
    let mut lock = Padlock::parse(&container("one_slot")).unwrap();
    let kek = input("os_kek");
    let new = NewSlot::Kek {
        kid: "keychain/test",
        kek: &kek,
        os_blob: None,
    };
    lock.add_slot_with(&SlotInput::Passphrase(PASSPHRASE), |_| true, &new, [0; 16])
        .unwrap();
    let after = lock.to_bytes().unwrap();
    assert_eq!(after, container("two_slot"));
    assert_eq!(body_of(&after), body_of(&container("one_slot")));
    assert_eq!(
        lock.add_slot_with(&kek_input(&kek), |_| true, &new, [0; 16])
            .err(),
        Some(PadlockError::KidExists)
    );
}

#[test]
fn v6_remove_slot_keeps_body() {
    let mut lock = Padlock::parse(&container("two_slot")).unwrap();
    assert_eq!(
        lock.remove_slot("pass/9").err(),
        Some(PadlockError::UnknownKid)
    );
    lock.remove_slot("pass/1").unwrap();
    let after = lock.to_bytes().unwrap();
    assert_eq!(after, container("os_only"));
    assert_eq!(body_of(&after), body_of(&container("two_slot")));
    assert_eq!(
        lock.remove_slot("keychain/test").err(),
        Some(PadlockError::LastSlot)
    );
    assert_eq!(
        *lock.unlock(&kek_input(&input("os_kek")), |_| true).unwrap(),
        input::<32>("root")
    );
}

#[test]
fn v7_unknown_slot_opens_and_survives_rewrites() {
    let bytes = container("unknown_slot");
    let mut lock = Padlock::parse(&bytes).unwrap();
    let kinds: Vec<_> = lock.slots().into_iter().map(|s| (s.kid, s.kind)).collect();
    assert_eq!(
        kinds,
        [
            ("pass/1".to_string(), SlotKind::Passphrase),
            ("keychain/test".to_string(), SlotKind::Kek),
            ("foo/1".to_string(), SlotKind::Foreign),
        ]
    );
    assert_eq!(lock.to_bytes().unwrap(), bytes);
    let kek = input("os_kek");
    assert_eq!(
        *lock.unlock(&kek_input(&kek), |_| true).unwrap(),
        input::<32>("root")
    );
    lock.remove_slot("keychain/test").unwrap();
    assert_eq!(
        lock.to_bytes().unwrap(),
        container("unknown_slot_os_removed")
    );
    let new = NewSlot::Kek {
        kid: "keychain/test",
        kek: &kek,
        os_blob: None,
    };
    lock.add_slot_with(&SlotInput::Passphrase(PASSPHRASE), |_| true, &new, [0; 16])
        .unwrap();
    assert_eq!(
        lock.to_bytes().unwrap(),
        container("unknown_slot_os_readded")
    );
    lock.remove_slot("keychain/test").unwrap();
    // Only the foreign slot would remain.
    assert_eq!(
        lock.remove_slot("pass/1").err(),
        Some(PadlockError::LastSlot)
    );
}

#[test]
fn v8_nested_recipients_make_a_slot_foreign() {
    let bytes = container("nested_foreign");
    let lock = Padlock::parse(&bytes).unwrap();
    let kinds: Vec<_> = lock.slots().into_iter().map(|s| s.kind).collect();
    assert_eq!(kinds, [SlotKind::Passphrase, SlotKind::Foreign]);
    assert_eq!(lock.to_bytes().unwrap(), bytes);
}

#[test]
fn v9_nfc_slot_opens_with_either_form() {
    let first = pass_slot("pass/nfc", NFC_COMPOSED);
    let lock = Padlock::create_with(
        &input("root"),
        &input("cek"),
        input("iv"),
        &first,
        input("salt_nfc"),
    )
    .unwrap();
    assert_eq!(lock.to_bytes().unwrap(), container("nfc_slot"));
    let root = lock
        .unlock(&SlotInput::Passphrase(NFC_DECOMPOSED), |_| true)
        .unwrap();
    assert_eq!(*root, input::<32>("root"));
}

#[test]
fn v10_kek_slot_with_os_blob() {
    let (kek, blob) = (input::<32>("os_kek2"), get("inputs", "os_blob"));
    let first = NewSlot::Kek {
        kid: "dpapi/0011223344556677",
        kek: &kek,
        os_blob: Some(&blob),
    };
    let lock =
        Padlock::create_with(&input("root"), &input("cek"), input("iv"), &first, [0; 16]).unwrap();
    assert_eq!(lock.to_bytes().unwrap(), container("blob_slot"));
    assert_eq!(lock.slots()[0].os_blob.as_deref(), Some(&blob[..]));
    let open = SlotInput::Kek {
        kid: "dpapi/0011223344556677",
        kek: &kek,
    };
    assert_eq!(*lock.unlock(&open, |_| true).unwrap(), input::<32>("root"));
}

#[test]
fn every_negative_vector_is_refused_with_its_own_error() {
    let doc = json();
    let negatives = doc["negatives"].as_object().unwrap();
    let mut rules = std::collections::BTreeSet::new();
    for (name, case) in negatives {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let got = Padlock::parse(&bytes).err().map(|e| format!("{e:?}"));
        assert_eq!(got.as_deref(), case["error"].as_str(), "{name}");
        rules.insert(case["rule"].as_str().unwrap().to_string());
    }
    assert_eq!(rules.len(), 16, "R1 to R16 each have a negative vector");
}

#[test]
fn a_huge_length_claim_is_refused_without_allocating_it() {
    let mut bytes = hex::decode("d860845b").unwrap();
    bytes.extend_from_slice(&[0xff; 8]);
    assert_eq!(Padlock::parse(&bytes).err(), Some(PadlockError::Malformed));
}

#[test]
fn unlock_failures() {
    let lock = Padlock::parse(&container("two_slot")).unwrap();
    let os_kek = input::<32>("os_kek");
    assert_eq!(
        lock.unlock(&kek_input(&[0; 32]), |_| true).err(),
        Some(PadlockError::WrongSecret)
    );
    assert_eq!(
        lock.unlock(&kek_input(&os_kek), |_| false).err(),
        Some(PadlockError::BindingRefused)
    );
    let other = SlotInput::Kek {
        kid: "keychain/other",
        kek: &os_kek,
    };
    assert_eq!(
        lock.unlock(&other, |_| true).err(),
        Some(PadlockError::NoMatchingSlot)
    );
    let os_only = Padlock::parse(&container("os_only")).unwrap();
    let pass = SlotInput::Passphrase(PASSPHRASE);
    assert_eq!(
        os_only.unlock(&pass, |_| true).err(),
        Some(PadlockError::NoMatchingSlot)
    );
    // The last ciphertext byte flipped: the slot unwraps, the body does not open.
    let mut bytes = container("two_slot");
    let ct = get("steps", "ciphertext");
    let at = bytes.windows(ct.len()).position(|w| w == ct).unwrap() + ct.len() - 1;
    bytes[at] ^= 1;
    let damaged = Padlock::parse(&bytes).unwrap();
    assert_eq!(
        damaged.unlock(&kek_input(&os_kek), |_| true).err(),
        Some(PadlockError::BodyAuthentication)
    );
}

#[test]
fn a_wrong_passphrase_returns_no_key() {
    let lock = Padlock::parse(&container("one_slot")).unwrap();
    let wrong = SlotInput::Passphrase("correct horse battery stapl");
    assert_eq!(
        lock.unlock(&wrong, |_| true).err(),
        Some(PadlockError::WrongSecret)
    );
}

#[test]
fn the_writer_refuses_what_the_reader_would() {
    let root = [7; 32];
    let low = Argon2Params {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };
    let weak = NewSlot::Passphrase {
        kid: "pass/1",
        passphrase: "x",
        params: low,
    };
    assert_eq!(
        Padlock::create(&root, &weak).err(),
        Some(PadlockError::KdfBounds)
    );
    let kek = [9; 32];
    let wrong_method = NewSlot::Passphrase {
        kid: "keychain/x",
        passphrase: "x",
        params: Argon2Params::DEFAULT,
    };
    assert_eq!(
        Padlock::create(&root, &wrong_method).err(),
        Some(PadlockError::Kid)
    );
    let big = vec![0; 2049];
    let blob = NewSlot::Kek {
        kid: "dpapi/1",
        kek: &kek,
        os_blob: Some(&big),
    };
    assert_eq!(
        Padlock::create(&root, &blob).err(),
        Some(PadlockError::OsBlob)
    );
    // A random padlock round-trips through its own reader and opens.
    let ok = NewSlot::Kek {
        kid: "secsvc/a",
        kek: &kek,
        os_blob: None,
    };
    let lock = Padlock::create(&root, &ok).unwrap();
    let again = Padlock::parse(&lock.to_bytes().unwrap()).unwrap();
    let open = SlotInput::Kek {
        kid: "secsvc/a",
        kek: &kek,
    };
    assert_eq!(*again.unlock(&open, |_| true).unwrap(), root);
}
