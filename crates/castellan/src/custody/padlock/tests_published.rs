// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Published vectors, one per cryptographic step (profile §6.1). The cose-wg
//! Examples are held as known answers from the vendored checkout
//! `Code/crates/cose-examples`, revision 53c9d634333bb4f529d78f5980fffa2667ee2c12.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use coset::{CoseEncrypt, CoseEncryptBuilder, HeaderBuilder, TaggedCborSerializable, iana};

use super::{Padlock, PadlockError, slot};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

// RFC 9106 §5.3: Argon2id, version 0x13, with secret K and associated data X.
#[test]
fn rfc9106_argon2id() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4; 12]).unwrap())
        .build()
        .unwrap();
    let argon =
        Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut tag = [0u8; 32];
    argon
        .hash_password_into(&[1; 32], &[2; 16], &mut tag)
        .unwrap();
    assert_eq!(
        tag.to_vec(),
        unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

// RFC 3394 §4.6: 256 bits of key data wrapped with a 256-bit KEK, through the
// profile's own wrap and unwrap.
#[test]
fn rfc3394_aes256_wrap_of_256_bit_key() {
    let kek = seq::<32>(0);
    let data: [u8; 32] = unhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
        .try_into()
        .unwrap();
    let wrapped = slot::wrap(&kek, &data).unwrap();
    assert_eq!(
        wrapped,
        unhex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    );
    assert_eq!(slot::unwrap(&kek, &wrapped).as_deref(), Some(&data));
    // RFC 3394 §2.2.3.1: a failed integrity check returns no key data.
    let mut bad = wrapped;
    bad[0] ^= 1;
    assert!(slot::unwrap(&kek, &bad).is_none());
}

// RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305.
#[test]
fn rfc8439_chacha20_poly1305() {
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let cipher = ChaCha20Poly1305::new_from_slice(&seq::<32>(0x80)).unwrap();
    let nonce = Nonce::try_from(&unhex("070000004041424344454647")[..]).unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let out = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(
        out,
        unhex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691"
        ))
    );
}

// cose-wg chacha-poly-examples/chacha-poly-01.json: COSE_Encrypt with
// ChaCha20/Poly1305 content, the profile's content layer. Its bytes are
// deterministic, so it is checked whole as well as step by step.
#[test]
fn cose_wg_chacha_poly_01() {
    let cbor = unhex(concat!(
        "D8608444A1011818A1054C26682306D4FB28CA01B43B8058241CD5D49DAA014CCAFFB30E765DC5CD",
        "410689AAE1C60B45648853298FF6808DB3FA8235DB818340A2012504477365632D32353640"
    ));
    let cek = unhex("0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100");
    let iv = unhex("26682306D4FB28CA01B43B80");
    let message = CoseEncrypt::from_tagged_slice(&cbor).unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(&cek).unwrap();
    let nonce = Nonce::try_from(&iv[..]).unwrap();
    let mut aad_seen = Vec::new();
    let plain = message
        .decrypt_ciphertext(
            b"",
            || chacha20poly1305::Error,
            |msg, aad| {
                aad_seen = aad.to_vec();
                cipher.decrypt(&nonce, Payload { msg, aad })
            },
        )
        .unwrap();
    // The Enc_structure coset builds is the example's AAD_hex.
    assert_eq!(aad_seen, unhex("8367456E637279707444A101181840"));
    assert_eq!(plain, b"This is the content.");
    let rebuilt = CoseEncryptBuilder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ChaCha20Poly1305)
                .build(),
        )
        .unprotected(HeaderBuilder::new().iv(iv.clone()).build())
        .create_ciphertext(b"This is the content.", b"", |msg, aad| {
            cipher.encrypt(&nonce, Payload { msg, aad }).unwrap()
        })
        .add_recipient(coset::CoseRecipient {
            unprotected: HeaderBuilder::new()
                .algorithm(iana::Algorithm::Direct)
                .key_id(b"sec-256".to_vec())
                .build(),
            ciphertext: Some(Vec::new()),
            ..Default::default()
        })
        .build();
    assert_eq!(rebuilt.to_tagged_vec().unwrap(), cbor);
    // A standard COSE message, but not this profile's: no content type.
    assert_eq!(Padlock::parse(&cbor).err(), Some(PadlockError::Version));
}

// cose-wg aes-wrap-examples/aes-wrap-256-04.json: an A256KW recipient. Its
// CEK is 16 bytes (A128GCM content), so the wrap is checked as a step and the
// recipient as a structure; RFC 3394 §4.6 covers the 32-byte size.
#[test]
fn cose_wg_aes_wrap_256_04() {
    use aes_kw::{KeyInit as _, KwAes256};
    let cbor = unhex(concat!(
        "D8608443A10101A1054CDDDC08972DF9BE62855291A1582470C0A7FEEA2254DD2C301963DAF77580",
        "EE31F7C4125246D436EB205B58AEFB5140DFDF51818340A2012404582430313863306165352D3464",
        "39622D343731622D626664362D6565663331346263373033375818DC4725A1E6FE212C3B2C268954",
        "C97E7422D4B85E6E131D72"
    ));
    let k = URL_SAFE_NO_PAD
        .decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg")
        .unwrap();
    let message = CoseEncrypt::from_tagged_slice(&cbor).unwrap();
    let recipient = &message.recipients[0];
    assert_eq!(recipient.protected.original_data.as_deref(), Some(&[][..]));
    assert_eq!(
        recipient.unprotected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::A256KW
        ))
    );
    assert_eq!(
        recipient.unprotected.key_id,
        b"018c0ae5-4d9b-471b-bfd6-eef314bc7037"
    );
    let wrapped = recipient.ciphertext.clone().unwrap();
    let kw = KwAes256::new_from_slice(&k).unwrap();
    let mut cek = [0u8; 16];
    kw.unwrap_key(&wrapped, &mut cek).unwrap();
    assert_eq!(cek.to_vec(), unhex("7A1B4CF7DCD2F9EC0F44B107B89BC7A5"));
    let mut again = [0u8; 24];
    assert_eq!(kw.wrap_key(&cek, &mut again).unwrap(), &wrapped[..]);
    assert_eq!(message.to_tagged_vec().unwrap(), cbor);
    assert_eq!(Padlock::parse(&cbor).err(), Some(PadlockError::Version));
}
