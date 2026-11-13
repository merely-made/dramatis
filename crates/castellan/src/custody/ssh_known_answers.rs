// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Known answers for the key formats the vault and the agent depend on.
//!
//! For each key type the agent signs, a fixed `ssh-keygen` key parses and
//! re-encodes to its own bytes (the vault stores slots as OpenSSH text), and
//! its public line and SHA-256 fingerprint are the pinned strings. Ed25519
//! and RSA PKCS#1 v1.5 signatures are deterministic, so their bytes are
//! pinned; ECDSA signatures are checked by verification. Recorded with
//! ssh-key 0.6.7; an `ssh-key` move must leave every answer unchanged.

use super::sign;
use super::tests::fixture;
use signature::Verifier;
use ssh_key::LineEnding;
use ssh_key::public::PublicKey;
use ssh_key::{HashAlg, PrivateKey};

const MESSAGE: &[u8] = b"castellan known-answer message";

fn fixture_text(name: &str) -> &'static str {
    match name {
        "ed25519" => include_str!("../../tests/fixtures/ssh/ed25519"),
        "rsa2048" => include_str!("../../tests/fixtures/ssh/rsa2048"),
        "ecdsa256" => include_str!("../../tests/fixtures/ssh/ecdsa256"),
        "ecdsa384" => include_str!("../../tests/fixtures/ssh/ecdsa384"),
        other => panic!("no fixture {other}"),
    }
}

struct Answer {
    name: &'static str,
    public_line: &'static str,
    fingerprint: &'static str,
    flags: u32,
    /// Hex of the SSH signature blob, for the deterministic signers.
    signature: Option<&'static str>,
}

const ANSWERS: &[Answer] = &[
    Answer {
        name: "ed25519",
        public_line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEExRL9gZAuuG20W4w8LbdQlgcxpN8grxsiCGc0ilLdk personae-p4a-fixture-ed25519",
        fingerprint: "SHA256:+d4XHFZtrPK2YisXiat/MWQBOJ0BEgCph0nsXEX5vWI",
        flags: 0,
        signature: Some(
            "7e30d60af5fe8dc2f381c5a0d14389dc9efa732f8f714cb22595ede1c432bcc910b08eb2d136072439b9e73f894eff02604e1def988fcba4ef34caab2f7ab001",
        ),
    },
    Answer {
        name: "rsa2048",
        public_line: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDhseUp0N9ywwcC5G8wnf+NCQIdfyeb2gVN2DKD5ZX3TAGRn7uVn+oeoZqIpX1TVhINskkI/N50BfmUbQiBiuY+a5Z9gCXDqUY1rmv2VSVOKjEyYgIzFiA6ZovDKYKvQUDH0kPbgjfyZ/MdIBqQR9Ue8ShYJpVG+4NMohXW3pht7jNHAhU/4GzXeJ8Cd9XyGVuu/X5EwLarz/mYXQ0Ll3p2ymfb1YO46xO2DXcQtI7YkEvg0MJWLOlwFHIkEaFkXMjV1/kvVAf+bC0n9++52mYkbfUhuC/3cn1cYY7WSzLpwTyii0plm/71BcT9MK5UbX+D8Nq1EH+2Xx/y4S8Q/xc7 personae-p4a-fixture-rsa2048",
        fingerprint: "SHA256:16QNuPT5D6hK9mePB8TzZ0GvwGtVlLolKsml0qWoxn8",
        flags: super::SSH_AGENT_RSA_SHA2_256,
        signature: Some(
            "e0b5435094725cff95d5511f3007ad2fbee96ef8b34b43a854f81843d891f30f4b35a1848ff4ed65341bbfa73899600673910fb0f6f681580477bff382e791f8a31a69944ad0133975bfe09a868029f2b626d182b7b1ef78f20aeee15809215e23d09e7cec825b0a411ad1a807ed73feb4d711aa7dd029445e08e27ec526dfd9977dc81d0fe5fd55168c339db53f7b6644073aedd694afb86d2e4e850caad29dcb6a1faebd5aa0af04e655f8d30a42f2c4bd6913e08bac769ab187cedd62461b0892835b6121c484e17bf8bb2f700c623b48635e9a01bb0132bad953cc68fd936ad3d20710903c8318083c97178b85096db2f67d1788f6086c54a32e9f6c27a4",
        ),
    },
    Answer {
        name: "ecdsa256",
        public_line: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhxmVG+om2fAtQCQUIjLhpyT443s6kngHbH0h1Gn6EV7CO6IY/XhQPo6OwYlSB6D5x0vhkjAxqeYGgEjCLBRGo= personae-p4a-fixture-ecdsa256",
        fingerprint: "SHA256:U11rEFtHGlO6Bk8xEwRNXee4aYw/YphLyD/FIVVlZuY",
        flags: 0,
        signature: None,
    },
    Answer {
        name: "ecdsa384",
        public_line: "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFoyUS2fBYp+uoqIc2NDGHFfs0xv4y4kuYD2NWPuRTxke4Dhj2fQ19+KauEqnOBw2Q9YbvzCRAel/e2Lm8zbyNReuw9FCcUHKFanSuOjTBxHcCtORceAXdEN8rsbe/ZQEw== personae-p4a-fixture-ecdsa384",
        fingerprint: "SHA256:yk3zVboDo4XOexfr+nZZ0LoOwJ62QIm+2ytYHX0y4Co",
        flags: 0,
        signature: None,
    },
];

fn signature_hex(signature: &ssh_key::Signature) -> String {
    hex::encode(signature.as_bytes())
}

#[test]
fn fixtures_re_encode_to_their_own_bytes() {
    for answer in ANSWERS {
        let text = fixture_text(answer.name);
        let key = PrivateKey::from_openssh(text).unwrap();
        let encoded = key.to_openssh(LineEnding::LF).unwrap();
        assert_eq!(encoded.as_str(), text, "{}", answer.name);
    }
}

#[test]
fn public_lines_and_fingerprints() {
    for answer in ANSWERS {
        let public = PublicKey::from(&fixture(answer.name));
        assert_eq!(
            public.to_openssh().unwrap(),
            answer.public_line,
            "{}",
            answer.name
        );
        assert_eq!(
            public.fingerprint(HashAlg::Sha256).to_string(),
            answer.fingerprint,
            "{}",
            answer.name
        );
    }
}

#[test]
fn signatures_verify_and_deterministic_ones_are_pinned() {
    for answer in ANSWERS {
        let key = fixture(answer.name);
        let signature = sign(key.key_data(), MESSAGE, answer.flags).unwrap();
        Verifier::verify(&PublicKey::from(&key), MESSAGE, &signature)
            .unwrap_or_else(|e| panic!("{}: {e}", answer.name));
        if let Some(pinned) = answer.signature {
            assert_eq!(signature_hex(&signature), pinned, "{}", answer.name);
        }
    }
}

#[test]
#[ignore = "prints the answers; run by hand when recording"]
fn print_answers() {
    for answer in ANSWERS {
        let key = fixture(answer.name);
        let public = PublicKey::from(&key);
        let signature = sign(key.key_data(), MESSAGE, answer.flags).unwrap();
        eprintln!(
            "ANSWER {} | {} | {} | {}",
            answer.name,
            public.to_openssh().unwrap(),
            public.fingerprint(HashAlg::Sha256),
            signature_hex(&signature)
        );
    }
}

/// `ssh-keygen -p` (OpenSSH 10.2p1) copies of three fixtures under the
/// passphrase below: aes256-ctr with bcrypt-pbkdf, as users' own files are.
#[test]
fn encrypted_fixtures_re_encode_and_decrypt_to_their_plain_keys() {
    for (name, encrypted) in [
        (
            "ed25519",
            include_str!("../../tests/fixtures/ssh/ed25519.encrypted"),
        ),
        (
            "ecdsa256",
            include_str!("../../tests/fixtures/ssh/ecdsa256.encrypted"),
        ),
        (
            "rsa2048",
            include_str!("../../tests/fixtures/ssh/rsa2048.encrypted"),
        ),
    ] {
        let key = PrivateKey::from_openssh(encrypted).unwrap();
        assert!(key.is_encrypted(), "{name}");
        assert_eq!(
            key.to_openssh(LineEnding::LF).unwrap().as_str(),
            encrypted,
            "{name}"
        );
        // `ssh-keygen -p` draws a new check integer, so the key data and
        // comment are compared rather than the whole text.
        let plain = key.decrypt("castellan known answer").unwrap();
        let expected = fixture(name);
        assert!(plain.key_data() == expected.key_data(), "{name}");
        assert_eq!(plain.comment(), expected.comment(), "{name}");
    }
}
