// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Unassociated keys through the custodian (release log D3, R7): minted,
//! stored sealed, signed with and released only for a granted principal, and
//! unrelated to every key the vault's master derives.

use custody_wire::contract::{Answer, UnassociatedAction};
use custody_wire::secret::Bytes;
use custody_wire::Operation;
use personae::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, UnassociatedKeypair};
use serde_json::json;

use super::h2_tests::{answer, base, config, vault};
use super::{Harness, code, djinn};

fn act(action: UnassociatedAction) -> Operation {
    Operation::Unassociated { action }
}

fn create(h: &mut Harness, session: u64) -> [u8; 32] {
    let Answer::PublicKey { key } = answer(h.outcome(session, act(UnassociatedAction::Create {}))) else { panic!() };
    key
}

#[test]
fn a_custodied_unassociated_key_signs_releases_and_links_to_nothing() {
    let dir = vault();
    let grants = base(json!([
        {"operation": "unassociated", "consent": "none"},
        {"operation": "release", "profile": "current", "salts": [{"prefix": "app/"}], "consent": "none"}
    ]));
    let mut h = Harness::new(config(&dir, "deny", grants.clone()));
    let session = h.open(djinn());
    assert_eq!(code(&h.outcome(session, act(UnassociatedAction::Create {}))), "locked", "a locked custodian mints nothing");
    h.unlock(session);
    let public = create(&mut h, session);

    let sign = act(UnassociatedAction::Sign { public_key: Bytes(public.to_vec()), message: Bytes(b"edition".to_vec()) });
    let Answer::Signature { public_key, signature, attestation } = answer(h.outcome(session, sign)) else { panic!() };
    assert_eq!((public_key, attestation), (public, None), "no attestation: nothing ties it to a root");
    assert!(Ed25519PublicKey::from_bytes(&public).unwrap().verify(b"edition", &Ed25519Signature::from_bytes(&signature)));

    let release = act(UnassociatedAction::Release { public_key: Bytes(public.to_vec()) });
    let Answer::Seed { public_key, seed } = answer(h.outcome(session, release)) else { panic!() };
    let released = Ed25519Keypair::from_seed(seed.expose().try_into().unwrap());
    assert_eq!(public_key, public);
    assert_eq!(released.public_key().to_bytes(), public);

    // Nothing the persona derives matches it.
    let Answer::PublicKey { key: master } = answer(h.outcome(session, Operation::PublicKey { source: custody_wire::contract::Source::Persona, profile: None })) else { panic!() };
    assert_ne!(master, public);

    // Stored sealed: the seed is nowhere in the file.
    let files: Vec<_> = walk(&dir.path().join("vault").join("unassociated"));
    assert_eq!(files.len(), 1);
    let stored = std::fs::read(&files[0]).unwrap();
    assert!(!stored.windows(32).any(|w| w == seed.expose()), "the file holds the key only sealed");

    // A restarted custodian reopens it after the unlock; a different key is unknown.
    drop(h);
    let mut again = Harness::new(config(&dir, "deny", grants));
    let session = again.open(djinn());
    again.unlock(session);
    let sign = act(UnassociatedAction::Sign { public_key: Bytes(public.to_vec()), message: Bytes(b"x".to_vec()) });
    assert!(matches!(answer(again.outcome(session, sign)), Answer::Signature { .. }));
    let stranger = UnassociatedKeypair::generate().public_key().to_bytes();
    let sign = act(UnassociatedAction::Sign { public_key: Bytes(stranger.to_vec()), message: Bytes(b"x".to_vec()) });
    assert_eq!(code(&again.outcome(session, sign)), "unassociated-unknown");
    let short = act(UnassociatedAction::Release { public_key: Bytes(vec![1; 5]) });
    assert_eq!(code(&again.outcome(session, short)), "operation-or-scope");
}

#[test]
fn without_the_grant_nothing_is_minted_or_signed() {
    let dir = vault();
    let mut h = Harness::new(config(&dir, "deny", base(json!([]))));
    let session = h.open(djinn());
    h.unlock(session);
    assert_eq!(code(&h.outcome(session, act(UnassociatedAction::Create {}))), "operation-denied");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}
