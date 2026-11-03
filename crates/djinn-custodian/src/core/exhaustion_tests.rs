// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::tests::{Harness, PASSPHRASE, config, djinn, vault};
use custody_wire::secret::Secret;

#[test]
fn generation_exhaustion_during_revoke_locks_and_closes_all_sessions() {
    let (dir, _) = vault();
    let mut harness = Harness::new(config(dir.path(), "deny", "none"));
    let session = harness.open(djinn());
    let admin = harness.open(custody_wire::Peer::Unix {
        uid: 0,
        gid: 0,
        pid: Some(1),
    });
    harness.unlock(session);
    harness.core.generation = u64::MAX - 1;
    harness.core.lock_now();
    assert_eq!(harness.core.generation(), u64::MAX);
    let (_, effects) = harness.request(
        admin,
        Operation::Revoke {
            principal: "djinn".into(),
        },
    );
    assert!(harness.core.status().locked);
    assert!(harness.core.exhausted);
    assert!(effects.close.contains(&session) && effects.close.contains(&admin));
    assert!(matches!(
        harness.outcome(
            admin,
            Operation::Unlock {
                passphrase: Secret::copy_from(PASSPHRASE.as_bytes())
            }
        ),
        Outcome::Refused { .. }
    ));
}

#[test]
fn generation_exhaustion_permanently_refuses_unlock_and_substantive_operations() {
    let (dir, _) = vault();
    let mut harness = Harness::new(config(dir.path(), "deny", "none"));
    let session = harness.open(djinn());
    harness.unlock(session);
    harness.core.generation = u64::MAX;
    let (_, effects) = harness.core.lock_now();
    assert!(
        effects.close.contains(&session),
        "exhaustion must disconnect clients holding the saturated generation"
    );
    assert!(harness.core.status().locked);
    let outcome = harness.outcome(
        session,
        Operation::Unlock {
            passphrase: Secret::copy_from(PASSPHRASE.as_bytes()),
        },
    );
    assert!(
        matches!(outcome, Outcome::Refused { .. }),
        "overflow must never permit a reused generation to unlock"
    );
    assert!(
        harness.core.status().locked,
        "overflow must retain no unlocked root"
    );
    let outcome = harness.outcome(
        session,
        Operation::Release {
            profile: "work".into(),
            salts: vec![custody_wire::secret::Bytes(b"mesh-author".to_vec())],
        },
    );
    assert!(matches!(outcome, Outcome::Refused { .. }));
}
