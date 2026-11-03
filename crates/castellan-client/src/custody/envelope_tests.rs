// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

// Moved from the door envelope's tests (djinn-slimming S2): custody
// answers inside `ostiary::wire`'s envelope keep their wire shape.
use ostiary::wire::AppHostMessage;

#[test]
fn released_custody_answer_preserves_exact_wire_fixture() {
    use crate::custody::{CustodyAnswer, CustodyRefusal};
    type Outgoing = AppHostMessage<(), (), Result<CustodyAnswer, CustodyRefusal>>;
    let answer = Outgoing::Answer {
        id: 9,
        answer: Ok(CustodyAnswer::Released {
            master: [0x5a; 32],
            keys: vec![],
        }),
    };
    let fixture = r#"{"type":"answer","id":9,"answer":{"Ok":{"answer":"released","master":"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo","keys":[]}}}"#;
    assert_eq!(serde_json::to_string(&answer).unwrap(), fixture);
    assert_eq!(serde_json::from_str::<Outgoing>(fixture).unwrap(), answer);
}

#[test]
fn released_answer_round_trips_nonempty_key_material() {
    use crate::custody::{CustodyAnswer, CustodyRefusal, ReleasedKey};
    use personae::IdentityProvider;
    type Outgoing = AppHostMessage<(), (), Result<CustodyAnswer, CustodyRefusal>>;
    let salt = b"test-release-key".to_vec();
    let provider = personae::InMemoryProvider::from_seed([9; 32]);
    let attestation = provider.attest_derived_key(&salt).unwrap();
    let answer = Outgoing::Answer {
        id: 9,
        answer: Ok(CustodyAnswer::Released {
            master: [0x5a; 32],
            keys: vec![ReleasedKey {
                salt,
                seed: [0x6b; 32],
                attestation,
            }],
        }),
    };
    let encoded = serde_json::to_string(&answer).unwrap();
    assert!(encoded.contains("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"));
    assert!(encoded.contains("a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"));
    assert_eq!(serde_json::from_str::<Outgoing>(&encoded).unwrap(), answer);
}
