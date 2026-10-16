// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use gaz::{LocalId, TypedKey};
use serde_json::json;

const LOCAL: &str = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

fn contact_ref(anchor: Anchor) -> SubjectRef {
    SubjectRef::Contact {
        scope: PersonaScope::new("work"),
        anchor,
    }
}

#[test]
fn saved_json_has_explicit_namespaces_and_no_biography() {
    let fixtures = [
        (
            SubjectRef::Profile {
                id: ProfileId("work".into()),
            },
            r#"{"Profile":{"id":"work"}}"#,
        ),
        (
            contact_ref(LOCAL.parse().unwrap()),
            r#"{"Contact":{"scope":"work","anchor":"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}}"#,
        ),
    ];
    for (subject, fixture) in fixtures {
        assert_eq!(serde_json::to_string(&subject).unwrap(), fixture);
        assert_eq!(
            serde_json::from_str::<SubjectRef>(fixture).unwrap(),
            subject
        );
    }
}

#[test]
fn binary_profile_and_local_contact_have_fixed_variant_order() {
    let profile = SubjectRef::Profile {
        id: ProfileId("work".into()),
    };
    assert_eq!(postcard::to_allocvec(&profile).unwrap(), b"\x00\x04work");
    let subject = contact_ref(LOCAL.parse().unwrap());
    let mut fixture = b"\x01\x04work\x02".to_vec();
    fixture.extend_from_slice(LocalId::parse(LOCAL).unwrap().as_bytes());
    assert_eq!(postcard::to_allocvec(&subject).unwrap(), fixture);
    assert_eq!(
        postcard::from_bytes::<SubjectRef>(&fixture).unwrap(),
        subject
    );
    assert!(postcard::from_bytes::<SubjectRef>(&[2]).is_err());
}

#[test]
fn every_existing_anchor_family_round_trips_inside_a_subject() {
    for text in [
        LOCAL,
        "did:plc:z72i7hdynmk6r22z27h6tvur",
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    ] {
        let subject = contact_ref(text.parse().unwrap());
        let json = serde_json::to_vec(&subject).unwrap();
        assert_eq!(
            serde_json::from_slice::<SubjectRef>(&json).unwrap(),
            subject
        );
        let bytes = postcard::to_allocvec(&subject).unwrap();
        assert_eq!(postcard::from_bytes::<SubjectRef>(&bytes).unwrap(), subject);
    }
}

#[test]
fn malformed_or_augmented_references_are_refused() {
    for value in [
        json!({"Contact":{"anchor":LOCAL}}),
        json!({"Contact":{"scope":"work","anchor":"Alice"}}),
        json!({"Contact":{"scope":"work","anchor":"did:plc:invalid"}}),
        json!({"Contact":{"scope":"work","anchor":LOCAL,"birth_date":"2000-01-01"}}),
        json!({"Profile":{"id":"work","birth_time":"noon"}}),
        json!({"Self":{}}),
        json!({"Profile":{"id":"work"},"Contact":{"scope":"work","anchor":LOCAL}}),
    ] {
        assert!(
            serde_json::from_value::<SubjectRef>(value.clone()).is_err(),
            "{value}"
        );
    }
}

#[test]
fn another_person_needs_no_login_and_reload_preserves_the_reference() {
    let local = LocalId::parse(LOCAL).unwrap();
    let contact = Contact::new_local("Someone else", local);
    assert!(contact.root().is_none());
    let subject = contact_ref(contact.anchor().clone());
    let mut book = ContactBook::new(PersonaScope::new("work"));
    book.insert(contact);
    let reloaded: ContactBook =
        serde_json::from_str(&serde_json::to_string(&book).unwrap()).unwrap();
    assert_eq!(
        subject.resolve_contact(&reloaded).unwrap().petname,
        "Someone else"
    );
}

#[test]
fn lookup_refuses_wrong_scope_missing_contact_and_profile_without_mutation() {
    let subject = contact_ref(LOCAL.parse().unwrap());
    let mut wrong = ContactBook::new(PersonaScope::new("personal"));
    wrong.insert(Contact::new_local(
        "Same anchor",
        LocalId::parse(LOCAL).unwrap(),
    ));
    let before = wrong.clone();
    assert_eq!(
        subject.resolve_contact(&wrong),
        Err(SubjectLookupError::Scope(ScopeMismatch {
            expected: PersonaScope::new("work"),
            found: PersonaScope::new("personal"),
        }))
    );
    assert_eq!(wrong, before);
    let empty = ContactBook::new(PersonaScope::new("work"));
    assert_eq!(
        subject.resolve_contact(&empty),
        Err(SubjectLookupError::MissingContact)
    );
    let profile = SubjectRef::Profile {
        id: ProfileId("work".into()),
    };
    assert_eq!(
        profile.resolve_contact(&wrong),
        Err(SubjectLookupError::NotContact)
    );
}

#[test]
fn rename_and_rotation_keep_the_subject_but_deletion_does_not_retarget_it() {
    let original = TypedKey::ed25519([1; 32]);
    let mut contact = Contact::new("Before", original);
    let subject = contact_ref(contact.anchor().clone());
    contact.petname = "After".into();
    contact.rotate_to(TypedKey::ed25519([2; 32]), None).unwrap();
    let mut book = ContactBook::new(PersonaScope::new("work"));
    book.insert(contact);
    assert_eq!(subject.resolve_contact(&book).unwrap().petname, "After");
    book.remove(&Anchor::Key(original));
    book.insert(Contact::new_local("After", LocalId::parse(LOCAL).unwrap()));
    assert_eq!(
        subject.resolve_contact(&book),
        Err(SubjectLookupError::MissingContact)
    );
}
