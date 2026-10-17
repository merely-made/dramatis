// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use gaz::{Anchor, LocalId, PersonaScope};
use personae::ProfileId;
use serde_json::json;

fn association() -> SubjectResourceAssociation {
    SubjectResourceAssociation::new(
        SubjectRef::Profile {
            id: ProfileId("personal".into()),
        },
        ResourceRef::new("personal-facts".into(), "birth-1".into(), "r1".into()).unwrap(),
        SubjectResourceRelationship::About,
    )
    .unwrap()
}

#[test]
fn association_has_a_fixed_versioned_json_fixture_and_binary_roundtrip() {
    let value = association();
    let fixture = r#"{"schema":"dramatis.subject-resource-association/v1","subject":{"Profile":{"id":"personal"}},"resource":{"domain":"personal-facts","id":"birth-1","revision":"r1"},"relationship":"About"}"#;
    assert_eq!(serde_json::to_string(&value).unwrap(), fixture);
    assert_eq!(
        serde_json::from_str::<SubjectResourceAssociation>(fixture).unwrap(),
        value
    );
    let bytes = postcard::to_allocvec(&value).unwrap();
    assert_eq!(
        postcard::from_bytes::<SubjectResourceAssociation>(&bytes).unwrap(),
        value
    );
    assert_eq!(
        postcard::to_allocvec(&SubjectResourceRelationship::About).unwrap(),
        [0]
    );
}

#[test]
fn empty_resource_components_refuse_on_construction_load_and_mutation() {
    for field in ["domain", "id", "revision"] {
        for empty in ["", " \n\t"] {
            let mut json = json!({"domain":"d","id":"i","revision":"r"});
            json[field] = json!(empty);
            assert!(serde_json::from_value::<ResourceRef>(json).is_err());
            let mut resource = association().resource;
            match field {
                "domain" => resource.domain = empty.into(),
                "id" => resource.id = empty.into(),
                _ => resource.revision = empty.into(),
            }
            assert!(resource.validate().is_err());
            assert!(
                SubjectResourceAssociation::new(
                    association().subject,
                    resource,
                    SubjectResourceRelationship::About
                )
                .is_err()
            );
        }
    }
    assert!(ResourceRef::new(" ".into(), "i".into(), "r".into()).is_err());
}

#[test]
fn association_refuses_schema_unknown_fields_missing_subject_and_bad_relationship() {
    for (field, bad) in [
        ("schema", json!("dramatis.subject-resource-association/v2")),
        ("schema", json!("")),
        ("relationship", json!("Owns")),
        ("grant", json!(true)),
        ("subject", json!({"Self":{}})),
    ] {
        let mut value = serde_json::to_value(association()).unwrap();
        value[field] = bad;
        assert!(serde_json::from_value::<SubjectResourceAssociation>(value).is_err());
    }
    let mut value = serde_json::to_value(association()).unwrap();
    value.as_object_mut().unwrap().remove("subject");
    assert!(serde_json::from_value::<SubjectResourceAssociation>(value).is_err());
    let mut value = serde_json::to_value(association()).unwrap();
    value["resource"]["latest"] = json!(true);
    assert!(serde_json::from_value::<SubjectResourceAssociation>(value).is_err());
    let mut value = association();
    value.schema = "future".into();
    let bytes = postcard::to_allocvec(&value).unwrap();
    assert!(postcard::from_bytes::<SubjectResourceAssociation>(&bytes).is_err());
}

#[test]
fn many_subjects_can_concern_one_resource_without_a_key_or_name_join() {
    let first = association();
    let mut second = first.clone();
    second.subject = SubjectRef::Contact {
        scope: PersonaScope::new("personal"),
        anchor: Anchor::Local(LocalId::from_random([7; 16])),
    };
    let values = vec![first.clone(), second, first];
    let reloaded: Vec<SubjectResourceAssociation> =
        serde_json::from_slice(&serde_json::to_vec(&values).unwrap()).unwrap();
    assert_eq!(values, reloaded);
    assert_eq!(
        reloaded.len(),
        3,
        "even duplicate associations are preserved"
    );
    assert_eq!(reloaded[0].resource, reloaded[1].resource);
    assert_ne!(reloaded[0].subject, reloaded[1].subject);
}

#[test]
fn opaque_identifiers_are_preserved_without_normalization_or_resolution() {
    let resource = ResourceRef::new(
        " personal-facts ".into(),
        "case/Sensitive".into(),
        "r01".into(),
    )
    .unwrap();
    let loaded: ResourceRef =
        serde_json::from_slice(&serde_json::to_vec(&resource).unwrap()).unwrap();
    assert_eq!(loaded, resource);
    assert_eq!(loaded.domain, " personal-facts ");
}

#[test]
fn about_convenience_sets_schema_and_preserves_nested_validation() {
    let value = association();
    let about = SubjectResourceAssociation::about(value.subject.clone(), value.resource.clone());
    assert_eq!(about, value);
    about.validate().unwrap();
    let mut invalid = value.resource;
    invalid.revision.clear();
    let invalid = SubjectResourceAssociation::about(value.subject, invalid);
    assert_eq!(invalid.schema, SUBJECT_RESOURCE_ASSOCIATION_SCHEMA);
    assert!(invalid.validate().is_err());
}
