// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use gaz::{Anchor, LocalId, PersonaScope};
use serde_json::json;

fn facts() -> BirthFacts {
    BirthFacts::new(
        SubjectRef::Contact {
            scope: PersonaScope::new("personal"),
            anchor: Anchor::Local(
                LocalId::parse("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap(),
            ),
        },
        CivilDate::new(2000, 2, 29).unwrap(),
        BirthTime::Unknown,
        None,
        None,
        FactSource::new("Reported by subject".into(), None).unwrap(),
    )
    .unwrap()
}

#[test]
fn unknown_time_fixture_stays_unknown_with_no_derived_instant() {
    let value = facts();
    let fixture = r#"{"schema":"dramatis.birth-facts/v1","subject":{"Contact":{"scope":"personal","anchor":"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}},"date":{"year":2000,"month":2,"day":29},"time":"Unknown","place":null,"timezone":null,"source":{"label":"Reported by subject","reference":null}}"#;
    assert_eq!(serde_json::to_string(&value).unwrap(), fixture);
    let loaded = serde_json::from_str::<BirthFacts>(fixture).unwrap();
    assert_eq!(loaded, value);
    assert_eq!(loaded.time, BirthTime::Unknown);
    assert!(loaded.timezone.is_none());
    assert!(loaded.place.is_none());
}

#[test]
fn known_and_approximate_fixtures_preserve_civil_inputs_and_source_exactly() {
    for (time, fixture) in [
        (
            BirthTime::known(23, 59, 59).unwrap(),
            r#"{"Known":{"hour":23,"minute":59,"second":59}}"#,
        ),
        (
            BirthTime::approximate(0, 0, 0, 86_400).unwrap(),
            r#"{"Approximate":{"hour":0,"minute":0,"second":0,"uncertainty_seconds":86400}}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&time).unwrap(), fixture);
        assert_eq!(serde_json::from_str::<BirthTime>(fixture).unwrap(), time);
        let mut value = facts();
        value.time = time;
        value.place = Some(
            BirthPlace::new(
                " City as entered ".into(),
                Some(40_712_800),
                Some(-74_006_000),
                "city centre, approximate".into(),
            )
            .unwrap(),
        );
        value.timezone = Some("America/New_York".into());
        value.source.reference = Some("family-note:original-2".into());
        value.validate().unwrap();
        assert_eq!(
            serde_json::from_slice::<BirthFacts>(&serde_json::to_vec(&value).unwrap()).unwrap(),
            value
        );
        assert_eq!(
            postcard::from_bytes::<BirthFacts>(&postcard::to_allocvec(&value).unwrap()).unwrap(),
            value
        );
    }
}

#[test]
fn unknown_and_all_clock_variant_binary_tags_remain_distinct() {
    assert_eq!(postcard::to_allocvec(&BirthTime::Unknown).unwrap(), [0]);
    assert_eq!(
        postcard::to_allocvec(&BirthTime::known(1, 2, 3).unwrap()).unwrap(),
        [1, 1, 2, 3]
    );
    assert_eq!(
        postcard::to_allocvec(&BirthTime::approximate(1, 2, 3, 1).unwrap()).unwrap(),
        [2, 1, 2, 3, 1]
    );
    let value = facts();
    assert_eq!(
        postcard::from_bytes::<BirthFacts>(&postcard::to_allocvec(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn gregorian_boundaries_and_century_leap_rules_are_enforced() {
    for (year, month, day) in [
        (1, 1, 1),
        (9999, 12, 31),
        (1600, 2, 29),
        (2000, 2, 29),
        (2024, 2, 29),
    ] {
        CivilDate::new(year, month, day).unwrap();
    }
    for (year, month, day) in [
        (0, 1, 1),
        (-1, 1, 1),
        (10_000, 1, 1),
        (1900, 2, 29),
        (2100, 2, 29),
        (2023, 2, 29),
        (2024, 4, 31),
        (2024, 0, 1),
        (2024, 13, 1),
        (2024, 1, 0),
        (2024, 1, 32),
    ] {
        assert!(
            CivilDate::new(year, month, day).is_err(),
            "{year}-{month}-{day}"
        );
        assert!(
            serde_json::from_value::<CivilDate>(json!({"year":year,"month":month,"day":day}))
                .is_err()
        );
    }
    let count = (1600..2000)
        .flat_map(|year| {
            (1..=12).flat_map(move |month| (1..=31).map(move |day| (year, month, day)))
        })
        .filter(|&(year, month, day)| CivilDate::new(year, month, day).is_ok())
        .count();
    assert_eq!(
        count, 146_097,
        "days in a complete Gregorian 400-year cycle"
    );
}

#[test]
fn clock_and_approximation_limits_refuse_on_load_and_explicit_validation() {
    for (hour, minute, second) in [(24, 0, 0), (0, 60, 0), (0, 0, 60), (255, 255, 255)] {
        assert!(BirthTime::known(hour, minute, second).is_err());
        assert!(BirthTime::approximate(hour, minute, second, 1).is_err());
        assert!(
            serde_json::from_value::<BirthTime>(
                json!({"Known":{"hour":hour,"minute":minute,"second":second}})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<BirthTime>(json!({"Approximate":{"hour":hour,"minute":minute,"second":second,"uncertainty_seconds":1}})).is_err());
    }
    for uncertainty in [0, 86_401, u32::MAX] {
        assert!(BirthTime::approximate(12, 0, 0, uncertainty).is_err());
        assert!(serde_json::from_value::<BirthTime>(json!({"Approximate":{"hour":12,"minute":0,"second":0,"uncertainty_seconds":uncertainty}})).is_err());
    }
    BirthTime::approximate(12, 0, 0, 1).unwrap();
    BirthTime::approximate(12, 0, 0, 86_400).unwrap();
    BirthTime::Unknown.validate().unwrap();
}

#[test]
fn coordinates_require_pairs_and_inclusive_geographic_ranges() {
    for (lat, lon) in [
        (None, None),
        (Some(90_000_000), Some(180_000_000)),
        (Some(-90_000_000), Some(-180_000_000)),
        (Some(0), Some(0)),
    ] {
        BirthPlace::new("Somewhere".into(), lat, lon, "reported".into()).unwrap();
    }
    for (lat, lon) in [
        (Some(0), None),
        (None, Some(0)),
        (Some(90_000_001), Some(0)),
        (Some(-90_000_001), Some(0)),
        (Some(0), Some(180_000_001)),
        (Some(0), Some(-180_000_001)),
        (Some(i32::MIN), Some(i32::MAX)),
    ] {
        assert!(BirthPlace::new("Somewhere".into(), lat, lon, "reported".into()).is_err());
        assert!(serde_json::from_value::<BirthPlace>(json!({"label":"Somewhere","latitude_microdegrees":lat,"longitude_microdegrees":lon,"precision":"reported"})).is_err());
    }
}

#[test]
fn every_provided_label_reference_precision_and_zone_must_be_nonempty() {
    for blank in ["", " \t\n", "\u{2003}"] {
        assert!(FactSource::new(blank.into(), None).is_err());
        assert!(FactSource::new("Reported".into(), Some(blank.into())).is_err());
        assert!(BirthPlace::new(blank.into(), None, None, "city".into()).is_err());
        assert!(BirthPlace::new("Place".into(), None, None, blank.into()).is_err());
        let mut value = facts();
        value.timezone = Some(blank.into());
        assert!(value.validate().is_err());
        assert!(
            serde_json::from_value::<BirthFacts>(serde_json::to_value(value).unwrap()).is_err()
        );
    }
}

#[test]
fn nested_mutation_cannot_bypass_facts_constructor_validator_or_deserializer() {
    for mutate in [
        |f: &mut BirthFacts| f.date.day = 30,
        |f: &mut BirthFacts| {
            f.time = BirthTime::Known {
                hour: 24,
                minute: 0,
                second: 0,
            }
        },
        |f: &mut BirthFacts| f.source.label.clear(),
        |f: &mut BirthFacts| f.source.reference = Some("".into()),
        |f: &mut BirthFacts| {
            f.place = Some(BirthPlace {
                label: "Town".into(),
                latitude_microdegrees: Some(0),
                longitude_microdegrees: None,
                precision: "city".into(),
            })
        },
        |f: &mut BirthFacts| f.schema = "dramatis.birth-facts/v2".into(),
    ] {
        let mut value = facts();
        mutate(&mut value);
        assert!(value.validate().is_err());
        assert!(
            serde_json::from_value::<BirthFacts>(serde_json::to_value(&value).unwrap()).is_err()
        );
        assert!(
            postcard::from_bytes::<BirthFacts>(&postcard::to_allocvec(&value).unwrap()).is_err()
        );
        if value.schema == BIRTH_FACTS_SCHEMA {
            assert!(
                BirthFacts::new(
                    value.subject,
                    value.date,
                    value.time,
                    value.place,
                    value.timezone,
                    value.source
                )
                .is_err()
            );
        }
    }
}

#[test]
fn strict_schema_rejects_missing_subject_derived_fields_and_unknown_nested_fields() {
    for pointer in [
        "/utc",
        "/date/calendar",
        "/source/verified",
        "/source/grant",
    ] {
        let mut value = serde_json::to_value(facts()).unwrap();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        value.pointer_mut(parent).unwrap()[field] = json!("invented");
        assert!(
            serde_json::from_value::<BirthFacts>(value).is_err(),
            "{pointer}"
        );
    }
    for field in ["schema", "subject", "date", "time", "source"] {
        let mut value = serde_json::to_value(facts()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<BirthFacts>(value).is_err(),
            "{field}"
        );
    }
    for time in [
        json!({"Unknown":{"hour":12}}),
        json!({"Known":{"hour":12,"minute":0,"second":0,"utc":"invented"}}),
        json!({"Approximate":{"hour":12,"minute":0,"second":0,"uncertainty_seconds":1,"utc":"invented"}}),
    ] {
        assert!(serde_json::from_value::<BirthTime>(time).is_err());
    }
}

#[test]
fn supplied_zone_is_preserved_without_claiming_resolver_validation() {
    let mut value = facts();
    value.timezone = Some("Unresolved/Original-Identifier".into());
    let loaded: BirthFacts = serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(loaded, value);
    assert_eq!(loaded.time, BirthTime::Unknown);
}

#[test]
fn optional_absence_and_duplicate_fields_do_not_invent_or_override_facts() {
    let mut value = serde_json::to_value(facts()).unwrap();
    for field in ["place", "timezone"] {
        value.as_object_mut().unwrap().remove(field);
    }
    value["source"].as_object_mut().unwrap().remove("reference");
    assert_eq!(
        serde_json::from_value::<BirthFacts>(value).unwrap(),
        facts()
    );
    assert!(
        serde_json::from_str::<CivilDate>(r#"{"year":2000,"month":2,"day":29,"day":28}"#).is_err()
    );
    assert!(
        serde_json::from_str::<BirthTime>(
            r#"{"Known":{"hour":12,"minute":0,"second":0,"hour":13}}"#
        )
        .is_err()
    );
}
