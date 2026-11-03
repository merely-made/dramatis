// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use personae::carry::{ACTION_TRANSPORT_EGRESS, KeyEpochId};
use personae::carry::{DevicePublicKey, issue_persona_device_grant};

use super::*;

const MASTER_SEED: [u8; 32] = [0x6d; 32];
const NOW_MS: u64 = 1_770_000_000_000;

fn persona() -> PersonaId {
    PersonaId::from_uuid(uuid::Uuid::from_u128(0x9001))
}

fn device() -> DeviceId {
    DeviceId::from_uuid(uuid::Uuid::from_u128(0x9002))
}

fn grant(actions: &[&str]) -> SignedDelegationCertificate {
    issue_persona_device_grant(
        MASTER_SEED,
        persona(),
        device(),
        DevicePublicKey([0x7a; 32]),
        actions,
        60_000,
        NOW_MS,
    )
    .expect("issuing a persona device grant")
}

const WRAPPING_KEY: [u8; 32] = [0x3c; 32];

fn test_epoch() -> KeyEpochId {
    KeyEpochId(uuid::Uuid::from_u128(0x9003))
}

fn material() -> WrappedEpochMaterial {
    WrappedEpochMaterial {
        index: blinded_epoch_index(persona(), test_epoch(), WRAPPING_KEY),
        wrap_format: "test/v1".into(),
        wrapped_key: vec![1, 2, 3],
    }
}

#[test]
fn a_certificate_round_trips_through_storage() {
    let root = tempfile::tempdir().unwrap();
    let certificate = grant(&[ACTION_TRANSPORT_EGRESS]);
    save_device_certificate(root.path(), device(), persona(), &certificate).unwrap();

    let back = load_device_certificate(root.path(), device(), persona())
        .unwrap()
        .expect("the certificate should be stored");
    assert_eq!(back, certificate);
    back.check().expect("the stored certificate checks");
}

#[test]
fn an_absent_certificate_reads_as_none() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        load_device_certificate(root.path(), device(), persona())
            .unwrap()
            .is_none()
    );
}

/// The reason the split exists. Under the old envelope this operation
/// re-signed the capability and produced a new content ref for a
/// statement that had not changed.
#[test]
fn appending_an_epoch_leaves_the_certificate_untouched() {
    let root = tempfile::tempdir().unwrap();
    let certificate = grant(&[ACTION_PRIVATE_READ]);
    let id = certificate.certificate.id();
    let cert_ref = save_device_certificate(root.path(), device(), persona(), &certificate).unwrap();

    let mut record = WrappedEpochRecord::new(id);
    record.epochs.push(material());
    save_wrapped_epoch_record(root.path(), &record).unwrap();

    let after = load_device_certificate(root.path(), device(), persona())
        .unwrap()
        .unwrap();
    assert_eq!(after.certificate.id(), id);
    assert_eq!(
        CarryRef::of(encode_certificate(&after).unwrap().as_slice()),
        cert_ref
    );
}

#[test]
fn a_private_read_grant_without_epoch_material_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let certificate = grant(&[ACTION_PRIVATE_READ]);

    let error = check_epoch_carriage(
        root.path(),
        &certificate,
        persona(),
        test_epoch(),
        WRAPPING_KEY,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains(ACTION_PRIVATE_READ));
}

#[test]
fn a_private_read_grant_with_matching_material_passes() {
    let root = tempfile::tempdir().unwrap();
    let certificate = grant(&[ACTION_PRIVATE_READ]);
    let mut record = WrappedEpochRecord::new(certificate.certificate.id());
    record.epochs.push(material());
    save_wrapped_epoch_record(root.path(), &record).unwrap();

    check_epoch_carriage(
        root.path(),
        &certificate,
        persona(),
        test_epoch(),
        WRAPPING_KEY,
    )
    .unwrap();
}

/// A grant that never promised private reading owes no carriage, so the
/// invariant must not fire on it.
#[test]
fn a_transport_only_grant_needs_no_epoch_material() {
    let root = tempfile::tempdir().unwrap();
    let certificate = grant(&[ACTION_TRANSPORT_EGRESS]);

    assert!(!requires_epoch_material(&certificate));
    check_epoch_carriage(
        root.path(),
        &certificate,
        persona(),
        test_epoch(),
        WRAPPING_KEY,
    )
    .unwrap();
}

fn issue_set(actions: &[&str], personas: &[PersonaId]) -> DeviceGrantSet {
    personae::carry::issue_device_grant_set(
        MASTER_SEED,
        device(),
        DevicePublicKey([0x7a; 32]),
        actions,
        personas,
        60_000,
        NOW_MS,
    )
    .expect("issuing the grant set")
}

/// The station shape end to end: one file on disk, and reading it back
/// without being told which personas to look for still recovers the set.
#[test]
fn a_station_set_round_trips_through_storage() {
    let root = tempfile::tempdir().unwrap();
    let set = issue_set(&[ACTION_TRANSPORT_EGRESS], &[]);
    save_device_grant_set(root.path(), device(), &set).unwrap();

    let back = load_device_grant_set(root.path(), device()).unwrap();
    assert_eq!(back, set);
    assert!(back.device.is_some());
    assert!(back.personas.is_empty());
}

#[test]
fn a_mixed_set_round_trips_with_every_member() {
    let root = tempfile::tempdir().unwrap();
    let other = PersonaId::from_uuid(uuid::Uuid::from_u128(0x9004));
    let set = issue_set(
        &[
            ACTION_TRANSPORT_EGRESS,
            personae::carry::ACTION_IDENTITY_ACT,
        ],
        &[persona(), other],
    );
    save_device_grant_set(root.path(), device(), &set).unwrap();

    let back = load_device_grant_set(root.path(), device()).unwrap();
    assert_eq!(back, set);
    assert_eq!(back.personas.len(), 2);
    for certificate in back.certificates() {
        certificate
            .check()
            .expect("every stored certificate checks");
    }
}

#[test]
fn an_unknown_device_loads_as_an_empty_set() {
    let root = tempfile::tempdir().unwrap();
    let set = load_device_grant_set(root.path(), device()).unwrap();

    assert!(set.is_empty());
}

/// The roster keeps one ref per device, so that ref has to move whenever
/// any member of the set does.
#[test]
fn the_set_ref_tracks_every_member() {
    let station = issue_set(&[ACTION_TRANSPORT_EGRESS], &[]);
    let with_persona = issue_set(
        &[
            ACTION_TRANSPORT_EGRESS,
            personae::carry::ACTION_IDENTITY_ACT,
        ],
        &[persona()],
    );

    assert_ne!(
        device_grant_set_ref(&station),
        device_grant_set_ref(&with_persona)
    );
    assert_eq!(
        device_grant_set_ref(&station),
        device_grant_set_ref(&station.clone())
    );
}
