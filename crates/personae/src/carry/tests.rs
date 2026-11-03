// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[test]
fn remote_auth_revocation_preserves_pandect_json_shape() {
    let device = DeviceId::from_uuid(Uuid::from_u128(0x2026_0812_0002));
    let persona = PersonaId::from_uuid(Uuid::from_u128(1));
    let set = issue_device_grant_set(
        [0x4d; 32],
        device,
        DevicePublicKey([0x5a; 32]),
        &[ACTION_TRANSPORT_EGRESS],
        &[],
        60_000,
        1_770_000_000_000,
    )
    .unwrap();
    let statements = revoke_device_grant_set([0x4d; 32], &set, 1_770_000_000_001).unwrap();
    assert_eq!(statements.len(), 1);
    statements[0].check().unwrap();
    let outcome = RemoteAuthRevocationOutcome {
        device_id: device,
        already_revoked: false,
        rotated_personas: vec![persona],
        refreshed_devices: vec![device],
        statements: statements.clone(),
    };
    // This is the old Pandect JSON envelope, including the complete signed statement.
    let fixture = serde_json::json!({
        "device_id": "00000000-0000-0000-0000-202608120002",
        "already_revoked": false,
        "rotated_personas": ["00000000-0000-0000-0000-000000000001"],
        "refreshed_devices": ["00000000-0000-0000-0000-202608120002"],
        "statements": statements,
    });
    assert_eq!(serde_json::to_value(&outcome).unwrap(), fixture);
    let decoded: RemoteAuthRevocationOutcome = serde_json::from_value(fixture).unwrap();
    assert_eq!(decoded, outcome);
    decoded.statements[0].check().unwrap();
}

// BLAKE3-256 of the empty input, from the BLAKE3 reference test vectors.
const EMPTY_BLAKE3: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

#[test]
fn carry_ref_display_is_fn_colon_hex() {
    let r = CarryRef::of(b"");
    assert_eq!(r.to_string(), format!("blake3:{EMPTY_BLAKE3}"));
}

#[test]
fn carry_ref_serializes_as_its_display_string() {
    let r = CarryRef::of(b"carry");
    let json = serde_json::to_string(&r).unwrap();
    assert_eq!(json, format!("\"{r}\""));
    let back: CarryRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn carry_ref_parses_its_own_display_form() {
    let r = CarryRef::of(b"round-trip");
    assert_eq!(r.to_string().parse::<CarryRef>().unwrap(), r);
}

#[test]
fn carry_ref_rejects_malformed_strings() {
    assert!("no-colon".parse::<CarryRef>().is_err());
    assert!("sha256:00".parse::<CarryRef>().is_err());
    assert!(
        format!("blake3:{}", "0".repeat(63))
            .parse::<CarryRef>()
            .is_err()
    );
    assert!("blake3:zz".parse::<CarryRef>().is_err());
}

#[test]
fn manifest_defaults_carry_the_schema_version() {
    let m = IdentityWalletManifest::default();
    assert_eq!(m.schema_version, WALLET_SCHEMA_VERSION);
    assert!(m.device_roster_ref.is_none());
}

#[test]
fn manifest_json_round_trips_with_refs() {
    let mut m = IdentityWalletManifest::default();
    m.device_roster_ref = Some(CarryRef::of(b"roster"));
    m.grant_index.push(DeviceGrantRef {
        device_id: DeviceId::new(),
        grant_ref: Some(CarryRef::of(b"grant")),
    });
    let json = serde_json::to_string(&m).unwrap();
    let back: IdentityWalletManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn device_public_key_round_trips_through_identity_type() {
    let keypair = Ed25519Keypair::from_seed([7u8; 32]);
    let stored = DevicePublicKey::from(keypair.public_key());
    assert_eq!(stored.to_public_key().unwrap(), keypair.public_key());
}
