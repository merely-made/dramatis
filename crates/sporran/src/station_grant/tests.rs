// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0


use personae::{IdentityProvider, InMemoryProvider};

use super::*;

#[test]
fn a_signed_grant_with_extra_authority_is_not_a_sited_station_grant() {
    let seed = [0x51; 32];
    let issuer = InMemoryProvider::from_seed(seed);
    let station = issuer.derive_keypair(b"sited-station-grant-test").unwrap();
    let device_id = DeviceId::new();
    // A grant carrying identity.act as well: the extra action lands on a
    // persona certificate, so the set has persona authority in it and the
    // station policy must refuse it.
    let signed = personae::carry::issue_device_grant_set(
        seed,
        device_id,
        DevicePublicKey::from(station.public_key()),
        &[TRANSPORT_EGRESS_SCOPE, "identity.act"],
        &[personae::PersonaId::new()],
        100,
        100,
    )
    .unwrap();
    let error = SitedStationGrant::from_signed(signed).unwrap_err();

    assert!(matches!(error, SitedStationGrantError::PersonaAuthority));
}

/// The custodian's signing step, as djinn performs it, over a fixed seed.
fn sign_with(
    root: &Path,
    seed: [u8; 32],
) -> impl FnOnce(&RemoteAuthGrantSpec) -> std::io::Result<DeviceGrantSet> + '_ {
    move |spec| {
        let actions: Vec<&str> = spec.scopes.iter().map(String::as_str).collect();
        let set = personae::carry::issue_device_grant_set(
            seed,
            spec.device_id,
            spec.delegatee_pubkey,
            &actions,
            &spec.personas,
            spec.expires_at_ms.unwrap() - spec.issued_at_ms,
            spec.issued_at_ms,
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        crate::save_device_grant_set(root, spec.device_id, &set)?;
        Ok(set)
    }
}

#[test]
fn a_station_grant_can_only_be_renewed_with_a_later_expiry() {
    let root = tempfile::tempdir().unwrap();
    let seed = [0x52; 32];
    let issuer = InMemoryProvider::from_seed(seed);
    let master = issuer.master_public_key().to_bytes();
    let device_id = DeviceId::new();
    let key = issuer
        .derive_keypair(b"sited-station-renewal-test")
        .unwrap();
    let first = SitedStationGrantRequest::new(
        device_id,
        key.public_key().to_bytes(),
        "Ridge north",
        100,
        200,
    )
    .unwrap();
    SitedStationGrant::issue_with(
        root.path(),
        master,
        master,
        first,
        sign_with(root.path(), seed),
    )
    .unwrap();

    let replacement = SitedStationGrantRequest::new(
        device_id,
        key.public_key().to_bytes(),
        "Ridge north",
        150,
        200,
    )
    .unwrap();
    let error = SitedStationGrant::issue_with(
        root.path(),
        master,
        master,
        replacement,
        sign_with(root.path(), seed),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        SitedStationGrantError::NonExtendingRenewal {
            existing_expires_at_ms: 200,
            requested_expires_at_ms: 200,
            ..
        }
    ));
}

#[test]
fn another_personas_wallet_cannot_commission_the_station() {
    let root = tempfile::tempdir().unwrap();
    let request =
        SitedStationGrantRequest::new(DeviceId::new(), [7; 32], "Ridge north", 100, 200)
            .unwrap();
    let error = SitedStationGrant::issue_with(
        root.path(),
        [1; 32],
        [2; 32],
        request,
        sign_with(root.path(), [0x53; 32]),
    )
    .unwrap_err();
    assert!(matches!(error, SitedStationGrantError::IssuerMismatch));
}
