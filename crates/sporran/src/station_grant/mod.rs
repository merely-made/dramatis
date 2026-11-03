// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Narrow, expiring RemoteAuth grants for sited Reticulum stations.
//!
//! Moved from Pandect to Sporran with the custodian (dramatis_repo D14): the station
//! policy is public grant vocabulary, so it lives beside the wallet's public
//! records. Signing the grant needs the wallet seed, which only djinn holds,
//! so [`SitedStationGrant::issue_with`] takes the custodian's signing step as
//! a function and keeps every policy check here.
//!
//! A station grant is a `DeviceGrantSet` holding exactly one device-scoped
//! `SignedDelegationCertificate`. This adapter fixes the station policy over
//! it: one derived station signing key, `transport.egress` only, no persona
//! authority at all, no subdelegation, and a mandatory hard expiry.
//!
//! The reconciliation this module once deferred is settled: the device grant
//! *is* a delegation certificate now, so `no-subdelegation` is read as
//! `remaining_delegation_depth == 0` and enforced by the grammar rather than
//! asserted as a string atom nobody checked.

use std::path::Path;

use personae::carry::{DeviceGrantSet, DeviceId};
use insigne::CheckFault;

use crate::{
    DeviceExposure, DeviceGrantError, DeviceMode, DevicePublicKey, RemoteAuthGrantSpec,
    certificate_device_id, device_grant_set_ref, device_is_fully_revoked, load_device_grant_set,
    load_device_roster,
};

/// The sole capability a sited station can receive.
pub const TRANSPORT_EGRESS_SCOPE: &str = "transport.egress";
/// The compulsory attenuation for a sited station grant.
pub const NO_SUBDELEGATION_ATTENUATION: &str = "no-subdelegation";

/// Inputs for issuing one sited-station RemoteAuth grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SitedStationGrantRequest {
    device_id: DeviceId,
    station_ed25519_public_key: [u8; 32],
    label: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl SitedStationGrantRequest {
    /// Create a request whose expiry is strictly after its issuance time.
    pub fn new(
        device_id: DeviceId,
        station_ed25519_public_key: [u8; 32],
        label: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, SitedStationGrantError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(SitedStationGrantError::EmptyLabel);
        }
        if expires_at_ms <= issued_at_ms {
            return Err(SitedStationGrantError::InvalidExpiryWindow {
                issued_at_ms,
                expires_at_ms,
            });
        }
        Ok(Self {
            device_id,
            station_ed25519_public_key,
            label,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// The station this request commissions.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The station's Ed25519 key the grant will authorize.
    pub fn station_ed25519_public_key(&self) -> [u8; 32] {
        self.station_ed25519_public_key
    }

    /// The label the roster shows.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// When the grant is issued.
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// The grant's mandatory expiry.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The RemoteAuth spec the custodian signs: one device certificate,
    /// `transport.egress` only, no persona, no subdelegation.
    pub fn remote_auth_spec(&self) -> RemoteAuthGrantSpec {
        RemoteAuthGrantSpec {
            device_id: self.device_id,
            delegatee_pubkey: DevicePublicKey(self.station_ed25519_public_key),
            label: self.label.clone(),
            exposure: DeviceExposure::ExposedEgress,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: Some(self.expires_at_ms),
            personas: Vec::new(),
            scopes: vec![TRANSPORT_EGRESS_SCOPE.into()],
            attenuations: vec![NO_SUBDELEGATION_ATTENUATION.into()],
            wrapped_private_epochs: Vec::new(),
        }
    }
}

/// A signed RemoteAuth envelope that passed the sited-station policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SitedStationGrant {
    grant: DeviceGrantSet,
}

impl SitedStationGrant {
    /// Issue and persist a narrow grant through the custodian's wallet.
    ///
    /// `issuer_public_key` must be the Persona public key that derived the
    /// station credential; `wallet_public_key` is the custodian's unlocked
    /// wallet root, so a different Persona cannot commission the station.
    /// `sign` is the custodian's issue step (castellan's
    /// `issue_remote_auth_device_grant`, inside djinn), which persists the
    /// grant and its roster record.
    pub fn issue_with(
        data_root: &Path,
        issuer_public_key: [u8; 32],
        wallet_public_key: [u8; 32],
        request: SitedStationGrantRequest,
        sign: impl FnOnce(&RemoteAuthGrantSpec) -> std::io::Result<DeviceGrantSet>,
    ) -> Result<Self, SitedStationGrantError> {
        if wallet_public_key != issuer_public_key {
            return Err(SitedStationGrantError::IssuerMismatch);
        }

        if let Some(existing) =
            Some(load_device_grant_set(data_root, request.device_id)?).filter(|set| !set.is_empty())
        {
            let existing = Self::from_signed(existing)?;
            if request.expires_at_ms <= existing.expires_at_ms() {
                return Err(SitedStationGrantError::NonExtendingRenewal {
                    device_id: request.device_id,
                    existing_expires_at_ms: existing.expires_at_ms(),
                    requested_expires_at_ms: request.expires_at_ms,
                });
            }
        }

        let grant = sign(&request.remote_auth_spec())?;
        Self::from_signed(grant)
    }

    /// Check a signed envelope's static station policy and signature.
    pub fn from_signed(grant: DeviceGrantSet) -> Result<Self, SitedStationGrantError> {
        let station_grant = Self { grant };
        station_grant.validate_policy()?;
        Ok(station_grant)
    }

    /// Load the active grant for a station, including host-side revocation.
    ///
    /// Expiry is fail-closed: `now_ms == expires_at_ms` is already expired.
    pub fn load_active(
        data_root: &Path,
        device_id: DeviceId,
        station_ed25519_public_key: [u8; 32],
        now_ms: u64,
    ) -> Result<Self, SitedStationGrantError> {
        let grant = Some(load_device_grant_set(data_root, device_id)?)
            .filter(|set| !set.is_empty())
            .ok_or(SitedStationGrantError::MissingGrant { device_id })?;
        let station_grant = Self::from_signed(grant)?;

        // Both records are consulted, because they answer different questions.
        // The roster list is this host's own index of what it revoked. The
        // ledger holds signed statements, which is what a revocation arriving
        // from a peer looks like: honouring only the list would mean a station
        // withdrawn elsewhere kept its authority here.
        if device_is_fully_revoked(data_root, device_id)? {
            return Err(SitedStationGrantError::Revoked { device_id });
        }
        let roster = load_device_roster(data_root)?.ok_or(SitedStationGrantError::MissingRoster)?;
        if roster.revoked.contains(&device_id) {
            return Err(SitedStationGrantError::Revoked { device_id });
        }
        let device = roster
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
            .ok_or(SitedStationGrantError::UnknownDevice { device_id })?;
        if device.mode != DeviceMode::RemoteAuth {
            return Err(SitedStationGrantError::NotRemoteAuth { device_id });
        }
        if device.exposure != DeviceExposure::ExposedEgress {
            return Err(SitedStationGrantError::NotExposedEgress { device_id });
        }
        if device.device_pubkey != DevicePublicKey(station_ed25519_public_key) {
            return Err(SitedStationGrantError::StationKeyMismatch { device_id });
        }
        let expected_ref = device_grant_set_ref(&station_grant.grant);
        if device.grant_ref != Some(expected_ref) {
            return Err(SitedStationGrantError::RosterGrantMismatch { device_id });
        }

        station_grant.authorize_at(device_id, station_ed25519_public_key, now_ms)?;
        Ok(station_grant)
    }

    /// Check that this grant is for the expected station and still live.
    ///
    /// This does not consult host storage. Use [`Self::load_active`] when a
    /// host must also reject revoked or stale roster entries.
    pub fn authorize_at(
        &self,
        device_id: DeviceId,
        station_ed25519_public_key: [u8; 32],
        now_ms: u64,
    ) -> Result<(), SitedStationGrantError> {
        self.validate_policy()?;
        if self.device_id() != device_id {
            return Err(SitedStationGrantError::DeviceMismatch {
                expected: device_id,
                actual: self.device_id(),
            });
        }
        if self.station_ed25519_public_key() != station_ed25519_public_key {
            return Err(SitedStationGrantError::StationKeyMismatch { device_id });
        }
        let expires_at_ms = self.expires_at_ms();
        if now_ms >= expires_at_ms {
            return Err(SitedStationGrantError::Expired {
                device_id,
                expires_at_ms,
                now_ms,
            });
        }
        Ok(())
    }

    /// The single device-scoped certificate a station grant is made of.
    ///
    /// `validate_policy` guarantees it is present, so the accessors below may
    /// rely on it. A station carries device authority and nothing else: no
    /// persona ever delegates to it.
    fn certificate(&self) -> &insigne::delegation::SignedDelegationCertificate {
        self.grant
            .device
            .as_ref()
            .expect("validate_policy requires a device certificate")
    }

    /// Borrow the signed wallet envelope for transport or durable storage.
    pub fn signed(&self) -> &DeviceGrantSet {
        &self.grant
    }

    /// When this grant was issued.
    pub fn issued_at_ms(&self) -> u64 {
        self.certificate().certificate.issued_at_ms
    }

    /// The mandatory fail-closed expiry of this grant.
    pub fn expires_at_ms(&self) -> u64 {
        self.certificate()
            .certificate
            .expires_at_ms
            .expect("validate_policy requires a station-grant expiry")
    }

    /// The RemoteAuth device this grant is bound to.
    pub fn device_id(&self) -> DeviceId {
        certificate_device_id(self.certificate())
            .expect("validate_policy requires a device-scoped certificate")
    }

    /// The Reticulum Ed25519 station key this grant authorizes.
    pub fn station_ed25519_public_key(&self) -> [u8; 32] {
        self.certificate().certificate.subject
    }

    /// The Persona root that signed this grant.
    pub fn issuer_public_key(&self) -> [u8; 32] {
        self.certificate().certificate.issuer
    }

    fn validate_policy(&self) -> Result<(), SitedStationGrantError> {
        let Some(certificate) = self.grant.device.as_ref() else {
            return Err(SitedStationGrantError::ScopeViolation);
        };
        certificate
            .check()
            .map_err(SitedStationGrantError::InvalidSignature)?;
        // A station holds device authority and nothing else. A persona
        // certificate in the set would mean some persona had delegated to an
        // unattended radio, which is exactly what this port refuses.
        if !self.grant.personas.is_empty() {
            return Err(SitedStationGrantError::PersonaAuthority);
        }
        if certificate_device_id(certificate).is_none() {
            return Err(SitedStationGrantError::ScopeViolation);
        }
        let scope = &certificate.certificate.scope;
        if scope.actions.len() != 1 || !scope.actions.contains(TRANSPORT_EGRESS_SCOPE) {
            return Err(SitedStationGrantError::ScopeViolation);
        }
        // `no-subdelegation` used to be a string atom nobody enforced. The
        // grammar enforces it now, so this reads the depth instead.
        if certificate.certificate.remaining_delegation_depth != 0 {
            return Err(SitedStationGrantError::AttenuationViolation);
        }
        let expires_at_ms = certificate
            .certificate
            .expires_at_ms
            .ok_or(SitedStationGrantError::MissingExpiry)?;
        if expires_at_ms <= certificate.certificate.issued_at_ms {
            return Err(SitedStationGrantError::InvalidExpiryWindow {
                issued_at_ms: certificate.certificate.issued_at_ms,
                expires_at_ms,
            });
        }
        Ok(())
    }
}

mod error;
pub use error::SitedStationGrantError;

#[cfg(test)]
mod tests;
