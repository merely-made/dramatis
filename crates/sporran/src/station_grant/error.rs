// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0


use std::fmt;
use super::*;

/// Why a sited-station grant could not be issued or used.
#[derive(Debug)]
pub enum SitedStationGrantError {
    /// The host wallet store could not be read or written.
    Storage(std::io::Error),
    /// The signed envelope could not be decoded, signed, or content-addressed.
    Envelope(DeviceGrantError),
    /// The commissioning label was blank.
    EmptyLabel,
    /// The expiry did not fall strictly after the issuance time.
    InvalidExpiryWindow {
        /// The grant's issuance time.
        issued_at_ms: u64,
        /// The grant's requested expiry time.
        expires_at_ms: u64,
    },
    /// The host wallet has no unlocked root to issue a grant with.
    WalletLocked,
    /// The credential's Persona did not match the host wallet root.
    IssuerMismatch,
    /// A replacement grant did not extend the existing live window.
    NonExtendingRenewal {
        /// The station whose grant was being replaced.
        device_id: DeviceId,
        /// The existing grant's expiry time.
        existing_expires_at_ms: u64,
        /// The requested replacement expiry time.
        requested_expires_at_ms: u64,
    },
    /// The host store has no signed grant for this device.
    MissingGrant {
        /// The requested device.
        device_id: DeviceId,
    },
    /// The host store has no device roster.
    MissingRoster,
    /// The requested device is absent from the host roster.
    UnknownDevice {
        /// The requested device.
        device_id: DeviceId,
    },
    /// The host has revoked this device.
    Revoked {
        /// The revoked device.
        device_id: DeviceId,
    },
    /// The roster records a different device mode.
    NotRemoteAuth {
        /// The incorrectly configured device.
        device_id: DeviceId,
    },
    /// The roster does not allow the device to act as egress.
    NotExposedEgress {
        /// The incorrectly configured device.
        device_id: DeviceId,
    },
    /// The signed envelope names a different device than expected.
    DeviceMismatch {
        /// The device the caller expected.
        expected: DeviceId,
        /// The device named by the envelope.
        actual: DeviceId,
    },
    /// The envelope or roster names a different station signing key.
    StationKeyMismatch {
        /// The affected device.
        device_id: DeviceId,
    },
    /// The roster does not point at the currently stored signed envelope.
    RosterGrantMismatch {
        /// The affected device.
        device_id: DeviceId,
    },
    /// The signed envelope did not check; the fault says which step failed.
    InvalidSignature(CheckFault),
    /// The envelope grants any Persona authority.
    PersonaAuthority,
    /// The envelope carries private-lane epoch material.
    PrivateEpochMaterial,
    /// The envelope grants anything other than `transport.egress`.
    ScopeViolation,
    /// The envelope permits any attenuation other than `no-subdelegation`.
    AttenuationViolation,
    /// The envelope has no expiry.
    MissingExpiry,
    /// The envelope's expiry has passed or arrived.
    Expired {
        /// The expired device.
        device_id: DeviceId,
        /// The strict expiry instant.
        expires_at_ms: u64,
        /// The instant used for evaluation.
        now_ms: u64,
    },
}

impl From<std::io::Error> for SitedStationGrantError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<DeviceGrantError> for SitedStationGrantError {
    fn from(error: DeviceGrantError) -> Self {
        Self::Envelope(error)
    }
}

impl fmt::Display for SitedStationGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "sited station wallet storage failed: {error}"),
            Self::Envelope(error) => write!(f, "sited station grant envelope failed: {error}"),
            Self::EmptyLabel => f.write_str("a sited station label must not be blank"),
            Self::InvalidExpiryWindow {
                issued_at_ms,
                expires_at_ms,
            } => write!(
                f,
                "sited station expiry {expires_at_ms} must be after issuance {issued_at_ms}"
            ),
            Self::WalletLocked => f.write_str("the host wallet root is locked or absent"),
            Self::IssuerMismatch => f.write_str(
                "the station credential was derived by a different Persona than the host wallet",
            ),
            Self::NonExtendingRenewal {
                device_id,
                existing_expires_at_ms,
                requested_expires_at_ms,
            } => write!(
                f,
                "replacement grant for sited station {} expires at {requested_expires_at_ms}, which does not extend existing expiry {existing_expires_at_ms}",
                device_id.as_uuid()
            ),
            Self::MissingGrant { device_id } => {
                write!(f, "sited station grant missing for {}", device_id.as_uuid())
            },
            Self::MissingRoster => f.write_str("the host device roster is missing"),
            Self::UnknownDevice { device_id } => {
                write!(
                    f,
                    "sited station device {} is absent from the host roster",
                    device_id.as_uuid()
                )
            },
            Self::Revoked { device_id } => {
                write!(f, "sited station device {} is revoked", device_id.as_uuid())
            },
            Self::NotRemoteAuth { device_id } => write!(
                f,
                "sited station device {} is not a RemoteAuth device",
                device_id.as_uuid()
            ),
            Self::NotExposedEgress { device_id } => write!(
                f,
                "sited station device {} is not an exposed egress",
                device_id.as_uuid()
            ),
            Self::DeviceMismatch { expected, actual } => write!(
                f,
                "sited station grant targets {}, not expected device {}",
                actual.as_uuid(),
                expected.as_uuid()
            ),
            Self::StationKeyMismatch { device_id } => write!(
                f,
                "sited station signing key does not match device {}",
                device_id.as_uuid()
            ),
            Self::RosterGrantMismatch { device_id } => write!(
                f,
                "sited station roster reference does not match device {} grant",
                device_id.as_uuid()
            ),
            Self::InvalidSignature(fault) => {
                write!(f, "sited station grant signature is invalid: {fault}")
            },
            Self::PersonaAuthority => {
                f.write_str("sited station grants must not authorize any persona")
            },
            Self::PrivateEpochMaterial => {
                f.write_str("sited station grants must not carry private epoch material")
            },
            Self::ScopeViolation => {
                f.write_str("sited station grants must contain only the transport.egress scope")
            },
            Self::AttenuationViolation => f.write_str(
                "sited station grants must contain only the no-subdelegation attenuation",
            ),
            Self::MissingExpiry => f.write_str("sited station grants require an expiry"),
            Self::Expired {
                device_id,
                expires_at_ms,
                now_ms,
            } => write!(
                f,
                "sited station device {} expired at {expires_at_ms}; evaluated at {now_ms}",
                device_id.as_uuid()
            ),
        }
    }
}

impl std::error::Error for SitedStationGrantError {}

