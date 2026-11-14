// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Importing Valve's Steam Guard mobile authenticator secrets.
//!
//! Valve does not publish this as an OTP standard. A Steam authenticator file
//! carries a 20-byte base64 `shared_secret`; castellan seals it as an item
//! with the Steam Guard code style. Codes are TOTP only (custody plan D7), so
//! a stored Steam item is kept, listed and reviewed but generates no code.

use std::fmt;

use base64::Engine as _;
use zeroize::Zeroizing;

const SHARED_SECRET_BYTES: usize = 20;

/// Failure while importing Steam Guard compatibility material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SteamGuardError {
    /// The `shared_secret` was not standard base64.
    InvalidBase64,
    /// Steam Guard shared secrets are exactly 20 bytes after decoding.
    InvalidSecretLength {
        /// Number of decoded bytes supplied.
        bytes: usize,
    },
    /// The account label was empty, padded, too long, or contained controls.
    InvalidAccount,
}

impl fmt::Display for SteamGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBase64 => formatter.write_str("Steam shared_secret is not valid base64"),
            Self::InvalidSecretLength { bytes } => write!(
                formatter,
                "Steam shared_secret decoded to {bytes} bytes; expected {SHARED_SECRET_BYTES}"
            ),
            Self::InvalidAccount => formatter
                .write_str("Steam account must be trimmed printable text of at most 256 bytes"),
        }
    }
}

impl std::error::Error for SteamGuardError {}

pub(super) fn decode_shared_secret(
    shared_secret: &str,
) -> Result<Zeroizing<[u8; SHARED_SECRET_BYTES]>, SteamGuardError> {
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(shared_secret)
            .map_err(|_| SteamGuardError::InvalidBase64)?,
    );
    let bytes = decoded.len();
    let secret = decoded
        .as_slice()
        .try_into()
        .map_err(|_| SteamGuardError::InvalidSecretLength { bytes })?;
    Ok(Zeroizing::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_steam_secret_shapes() {
        assert_eq!(
            decode_shared_secret("not base64").unwrap_err(),
            SteamGuardError::InvalidBase64
        );
        assert!(matches!(
            decode_shared_secret("AQID").unwrap_err(),
            SteamGuardError::InvalidSecretLength { bytes: 3 }
        ));
        assert_eq!(
            decode_shared_secret("zvIayp3JPvtvX/QGHqsqKBk/44s=")
                .unwrap()
                .len(),
            SHARED_SECRET_BYTES
        );
    }
}
