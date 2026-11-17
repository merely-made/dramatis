// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Certificate requirements for signed custody principals.

use super::{Matcher, PolicyError, PrincipalRule};

pub(super) fn validate(rule: &PrincipalRule, require_pin: bool) -> Result<(), PolicyError> {
    if let Matcher::Signed { certificate_sha1, .. } = &rule.matcher {
        if certificate_sha1.as_ref().is_some_and(|pin|
            pin.len() != 40 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit())) {
            return Err(PolicyError(format!("{}: expected a 40-digit signing certificate SHA-1 fingerprint", rule.name)));
        }
        if require_pin && certificate_sha1.is_none() {
            return Err(PolicyError(format!("{}: protected Keychain custody requires an exact signing certificate", rule.name)));
        }
    }
    Ok(())
}
