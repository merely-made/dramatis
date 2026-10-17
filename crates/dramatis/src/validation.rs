// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use core::fmt;

/// A structural contract violation, not an authority or authenticity decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidationError {
    /// The field that failed its structural check.
    pub field: &'static str,
    /// The violated constraint.
    pub reason: &'static str,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl core::error::Error for ValidationError {}

pub(crate) fn require(
    valid: bool,
    field: &'static str,
    reason: &'static str,
) -> Result<(), ValidationError> {
    if valid {
        Ok(())
    } else {
        Err(ValidationError { field, reason })
    }
}

pub(crate) fn nonempty(text: &str, field: &'static str) -> Result<(), ValidationError> {
    require(
        !text.trim().is_empty(),
        field,
        "must contain non-whitespace text",
    )
}

// Each public mutable struct has one validator, used by construction, explicit
// revalidation, and strict deserialization. The wire field order matches the
// public struct's Serialize order for binary codecs as well as JSON.
macro_rules! validated_deserialize {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Wire { $($field: $ty),* }
                let wire = <Wire as serde::Deserialize>::deserialize(deserializer)?;
                let value = Self { $($field: wire.$field),* };
                value.validate().map_err(serde::de::Error::custom)?;
                Ok(value)
            }
        }
    };
}

pub(crate) use validated_deserialize;
