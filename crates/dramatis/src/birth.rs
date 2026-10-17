// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Reusable asserted birth facts, independent of credentials and calculations.
//!
//! Gregorian civil inputs are preserved as supplied. Unknown time has no clock
//! value. UTC, timezone resolution and chart results belong to separate derived
//! resources. The resident personal-facts domain owns revisions and admission;
//! these plain values confer no access and perform no storage or disclosure.

use serde::{Deserialize, Serialize};

use crate::subject::SubjectRef;
pub use crate::validation::ValidationError;
use crate::validation::{nonempty, require, validated_deserialize};

/// Supported original-facts schema; not a calculation schema.
pub const BIRTH_FACTS_SCHEMA: &str = "dramatis.birth-facts/v1";
/// Largest supported uncertainty radius for an approximate civil time.
pub const MAX_BIRTH_TIME_UNCERTAINTY_SECONDS: u32 = 86_400;

/// Original date, interpreted in the proleptic Gregorian calendar.
/// Other calendars require explicit upstream conversion with separate evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CivilDate {
    /// Gregorian year, 1 through 9999 (no year zero).
    pub year: i32,
    /// Month, 1 through 12.
    pub month: u8,
    /// Day, validated against month and leap year.
    pub day: u8,
}

validated_deserialize!(CivilDate {
    year: i32,
    month: u8,
    day: u8
});

impl CivilDate {
    /// Construct a valid civil date without timezone interpretation.
    pub fn new(year: i32, month: u8, day: u8) -> Result<Self, ValidationError> {
        let value = Self { year, month, day };
        value.validate()?;
        Ok(value)
    }

    /// Validate Gregorian range and leap-day rules after any mutation.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require(
            (1..=9999).contains(&self.year),
            "date.year",
            "must be in 1..=9999",
        )?;
        let leap = self.year % 4 == 0 && (self.year % 100 != 0 || self.year % 400 == 0);
        let days = match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => {
                return Err(ValidationError {
                    field: "date.month",
                    reason: "must be in 1..=12",
                });
            },
        };
        require(
            (1..=days).contains(&self.day),
            "date.day",
            "invalid day for Gregorian month/year",
        )
    }
}

/// Original local civil time assertion, not a resolved instant.
/// Serde uses external tags; binary variant order is Unknown, Known, Approximate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BirthTimeWire")]
pub enum BirthTime {
    /// No time was supplied. Never default this to noon or midnight.
    Unknown,
    /// Reported clock time; even exact civil time may resolve ambiguously.
    Known { hour: u8, minute: u8, second: u8 },
    /// Estimate with a positive uncertainty radius in seconds on either side.
    /// This is not a UTC interval; local date boundaries may be crossed.
    Approximate {
        hour: u8,
        minute: u8,
        second: u8,
        uncertainty_seconds: u32,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum BirthTimeWire {
    Unknown,
    Known {
        hour: u8,
        minute: u8,
        second: u8,
    },
    Approximate {
        hour: u8,
        minute: u8,
        second: u8,
        uncertainty_seconds: u32,
    },
}

impl TryFrom<BirthTimeWire> for BirthTime {
    type Error = ValidationError;

    fn try_from(wire: BirthTimeWire) -> Result<Self, Self::Error> {
        let value = match wire {
            BirthTimeWire::Unknown => Self::Unknown,
            BirthTimeWire::Known {
                hour,
                minute,
                second,
            } => Self::Known {
                hour,
                minute,
                second,
            },
            BirthTimeWire::Approximate {
                hour,
                minute,
                second,
                uncertainty_seconds,
            } => Self::Approximate {
                hour,
                minute,
                second,
                uncertainty_seconds,
            },
        };
        value.validate()?;
        Ok(value)
    }
}

impl BirthTime {
    /// Construct a known local clock time.
    pub fn known(hour: u8, minute: u8, second: u8) -> Result<Self, ValidationError> {
        let value = Self::Known {
            hour,
            minute,
            second,
        };
        value.validate()?;
        Ok(value)
    }

    /// Construct an approximate local time with a bounded uncertainty radius.
    pub fn approximate(
        hour: u8,
        minute: u8,
        second: u8,
        uncertainty_seconds: u32,
    ) -> Result<Self, ValidationError> {
        let value = Self::Approximate {
            hour,
            minute,
            second,
            uncertainty_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    /// Check the supplied clock without inventing or resolving an instant.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let (hour, minute, second) = match *self {
            Self::Unknown => return Ok(()),
            Self::Known {
                hour,
                minute,
                second,
            } => (hour, minute, second),
            Self::Approximate {
                hour,
                minute,
                second,
                uncertainty_seconds,
            } => {
                require(
                    (1..=MAX_BIRTH_TIME_UNCERTAINTY_SECONDS).contains(&uncertainty_seconds),
                    "time.uncertainty_seconds",
                    "must be in 1..=86400",
                )?;
                (hour, minute, second)
            },
        };
        require(hour <= 23, "time.hour", "must be in 0..=23")?;
        require(minute <= 59, "time.minute", "must be in 0..=59")?;
        require(
            second <= 59,
            "time.second",
            "must be in 0..=59; leap seconds are not civil inputs here",
        )
    }
}

/// Place as supplied, with optional coordinates and explicit stated precision.
/// The label is not a geocoding or verified identity claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BirthPlace {
    /// Original supplied place label, without normalization.
    pub label: String,
    /// Optional signed latitude in millionths of a degree.
    pub latitude_microdegrees: Option<i32>,
    /// Optional signed longitude, required if latitude is supplied.
    pub longitude_microdegrees: Option<i32>,
    /// E.g. city, hospital, or a stated uncertainty; preserved verbatim.
    pub precision: String,
}

validated_deserialize!(BirthPlace {
    label: String, latitude_microdegrees: Option<i32>,
    longitude_microdegrees: Option<i32>, precision: String,
});

impl BirthPlace {
    /// Construct a place; coordinates must be supplied together or both absent.
    pub fn new(
        label: String,
        latitude_microdegrees: Option<i32>,
        longitude_microdegrees: Option<i32>,
        precision: String,
    ) -> Result<Self, ValidationError> {
        let value = Self {
            label,
            latitude_microdegrees,
            longitude_microdegrees,
            precision,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate text and inclusive coordinate bounds without geocoding.
    pub fn validate(&self) -> Result<(), ValidationError> {
        nonempty(&self.label, "place.label")?;
        nonempty(&self.precision, "place.precision")?;
        require(
            self.latitude_microdegrees.is_some() == self.longitude_microdegrees.is_some(),
            "place.coordinates",
            "latitude and longitude must be supplied together",
        )?;
        if let Some(latitude) = self.latitude_microdegrees {
            require(
                (-90_000_000..=90_000_000).contains(&latitude),
                "place.latitude_microdegrees",
                "must be in -90000000..=90000000",
            )?;
        }
        if let Some(longitude) = self.longitude_microdegrees {
            require(
                (-180_000_000..=180_000_000).contains(&longitude),
                "place.longitude_microdegrees",
                "must be in -180000000..=180000000",
            )?;
        }
        Ok(())
    }
}

/// Attribution of the asserted facts, not a proof of their truth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FactSource {
    /// Supplied attribution, not an authenticity conclusion.
    pub label: String,
    /// Optional source locator, interpreted by the receiving data owner.
    pub reference: Option<String>,
}

validated_deserialize!(FactSource { label: String, reference: Option<String> });

impl FactSource {
    /// Construct nonempty source attribution with an optional source locator.
    pub fn new(label: String, reference: Option<String>) -> Result<Self, ValidationError> {
        let value = Self { label, reference };
        value.validate()?;
        Ok(value)
    }

    /// Validate the label and any provided locator after mutation.
    pub fn validate(&self) -> Result<(), ValidationError> {
        nonempty(&self.label, "source.label")?;
        if let Some(reference) = &self.reference {
            nonempty(reference, "source.reference")?;
        }
        Ok(())
    }
}

/// Versioned original facts for an explicit subject, independent of the actor.
/// Mutable callers must revalidate before use/serialization/admission. Durable
/// revision identity lives in the resident's resource envelope, not this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BirthFacts {
    /// Exact supported original-facts schema identifier.
    pub schema: String,
    /// Who these facts concern, independently of the actor recording them.
    pub subject: SubjectRef,
    /// Original Gregorian civil date, not a UTC date.
    pub date: CivilDate,
    /// Original reported civil time or explicit absence/uncertainty.
    pub time: BirthTime,
    /// Optional original place assertion with stated precision.
    pub place: Option<BirthPlace>,
    /// Supplied IANA identifier text, preserved verbatim. Only nonemptiness is
    /// checked here; the receiving resolver validates names and historical rules.
    pub timezone: Option<String>,
    /// Attribution of this assertion; not a permission grant.
    pub source: FactSource,
}

validated_deserialize!(BirthFacts {
    schema: String, subject: SubjectRef, date: CivilDate, time: BirthTime,
    place: Option<BirthPlace>, timezone: Option<String>, source: FactSource,
});

impl BirthFacts {
    /// Construct supported, validated facts without any UTC/timezone conversion.
    pub fn new(
        subject: SubjectRef,
        date: CivilDate,
        time: BirthTime,
        place: Option<BirthPlace>,
        timezone: Option<String>,
        source: FactSource,
    ) -> Result<Self, ValidationError> {
        let value = Self {
            schema: BIRTH_FACTS_SCHEMA.into(),
            subject,
            date,
            time,
            place,
            timezone,
            source,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate the schema and every nested fact; no subject access or source
    /// authenticity check is implied. SubjectRef's existing semantics remain.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require(
            self.schema == BIRTH_FACTS_SCHEMA,
            "birth.schema",
            "unsupported schema",
        )?;
        self.date.validate()?;
        self.time.validate()?;
        if let Some(place) = &self.place {
            place.validate()?;
        }
        if let Some(timezone) = &self.timezone {
            nonempty(timezone, "timezone")?;
        }
        self.source.validate()
    }
}

#[cfg(test)]
#[path = "birth_tests.rs"]
mod tests;
