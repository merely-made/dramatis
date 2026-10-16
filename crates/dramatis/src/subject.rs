// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! References to the subject of a record, independently of who acts on it.
//!
//! A reference carries no biographical facts or authority. The receiving host
//! supplies the resident/vault context and authorizes access before lookup.
//! Identifiers are local to that context, not global person identities.

use core::fmt;

use gaz::{Anchor, Contact, ContactBook, PersonaScope, ScopeMismatch};
use personae::ProfileId;
use serde::{Deserialize, Serialize};

/// Who a saved record is about, independently of its author or acting persona.
///
/// The profile and contact namespaces are deliberately distinct. A local Gaz
/// anchor can name another person without creating a profile, key or login.
/// Names, birth facts and calculated results belong in separately owned data.
/// Serializing this value neither admits a record nor authorizes disclosure.
///
/// Serde uses an externally tagged enum. Variant order is the binary format;
/// retain this order when extending the contract. Existing identity views,
/// receipts, profile ids and Gaz records retain their own formats unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SubjectRef {
    /// An existing profile in the receiving host's vault context.
    /// Existence and access remain the resident's checks; this is not `Self`.
    Profile {
        /// Stable vault profile id; not a `PersonaId` or a display name.
        id: ProfileId,
    },
    /// A contact in one explicitly named Gaz book.
    Contact {
        /// The book's existing opaque scope label, not an inferred profile id.
        scope: PersonaScope,
        /// The contact's original anchor, retained across key rotation.
        anchor: Anchor,
    },
}

impl SubjectRef {
    /// Look up a contact in a book the receiving host has already authorized.
    ///
    /// Refuses a profile reference, a different book scope, or a missing record.
    /// Never searches by name/current key, falls back to the acting persona,
    /// creates a record, or changes trust. This checks local structure only:
    /// even successful lookup grants no access to separately held birth facts.
    pub fn resolve_contact<'a>(
        &self,
        book: &'a ContactBook,
    ) -> Result<&'a Contact, SubjectLookupError> {
        let Self::Contact { scope, anchor } = self else {
            return Err(SubjectLookupError::NotContact);
        };
        book.verify_scope(scope)
            .map_err(SubjectLookupError::Scope)?;
        book.get(anchor).ok_or(SubjectLookupError::MissingContact)
    }
}

/// Why structural contact lookup could not resolve a subject.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectLookupError {
    /// A profile reference cannot resolve through a contact book.
    NotContact,
    /// The caller supplied a book outside the reference's scope.
    Scope(ScopeMismatch),
    /// No contact remains under this anchor in the specified book.
    MissingContact,
}

impl fmt::Display for SubjectLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotContact => f.write_str("the subject is a profile, not a contact"),
            Self::Scope(error) => error.fmt(f),
            Self::MissingContact => f.write_str("the subject contact is absent from its book"),
        }
    }
}

impl core::error::Error for SubjectLookupError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Scope(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "subject_tests.rs"]
mod tests;
