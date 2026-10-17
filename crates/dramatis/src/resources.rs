// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Plain subject/resource associations. References convey no authority.
//!
//! The receiving resident supplies envelope context and owns durable revisions,
//! admission and disclosure. Several associations may name the same resource;
//! names, matching facts and keys do not deduplicate subjects or resources.

use serde::{Deserialize, Serialize};

use crate::subject::SubjectRef;
pub use crate::validation::ValidationError;
use crate::validation::{nonempty, require, validated_deserialize};

/// Supported association schema. Unknown versions refuse rather than upgrade.
pub const SUBJECT_RESOURCE_ASSOCIATION_SCHEMA: &str = "dramatis.subject-resource-association/v1";

/// An exact resource revision in its owner's domain, within resident context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceRef {
    /// Owning data domain, interpreted by the receiving resident.
    pub domain: String,
    /// Stable resource id in that domain.
    pub id: String,
    /// Exact revision; never an implicit request for latest.
    pub revision: String,
}

validated_deserialize!(ResourceRef {
    domain: String,
    id: String,
    revision: String
});

impl ResourceRef {
    /// Construct a structurally valid reference without resolving it.
    pub fn new(domain: String, id: String, revision: String) -> Result<Self, ValidationError> {
        let value = Self {
            domain,
            id,
            revision,
        };
        value.validate()?;
        Ok(value)
    }

    /// Revalidate after public-field mutation and before host admission/use.
    /// Input spelling is preserved; surrounding whitespace is not normalized.
    pub fn validate(&self) -> Result<(), ValidationError> {
        nonempty(&self.domain, "resource.domain")?;
        nonempty(&self.id, "resource.id")?;
        nonempty(&self.revision, "resource.revision")
    }
}

/// The structural relationship of a subject to a resource.
/// Binary variant order is part of the format; `About` is variant zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SubjectResourceRelationship {
    /// The resource concerns this subject; this is not an ownership grant.
    About,
}

/// One explicit subject/resource link, separate from the acting persona.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SubjectResourceAssociation {
    /// Exact supported schema identifier.
    pub schema: String,
    /// Who the resource concerns; subject existence/access is a host check.
    pub subject: SubjectRef,
    /// The exact resource revision concerned.
    pub resource: ResourceRef,
    /// How this subject relates to the resource.
    pub relationship: SubjectResourceRelationship,
}

validated_deserialize!(SubjectResourceAssociation {
    schema: String,
    subject: SubjectRef,
    resource: ResourceRef,
    relationship: SubjectResourceRelationship,
});

impl SubjectResourceAssociation {
    /// Build an About link with the supported schema. This convenience does
    /// not validate mutable resource fields; call `validate()` before use or
    /// admission, or use the fallible `new` constructor to check immediately.
    pub fn about(subject: SubjectRef, resource: ResourceRef) -> Self {
        Self {
            schema: SUBJECT_RESOURCE_ASSOCIATION_SCHEMA.into(),
            subject,
            resource,
            relationship: SubjectResourceRelationship::About,
        }
    }

    /// Construct an association using the current schema, without admission.
    pub fn new(
        subject: SubjectRef,
        resource: ResourceRef,
        relationship: SubjectResourceRelationship,
    ) -> Result<Self, ValidationError> {
        let value = Self {
            schema: SUBJECT_RESOURCE_ASSOCIATION_SCHEMA.into(),
            subject,
            resource,
            relationship,
        };
        value.validate()?;
        Ok(value)
    }

    /// Check schema and nested resource data. SubjectRef retains its existing
    /// opaque label semantics; this does not check existence, access or trust.
    pub fn validate(&self) -> Result<(), ValidationError> {
        require(
            self.schema == SUBJECT_RESOURCE_ASSOCIATION_SCHEMA,
            "association.schema",
            "unsupported schema",
        )?;
        self.resource.validate()
    }
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
