// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Association claims: the layer above an unassociated key (release log D3).
//!
//! An unassociated key has no derivation from any root, so nothing links it
//! to one until its holder says so. A claim is that statement: the subject key
//! signs "I act under `associate`, within this scope, for this long". Unlike a
//! [`crate::DerivedKeyAttestation`] it binds no derivation, so it proves the
//! subject's consent only; a verifier that wants the associate's consent too
//! needs the associate's own claim or delegation naming the subject.
//! The subject withdraws a claim with a signed revocation.

use serde::{Deserialize, Serialize};

#[cfg(feature = "verify")]
use crate::check::CheckFault;
use crate::delegation::{CapabilityScope, path_covers, push_bytes, push_expiry, push_scope};

const CLAIM_VERSION: u16 = 1;
const CLAIM_DOMAIN: &[u8] = b"insigne/association-claim/v1";
const REVOCATION_DOMAIN: &[u8] = b"insigne/association-revocation/v1";

/// Stable content identifier for one association claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssociationId(pub [u8; 32]);

/// What a holder of an unassociated key asserts about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationClaim {
    version: u16,
    /// The unassociated public key making the claim, and its signer.
    pub subject: [u8; 32],
    /// The root or persona public key the subject says it acts under.
    pub associate: [u8; 32],
    /// What the association covers.
    pub scope: CapabilityScope,
    /// Subject-asserted creation time committed by the signature.
    pub issued_at_ms: u64,
    /// First millisecond at which the claim holds.
    pub not_before_ms: u64,
    /// Last millisecond at which the claim holds, or unbounded.
    pub expires_at_ms: Option<u64>,
    /// Subject-chosen uniqueness, allowing two otherwise identical claims.
    pub nonce: [u8; 32],
}

impl AssociationClaim {
    /// Construct a versioned claim payload.
    pub fn new(
        subject: [u8; 32],
        associate: [u8; 32],
        scope: CapabilityScope,
        issued_at_ms: u64,
        not_before_ms: u64,
        expires_at_ms: Option<u64>,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            version: CLAIM_VERSION,
            subject,
            associate,
            scope,
            issued_at_ms,
            not_before_ms,
            expires_at_ms,
            nonce,
        }
    }

    /// Whether the claim is structurally valid on its own. A key cannot
    /// associate with itself.
    pub fn is_well_formed(&self) -> bool {
        self.version == CLAIM_VERSION
            && self.subject != [0; 32]
            && self.associate != [0; 32]
            && self.subject != self.associate
            && self.scope.attenuates(&self.scope)
            && self.issued_at_ms <= self.not_before_ms
            && self
                .expires_at_ms
                .is_none_or(|end| end >= self.not_before_ms)
    }

    /// Whether the claim is in force at `at_ms` (revocation aside).
    pub fn active_at(&self, at_ms: u64) -> bool {
        self.is_well_formed()
            && at_ms >= self.not_before_ms
            && self.expires_at_ms.is_none_or(|end| at_ms <= end)
    }

    /// Whether the claim covers one action at the evaluation time.
    pub fn covers(&self, path: &str, action: &str, at_ms: u64) -> bool {
        self.active_at(at_ms)
            && path_covers(&self.scope.path_prefix, path)
            && self.scope.actions.contains(action)
    }

    /// Stable content id: BLAKE3 over the signing bytes.
    #[cfg(feature = "digest")]
    pub fn id(&self) -> AssociationId {
        AssociationId(*blake3::hash(&self.signing_bytes()).as_bytes())
    }

    /// The canonical bytes the subject signs and a checker verifies.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, CLAIM_DOMAIN);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.subject);
        bytes.extend_from_slice(&self.associate);
        push_scope(&mut bytes, &self.scope);
        bytes.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.not_before_ms.to_le_bytes());
        push_expiry(&mut bytes, self.expires_at_ms);
        bytes.extend_from_slice(&self.nonce);
        bytes
    }
}

/// A claim and the subject's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAssociationClaim {
    /// The statement the signature commits.
    pub claim: AssociationClaim,
    signature: Vec<u8>,
}

impl SignedAssociationClaim {
    /// Assemble from parts. Nothing is checked here.
    pub fn from_parts(claim: AssociationClaim, signature: Vec<u8>) -> Self {
        Self { claim, signature }
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Check the claim's fields and the subject's signature.
    #[cfg(feature = "verify")]
    pub fn check(&self) -> Result<CheckedAssociation<'_>, CheckFault> {
        if !self.claim.is_well_formed() {
            return Err(CheckFault::Malformed);
        }
        if !crate::check::ed25519(
            &self.claim.subject,
            &self.signature,
            &self.claim.signing_bytes(),
        ) {
            return Err(CheckFault::BadSignature);
        }
        Ok(CheckedAssociation { signed: self })
    }
}

/// A claim whose fields and signature checked. A local conclusion, not
/// serializable.
#[cfg(feature = "verify")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedAssociation<'a> {
    signed: &'a SignedAssociationClaim,
}

#[cfg(feature = "verify")]
impl<'a> CheckedAssociation<'a> {
    /// The claim that checked.
    pub fn claim(&self) -> &'a AssociationClaim {
        &self.signed.claim
    }
}

/// The subject's withdrawal of one claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationRevocation {
    version: u16,
    /// The claim withdrawn.
    pub claim: AssociationId,
    /// The subject key which made it, and signs this.
    pub subject: [u8; 32],
    /// Subject-asserted revocation time committed by the signature.
    pub at_ms: u64,
    /// Subject-chosen uniqueness.
    pub nonce: [u8; 32],
}

impl AssociationRevocation {
    /// Construct a versioned revocation payload.
    pub fn new(claim: AssociationId, subject: [u8; 32], at_ms: u64, nonce: [u8; 32]) -> Self {
        Self {
            version: CLAIM_VERSION,
            claim,
            subject,
            at_ms,
            nonce,
        }
    }

    /// The canonical bytes the subject signs and a checker verifies.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, REVOCATION_DOMAIN);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.claim.0);
        bytes.extend_from_slice(&self.subject);
        bytes.extend_from_slice(&self.at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }
}

/// A revocation and the subject's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAssociationRevocation {
    /// The statement the signature commits.
    pub revocation: AssociationRevocation,
    signature: Vec<u8>,
}

impl SignedAssociationRevocation {
    /// Assemble from parts. Nothing is checked here.
    pub fn from_parts(revocation: AssociationRevocation, signature: Vec<u8>) -> Self {
        Self {
            revocation,
            signature,
        }
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Check that this revocation names `claim`, comes from its subject and
    /// is signed by it.
    #[cfg(feature = "verify")]
    pub fn check_for(&self, claim: &AssociationClaim) -> Result<(), CheckFault> {
        let revocation = &self.revocation;
        if revocation.version != CLAIM_VERSION
            || revocation.claim != claim.id()
            || revocation.subject != claim.subject
        {
            return Err(CheckFault::Malformed);
        }
        if !crate::check::ed25519(
            &revocation.subject,
            &self.signature,
            &revocation.signing_bytes(),
        ) {
            return Err(CheckFault::BadSignature);
        }
        Ok(())
    }
}
