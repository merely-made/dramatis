// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The unassociated key tier (release log plan, D3 and R7).
//!
//! An [`UnassociatedKeypair`] is a fresh Ed25519 key born outside the master's
//! derivation tree: no persona seed, salt or attestation reaches it, so
//! nothing a carrier publishes under it links to a root. A holder may later
//! *associate* it by signing an [`AssociationClaim`] (scoped, expiring,
//! revocable), a layer above the key rather than a derivation of it.
//!
//! The type follows [`DerivedKeypair`]'s custody rules: no public constructor
//! takes raw seed bytes (so a master seed cannot be passed off as one), the
//! key zeroizes on drop, and it reads as the keypair it wraps. It persists
//! only sealed under a caller-held key ([`UnassociatedKeypair::seal`]).

use insigne::association::{
    AssociationClaim, AssociationRevocation, SignedAssociationClaim, SignedAssociationRevocation,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DerivedKeypair, Ed25519Keypair, IdentityError, seal_bytes, unseal_bytes};

const SEAL_AAD: &[u8] = b"personae/unassociated-keypair/v1";

/// A custodied key with no derivation from any root.
#[derive(Clone)]
pub struct UnassociatedKeypair(Ed25519Keypair);

impl UnassociatedKeypair {
    /// Generate a fresh key from OS randomness.
    pub fn generate() -> Self {
        Self(Ed25519Keypair::generate())
    }

    /// The keypair itself, for an API that takes a plain one.
    pub fn into_keypair(self) -> Ed25519Keypair {
        self.0
    }

    /// Seal the key for storage under a 32-byte key the caller holds.
    pub fn seal(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, IdentityError> {
        let mut seed = self.0.to_seed();
        let sealed = seal_bytes(storage_key, SEAL_AAD, &seed);
        seed.zeroize();
        sealed
    }

    /// Restore a key that [`Self::seal`] sealed.
    pub fn unseal(storage_key: &[u8; 32], sealed: &[u8]) -> Result<Self, IdentityError> {
        let mut plain = unseal_bytes(storage_key, SEAL_AAD, sealed)?;
        let seed = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| {
            IdentityError::DerivationFailed("sealed unassociated key is malformed".into())
        });
        plain.zeroize();
        Ok(Self(Ed25519Keypair::from_seed(seed?)))
    }

    /// Sign a claim that this key is associated with `claim.associate`.
    ///
    /// The claim must name this key as its subject.
    pub fn sign_association(
        &self,
        claim: AssociationClaim,
    ) -> Result<SignedAssociationClaim, IdentityError> {
        if claim.subject != self.0.public_key().to_bytes() || !claim.is_well_formed() {
            return Err(IdentityError::DerivationFailed(
                "association claim does not name this key".into(),
            ));
        }
        let signature = self.0.sign(&claim.signing_bytes()).to_bytes().to_vec();
        Ok(SignedAssociationClaim::from_parts(claim, signature))
    }

    /// Sign the withdrawal of a claim this key made.
    pub fn sign_association_revocation(
        &self,
        revocation: AssociationRevocation,
    ) -> Result<SignedAssociationRevocation, IdentityError> {
        if revocation.subject != self.0.public_key().to_bytes() {
            return Err(IdentityError::DerivationFailed(
                "association revocation does not name this key".into(),
            ));
        }
        let signature = self.0.sign(&revocation.signing_bytes()).to_bytes().to_vec();
        Ok(SignedAssociationRevocation::from_parts(
            revocation, signature,
        ))
    }
}

impl std::ops::Deref for UnassociatedKeypair {
    type Target = Ed25519Keypair;

    fn deref(&self) -> &Ed25519Keypair {
        &self.0
    }
}

impl ZeroizeOnDrop for UnassociatedKeypair {}

/// Which D3 tier a carrier key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTier {
    /// Derived from a root as a disposable persona.
    Associated,
    /// Born outside any root's derivation tree.
    Unassociated,
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::DerivedKeypair {}
    impl Sealed for crate::UnassociatedKeypair {}
}

/// A key a transport may bind: one of the two custody types.
///
/// Sealed, so a master `Ed25519Keypair` cannot be given an implementation
/// (vault lock plan, ruling 96).
pub trait CarrierKeypair: sealed::Sealed {
    /// The keypair, to read the seed or sign with.
    fn keypair(&self) -> &Ed25519Keypair;

    /// The tier this key belongs to.
    fn tier(&self) -> KeyTier;
}

impl CarrierKeypair for DerivedKeypair {
    fn keypair(&self) -> &Ed25519Keypair {
        self
    }

    fn tier(&self) -> KeyTier {
        KeyTier::Associated
    }
}

impl CarrierKeypair for UnassociatedKeypair {
    fn keypair(&self) -> &Ed25519Keypair {
        &self.0
    }

    fn tier(&self) -> KeyTier {
        KeyTier::Unassociated
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use insigne::CapabilityScope;

    use super::*;
    use crate::{IdentityProvider, InMemoryProvider};

    fn scope() -> CapabilityScope {
        CapabilityScope {
            domain: "release-log".into(),
            resource: vec![4; 32],
            path_prefix: "/site".into(),
            actions: BTreeSet::from(["speak-for".to_string()]),
        }
    }

    fn claim(key: &UnassociatedKeypair, root: [u8; 32]) -> AssociationClaim {
        AssociationClaim::new(
            key.public_key().to_bytes(),
            root,
            scope(),
            5,
            10,
            Some(100),
            [3; 32],
        )
    }

    #[test]
    fn fresh_keys_share_nothing_with_a_persona() {
        let provider = InMemoryProvider::from_seed([9; 32]);
        let key = UnassociatedKeypair::generate();
        let derived = provider.derive_keypair(b"salt").unwrap();
        let known = [
            provider.master_public_key().to_bytes(),
            derived.public_key().to_bytes(),
        ];
        assert!(!known.contains(&key.public_key().to_bytes()));
        assert_ne!(
            key.public_key().to_bytes(),
            UnassociatedKeypair::generate().public_key().to_bytes()
        );
        assert_eq!(key.tier(), KeyTier::Unassociated);
        assert_eq!(
            provider.derived_keypair(b"salt").unwrap().tier(),
            KeyTier::Associated
        );
    }

    #[test]
    fn sealed_key_round_trips_and_refuses_the_wrong_key() {
        let key = UnassociatedKeypair::generate();
        let sealed = key.seal(&[1; 32]).unwrap();
        let back = UnassociatedKeypair::unseal(&[1; 32], &sealed).unwrap();
        assert_eq!(back.public_key().to_bytes(), key.public_key().to_bytes());
        assert!(UnassociatedKeypair::unseal(&[2; 32], &sealed).is_err());
    }

    #[test]
    fn association_claim_verifies_scopes_and_revokes() {
        let key = UnassociatedKeypair::generate();
        let root = InMemoryProvider::from_seed([5; 32])
            .master_public_key()
            .to_bytes();
        let signed = key.sign_association(claim(&key, root)).unwrap();
        let checked = signed.check().expect("a signed claim checks");
        assert!(checked.claim().active_at(50));
        assert!(!checked.claim().active_at(101), "expired");
        assert!(checked.claim().covers("/site/a", "speak-for", 50));
        assert!(!checked.claim().covers("/other", "speak-for", 50));
        assert!(!checked.claim().covers("/site", "admin", 50));

        let mut tampered = signed.clone();
        tampered.claim.associate = [8; 32];
        assert_eq!(tampered.check(), Err(insigne::CheckFault::BadSignature));

        let revocation = key
            .sign_association_revocation(AssociationRevocation::new(
                signed.claim.id(),
                key.public_key().to_bytes(),
                60,
                [4; 32],
            ))
            .unwrap();
        assert!(revocation.check_for(&signed.claim).is_ok());

        let other = claim(&key, [6; 32]);
        assert!(revocation.check_for(&other).is_err(), "names another claim");
    }

    #[test]
    fn another_key_cannot_sign_the_claim() {
        let key = UnassociatedKeypair::generate();
        let other = UnassociatedKeypair::generate();
        assert!(other.sign_association(claim(&key, [5; 32])).is_err());
    }
}
