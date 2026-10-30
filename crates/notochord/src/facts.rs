// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Carrier-observed facts, and the subset of them a proof may bind.
//!
//! The split this module exists for (Notochord plan, N0): what the *carrier
//! observed* and what the *initiator claimed* are different kinds of thing,
//! and mixing them into one struct makes the D4 rule ("transport facts are
//! facts, not claims") a discipline rather than a property of the types.
//!
//! - [`SessionFacts`] is built by the accepting carrier adapter and is
//!   deliberately **not** serializable: nothing decoded from application bytes
//!   can construct one, so a hello cannot smuggle in an authenticated peer or
//!   a local interface.
//! - [`crate::SessionClaims`] is what a hello asserts, and is worth exactly as
//!   much as the proof over it.
//! - [`ProofBinding`] is the intersection: the facts *both* peers can derive
//!   independently, and therefore the only ones a signature can cover.

/// Which carrier delivered a session.
///
/// Mirrors `mere-transport::TransportKind`. It is redeclared here rather than
/// imported because this crate must not depend on the transport stack (and
/// therefore on iroh, p2panda, and QUIC); the carrier adapter maps between
/// them. Named `CarrierKind` so the two can be imported side by side in that
/// adapter without a rename.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarrierKind {
    /// In-process paired fixture.
    Memory,
    /// p2panda / iroh.
    P2panda,
    /// Reticulum, over any retinue interface.
    Reticulum,
    /// A carrier this crate has no specific knowledge of.
    Other,
}

/// Where a session physically arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngressFacts {
    /// The local interface it arrived on, when the carrier tracks one.
    ///
    /// Opaque and local: meaningful only to the node that assigned it, not
    /// stable across restarts, and never on the wire. It may inform the
    /// owner's policy; it can never enter a transcript, because the far end
    /// cannot reconstruct it. See [`ProofBinding`].
    pub local_interface: Option<u64>,
    /// The link identifier, when the carrier has link identity.
    ///
    /// Shared, unlike the interface: both ends of a retinue link compute the
    /// same value, which is what lets a proof be pinned to one link.
    pub shared_link: Option<[u8; 16]>,
}

/// What the carrier observed about one inbound session.
///
/// Constructed by the accepting adapter, never decoded. `authenticated_initiator`
/// is `Some` only when the carrier itself proved the initiator: p2panda
/// authenticates its connections, Memory knows its counterparty by
/// construction, and Reticulum best-effort acceptance honestly reports `None`
/// and lets the session proof establish a subject instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionFacts {
    /// The protocol (ALPN) the session was accepted for.
    pub protocol: Vec<u8>,
    /// The carrier that delivered it.
    pub transport: CarrierKind,
    /// The initiator's identity, when the carrier authenticated it.
    pub authenticated_initiator: Option<[u8; 32]>,
    /// Where it arrived.
    pub ingress: IngressFacts,
}

impl SessionFacts {
    /// Facts for a carrier with no peer authentication and no bearer detail.
    pub fn new(protocol: impl Into<Vec<u8>>, transport: CarrierKind) -> Self {
        Self {
            protocol: protocol.into(),
            transport,
            authenticated_initiator: None,
            ingress: IngressFacts::default(),
        }
    }

    /// Facts for a carrier that authenticated the initiator.
    pub fn authenticated(
        protocol: impl Into<Vec<u8>>,
        transport: CarrierKind,
        initiator: [u8; 32],
    ) -> Self {
        Self {
            authenticated_initiator: Some(initiator),
            ..Self::new(protocol, transport)
        }
    }

    /// Add the bearer detail a link-oriented carrier observed.
    pub fn with_ingress(
        mut self,
        local_interface: Option<u64>,
        shared_link: Option<[u8; 16]>,
    ) -> Self {
        self.ingress = IngressFacts {
            local_interface,
            shared_link,
        };
        self
    }

    /// The binding a *responder* signs against: only what the far end can also
    /// derive. The local interface is dropped here, deliberately.
    pub fn proof_binding(&self) -> ProofBinding {
        ProofBinding {
            protocol: self.protocol.clone(),
            initiator_transport_identity: self.authenticated_initiator,
            shared_link: self.ingress.shared_link,
        }
    }

    /// Bind an independently verified secure channel without changing any
    /// carrier observation. Local interface identity remains excluded.
    pub fn secure_proof_binding(&self, channel: &SecureChannelFacts) -> SecureProofBinding {
        self.proof_binding().with_secure_channel(channel.clone())
    }
}

/// The facts a session proof covers.
///
/// Every field must be independently derivable by both peers, or an honest
/// session cannot be admitted. Note what
/// `initiator_transport_identity` means: it is **the initiator's** transport
/// identity in both roles. The responder fills it from the peer the carrier
/// authenticated; the initiator fills it from its own local transport
/// identity. It must never be read as "the other end" on both sides, or the
/// two would sign different bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProofBinding {
    /// The protocol the session was accepted for.
    pub protocol: Vec<u8>,
    /// The initiator's carrier-proved identity, when there is one.
    pub initiator_transport_identity: Option<[u8; 32]>,
    /// The shared link identifier, when the carrier has link identity.
    pub shared_link: Option<[u8; 16]>,
}

impl ProofBinding {
    /// The binding an *initiator* signs, from its own local transport
    /// identity and the link it is about to speak on.
    ///
    /// `local_transport_identity` is this node's own identity on an
    /// authenticating carrier, and `None` on one that cannot prove peers.
    pub fn initiator(
        protocol: impl Into<Vec<u8>>,
        local_transport_identity: Option<[u8; 32]>,
        shared_link: Option<[u8; 16]>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            initiator_transport_identity: local_transport_identity,
            shared_link,
        }
    }

    /// Add independently verified channel facts to the v2 admission binding.
    /// The legacy binding shape and v1 transcript remain unchanged.
    pub fn with_secure_channel(self, secure_channel: SecureChannelFacts) -> SecureProofBinding {
        SecureProofBinding {
            carrier: self,
            secure_channel,
        }
    }
}

/// Facts established by a secure-channel implementation, never decoded from
/// an admission hello. The transport adapter constructs this only after the
/// channel handshake and its identity proofs have verified.
///
/// Identities are ordered by their channel roles on both ends: `initiator`
/// never means "the remote peer". The handshake hash identifies this one
/// channel; a static key alone cannot provide that binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureChannelFacts {
    /// Exact cryptographic and identity-proof profile, including its suite.
    pub profile: Vec<u8>,
    /// Version of that secure-channel profile, independent of admission wire version.
    pub version: u16,
    /// Authenticated channel handshake hash (32 or 64 bytes).
    pub handshake_hash: Vec<u8>,
    /// Ed25519 application identity proved by the channel initiator.
    pub initiator: [u8; 32],
    /// Ed25519 application identity proved by the channel responder.
    pub responder: [u8; 32],
    /// Application protocol authenticated inside the secure channel.
    pub protocol: Vec<u8>,
}

impl SecureChannelFacts {
    /// Assemble local verified facts. Admission additionally checks their
    /// bounded shape. The service adapter checks its expected inner protocol.
    pub fn new(
        profile: impl Into<Vec<u8>>,
        version: u16,
        handshake_hash: impl Into<Vec<u8>>,
        initiator: [u8; 32],
        responder: [u8; 32],
        protocol: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            version,
            handshake_hash: handshake_hash.into(),
            initiator,
            responder,
            protocol: protocol.into(),
        }
    }

    /// Validate only the common bounded shape. Selection of the permitted
    /// cryptographic profile remains the secure-channel/service owner's rule.
    pub fn is_valid(&self) -> bool {
        !self.profile.is_empty()
            && self.profile.len() <= 128
            && self.version != 0
            && matches!(self.handshake_hash.len(), 32 | 64)
            && !self.protocol.is_empty()
            && self.protocol.len() <= 255
    }
}

/// Common, role-ordered v2 proof context. Carrier observations and secure
/// observations stay separate even when a service requires their keys to match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureProofBinding {
    /// Shared carrier observations; no local interface appears here.
    pub carrier: ProofBinding,
    /// Secure-channel observations, independently established by both peers.
    pub secure_channel: SecureChannelFacts,
}

impl SecureProofBinding {
    /// Refuse malformed facts before signing/admitting. Outer and inner
    /// protocols can deliberately differ (for an opaque carrier tunnel); both
    /// are signed independently. The service checks its expected inner protocol.
    pub fn is_valid(&self) -> bool {
        self.secure_channel.is_valid()
            && !self.carrier.protocol.is_empty()
            && self.carrier.protocol.len() <= 255
    }
}

/// Explicit relationship between carrier identity and secure application identity.
/// Both choices still require the secure initiator to prove the admitted subject
/// or its attested session-signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureIdentityPolicy {
    /// If the carrier authenticated a peer, that key must equal the secure
    /// initiator. Honest absent carrier authentication remains absent.
    MatchCarrierWhenPresent,
    /// Permit a distinct carrier identity when the secure initiator is the
    /// subject or the subject's checked, transcript-signing derived key.
    AttestedApplication,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_roles_derive_the_same_binding_on_an_authenticated_carrier() {
        let initiator_key = [7u8; 32];
        let link = [3u8; 16];

        // Responder: reads the initiator identity off its own acceptance.
        let responder =
            SessionFacts::authenticated(b"p".to_vec(), CarrierKind::P2panda, initiator_key)
                .with_ingress(Some(41), Some(link))
                .proof_binding();
        // Initiator: uses its own transport identity.
        let initiator = ProofBinding::initiator(b"p".to_vec(), Some(initiator_key), Some(link));

        assert_eq!(responder, initiator);
    }

    #[test]
    fn the_local_interface_never_reaches_the_binding() {
        let facts = SessionFacts::new(b"p".to_vec(), CarrierKind::Reticulum)
            .with_ingress(Some(9), Some([1; 16]));
        let other_interface = SessionFacts::new(b"p".to_vec(), CarrierKind::Reticulum)
            .with_ingress(Some(1_000), Some([1; 16]));

        assert_ne!(facts.ingress, other_interface.ingress);
        assert_eq!(
            facts.proof_binding(),
            other_interface.proof_binding(),
            "a purely local number cannot change what gets signed"
        );
    }
}
