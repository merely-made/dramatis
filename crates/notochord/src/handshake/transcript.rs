// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Canonical transcript bytes, length-prefixed so no two different field sets
/// can collide.
///
/// Only values **both ends derive independently** may appear here. That is why
/// a local interface id is absent: it is meaningful only to the node that
/// assigned it, is not stable across restarts, and never goes on the wire, so
/// an initiator could not sign it and a responder demanding it would reject
/// every honest session. It stays on [`SessionFacts`] as policy context and
/// never reaches a [`ProofBinding`].
///
/// A Reticulum link id, by contrast, *is* shared: both ends of a link compute
/// the same value, which is what lets the transcript pin a proof to one link.
pub(super) fn transcript(hello: &SessionHello, binding: &ProofBinding) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, TRANSCRIPT_DOMAIN);
    bytes.extend_from_slice(&hello.version.to_le_bytes());
    bytes.extend_from_slice(&hello.network.0);
    push_bytes(&mut bytes, hello.profile.id.as_bytes());
    bytes.extend_from_slice(&hello.profile.revision.to_le_bytes());
    push_bytes(&mut bytes, &binding.protocol);
    push_bytes(&mut bytes, hello.action.domain.as_bytes());
    push_bytes(&mut bytes, hello.action.path.as_bytes());
    push_bytes(&mut bytes, hello.action.action.as_bytes());
    bytes.push(class_tag(hello.class));
    bytes.extend_from_slice(&hello.nonce);
    bytes.extend_from_slice(&hello.subject);
    push_option(
        &mut bytes,
        binding
            .initiator_transport_identity
            .as_ref()
            .map(|p| &p[..]),
    );
    push_option(&mut bytes, binding.shared_link.as_ref().map(|l| &l[..]));
    bytes.extend_from_slice(&(hello.delegations.len() as u64).to_le_bytes());
    for signed in &hello.delegations {
        bytes.extend_from_slice(&signed.certificate.id().0);
    }
    bytes
}

pub(super) fn secure_transcript(hello: &SessionHello, binding: &SecureProofBinding) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, SECURE_TRANSCRIPT_DOMAIN);
    push_bytes(&mut bytes, &transcript(hello, &binding.carrier));
    let channel = &binding.secure_channel;
    push_bytes(&mut bytes, &channel.profile);
    bytes.extend_from_slice(&channel.version.to_le_bytes());
    push_bytes(&mut bytes, &channel.handshake_hash);
    push_bytes(&mut bytes, b"initiator");
    bytes.extend_from_slice(&channel.initiator);
    push_bytes(&mut bytes, b"responder");
    bytes.extend_from_slice(&channel.responder);
    push_bytes(&mut bytes, &channel.protocol);
    bytes
}

fn class_tag(class: TrafficClass) -> u8 {
    match class {
        TrafficClass::Control => 0,
        TrafficClass::Interactive => 1,
        TrafficClass::Background => 2,
        TrafficClass::Transit => 3,
    }
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

fn push_option(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            push_bytes(bytes, value);
        },
        None => bytes.push(0),
    }
}
