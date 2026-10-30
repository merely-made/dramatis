// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Admission bound to separately verified secure-channel facts.
//!
//! The carrier-only v1 APIs retain their existing transcript and policy
//! semantics. These v2 entrypoints always bind a channel and never retry v1.

use crate::{
    AdmittedPrincipal, AdmittedSession, DenyReason, LocalNetworkPolicy, RevocationLedger,
    SECURE_WIRE_VERSION, SecureChannelFacts, SecureIdentityPolicy, SessionDecision, SessionFacts,
    SessionHello, SessionReply,
};

/// An admitted application session plus the verified secure channel it used.
/// Carrier observations remain untouched in `session.facts`.
#[derive(Debug)]
pub struct AdmittedSecureSession<S> {
    /// The existing admitted-session shape, including the original carrier facts.
    pub session: AdmittedSession<S>,
    /// Independently verified secure-channel facts retained for owner policy.
    pub secure_channel: SecureChannelFacts,
}

impl<S> AdmittedSecureSession<S> {
    /// Retain the admitted application session after consuming channel policy context.
    pub fn into_session(self) -> AdmittedSession<S> {
        self.session
    }

    /// Return the admitted stream after applying all required owner policy.
    pub fn into_stream(self) -> S {
        self.session.stream
    }
}

/// Verify and admit a v2 hello using carrier and secure-channel observations.
/// `identity_policy` is selected by the service owner, never from a hello.
#[allow(clippy::too_many_arguments)]
pub fn admit_secure(
    policy: &LocalNetworkPolicy,
    ledger: &RevocationLedger,
    hello_bytes: &[u8],
    facts: &SessionFacts,
    secure_channel: &SecureChannelFacts,
    identity_policy: SecureIdentityPolicy,
    now_ms: u64,
    active_sessions: u32,
) -> (Vec<u8>, Result<AdmittedPrincipal, DenyReason>) {
    let outcome = evaluate_secure(
        policy,
        ledger,
        hello_bytes,
        facts,
        secure_channel,
        identity_policy,
        now_ms,
        active_sessions,
    );
    let reply = match &outcome {
        Ok((principal, hello)) => SessionReply::Accept {
            session_id: principal.session_id,
            class: principal.class,
            limits: policy.limits.clamped(),
            profile_revision: policy
                .accepted_profiles
                .iter()
                .find(|profile| profile.id == hello.profile.id)
                .map(|profile| profile.revision)
                .unwrap_or(hello.profile.revision),
        },
        Err(reason) => SessionReply::Reject {
            reason: reason.clone(),
        },
    };
    (
        postcard::to_allocvec(&reply).unwrap_or_default(),
        outcome.map(|(principal, _)| principal),
    )
}

/// The decision-only v2 responder, analogous to [`crate::respond`].
#[allow(clippy::too_many_arguments)]
pub fn respond_secure(
    policy: &LocalNetworkPolicy,
    ledger: &RevocationLedger,
    hello_bytes: &[u8],
    facts: &SessionFacts,
    secure_channel: &SecureChannelFacts,
    identity_policy: SecureIdentityPolicy,
    now_ms: u64,
    active_sessions: u32,
) -> (Vec<u8>, SessionDecision) {
    let (reply, outcome) = admit_secure(
        policy,
        ledger,
        hello_bytes,
        facts,
        secure_channel,
        identity_policy,
        now_ms,
        active_sessions,
    );
    let decision = match outcome {
        Ok(principal) => SessionDecision::Accept {
            class: principal.class,
        },
        Err(reason) => SessionDecision::Deny { reason },
    };
    (reply, decision)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_secure(
    policy: &LocalNetworkPolicy,
    ledger: &RevocationLedger,
    hello_bytes: &[u8],
    facts: &SessionFacts,
    secure_channel: &SecureChannelFacts,
    identity_policy: SecureIdentityPolicy,
    now_ms: u64,
    active_sessions: u32,
) -> Result<(AdmittedPrincipal, SessionHello), DenyReason> {
    let binding = facts.secure_proof_binding(secure_channel);
    if !binding.is_valid() {
        return Err(DenyReason::InvalidSecureChannel);
    }
    let hello = SessionHello::decode(hello_bytes, &policy.limits.clamped())
        .map_err(|_| DenyReason::MalformedHello)?;
    if hello.version != SECURE_WIRE_VERSION {
        return Err(DenyReason::UnsupportedWireVersion {
            requested: hello.version,
            supported: SECURE_WIRE_VERSION,
        });
    }
    if !hello.verify_secure_proof(&binding) {
        return Err(DenyReason::SessionProofInvalid);
    }
    // The preceding proof checked the attestation's signature/salt, its
    // master == hello.subject, and the derived key's transcript signature.
    // Therefore either identity below is an authenticated application subject,
    // rather than an unproved association between two valid handshakes.
    if secure_channel.initiator != hello.subject
        && secure_channel.initiator != *hello.session_signer.derived()
    {
        return Err(DenyReason::SubjectNotSecurePeer);
    }
    if identity_policy == SecureIdentityPolicy::MatchCarrierWhenPresent
        && let Some(carrier_peer) = facts.authenticated_initiator
        && carrier_peer != secure_channel.initiator
    {
        return Err(DenyReason::SecureChannelIdentityMismatch);
    }
    match policy.evaluate_secure_proved(facts, &hello.claims(), ledger, now_ms, active_sessions) {
        SessionDecision::Deny { reason } => Err(reason),
        SessionDecision::Accept { class } => Ok((
            AdmittedPrincipal {
                subject: hello.subject,
                class,
                session_id: hello.secure_session_id(&binding),
                action: hello.action.clone(),
            },
            hello,
        )),
    }
}

/// Bounded async v2 admission. On refusal the stream is finished and cannot
/// escape as an admitted session; on success both fact records are retained.
#[cfg(feature = "tokio")]
#[allow(clippy::too_many_arguments)]
pub async fn admit_session_secure<S>(
    mut stream: S,
    policy: &LocalNetworkPolicy,
    ledger: &RevocationLedger,
    facts: &SessionFacts,
    secure_channel: &SecureChannelFacts,
    identity_policy: SecureIdentityPolicy,
    now_ms: u64,
    active_sessions: u32,
) -> Result<Result<AdmittedSecureSession<S>, DenyReason>, crate::IoHandshakeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let limits = policy.limits.clamped();
    let hello_bytes = crate::read_frame(&mut stream, limits.max_hello_bytes).await?;
    let (reply, outcome) = admit_secure(
        policy,
        ledger,
        &hello_bytes,
        facts,
        secure_channel,
        identity_policy,
        now_ms,
        active_sessions,
    );
    crate::write_frame(&mut stream, &reply, limits.max_reply_bytes).await?;
    match outcome {
        Ok(principal) => {
            let claims = SessionHello::decode(&hello_bytes, &limits)?.claims();
            Ok(Ok(AdmittedSecureSession {
                session: AdmittedSession {
                    stream,
                    principal,
                    claims,
                    facts: facts.clone(),
                    limits,
                },
                secure_channel: secure_channel.clone(),
            }))
        },
        Err(reason) => {
            let _ = stream.shutdown().await;
            Ok(Err(reason))
        },
    }
}
