// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use std::time::SystemTime;

use custody_wire::contract::{Petition, Source};
use custody_wire::remote_approval::route::RemoteState;
use custody_wire::remote_approval::{
    ApprovalOperation, ApprovalProof, ApprovalRequest, WEEK_SECONDS, enrollment_scope,
};
use insigne::delegation::DelegationParent;
use notochord::{RevocationLedger, TrustedRoot, validate_chain};
use serde::Deserialize;

use super::*;

pub fn enrollment(
    state: RemoteState,
    subject: &str,
    seconds: &str,
) -> Result<DelegationCertificate, String> {
    let subject = hex_key(subject)?;
    let seconds: u64 = seconds.parse().map_err(|_| "invalid grant duration")?;
    if seconds == 0 || seconds > state.max_grant_seconds.min(WEEK_SECONDS) {
        return Err("grant duration exceeds target policy".into());
    }
    let now = wall_ms()?;
    let mut nonce = [0; 32];
    nonce[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    nonce[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    Ok(DelegationCertificate::new(
        DelegationParent::Root(state.root_authority),
        state.root_issuer,
        subject,
        enrollment_scope(state.target, &state.profile, state.actions),
        now,
        now,
        Some(
            now.checked_add(seconds * 1000)
                .ok_or("grant time overflow")?,
        ),
        1,
        nonce,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalInput {
    state: RemoteState,
    petition: Petition,
    request: ApprovalRequest,
    enrollment: Option<SignedDelegationCertificate>,
}

pub fn approval(
    client: &Client,
    profile: &str,
    input: ApprovalInput,
) -> Result<ApprovalProof, String> {
    let ApprovalInput {
        state,
        petition,
        request,
        enrollment,
    } = input;
    let now = wall_ms()?;
    let Answer::PublicKey { key: issuer } = call(
        client,
        Operation::PublicKey {
            source: Source::Persona,
            profile: Some(profile.into()),
        },
    )?
    else {
        return Err("no approving public identity".into());
    };
    let digest = blake3::Hash::from_hex(&petition.digest).map_err(|_| "invalid petition digest")?;
    if state.target != request.target
        || state.profile != request.profile
        || state.instance != request.instance
        || state.generation != request.generation
        || petition.profile != request.profile
        || petition.generation != request.generation
        || request.operation
            != (ApprovalOperation::Consent {
                request: petition.request,
                digest: *digest.as_bytes(),
            })
        || !state.actions.contains(&request.operation.action())
        || now < request.issued_at_ms
        || now >= request.expires_at_ms
        || request.expires_at_ms.saturating_sub(request.issued_at_ms) > 120_000
    {
        return Err("challenge does not match authenticated target or petition".into());
    }
    // Show the actual public operation before the local OS authenticates signing.
    eprintln!(
        "target={} profile={} operation={} namespace={} payload={} expires_at_ms={}",
        blake3::Hash::from_bytes(state.target).to_hex(),
        request.profile,
        petition.operation,
        petition.namespace,
        petition.payload_digest,
        request.expires_at_ms
    );
    let root = TrustedRoot {
        authority: state.root_authority,
        issuer: state.root_issuer,
    };
    let mut chain = Vec::new();
    let statement = if let Some(grant) = enrollment {
        if !state.enrollments.contains(&grant) {
            return Err("device enrollment is not currently registered".into());
        }
        validate_chain(
            std::slice::from_ref(&grant),
            issuer,
            &[root],
            &RevocationLedger::new(),
            1,
            now,
        )
        .map_err(|_| "invalid device enrollment")?;
        let statement = request.approval_for_device(&grant, now);
        chain.push(grant);
        statement
    } else {
        if issuer != state.root_issuer {
            return Err("approver is neither the pinned root nor an enrolled device".into());
        }
        request.approval_statement(DelegationParent::Root(state.root_authority), issuer, now)
    };
    chain.push(sign(client, profile, statement)?);
    validate_chain(
        &chain,
        request.target,
        &[root],
        &RevocationLedger::new(),
        2,
        wall_ms()?,
    )
    .map_err(|_| "completed proof does not check or has expired")?;
    Ok(ApprovalProof { chain })
}

fn wall_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|time| u64::try_from(time.as_millis()).ok())
        .ok_or("invalid system clock".into())
}

fn hex_key(value: &str) -> Result<[u8; 32], String> {
    blake3::Hash::from_hex(value)
        .map(|hash| *hash.as_bytes())
        .map_err(|_| "invalid public key hex".into())
}
