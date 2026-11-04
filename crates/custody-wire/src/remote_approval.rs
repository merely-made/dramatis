// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Public records for root-authorized custody approval (custody plan VL-U).
//! These are portable statements, not a new IPC operation or an OS-presence
//! credential. A relay carries them without receiving any vault key. Hosts
//! authenticate the target channel and pin its identity independently.

use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
};
use serde::{Deserialize, Serialize};

/// A purpose separate from pairing, graph writes and transport authentication.
pub const DOMAIN: &str = "merely.custody.remote-approval/v1";
/// The selected default for newly issued device approval grants.
pub const WEEK_SECONDS: u64 = 604_800;

/// The custody action the target's protected policy permits remotely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalAction {
    Unlock,
    Consent,
}

impl ApprovalAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::Consent => "consent",
        }
    }
}

/// The exact operation being approved. Consent never creates an operation or
/// widens a requester's existing grant; the target rechecks its own petition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ApprovalOperation {
    /// Finite duration selected by the owner. Indefinite remote unlock is not
    /// part of the first portable slice.
    Unlock { seconds: u64 },
    /// A custodian-generated petition, including its digest of the operation.
    Consent { request: u64, digest: [u8; 32] },
}

impl ApprovalOperation {
    pub fn action(&self) -> ApprovalAction {
        match self {
            Self::Unlock { .. } => ApprovalAction::Unlock,
            Self::Consent { .. } => ApprovalAction::Consent,
        }
    }
}

/// A fresh challenge created and retained by the target while locked or open.
/// Times are target-clock milliseconds; the request lifetime is independent
/// of a week's authorization. The approving UI must display the operation,
/// profile and requested duration from this authenticated target's record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub target: [u8; 32],
    pub profile: String,
    pub instance: String,
    pub generation: u64,
    pub nonce: [u8; 32],
    pub operation: ApprovalOperation,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// The ordinary Insigne chain: a direct root approval, or a root's device
/// grant followed by that device's one-request approval. Signing stays in
/// the approving custodian via Personae's `Issue`/existing signing service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProof {
    pub chain: Vec<SignedDelegationCertificate>,
}

/// Scope of a root's revocable enrollment of an approving device. Target and
/// profile are exact: hex encodes arbitrary profile bytes without slash or
/// adjacent-name ambiguities in Insigne's existing path grammar.
pub fn enrollment_scope(
    target: [u8; 32],
    profile: &str,
    actions: impl IntoIterator<Item = ApprovalAction>,
) -> CapabilityScope {
    CapabilityScope {
        domain: DOMAIN.into(),
        resource: target.to_vec(),
        path_prefix: format!("/vaults/{}", hex(profile.as_bytes())),
        actions: actions
            .into_iter()
            .map(|action| action.as_str().into())
            .collect(),
    }
}

impl ApprovalRequest {
    /// The enrolled device's one-request statement, narrowed to the parent's
    /// remaining lifetime. The target independently checks the parent proof.
    pub fn approval_for_device(
        &self,
        enrollment: &SignedDelegationCertificate,
        at_ms: u64,
    ) -> DelegationCertificate {
        let mut statement = self.approval_statement(
            DelegationParent::Certificate(enrollment.certificate.id()),
            enrollment.certificate.subject,
            at_ms,
        );
        statement.expires_at_ms = Some(
            enrollment
                .certificate
                .expires_at_ms
                .map_or(self.expires_at_ms, |expires| {
                    expires.min(self.expires_at_ms)
                }),
        );
        statement
    }

    /// Existing delegation fields bind every request field; no additional
    /// signature format, JSON canonicalization or transport-specific proof.
    pub fn scope(&self) -> CapabilityScope {
        let mut scope = enrollment_scope(self.target, &self.profile, [self.operation.action()]);
        let operation = match &self.operation {
            ApprovalOperation::Unlock { seconds } => format!("unlock/{seconds}"),
            ApprovalOperation::Consent { request, digest } => {
                format!("consent/{request}/{}", hex(digest))
            },
        };
        scope.path_prefix.push_str(&format!(
            "/requests/{}/{}/{}/{}/{}/{operation}",
            hex(self.instance.as_bytes()),
            self.generation,
            hex(&self.nonce),
            self.issued_at_ms,
            self.expires_at_ms,
        ));
        scope
    }

    /// An approver signs this statement only after authenticating the owner.
    /// `parent` is the device's enrollment id, or the directly trusted root.
    /// The receiver independently verifies all fields and permission.
    pub fn approval_statement(
        &self,
        parent: DelegationParent,
        issuer: [u8; 32],
        at_ms: u64,
    ) -> DelegationCertificate {
        DelegationCertificate::new(
            parent,
            issuer,
            self.target,
            self.scope(),
            at_ms,
            at_ms,
            Some(self.expires_at_ms),
            0,
            self.nonce,
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
