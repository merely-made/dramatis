// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Public-only approval route. A transport authenticates its target separately;
//! forwarding a command is never permission to execute a custody operation.

use insigne::delegation::{SignedDelegationCertificate, SignedDelegationRevocation};
use serde::{Deserialize, Serialize};

use super::{ApprovalAction, ApprovalProof, ApprovalRequest};
use crate::contract::Petition;

/// Only these records cross an approval relay, never general custody requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RemoteCommand {
    State {},
    Challenge {},
    Enroll {
        grant: SignedDelegationCertificate,
    },
    Revoke {
        revocation: SignedDelegationRevocation,
    },
    Approve {
        nonce: [u8; 32],
        proof: ApprovalProof,
    },
    Unlock {},
}

/// Protected target pins plus current public authority records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteState {
    pub root_authority: [u8; 32],
    pub root_issuer: [u8; 32],
    pub target: [u8; 32],
    pub profile: String,
    pub instance: String,
    pub generation: u64,
    pub locked: bool,
    pub actions: Vec<ApprovalAction>,
    pub max_grant_seconds: u64,
    /// Active registered grants only. Reading this never renews their expiry.
    pub enrollments: Vec<SignedDelegationCertificate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RemoteReply {
    State {
        state: RemoteState,
    },
    Challenge {
        petition: Petition,
        request: ApprovalRequest,
    },
    Done {},
    Refused {
        code: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_route_rejects_credentials_general_operations_and_approval_hints() {
        for value in [
            serde_json::json!({"command":"state","passphrase":"credential"}),
            serde_json::json!({"command":"challenge","approved":true}),
            serde_json::json!({"command":"unlock","passphrase":"credential"}),
            serde_json::json!({"command":"sign","message":[]}),
            serde_json::json!({"command":"release","salts":[]}),
        ] {
            assert!(serde_json::from_value::<RemoteCommand>(value).is_err());
        }
    }
}
