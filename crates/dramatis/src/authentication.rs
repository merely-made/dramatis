// SPDX-License-Identifier: MPL-2.0
//! Public local authentication requests and receipts. Secrets stay with the resident.
use serde::{Deserialize, Serialize};

/// Ask Djinn to verify the current credential and collect a replacement natively.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePassphraseIntentV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassphraseChangeFailureV1 {
    Locked,
    Unsupported,
    CurrentPassphraseRejected,
    InvalidNewPassphrase,
    ConfirmationMismatch,
    UiUnavailable,
    StorageFailure,
}

/// Only a successful durable replacement yields Changed. No credential is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PassphraseChangeReceiptV1 {
    Changed,
    Cancelled,
    Rejected { reason: PassphraseChangeFailureV1 },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_request_cannot_carry_credentials_and_receipts_round_trip() {
        assert!(
            serde_json::from_str::<ChangePassphraseIntentV1>(r#"{"passphrase":"secret"}"#).is_err()
        );
        for value in [
            PassphraseChangeReceiptV1::Changed,
            PassphraseChangeReceiptV1::Cancelled,
            PassphraseChangeReceiptV1::Rejected {
                reason: PassphraseChangeFailureV1::CurrentPassphraseRejected,
            },
        ] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(value, serde_json::from_str(&json).unwrap());
        }
    }
}

/// The established family/application profile override. Its spelling preserves existing installations.
pub const PROFILE_ENV: &str = "GRAPHSHELL_PROFILE";

pub fn env_profile() -> Option<personae::ProfileId> {
    std::env::var(PROFILE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(personae::ProfileId)
}

