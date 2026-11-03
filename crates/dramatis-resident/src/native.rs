// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Public native-interaction requests and bounded results.

use serde::{Deserialize, Serialize};
use dramatis::intents::SshUnlockPolicyIntentV1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NativeIdentityAction {
    ImportSshPrivate {
        unlock_policy: SshUnlockPolicyIntentV1,
    },
    /// Unlock the vault on the resident's own surface: OS presence first,
    /// then a passphrase box (vault lock ruling 47). Nothing crosses back.
    UnlockVault,
}

/// Public result of a native-only identity interaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeIdentityResult {
    ImportedSshPrivate {
        fingerprint: String,
        comment: String,
        unlock_policy: String,
        replaced_existing: bool,
    },
    /// The vault is unlocked (or already was).
    UnlockedVault,
    Cancelled,
    Rejected {
        reason: NativeIdentityFailure,
    },
}

/// Bounded public failure vocabulary. Local paths, key bytes, passphrases,
/// and parser diagnostics never become native-messaging responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeIdentityFailure {
    WrongSession,
    UiUnavailable,
    SelectedFileUnreadable,
    SelectedFileTooLarge,
    InvalidPrivateKey,
    IncorrectPassphrase,
    ImportRejected,
    /// The vault refused the unlock for a reason other than the passphrase.
    UnlockRejected,
}

