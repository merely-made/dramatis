// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The macOS consent channel: `djinn-custodian consent`, a launchd agent in
//! the owner's Aqua session, signed under its own identifier
//! (`com.merely.djinn.custodian.consent`) so the custodian's policy admits it
//! as the consent channel by code signature, not as "some process of this
//! user". It puts each petition to the owner through LocalAuthentication's
//! `deviceOwnerAuthentication` (Touch ID where enrolled, else the account
//! password), the macOS counterpart of Windows Hello and polkit `auth_self`.
//! A message box is not presence and is not used: only the OS's own
//! authentication result approves. Unavailability, cancellation, timeout and
//! every error are a refusal, like the other platforms.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use custody_wire::Petition;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::helper::{Verifier, message};

/// The owner's presence, asked of the OS.
pub struct Presence {
    /// How long the owner has; the custody consent expiry by default.
    pub deadline: Duration,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            deadline: custody_wire::limits::CONSENT,
        }
    }
}

impl Verifier for Presence {
    fn verify(&self, petition: &Petition) -> bool {
        authenticate(&message(petition), self.deadline)
    }
}

/// Ask the OS to authenticate the owner for `reason`; `true` only on success.
pub fn authenticate(reason: &str, deadline: Duration) -> bool {
    let policy = LAPolicy::DeviceOwnerAuthentication;
    let context = unsafe { LAContext::new() };
    if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
        return false;
    }
    let (sender, receiver) = mpsc::channel::<bool>();
    let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        let _ = sender.send(success.as_bool());
    });
    let reason = NSString::from_str(reason);
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };
    let accepted = receiver.recv_timeout(deadline).unwrap_or(false);
    // A timeout or a decided prompt: either way the context is finished.
    unsafe { context.invalidate() };
    accepted
}
