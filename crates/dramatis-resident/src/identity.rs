// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Secret-free identity authority supplied to presentation adapters.

use dramatis::view::IdentitySurfaceSnapshot;

/// What the identity endpoint reads from the resident's identity authority:
/// the secret-free snapshot the cards project, and typed intents applied
/// back.
///
/// A host's door adapter can add retained door keys and transport framing.
/// This service contract needs neither graph projections nor a native surface.
pub trait IdentityAuthority: Send + Sync + 'static {
    /// The secret-free read model the identity cards project.
    fn snapshot(&self) -> std::io::Result<IdentitySurfaceSnapshot>;

    /// Apply one typed identity intent from an admitted session. The error
    /// is the reason shown to the caller.
    fn apply_intent(&self, intent: &str, payload: &[u8]) -> Result<(), String>;
}

