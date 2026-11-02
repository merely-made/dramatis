// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The application side of Castellan's custody route: the calls an
//! application makes over Djinn's door, their answers, sealed payloads and
//! quarantine review, and (with `client`) the custody and identity clients.
//! The door contract is `ostiary`; Castellan itself, which holds the
//! secrets, stays in Mere beside Djinn's resident.

#[cfg(all(any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody;
#[cfg(all(any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody_payload;
#[cfg(all(any(unix, windows), not(target_arch = "wasm32")))]
pub mod quarantine;

#[cfg(all(feature = "client", any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody_client;
#[cfg(all(feature = "client", any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody_identity;
