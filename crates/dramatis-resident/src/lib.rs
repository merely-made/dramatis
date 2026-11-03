// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Resident identity and custody service over the independently launched custodian.
//! Hosts supply admission, projections, native interaction and service lifetimes.
pub mod custody;
pub mod custody_host;
pub mod custodian;
pub mod enrollment;
pub mod identity;
pub mod identity_ui;
pub mod keeper;
pub mod native;
#[cfg(feature = "in-process-custody")]
pub mod profile;
pub mod startup_vault;
