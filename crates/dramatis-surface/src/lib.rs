// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! **Dramatis as a producer.** The roster, quarantine review, vault lock and
//! passphrase change, offered to any host as portable cards plus bounded action
//! forms, and not as a window.
//!
//! A host mounts a [`DramatisSurface`] the way it mounts any projection
//! endpoint: it reads a snapshot, resolves each card, advertises each card's
//! actions, and sends back the intent a person chose. Everything stateful is
//! Dramatis's own ([`state`], [`worker`]); everything the host draws is
//! secret-free public metadata. Djinn still owns the vault and still shows the
//! consent and passphrase prompts natively, so a host that renders this
//! surface cannot approve anything on the person's behalf. It can only name
//! which item it presents, and Djinn's prompt names the exact item again.
//!
//! Contract only: this crate names Graphshell's published leaves from
//! crates.io (`chirograph`, `graphshell-endpoint`, `sceno`, `scenotime`) and no
//! toolkit, no host and no Mere crate. The card vocabulary fits quarantine
//! review as it stands (labelled values and badges), so no contract change is
//! carried.
//!
//! The carrier is the host's choice. This crate is written to run in the
//! host's process. Running it as a child over the stdio carrier waits for that
//! carrier to authenticate its peer; until then a custody surface does not
//! cross an unauthenticated pipe.

mod cards;
pub mod intents;
pub mod state;
mod surface;
pub mod worker;

pub use state::{Reply, Request, Snapshot, State, declaration, endpoint, execute_at};
pub use surface::{Custody, DramatisSurface, SURFACE_SESSION, SurfaceError};
pub use worker::Worker;
