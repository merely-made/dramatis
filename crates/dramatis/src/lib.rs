// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Secret-free identity contracts for applications using the Djinn resident.
//!
//! *Dramatis personae*: the persons of the drama. The tier holds both sides of
//! identity, your faces and the other players, which is why the name is the
//! full cast list rather than any one role:
//!
//! - **personae** — the trust-plane spine: master keypair, per-protocol
//!   derivation, sealed records, carry.
//! - **gaz** — stored contacts: anchored records, petnames, per-endpoint
//!   trust, kith/kin tiers.
//! - **gazette** — handle resolution: turning a name into reachable,
//!   unverified address claims.
//!
//! The boundaries are the point:
//!
//! - **Not the data plane.** Persistence is the eidetic family (muniment,
//!   muniment journals, chartulary). The planes bond at the seal seam and the sync gate;
//!   dramatis holds keys and trust, never the bytes they seal.
//! - **Not a product.** *Persona* is an in-product term for a face; dramatis
//!   names the tier so the term stays free.
//!
//! The dramatis repo plan's DR-A moved the identity surface's plain types
//! here (ruling D24): [`intents`], [`view`], [`receipts`] and, with DR-C, the
//! [`roster`]. Member crates remain separate dependencies. Vault custody
//! belongs to Castellan, composed only inside Djinn in Mere.
//!
//! [`resources`] adds explicit subject/resource links, and [`birth`] describes
//! reusable original biographical facts. These values may be private personal
//! data: they do not join the public identity views. The receiving resident
//! personal-facts domain owns their durable revisions, admission and access.

#![doc(html_no_source)]

pub mod birth;
pub mod intents;
pub mod receipts;
pub mod resources;
pub mod roster;
pub mod subject;
pub mod view;

mod validation;

pub mod authentication;
