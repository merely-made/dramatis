// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The intents the surface advertises and the one schema that carries a choice.
//!
//! Only [`ASSIGN_IMPORT_INTENT`] has an input form. Every other action is
//! decided by the card it sits on: the target names the persona, the
//! quarantined item or the vault, and the surface checks that target against
//! the snapshot the host acted on before it queues anything.

/// Ask Djinn to read again. Offered on the status card.
pub const RECONNECT_INTENT: &str = "dramatis.reconnect";
pub const RECONNECT_SCHEMA: &str = "dramatis.reconnect/v1";
/// Unlock the vault. Djinn asks for the passphrase in its own prompt.
pub const UNLOCK_INTENT: &str = "dramatis.vault.unlock";
pub const UNLOCK_SCHEMA: &str = "dramatis.vault.unlock/v1";
/// Lock the vault.
pub const LOCK_INTENT: &str = "dramatis.vault.lock";
pub const LOCK_SCHEMA: &str = "dramatis.vault.lock/v1";
/// Change the vault passphrase. Djinn asks for both passphrases natively.
pub const CHANGE_PASSPHRASE_INTENT: &str = "dramatis.passphrase.change";
pub const CHANGE_PASSPHRASE_SCHEMA: &str = "dramatis.passphrase.change/v1";
/// Choose the persona on the card the action sits on.
pub const CHOOSE_PERSONA_INTENT: &str = "dramatis.persona.choose";
pub const CHOOSE_PERSONA_SCHEMA: &str = "dramatis.persona.choose/v1";
/// Accept the quarantined item on the card.
pub const ACCEPT_ITEM_INTENT: &str = "dramatis.quarantine.accept";
pub const ACCEPT_ITEM_SCHEMA: &str = "dramatis.quarantine.accept/v1";
/// Delete the quarantined item on the card.
pub const DELETE_ITEM_INTENT: &str = "dramatis.quarantine.delete";
pub const DELETE_ITEM_SCHEMA: &str = "dramatis.quarantine.delete/v1";
/// Assign an older import to the chosen persona. The form's one field names
/// the destination, so the payload says where the items will go.
pub const ASSIGN_IMPORT_INTENT: &str = "dramatis.import.assign";
pub const ASSIGN_IMPORT_SCHEMA: &str = "dramatis.import.assign/v1";
/// The form field of [`ASSIGN_IMPORT_INTENT`]: the destination persona's id.
pub const ASSIGN_DESTINATION_FIELD: &str = "persona";
