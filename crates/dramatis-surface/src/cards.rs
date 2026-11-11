// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The cards: a pure function of the secret-free [`State`].
//!
//! The same words the application's window used, as labelled values and badges.
//! Each card also names what its actions mean ([`Target`]) so an intent is
//! decided by the card it was sent to and never by free text.
use crate::intents::*;
use crate::state::{Snapshot, State};
use chirograph::{
    ActionFormChoiceV1, ActionFormFieldV1, ActionFormV1, AdvertisedAction, CardValueV1,
    IntentEffect, IntentReference, PortableCardV1,
};
use dramatis::view::VaultLockView;
use personae::ProfileId;

/// What a card's actions act on, indexed into the snapshot it was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Status,
    Vault,
    Authentication,
    Persona(ProfileId),
    Import(usize),
    Quarantine(usize),
    Summary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelCard {
    pub key: String,
    pub card: PortableCardV1,
    pub actions: Vec<AdvertisedAction>,
    pub target: Target,
}

fn value(label: &str, value: impl Into<String>) -> CardValueV1 {
    CardValueV1 {
        label: label.into(),
        value: value.into(),
    }
}

fn action(
    intent: &str,
    schema: &str,
    label: &str,
    explanation: &str,
    effect: IntentEffect,
) -> AdvertisedAction {
    AdvertisedAction {
        intent: IntentReference(intent.into()),
        label: label.into(),
        explanation: explanation.into(),
        payload_schema: schema.into(),
        input_form: None,
        effect,
        icon: None,
    }
}

fn card(title: &str, values: Vec<CardValueV1>, badges: &[&str]) -> PortableCardV1 {
    PortableCardV1 {
        title: title.into(),
        values,
        badges: badges.iter().map(|b| (*b).into()).collect(),
        media: Vec::new(),
    }
}

/// Every card the surface serves for `state`, in reading order.
///
/// An action is advertised only when the vault's lock state allows it:
/// nothing that reaches a secret is offered while the vault is locked. While a
/// request is outstanding the actions stay on their cards, so the controls a
/// person was using keep their place, and the status card carries the `busy`
/// badge; a host shows them disabled and `invoke` refuses them until Djinn
/// answers.
pub(crate) fn model(state: &State) -> Vec<ModelCard> {
    let mut cards = vec![status(state)];
    let Some(snapshot) = &state.snapshot else {
        return cards;
    };
    let locked = snapshot.lock == VaultLockView::Locked;
    cards.push(vault(locked));
    cards.push(authentication(locked));
    cards.extend(personae(snapshot, locked));
    if !locked {
        cards.extend(imports(snapshot));
    }
    cards.push(summary(snapshot, locked));
    if !locked {
        cards.extend(quarantine(snapshot));
    }
    cards
}

fn status(state: &State) -> ModelCard {
    let connection = match &state.snapshot {
        None => "Identity pending. Djinn must be running to manage your personae.",
        Some(_) => "Connected to Djinn.",
    };
    let mut values = vec![
        value("Connection", connection),
        value("Notice", state.notice.clone()),
    ];
    if state.busy {
        values.push(value("Request", "Waiting for Djinn."));
    }
    ModelCard {
        key: "dramatis:status".into(),
        // The badge `status` is the live region: it stays the first card and
        // keeps its place whatever the notice says.
        card: card(
            "Status",
            values,
            if state.busy {
                &["status", "busy"]
            } else {
                &["status"]
            },
        ),
        actions: vec![action(
            RECONNECT_INTENT,
            RECONNECT_SCHEMA,
            "Reconnect",
            "Ask Djinn for the current roster and vault state.",
            IntentEffect::Curation,
        )],
        target: Target::Status,
    }
}

fn vault(locked: bool) -> ModelCard {
    let (state, detail) = if locked {
        (
            "Locked",
            "Vault locked. Unlock with Djinn to choose a persona or review imports.",
        )
    } else {
        (
            "Unlocked",
            "Vault unlocked. Djinn holds your credentials and asks for consent.",
        )
    };
    let actions = if locked {
        vec![action(
            UNLOCK_INTENT,
            UNLOCK_SCHEMA,
            "Unlock with Djinn",
            "Djinn asks for the vault passphrase in its own native prompt.",
            IntentEffect::ExternalEffect,
        )]
    } else {
        vec![action(
            LOCK_INTENT,
            LOCK_SCHEMA,
            "Lock vault",
            "Djinn locks the vault. Quarantined items stay sealed until you unlock it.",
            IntentEffect::DomainTruth,
        )]
    };
    ModelCard {
        key: "dramatis:vault".into(),
        card: card(
            "Vault",
            vec![value("State", state), value("Detail", detail)],
            &["vault"],
        ),
        actions,
        target: Target::Vault,
    }
}

fn authentication(locked: bool) -> ModelCard {
    ModelCard {
        key: "dramatis:authentication".into(),
        card: card(
            "Authentication",
            vec![value(
                "Passphrase",
                "Change the passphrase for this computer’s vault. Djinn asks for the current and new passphrases in its own native prompts.",
            )],
            &["authentication"],
        ),
        actions: if locked {
            Vec::new()
        } else {
            vec![action(
                CHANGE_PASSPHRASE_INTENT,
                CHANGE_PASSPHRASE_SCHEMA,
                "Change passphrase…",
                "Djinn opens its native prompts. This surface never sees a passphrase.",
                IntentEffect::ExternalEffect,
            )]
        },
        target: Target::Authentication,
    }
}

fn personae(snapshot: &Snapshot, locked: bool) -> Vec<ModelCard> {
    snapshot
        .roster
        .entries
        .iter()
        .map(|entry| {
            let choice = if entry.chosen {
                "In use."
            } else if locked {
                "Unlock the vault to choose a persona."
            } else {
                "Available to choose."
            };
            let mut actions = Vec::new();
            if !locked && !entry.chosen {
                actions.push(action(
                    CHOOSE_PERSONA_INTENT,
                    CHOOSE_PERSONA_SCHEMA,
                    &format!("Choose {}", entry.display_name),
                    "Make this the persona in use. Djinn remembers the choice.",
                    IntentEffect::DomainTruth,
                ));
            }
            ModelCard {
                key: format!("dramatis:persona:{}", entry.id.0),
                card: card(
                    &entry.display_name,
                    vec![
                        value("Persona", entry.id.0.clone()),
                        value("Slots", entry.slot_count.to_string()),
                        value("Choice", choice),
                    ],
                    &[if entry.chosen { "in use" } else { "persona" }],
                ),
                actions,
                target: Target::Persona(entry.id.clone()),
            }
        })
        .collect()
}

fn imports(snapshot: &Snapshot) -> Vec<ModelCard> {
    let chosen = snapshot.roster.chosen_entry();
    snapshot
        .unassigned
        .iter()
        .enumerate()
        .map(|(index, import)| {
            let destination = chosen
                .map(|entry| entry.display_name.clone())
                .unwrap_or_else(|| snapshot.roster.chosen.0.clone());
            let mut values = vec![
                value("Import store", import.store.0.clone()),
                value("Destination", destination.clone()),
                value(
                    "Note",
                    "Assignment preserves each item’s state. Quarantined items still need review.",
                ),
            ];
            values.extend(
                import
                    .titles
                    .iter()
                    .take(8)
                    .map(|t| value("Item", t.clone())),
            );
            let mut assign = action(
                ASSIGN_IMPORT_INTENT,
                ASSIGN_IMPORT_SCHEMA,
                "Assign to this persona",
                "Ask Djinn to assign these older imports to the persona you name.",
                IntentEffect::DomainTruth,
            );
            assign.input_form = Some(ActionFormV1::new(ASSIGN_IMPORT_SCHEMA).with_field(
                ActionFormFieldV1::choice(
                    ASSIGN_DESTINATION_FIELD,
                    "Destination persona",
                    [ActionFormChoiceV1::new(
                        snapshot.roster.chosen.0.clone(),
                        destination,
                    )],
                ),
            ));
            ModelCard {
                key: format!("dramatis:import:{index}"),
                card: card(
                    &format!("{} items · {}", import.item_count, import.persona),
                    values,
                    &["older import"],
                ),
                actions: vec![assign],
                target: Target::Import(index),
            }
        })
        .collect()
}

fn summary(snapshot: &Snapshot, locked: bool) -> ModelCard {
    let mut values = Vec::new();
    if snapshot.roster.entries.is_empty() {
        values.push(value(
            "Personae",
            "No personae yet. Create one with Djinn's personae-vault tool.",
        ));
    }
    values.push(value(
        "Quarantine review",
        if locked {
            "Quarantined items stay sealed while the vault is locked.".to_string()
        } else if snapshot.cards.is_empty() {
            "No quarantined imports for this persona.".to_string()
        } else {
            format!(
                "{} quarantined imports for this persona.",
                snapshot.cards.len()
            )
        },
    ));
    ModelCard {
        key: "dramatis:summary".into(),
        card: card("Quarantine review", values, &["summary"]),
        actions: Vec::new(),
        target: Target::Summary,
    }
}

fn quarantine(snapshot: &Snapshot) -> Vec<ModelCard> {
    snapshot
        .cards
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let mut values = vec![value("Import store", entry.store.0.clone())];
            if let Some(subtitle) = &entry.item.subtitle {
                values.push(value("Details", subtitle.clone()));
            }
            values.push(value(
                "Credentials",
                entry
                    .item
                    .credentials
                    .iter()
                    .filter_map(|c| c.kind.cxf_type())
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
            values.push(value(
                "Review",
                match &entry.accept_blocked {
                    Some(reason) => reason.clone(),
                    None => "Imported for review. Djinn checks acceptance and asks for your consent."
                        .to_string(),
                },
            ));
            let mut badges = vec!["quarantined"];
            let mut actions = Vec::new();
            if entry.accept_blocked.is_some() {
                badges.push("accept blocked");
            }
            {
                if entry.accept_blocked.is_none() {
                    actions.push(action(
                        ACCEPT_ITEM_INTENT,
                        ACCEPT_ITEM_SCHEMA,
                        "Accept",
                        "Ask Djinn to accept this item. Djinn asks for your consent naming the item.",
                        IntentEffect::DomainTruth,
                    ));
                }
                actions.push(action(
                    DELETE_ITEM_INTENT,
                    DELETE_ITEM_SCHEMA,
                    "Delete",
                    "Ask Djinn to delete this item. Djinn asks for your consent naming the item.",
                    IntentEffect::DomainTruth,
                ));
            }
            ModelCard {
                key: format!("dramatis:quarantine:{}", entry.item.id),
                card: card(&entry.item.title, values, &badges),
                actions,
                target: Target::Quarantine(index),
            }
        })
        .collect()
}
