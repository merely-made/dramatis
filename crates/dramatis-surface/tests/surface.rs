// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The surface as a host sees it: snapshot, resolved cards, advertised actions
//! and the requests an intent queues.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use castellan_client::quarantine::{QuarantineCard, ReviewAction, UnassignedImport};
use chirograph::{
    AdvertisedAction, ContentHash, IntentInvocation, IntentResult, PortableCardV1,
    ProjectionSnapshot, ResourceRequest,
};
use dramatis::{
    roster::{Roster, RosterEntry},
    view::VaultLockView,
};
use dramatis_surface::intents::*;
use dramatis_surface::{Custody, DramatisSurface, Reply, Request, Snapshot};
use graphshell_endpoint::{IntentSink, PresentationSource, ProjectionSource};
use personae::ProfileId;
use sceno::InstanceId;

#[derive(Clone, Default)]
struct Fake {
    sent: Rc<RefCell<Vec<Request>>>,
    replies: Rc<RefCell<Vec<(Reply, bool)>>>,
}
impl Custody for Fake {
    fn send(&mut self, request: Request) {
        self.sent.borrow_mut().push(request);
    }
    fn drain(&mut self) -> Vec<(Reply, bool)> {
        std::mem::take(&mut *self.replies.borrow_mut())
    }
}

fn item(title: &str, byte: u8) -> chatelaine::Item {
    chatelaine::Item {
        id: chatelaine::ItemId::from_random([byte; 16]),
        source_id: None,
        title: title.into(),
        subtitle: Some("Imported from a browser export".into()),
        scope: None,
        tags: vec![],
        favorite: false,
        created_at: None,
        modified_at: None,
        credentials: vec![chatelaine::Credential {
            id: chatelaine::CredentialId::from_random([2; 16]),
            kind: chatelaine::CredentialKind::CreditCard {
                card_type: None,
                expiry: None,
                last_four: chatelaine::LastFour::parse("4242").ok(),
            },
        }],
        state: chatelaine::ItemState::Quarantined,
    }
}

fn snapshot(locked: bool, blocked: bool, imports: bool) -> Snapshot {
    let entry = |id: &str, name: &str, chosen| RosterEntry {
        id: ProfileId(id.into()),
        display_name: name.into(),
        slot_count: 0,
        chosen,
    };
    Snapshot {
        lock: if locked {
            VaultLockView::Locked
        } else {
            VaultLockView::Unlocked
        },
        roster: Roster {
            chosen: ProfileId("family".into()),
            description: String::new(),
            entries: vec![
                entry("family", "Family", true),
                entry("work", "Work", false),
            ],
        },
        cards: if locked {
            vec![]
        } else {
            vec![QuarantineCard {
                store: ProfileId("family".into()),
                persona: *personae::PersonaId::new().as_uuid(),
                item: item("Imported payment card for review", 1),
                revision: "exact-reviewed-metadata".into(),
                accept_blocked: blocked.then(|| "This credential type is not supported.".into()),
            }]
        },
        unassigned: if imports && !locked {
            vec![UnassignedImport {
                store: ProfileId("family".into()),
                persona: *personae::PersonaId::new().as_uuid(),
                titles: vec!["Older imported card".into()],
                item_count: 1,
                revision: "older-reviewed-metadata".into(),
            }]
        } else {
            vec![]
        },
    }
}

struct Host {
    surface: DramatisSurface<Fake>,
    fake: Fake,
}
impl Host {
    fn new(snapshot: Option<Snapshot>, notice: &str) -> Self {
        let fake = Fake::default();
        fake.replies.borrow_mut().push((
            Reply {
                snapshot,
                notice: notice.into(),
            },
            true,
        ));
        Self {
            surface: DramatisSurface::new(fake.clone()),
            fake,
        }
    }
    fn read(&mut self) -> ProjectionSnapshot {
        let request = self.surface.request();
        self.surface.snapshot(request).unwrap()
    }
    /// Every card with its instance, resolved the way a host does.
    fn cards(&mut self) -> Vec<(InstanceId, PortableCardV1, Vec<AdvertisedAction>)> {
        let snapshot = self.read();
        let mut out = Vec::new();
        for binding in &snapshot.presentation.bindings {
            let offer = &snapshot.presentation.offers[&binding.key][0];
            let bytes = self
                .surface
                .resource(ResourceRequest {
                    session: snapshot.session.clone(),
                    resource: offer.resource,
                })
                .unwrap()
                .bytes;
            assert_eq!(ContentHash::of(&bytes), offer.resource);
            out.push((
                binding.instance,
                serde_json::from_slice(&bytes).unwrap(),
                offer.semantics.actions.clone(),
            ));
        }
        out
    }
    fn find(&mut self, title: &str) -> (InstanceId, PortableCardV1, Vec<AdvertisedAction>) {
        self.cards()
            .into_iter()
            .find(|(_, card, _)| card.title == title)
            .unwrap_or_else(|| panic!("no card titled {title}"))
    }
    fn invoke(&mut self, title: &str, intent: &str, payload: Vec<u8>) -> IntentResult {
        let snapshot = self.read();
        let (target, _, _) = self.find(title);
        self.surface
            .invoke(IntentInvocation {
                session: snapshot.session,
                target,
                observed_epoch: snapshot.scene.epoch,
                observed_revision: snapshot.scene.revision,
                intent: intent.into(),
                payload,
            })
            .unwrap()
    }
    fn sent(&self) -> Vec<Request> {
        self.fake.sent.borrow().clone()
    }
}

fn intents(actions: &[AdvertisedAction]) -> Vec<&str> {
    actions.iter().map(|a| a.intent.0.as_str()).collect()
}
fn value<'a>(card: &'a PortableCardV1, label: &str) -> &'a str {
    &card.values.iter().find(|v| v.label == label).unwrap().value
}

#[test]
fn an_absent_djinn_serves_only_a_status_card_with_reconnect() {
    let mut host = Host::new(None, "Djinn is unavailable. Identity is pending.");
    let cards = host.cards();
    assert_eq!(cards.len(), 1);
    let (_, status, actions) = &cards[0];
    assert!(status.badges.contains(&"status".to_string()));
    assert!(value(status, "Connection").contains("Identity pending"));
    assert_eq!(
        value(status, "Notice"),
        "Djinn is unavailable. Identity is pending."
    );
    assert_eq!(intents(actions), [RECONNECT_INTENT]);
}

#[test]
fn the_unlocked_surface_serves_roster_quarantine_and_every_action_form() {
    let mut host = Host::new(Some(snapshot(false, false, true)), "");
    let cards = host.cards();
    let titles: Vec<_> = cards.iter().map(|(_, c, _)| c.title.as_str()).collect();
    assert_eq!(titles.len(), 8);
    assert_eq!(
        [
            titles[0], titles[1], titles[2], titles[3], titles[4], titles[6], titles[7]
        ],
        [
            "Status",
            "Vault",
            "Authentication",
            "Family",
            "Work",
            "Quarantine review",
            "Imported payment card for review"
        ]
    );
    assert!(titles[5].starts_with("1 items · "));
    let (_, vault, vault_actions) = host.find("Vault");
    assert_eq!(value(&vault, "State"), "Unlocked");
    assert_eq!(intents(&vault_actions), [LOCK_INTENT]);
    let (_, _, auth) = host.find("Authentication");
    assert_eq!(intents(&auth), [CHANGE_PASSPHRASE_INTENT]);
    let (_, family, family_actions) = host.find("Family");
    assert!(family.badges.contains(&"in use".to_string()));
    assert!(family_actions.is_empty());
    let (_, work, work_actions) = host.find("Work");
    assert_eq!(intents(&work_actions), [CHOOSE_PERSONA_INTENT]);
    assert_eq!(value(&work, "Choice"), "Available to choose.");
    let (_, review, review_actions) = host.find("Imported payment card for review");
    assert_eq!(value(&review, "Import store"), "family");
    assert_eq!(value(&review, "Details"), "Imported from a browser export");
    assert!(value(&review, "Credentials").contains("credit-card"));
    assert!(value(&review, "Review").starts_with("Imported for review."));
    assert_eq!(
        intents(&review_actions),
        [ACCEPT_ITEM_INTENT, DELETE_ITEM_INTENT]
    );
    let import = cards
        .iter()
        .find(|(_, c, _)| c.badges == ["older import"])
        .unwrap();
    assert_eq!(value(&import.1, "Destination"), "Family");
    let form = import.2[0].input_form.as_ref().unwrap();
    form.validate().unwrap();
    assert_eq!(form.fields[0].choices.len(), 1);
    assert_eq!(form.fields[0].choices[0].value, "family");
}

#[test]
fn no_card_carries_a_card_number_or_a_secret_field() {
    let mut host = Host::new(Some(snapshot(false, false, true)), "");
    let encoded = serde_json::to_string(
        &host
            .cards()
            .iter()
            .map(|(_, c, _)| c.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    // The fixture's last four digits are metadata chatelaine keeps secret-free
    // for the item, but the review card names only the credential kind.
    assert!(!encoded.contains("4242"));
    assert!(!encoded.contains("passphrase\":"));
}

#[test]
fn a_locked_vault_offers_only_unlock_and_reconnect_and_no_persona_actions() {
    let mut host = Host::new(Some(snapshot(true, false, true)), "");
    let cards = host.cards();
    assert!(cards.iter().all(|(_, c, _)| c.badges != ["quarantined"]));
    assert!(cards.iter().all(|(_, c, _)| c.badges != ["older import"]));
    let (_, vault, vault_actions) = host.find("Vault");
    assert_eq!(value(&vault, "State"), "Locked");
    assert_eq!(intents(&vault_actions), [UNLOCK_INTENT]);
    assert!(host.find("Authentication").2.is_empty());
    let (_, work, work_actions) = host.find("Work");
    assert!(work_actions.is_empty());
    assert_eq!(
        value(&work, "Choice"),
        "Unlock the vault to choose a persona."
    );
    assert!(value(&host.find("Quarantine review").1, "Quarantine review").contains("sealed"));
    assert_eq!(
        host.invoke("Work", CHOOSE_PERSONA_INTENT, vec![]),
        IntentResult::Rejected {
            reason: "intent was not advertised for the selected card".into()
        }
    );
    assert!(host.sent().is_empty());
}

#[test]
fn unsupported_acceptance_is_not_offered_but_delete_names_the_exact_card() {
    let mut host = Host::new(Some(snapshot(false, true, false)), "");
    let (_, review, actions) = host.find("Imported payment card for review");
    assert!(review.badges.contains(&"accept blocked".to_string()));
    assert_eq!(
        value(&review, "Review"),
        "This credential type is not supported."
    );
    assert_eq!(intents(&actions), [DELETE_ITEM_INTENT]);
    let refused = host.invoke(
        "Imported payment card for review",
        ACCEPT_ITEM_INTENT,
        vec![],
    );
    assert!(matches!(refused, IntentResult::Rejected { .. }));
    assert!(host.sent().is_empty());
    let accepted = host.invoke(
        "Imported payment card for review",
        DELETE_ITEM_INTENT,
        vec![],
    );
    assert_eq!(accepted, IntentResult::Accepted);
    match &host.sent()[..] {
        [Request::Review(r)] => {
            assert_eq!(r.action, ReviewAction::Delete);
            assert_eq!(r.profile.0, "family");
            assert_eq!(r.store.0, "family");
            assert_eq!(r.revision, "exact-reviewed-metadata");
        },
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepting_and_choosing_queue_exactly_one_request_and_busy_blocks_the_next() {
    let mut host = Host::new(Some(snapshot(false, false, false)), "");
    assert_eq!(
        host.invoke(
            "Imported payment card for review",
            ACCEPT_ITEM_INTENT,
            vec![]
        ),
        IntentResult::Accepted
    );
    assert!(matches!(&host.sent()[..], [Request::Review(r)] if r.action == ReviewAction::Accept));
    // While Djinn may be at a prompt nothing is advertised, and the status
    // card says it is waiting.
    let cards = host.cards();
    assert!(cards.iter().all(|(_, _, actions)| actions.is_empty()));
    assert_eq!(
        value(&host.find("Status").1, "Request"),
        "Waiting for Djinn."
    );
    // The answer returns, with its notice, and actions come back.
    host.fake.replies.borrow_mut().push((
        Reply {
            snapshot: Some(snapshot(false, false, false)),
            notice: "Review cancelled.".into(),
        },
        true,
    ));
    let status = host.find("Status");
    assert_eq!(value(&status.1, "Notice"), "Review cancelled.");
    assert_eq!(intents(&status.2), [RECONNECT_INTENT]);
    assert_eq!(
        host.invoke("Work", CHOOSE_PERSONA_INTENT, vec![]),
        IntentResult::Accepted
    );
    assert!(matches!(host.sent().last(), Some(Request::Select(p)) if p.0 == "work"));
}

#[test]
fn vault_lock_unlock_and_passphrase_change_are_public_requests() {
    let mut host = Host::new(Some(snapshot(false, false, false)), "");
    assert_eq!(
        host.invoke("Authentication", CHANGE_PASSPHRASE_INTENT, vec![]),
        IntentResult::Accepted
    );
    assert!(matches!(
        host.sent().last(),
        Some(Request::ChangePassphrase)
    ));
    host.fake.replies.borrow_mut().push((
        Reply {
            snapshot: Some(snapshot(false, false, false)),
            notice: String::new(),
        },
        true,
    ));
    assert_eq!(
        host.invoke("Vault", LOCK_INTENT, vec![]),
        IntentResult::Accepted
    );
    assert!(matches!(host.sent().last(), Some(Request::Lock)));
    host.fake.replies.borrow_mut().push((
        Reply {
            snapshot: Some(snapshot(true, false, false)),
            notice: String::new(),
        },
        true,
    ));
    assert_eq!(
        host.invoke("Vault", UNLOCK_INTENT, vec![]),
        IntentResult::Accepted
    );
    assert!(matches!(host.sent().last(), Some(Request::Unlock)));
}

#[test]
fn older_import_assignment_names_the_destination_and_exact_revision() {
    let mut host = Host::new(Some(snapshot(false, false, true)), "");
    let (_, card, actions) = host
        .cards()
        .into_iter()
        .find(|(_, c, _)| c.badges == ["older import"])
        .unwrap();
    let action = &actions[0];
    let title = card.title.clone();
    // No destination: refused by the form, nothing queued.
    let none = host.invoke(&title, ASSIGN_IMPORT_INTENT, vec![]);
    assert!(matches!(none, IntentResult::Rejected { .. }));
    // A destination the form does not offer is refused.
    let mut wrong = BTreeMap::new();
    wrong.insert(ASSIGN_DESTINATION_FIELD.to_string(), "work".to_string());
    assert!(action.compose_payload(&wrong).is_err());
    let forged = serde_json::to_vec(&serde_json::json!({
        "schema": ASSIGN_IMPORT_SCHEMA, "persona": "work"
    }))
    .unwrap();
    assert!(matches!(
        host.invoke(&title, ASSIGN_IMPORT_INTENT, forged),
        IntentResult::Rejected { .. }
    ));
    assert!(host.sent().is_empty());
    let mut chosen = BTreeMap::new();
    chosen.insert(ASSIGN_DESTINATION_FIELD.to_string(), "family".to_string());
    let payload = action.compose_payload(&chosen).unwrap();
    assert_eq!(
        host.invoke(&title, ASSIGN_IMPORT_INTENT, payload),
        IntentResult::Accepted
    );
    assert!(matches!(&host.sent()[..], [Request::Assign(r)]
        if r.profile.0 == "family" && r.revision == "older-reviewed-metadata"));
}

#[test]
fn an_intent_against_an_old_snapshot_is_stale_and_queues_nothing() {
    let mut host = Host::new(Some(snapshot(false, false, false)), "");
    let old = host.read();
    let (target, _, _) = host.find("Work");
    host.fake.replies.borrow_mut().push((
        Reply {
            snapshot: Some(snapshot(true, false, false)),
            notice: String::new(),
        },
        false,
    ));
    let result = host
        .surface
        .invoke(IntentInvocation {
            session: old.session.clone(),
            target,
            observed_epoch: old.scene.epoch,
            observed_revision: old.scene.revision,
            intent: CHOOSE_PERSONA_INTENT.into(),
            payload: vec![],
        })
        .unwrap();
    assert!(matches!(result, IntentResult::Stale { .. }));
    assert!(host.sent().is_empty());
}

#[test]
fn the_status_card_keeps_its_place_whatever_the_notice_says() {
    let mut host = Host::new(Some(snapshot(false, false, false)), "");
    let before = host.cards();
    assert_eq!(before[0].1.title, "Status");
    host.fake.replies.borrow_mut().push((
        Reply {
            snapshot: Some(snapshot(false, false, false)),
            notice: "Passphrase changed.".into(),
        },
        true,
    ));
    let after = host.cards();
    assert_eq!(after[0].1.title, "Status");
    assert_eq!(after.len(), before.len());
    assert_eq!(value(&after[0].1, "Notice"), "Passphrase changed.");
}

#[test]
fn a_session_other_than_the_surfaces_is_refused() {
    let mut host = Host::new(None, "");
    let mut request = host.surface.request();
    request.session.0 = "native:other".into();
    assert!(host.surface.snapshot(request).is_err());
}
