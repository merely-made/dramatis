// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Absolute authorization lifetime on a real synthetic vault, with injected time.

use super::*;

const WEEK: Duration = Duration::from_secs(604_800);

#[test]
fn activity_reconnect_and_duplicate_unlock_do_not_extend_the_week() {
    let (dir, _) = vault();
    let policy = config(dir.path(), "deny", "none");
    assert_eq!(policy.max_unlocked_seconds, Some(WEEK.as_secs()));
    let mut h = Harness::new(policy);
    let session = h.open(djinn());
    let start = h.now;
    h.unlock(session);
    let generation = h.core.generation();
    assert_eq!(h.core.next_deadline(), Some(start + WEEK));
    h.now = start + WEEK - Duration::from_secs(1);
    assert!(matches!(
        h.outcome(session, release(&["mesh-author"])),
        Outcome::Success { .. }
    ));
    let second = h.open(djinn());
    h.unlock(second);
    assert_eq!(h.core.generation(), generation);
    assert_eq!(h.core.next_deadline(), Some(start + WEEK));
    h.now = start + WEEK;
    let (_, effects) = h.request(second, Operation::Status {});
    assert!(h.core.status().locked);
    assert!(effects.messages.iter().any(|(_, message)| matches!(message,
        ServerMessage::Fact(fact) if fact.cause == FactCause::Lock)));
    assert_eq!(
        code(&h.outcome(second, release(&["mesh-author"]))),
        "locked"
    );
    assert_eq!(h.core.next_deadline(), None);
    h.unlock(second);
    assert_eq!(h.core.next_deadline(), Some(h.now + WEEK));
}

#[test]
fn configured_duration_expires_on_tick_and_cancels_pending_approval() {
    let (dir, _) = vault();
    let mut policy = config(dir.path(), "channel", "per-generation");
    policy.max_unlocked_seconds = Some(10);
    let mut h = Harness::new(policy);
    let helper = h.open(consent_helper());
    let session = h.open(djinn());
    h.unlock(session);
    let (id, requested) = h.request(session, release(&["mesh-author"]));
    assert!(petition_in(&requested, helper).is_some());
    h.now += Duration::from_secs(10);
    let expired = h.core.tick(h.now);
    assert!(h.core.status().locked);
    assert!(
        outcome_for(&expired, session, id).is_some_and(|outcome| code(&outcome) == "invalidated")
    );
    assert_eq!(h.core.next_deadline(), None);
}

#[test]
fn failed_unlock_has_no_deadline_and_explicit_indefinite_policy_still_locks() {
    let (dir, _) = vault();
    let mut policy = config(dir.path(), "deny", "none");
    policy.max_unlocked_seconds = None;
    let mut h = Harness::new(policy);
    let session = h.open(djinn());
    let wrong = h.outcome(
        session,
        Operation::Unlock {
            passphrase: Secret::copy_from(b"wrong"),
        },
    );
    assert!(!matches!(wrong, Outcome::Success { .. }));
    assert_eq!(h.core.next_deadline(), None);
    h.unlock(session);
    h.now += WEEK * 2;
    h.core.tick(h.now);
    assert!(!h.core.status().locked);
    assert_eq!(h.core.next_deadline(), None);
    h.outcome(session, Operation::Lock {});
    assert!(h.core.status().locked);
}

#[test]
fn owner_policy_refuses_zero_and_overflow_and_accepts_explicit_indefinite() {
    let (dir, _) = vault();
    let mut json = serde_json::json!({"vault":{"directory":dir.path()},"owner":{},
        "consent":"deny","principals":[],"max_unlocked_seconds":0});
    assert!(Config::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    json["max_unlocked_seconds"] = serde_json::json!(u64::MAX);
    assert!(Config::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    json["max_unlocked_seconds"] = serde_json::Value::Null;
    assert_eq!(
        Config::parse(&serde_json::to_vec(&json).unwrap())
            .unwrap()
            .max_unlocked_seconds,
        None
    );
}
