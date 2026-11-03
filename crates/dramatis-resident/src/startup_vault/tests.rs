// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::collections::VecDeque;

struct Script(VecDeque<Option<&'static str>>, Vec<Ask>);

impl Prompt for Script {
    fn ask(&mut self, ask: &Ask) -> Result<Answer, String> {
        self.1.push(ask.clone());
        match self.0.pop_front() {
            Some(Some(text)) => Ok(Answer::Passphrase(Zeroizing::new(text.into()))),
            Some(None) => Ok(Answer::Cancelled),
            None => Err("script ended".into()),
        }
    }
}

fn script(answers: &[Option<&'static str>]) -> Script {
    Script(answers.iter().copied().collect(), Vec::new())
}

struct Log(Vec<String>);

impl Waiting for Log {
    fn emit(&mut self, event: &str, _fields: serde_json::Value) {
        self.0.push(event.into());
    }
}

fn start(dir: &Path, prompt: &mut Script) -> (Result<Started, String>, Vec<String>, Vec<Duration>) {
    start_as(dir, VaultChoice::Passphrase, prompt)
}

fn start_as(
    dir: &Path,
    choice: VaultChoice,
    prompt: &mut Script,
) -> (Result<Started, String>, Vec<String>, Vec<Duration>) {
    let mut log = Log(Vec::new());
    let mut slept = Vec::new();
    let started = open(dir, choice, prompt, &mut log, &mut |wait| slept.push(wait));
    (started, log.0, slept)
}

fn create(dir: &Path) {
    let (started, ..) = start(dir, &mut script(&[Some("right"), Some("right")]));
    let started = started.unwrap();
    let id = personae::vault::ProfileId("p".into());
    bootstrap::load_or_create_profile(&*started.opened.storage, &id).unwrap();
}

#[test]
fn first_run_asks_twice_and_a_mismatch_asks_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = script(&[Some("one"), Some("two"), Some("right"), Some("right")]);
    let (started, events, _) = start(dir.path(), &mut prompt);
    assert!(started.is_ok());
    assert_eq!(events, ["waiting-for-unlock", "vault-created"]);
    assert_eq!(prompt.1[0], Ask::Create { retry: None });
    assert_eq!(prompt.1[1], Ask::Confirm);
    assert_eq!(
        prompt.1[2],
        Ask::Create {
            retry: Some("The two passphrases did not match.".into())
        }
    );
}

#[test]
fn a_wrong_passphrase_and_a_cancel_ask_again_and_the_right_one_opens() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path());
    let mut prompt = script(&[Some("wrong"), None, Some("right")]);
    let (started, events, slept) = start(dir.path(), &mut prompt);
    let started = started.unwrap();
    assert_eq!(
        events,
        [
            "waiting-for-unlock",
            "unlock-refused",
            "unlock-cancelled",
            "unlocked-at-start"
        ]
    );
    assert_eq!(
        slept,
        [backoff(0)],
        "only the cancel waits; Argon2 throttles a miss"
    );
    assert!(matches!(prompt.1[1], Ask::Unlock { retry: Some(_) }));
    let (_, choice) = started.into_parts();
    assert_eq!(choice, VaultChoice::Passphrase);
}

#[test]
fn an_empty_passphrase_is_refused_without_opening() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path());
    let mut prompt = script(&[Some(""), Some("right")]);
    let (started, events, _) = start(dir.path(), &mut prompt);
    assert!(started.is_ok());
    assert_eq!(events, ["waiting-for-unlock", "unlocked-at-start"]);
}

#[test]
fn with_nothing_to_ask_with_the_start_fails() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path());
    let (started, ..) = start(dir.path(), &mut script(&[]));
    assert!(started.is_err());
}

#[test]
fn a_handed_over_passphrase_gets_one_try() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path());
    let mut log = Log(Vec::new());
    let wrong = open(
        dir.path(),
        VaultChoice::Passphrase,
        &mut Given::new(Zeroizing::new("wrong".into())),
        &mut log,
        &mut |_| panic!("a handed-over passphrase never waits"),
    );
    assert!(wrong.is_err());
    let right = open(
        dir.path(),
        VaultChoice::Passphrase,
        &mut Given::new(Zeroizing::new("right".into())),
        &mut log,
        &mut |_| panic!("a handed-over passphrase never waits"),
    );
    assert!(right.is_ok());
}

#[test]
fn a_handed_over_passphrase_creates_a_missing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let created = open(
        dir.path(),
        VaultChoice::Passphrase,
        &mut Given::new(Zeroizing::new("new".into())),
        &mut Log(Vec::new()),
        &mut |_| panic!("a handed-over passphrase never waits"),
    );
    assert!(created.is_ok());
}

#[test]
fn the_choice_follows_the_platform_the_flag_and_the_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(choose(dir.path(), true), VaultChoice::Passphrase);
    let bare = choose(dir.path(), false);
    assert_eq!(bare == VaultChoice::AutoOs, cfg!(windows));
    std::fs::write(dir.path().join(PASSPHRASE_VAULT_FILE), b"{}").unwrap();
    assert_eq!(choose(dir.path(), false), VaultChoice::Passphrase);
}

/// Rulings 5, 76 and 80 on Windows: an OS-rooted vault opens unattended
/// until its lock persists, then waits for the passphrase, and opens
/// unattended again once that unlock cleared the marker.
#[cfg(windows)]
#[test]
fn a_persisted_lock_makes_the_os_vault_wait_for_its_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    {
        let storage = SealedProfileStorage::open_auto_os(dir.path())
            .unwrap()
            .unwrap();
        let id = personae::vault::ProfileId("p".into());
        bootstrap::load_or_create_profile(&storage, &id).unwrap();
        storage.enroll_passphrase(b"right").unwrap();
    }
    assert_eq!(
        choose(dir.path(), true),
        VaultChoice::AutoOs,
        "the OS vault is there"
    );

    let (unattended, events, _) = start_as(dir.path(), VaultChoice::AutoOs, &mut script(&[]));
    assert!(unattended.is_ok());
    assert!(events.is_empty(), "no lock persisted: no prompt");

    castellan::custody::persist_lock(dir.path()).unwrap();
    let mut prompt = script(&[Some("wrong"), None, Some("right")]);
    let (started, events, slept) = start_as(dir.path(), VaultChoice::AutoOs, &mut prompt);
    let (opened, choice) = started.unwrap().into_parts();
    assert_eq!(choice, VaultChoice::AutoOs);
    assert!(!opened.storage.is_locked());
    assert_eq!(
        events,
        [
            "waiting-for-unlock",
            "unlock-refused",
            "unlock-cancelled",
            "unlocked-at-start"
        ]
    );
    assert_eq!(slept, [backoff(0)]);
    assert!(
        !castellan::custody::lock_persisted(dir.path()),
        "the unlock cleared the marker"
    );
    drop(opened);

    let (again, events, _) = start_as(dir.path(), VaultChoice::AutoOs, &mut script(&[]));
    assert!(again.is_ok());
    assert!(events.is_empty());
}

#[test]
fn backoff_doubles_to_thirty_seconds() {
    let waits: Vec<u64> = (0..8).map(|n| backoff(n).as_secs()).collect();
    assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
}
