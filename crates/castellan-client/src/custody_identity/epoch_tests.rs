// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

fn actorless_fixture() -> (CustodyIdentity, mpsc::Receiver<Job>) {
    use personae::IdentityProvider as _;
    let root = personae::InMemoryProvider::from_seed([7; 32]);
    let master = root.master_public_key();
    let (jobs, receiver) = mpsc::channel();
    let identity = CustodyIdentity {
        endpoint: "/tmp/alembic-no-custody-runtime-test.sock".into(),
        app: AppId::new("turnstone"),
        declaration: None,
        requested_profile: None,
        master,
        status: ResidentStatus {
            lock: VaultLockView::Unlocked,
            protection: dramatis::view::VaultProtectionView::Ephemeral,
            profile: Some(ProfileId("test".into())),
            persona_public_key: Some(master.to_bytes()),
            wallet_public_key: None,
            wallet_root: None,
            custody_epoch: None,
        },
        jobs: Mutex::new(Some(jobs)),
        job_thread: Mutex::new(None),
        watch_thread: Mutex::new(None),
        call_timeout: Some(Duration::from_secs(2)),
        held: Arc::default(),
        locked: Arc::new(AtomicBool::new(false)),
        epoch: Arc::new(AtomicU64::new(1)),
        stop: Arc::new(AtomicBool::new(false)),
    };
    (identity, receiver)
}

#[test]
fn bounded_payload_is_safe_inside_tokio_runtime() {
    const CHILD: &str = "MERE_CUSTODY_NESTED_RUNTIME_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "custody_identity::epoch_tests::bounded_payload_is_safe_inside_tokio_runtime",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "payload must not panic in Tokio: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "child must execute the payload regression"
        );
        return;
    }
    let (identity, _receiver) = actorless_fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let _ = eidetic::PayloadSealer::seal(&identity, &eidetic::Hash::of(b"test"), b"test");
    });
}

#[test]
fn fresh_status_must_match_original_authoritative_epoch_profile_and_master() {
    let (mut identity, _receiver) = actorless_fixture();
    identity.status.custody_epoch = Some(crate::custody::CustodyEpoch {
        instance: "test-custodian".into(),
        generation: 4,
    });
    let original = identity.status.clone();
    assert!(identity.status_matches_binding(&original));
    let mut changed = original.clone();
    changed.custody_epoch.as_mut().unwrap().generation += 1;
    assert!(!identity.status_matches_binding(&changed));
    let mut changed = original.clone();
    changed.profile = Some(ProfileId("other".into()));
    assert!(!identity.status_matches_binding(&changed));
    let mut changed = original.clone();
    changed.persona_public_key = Some([0; 32]);
    assert!(!identity.status_matches_binding(&changed));
    let mut changed = original;
    changed.custody_epoch = None;
    assert!(!identity.status_matches_binding(&changed));
}

#[test]
fn simultaneous_callers_can_enqueue_without_waiting_for_each_other() {
    let (identity, receiver) = actorless_fixture();
    let identity = Arc::new(identity);
    let first = identity.clone();
    let one = std::thread::spawn(move || first.status());
    let first_job = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("first caller queued");
    let second = identity.clone();
    let two = std::thread::spawn(move || second.status());
    let second_job = receiver.recv_timeout(Duration::from_millis(500));
    assert!(
        second_job.is_ok(),
        "another caller must enqueue before the first answer"
    );
    first_job.run(None);
    second_job.unwrap().run(None);
    assert!(one.join().unwrap().is_err());
    assert!(two.join().unwrap().is_err());
}

#[cfg(unix)]
#[test]
fn watcher_drop_joins_while_handshake_is_stalled() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    use std::time::Instant;
    let path = std::path::PathBuf::from(format!(
        "/tmp/alembic-watch-{}.sock",
        uuid::Uuid::new_v4().simple()
    ));
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            let _ = accepted_tx.send(());
            let _ = stop_rx.recv_timeout(Duration::from_secs(3));
        }
    });
    let (identity, _receiver) = actorless_fixture();
    identity.watch(path.to_str().unwrap().into(), AppId::new("turnstone"), None);
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("watcher connected");
    let start = Instant::now();
    drop(identity);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "watcher stop must interrupt stalled handshake"
    );
    let _ = stop_tx.send(());
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn failed_initialization_closes_and_joins_actor() {
    let (sender, receiver) = mpsc::channel::<Job>();
    let exited = Arc::new(AtomicBool::new(false));
    let observed = exited.clone();
    let worker = std::thread::spawn(move || {
        while receiver.recv().is_ok() {}
        observed.store(true, Ordering::SeqCst);
    });
    let result: Result<(), ()> = (|| {
        let _starting = StartingActor {
            sender: Some(sender),
            thread: Some(worker),
            stop: Arc::new(AtomicBool::new(false)),
        };
        Err(())
    })();
    assert!(result.is_err());
    assert!(
        exited.load(Ordering::SeqCst),
        "constructor failure must join its actor"
    );
}

#[test]
fn caller_timeout_retires_a_queued_job_before_dispatch() {
    let (sender, receiver) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        ask_on_bounded(&sender, Some(Duration::from_millis(30)), |_| Ok(()))
    });
    let job: Job = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        caller.join().unwrap(),
        Err(CustodyClientError::Transport(_))
    ));
    assert!(job.expired());
    assert!(job.run(None), "expired job must not touch a provider");
}

#[test]
fn timed_out_or_cancelled_queued_job_never_dispatches() {
    let calls = Arc::new(AtomicU64::new(0));
    for (deadline, cancelled) in [
        (Some(Instant::now()), false),
        (Some(Instant::now() + Duration::from_secs(30)), true),
    ] {
        let observed = calls.clone();
        let job = Job {
            deadline,
            cancelled: Arc::new(AtomicBool::new(cancelled)),
            call: Box::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                true
            }),
        };
        assert!(job.run(None));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let observed = calls.clone();
    let job = Job {
        deadline: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        call: Box::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            true
        }),
    };
    assert!(job.run(None));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn custody_epoch_remembers_lock_unlock_between_observations() {
    let locked = AtomicBool::new(false);
    let epoch = AtomicU64::new(1);
    let admitted = epoch.load(Ordering::SeqCst);
    invalidate_epoch(&locked, &epoch);
    invalidate_epoch(&locked, &epoch);
    locked.store(false, Ordering::SeqCst);
    assert!(!locked.load(Ordering::SeqCst));
    assert_ne!(epoch.load(Ordering::SeqCst), admitted);
    assert_eq!(epoch.load(Ordering::SeqCst), 2);
    invalidate_epoch(&locked, &epoch);
    assert_eq!(epoch.load(Ordering::SeqCst), 3);
}

#[test]
fn custody_epoch_exhaustion_does_not_reuse_an_old_generation() {
    let epoch = AtomicU64::new(u64::MAX);
    advance_epoch(&epoch);
    assert_eq!(epoch.load(Ordering::SeqCst), 0);
    advance_epoch(&epoch);
    assert_eq!(epoch.load(Ordering::SeqCst), 0);
}
