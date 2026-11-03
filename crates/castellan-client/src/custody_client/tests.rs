// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use personae::{IdentityProvider, InMemoryProvider};

use super::*;
use crate::custody::ReleasedKey;

#[cfg(unix)]
#[test]
fn bounded_custody_status_times_out_a_stalled_handshake() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    use std::time::{Duration, Instant};
    let path = std::path::PathBuf::from(format!(
        "/tmp/alembic-status-{}.sock",
        uuid::Uuid::new_v4().simple()
    ));
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && stopped.try_recv().is_err() {
            match listener.accept() {
                Ok((_stream, _)) => {
                    let _ = stopped.recv_timeout(Duration::from_secs(3));
                    break;
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                },
                Err(_) => break,
            }
        }
    });
    let start = Instant::now();
    let result = BlockingCustodyClient::status_at_timeout(
        path.to_str().unwrap(),
        AppId::new("turnstone"),
        None,
        Duration::from_millis(150),
    );
    let elapsed = start.elapsed();
    let _ = stop.send(());
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        matches!(result, Err(CustodyClientError::Transport(AppClientError::Io(ref error)))
        if error.kind() == std::io::ErrorKind::TimedOut)
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "status must not wait for the stalled resident"
    );
}

fn release_of(provider: &InMemoryProvider, salts: &[&[u8]]) -> CustodyAnswer {
    CustodyAnswer::Released {
        master: provider.master_public_key().to_bytes(),
        keys: salts
            .iter()
            .map(|salt| ReleasedKey {
                salt: salt.to_vec(),
                seed: provider.derive_keypair(salt).unwrap().to_seed(),
                attestation: provider.attest_derived_key(salt).unwrap(),
            })
            .collect(),
    }
}

#[test]
fn a_release_answers_its_salts_and_locks_the_rest() {
    let provider = InMemoryProvider::from_seed([0x41; 32]);
    let keys = expect_released(release_of(&provider, &[b"mesh-author"])).unwrap();
    assert_eq!(
        keys.derive_keypair(b"mesh-author").unwrap().to_seed(),
        provider.derive_keypair(b"mesh-author").unwrap().to_seed()
    );
    assert!(matches!(
        keys.derive_keypair(b"anything-else"),
        Err(IdentityError::Locked)
    ));
}

#[test]
fn a_release_whose_key_is_not_its_attestations_is_refused() {
    let provider = InMemoryProvider::from_seed([0x42; 32]);
    let CustodyAnswer::Released { master, mut keys } = release_of(&provider, &[b"mesh-author"])
    else {
        unreachable!()
    };
    keys[0].seed = [0x13; 32];
    let forged = CustodyAnswer::Released { master, keys };
    assert!(matches!(
        expect_released(forged),
        Err(CustodyClientError::Release(_))
    ));
}

#[test]
fn absent_and_locked_are_pending_and_nothing_else_is() {
    let absent = CustodyClientError::Absent(AppClientError::Closed);
    assert!(absent.is_pending());
    assert!(CustodyClientError::Refused(CustodyRefusal::Locked).is_pending());
    assert!(!CustodyClientError::Refused(CustodyRefusal::NotReleasable).is_pending());
}
