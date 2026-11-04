// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use custody_wire::remote_approval::{ApprovalAction, enrollment_scope};
use insigne::delegation::{DelegationCertificate, DelegationRevocation};
use personae::delegation::Issue;
use personae::{IdentityProvider, InMemoryProvider};

const NOW: u64 = 1_790_000_000_000;

struct Fixture {
    directory: tempfile::TempDir,
    root: InMemoryProvider,
    policy: ApprovalPolicy,
}

impl Fixture {
    fn new() -> Self {
        let root = InMemoryProvider::from_seed([0x31; 32]);
        let issuer = root.master_public_key().to_bytes();
        let policy = ApprovalPolicy::weekly(
            TrustedRoot {
                authority: issuer,
                issuer,
            },
            [3; 32],
            "work".into(),
            [ApprovalAction::Consent],
        );
        Self {
            directory: tempfile::tempdir().unwrap(),
            root,
            policy,
        }
    }
    fn grant(&self) -> SignedDelegationCertificate {
        SignedDelegationCertificate::issue(
            &self.root,
            DelegationCertificate::new(
                insigne::delegation::DelegationParent::Root(self.policy.root.authority),
                self.policy.root.issuer,
                InMemoryProvider::from_seed([2; 32])
                    .master_public_key()
                    .to_bytes(),
                enrollment_scope(self.policy.target, "work", [ApprovalAction::Consent]),
                NOW,
                NOW,
                Some(NOW + 604_800_000),
                1,
                [4; 32],
            ),
        )
        .unwrap()
    }
    fn initialize(&self) -> EnrollmentStore {
        EnrollmentStore::initialize(self.directory.path(), &self.policy).unwrap();
        EnrollmentStore::open(self.directory.path(), &self.policy).unwrap()
    }
    fn revoke(&self, grant: &SignedDelegationCertificate) -> SignedDelegationRevocation {
        SignedDelegationRevocation::issue(
            &self.root,
            DelegationRevocation::new(
                grant.certificate.id(),
                grant.certificate.issuer,
                grant.certificate.scope.clone(),
                NOW,
                [5; 32],
            ),
        )
        .unwrap()
    }
}

#[test]
fn missing_state_never_initializes_and_explicit_setup_never_overwrites() {
    let f = Fixture::new();
    assert_eq!(
        EnrollmentStore::open(f.directory.path(), &f.policy).err(),
        Some(Refusal("remote-store-missing"))
    );
    assert!(!f.directory.path().join(FILE).exists());
    let store = f.initialize();
    assert!(EnrollmentStore::initialize(f.directory.path(), &f.policy).is_err());
    assert!(
        EnrollmentStore::open(f.directory.path(), &f.policy).is_err(),
        "one exclusive database owner"
    );
    drop(store);
    assert!(EnrollmentStore::open(f.directory.path(), &f.policy).is_ok());
}

#[test]
fn enrollment_and_revocation_survive_reopen_and_duplicate_delivery_is_idempotent() {
    let f = Fixture::new();
    let grant = f.grant();
    let mut store = f.initialize();
    store.enroll(grant.clone(), NOW).unwrap();
    let revision = store.revision;
    store.enroll(grant.clone(), NOW + 1).unwrap();
    assert_eq!(store.revision, revision);
    drop(store);
    let mut store = EnrollmentStore::open(f.directory.path(), &f.policy).unwrap();
    assert_eq!(store.snapshot().unwrap().enrollments, vec![grant.clone()]);
    assert!(store.revoke(f.revoke(&grant), NOW).unwrap());
    assert!(!store.revoke(f.revoke(&grant), NOW + 1).unwrap());
    drop(store);
    let mut store = EnrollmentStore::open(f.directory.path(), &f.policy).unwrap();
    assert!(store.snapshot().unwrap().ledger.revokes(&grant.certificate));
    assert!(
        store.enroll(grant, NOW + 1).is_err(),
        "an old grant cannot undo a durable withdrawal"
    );
}

#[test]
fn an_out_of_order_signed_withdrawal_blocks_later_enrollment_after_restart() {
    let f = Fixture::new();
    let grant = f.grant();
    let mut store = f.initialize();
    assert!(store.revoke(f.revoke(&grant), NOW).unwrap());
    drop(store);
    let mut store = EnrollmentStore::open(f.directory.path(), &f.policy).unwrap();
    assert!(store.snapshot().unwrap().ledger.revokes(&grant.certificate));
    assert!(store.enroll(grant, NOW).is_err());
}

#[test]
fn every_persisted_record_is_checked_and_missing_or_corrupt_state_fails_closed() {
    for bytes in [b"garbage".to_vec(), b"{}".to_vec()] {
        let f = Fixture::new();
        let mut store = f.initialize();
        pollster::block_on(store.backend.put(SLOT, &bytes)).unwrap();
        assert!(store.snapshot().is_err());
        assert_eq!(
            store.snapshot().err().map(|e| e.0),
            Some("remote-store-unavailable")
        );
        drop(store);
        assert!(EnrollmentStore::open(f.directory.path(), &f.policy).is_err());
    }
    let f = Fixture::new();
    let mut store = f.initialize();
    pollster::block_on(store.backend.delete(SLOT)).unwrap();
    assert!(store.snapshot().is_err());
    drop(store);
    assert!(EnrollmentStore::open(f.directory.path(), &f.policy).is_err());
}

#[test]
fn a_changed_root_target_or_profile_cannot_reuse_the_database() {
    for change in [0, 1, 2] {
        let f = Fixture::new();
        drop(f.initialize());
        let mut policy = f.policy.clone();
        match change {
            0 => policy.root.issuer = [8; 32],
            1 => policy.target = [9; 32],
            _ => policy.profile = "other".into(),
        }
        assert_eq!(
            EnrollmentStore::open(f.directory.path(), &policy).err(),
            Some(Refusal("remote-store-binding"))
        );
    }
}

#[test]
fn invalid_grants_and_revocations_cannot_change_the_ledger_or_poison_good_state() {
    let f = Fixture::new();
    let mut store = f.initialize();
    let grant = f.grant();
    let mut tampered = grant.clone();
    tampered.certificate.scope.path_prefix.push_str("/changed");
    assert!(store.enroll(tampered, NOW).is_err());
    store.enroll(grant.clone(), NOW).unwrap();
    let mut revoke = f.revoke(&grant);
    revoke.revocation.issuer = [7; 32];
    assert!(store.revoke(revoke, NOW).is_err());
    assert!(!store.snapshot().unwrap().ledger.revokes(&grant.certificate));
    let mut future = f.revoke(&grant);
    future.revocation.at_ms = NOW + 1;
    future = SignedDelegationRevocation::issue(&f.root, future.revocation).unwrap();
    assert!(store.revoke(future, NOW).is_err());
    assert!(store.revoke(f.revoke(&grant), NOW).unwrap());
}

#[test]
fn restoring_an_older_revision_in_the_live_database_is_detected() {
    let f = Fixture::new();
    let mut store = f.initialize();
    let old = pollster::block_on(store.backend.get(SLOT))
        .unwrap()
        .unwrap();
    store.enroll(f.grant(), NOW).unwrap();
    pollster::block_on(store.backend.put(SLOT, &old)).unwrap();
    assert_eq!(
        store.snapshot().err().map(|e| e.0),
        Some("remote-store-binding")
    );
}

#[test]
fn expired_records_survive_as_history_but_cannot_be_installed_again() {
    let f = Fixture::new();
    let mut store = f.initialize();
    let grant = f.grant();
    store.enroll(grant.clone(), NOW).unwrap();
    assert!(store.enroll(grant, NOW + 604_800_000).is_err());
    drop(store);
    assert!(EnrollmentStore::open(f.directory.path(), &f.policy).is_ok());
}

#[test]
fn narrowed_owner_settings_keep_history_and_revocation_without_reauthorizing_it() {
    let f = Fixture::new();
    let mut store = f.initialize();
    let grant = f.grant();
    store.enroll(grant.clone(), NOW).unwrap();
    store.revoke(f.revoke(&grant), NOW).unwrap();
    drop(store);
    let mut narrowed = f.policy.clone();
    narrowed.actions.clear();
    narrowed.max_grant_seconds = 60;
    let mut store = EnrollmentStore::open(f.directory.path(), &narrowed).unwrap();
    assert!(store.snapshot().unwrap().ledger.revokes(&grant.certificate));
    assert!(store.enroll(grant, NOW).is_err());
}

#[cfg(unix)]
#[test]
fn indirect_or_desktop_writable_state_is_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    std::fs::set_permissions(f.directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(EnrollmentStore::initialize(f.directory.path(), &f.policy).is_err());
    std::fs::set_permissions(f.directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path().join("state"), f.directory.path().join(FILE)).unwrap();
    assert!(EnrollmentStore::initialize(f.directory.path(), &f.policy).is_err());
    assert!(EnrollmentStore::open(f.directory.path(), &f.policy).is_err());
}
