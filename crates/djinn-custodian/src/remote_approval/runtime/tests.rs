// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use custody_wire::remote_approval::enrollment_scope;
use insigne::delegation::{DelegationCertificate, DelegationParent, DelegationRevocation};
use notochord::TrustedRoot;
use personae::delegation::Issue;
use personae::{IdentityProvider, InMemoryProvider};

const NOW: u64 = 1_790_000_000_000;

struct Fixture {
    _directory: tempfile::TempDir,
    root: InMemoryProvider,
    grant: SignedDelegationCertificate,
    runtime: RemoteRuntime,
    now: Instant,
}

impl Fixture {
    fn new() -> Self {
        let directory = crate::tests::protected_directory();
        let root = InMemoryProvider::from_seed([1; 32]);
        let device = InMemoryProvider::from_seed([2; 32]);
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
        EnrollmentStore::initialize(directory.path(), &policy).unwrap();
        let mut runtime =
            RemoteRuntime::open(directory.path(), policy, "instance".into(), 1).unwrap();
        let grant = SignedDelegationCertificate::issue(
            &root,
            DelegationCertificate::new(
                DelegationParent::Root(issuer),
                issuer,
                device.master_public_key().to_bytes(),
                enrollment_scope([3; 32], "work", [ApprovalAction::Consent]),
                NOW,
                NOW,
                Some(NOW + 5000),
                1,
                [4; 32],
            ),
        )
        .unwrap();
        runtime.enroll(grant.clone(), NOW).unwrap();
        let now = Instant::now();
        let request = runtime
            .begin(
                ApprovalOperation::Consent {
                    request: 1,
                    digest: [7; 32],
                },
                NOW,
                now,
            )
            .unwrap();
        let proof = ApprovalProof {
            chain: vec![
                grant.clone(),
                SignedDelegationCertificate::issue(
                    &device,
                    request.approval_for_device(&grant, NOW),
                )
                .unwrap(),
            ],
        };
        let (_, authority) = runtime.accept(request.nonce, &proof, NOW, now).unwrap();
        runtime.remember(("client".into(), 0, 1), authority, None, NOW, now);
        Self {
            _directory: directory,
            root,
            grant,
            runtime,
            now,
        }
    }
    fn revoke(&self) -> SignedDelegationRevocation {
        SignedDelegationRevocation::issue(
            &self.root,
            DelegationRevocation::new(
                self.grant.certificate.id(),
                self.grant.certificate.issuer,
                self.grant.certificate.scope.clone(),
                NOW,
                [8; 32],
            ),
        )
        .unwrap()
    }
    fn cached(&mut self, wall: u64, now: Instant) -> Result<bool> {
        self.runtime.cached("client", 0, 1, wall, now)
    }
}

#[test]
fn every_cache_hit_checks_the_current_stored_revocation_ledger() {
    let mut f = Fixture::new();
    assert!(f.cached(NOW, f.now).unwrap());
    // Bypass the runtime's normal cache clear: the lookup must consult storage.
    f.runtime.store.revoke(f.revoke(), NOW).unwrap();
    assert!(!f.cached(NOW, f.now).unwrap());
}

#[test]
fn invalid_remote_withdrawals_cannot_cancel_good_cached_authorization() {
    let mut f = Fixture::new();
    let mut revoke = f.revoke();
    revoke.revocation.issuer = [9; 32];
    assert!(f.runtime.revoke(revoke, NOW).is_err());
    assert!(f.cached(NOW, f.now).unwrap());
}

#[test]
fn cache_use_reconnect_and_clock_changes_never_renew_the_original_bound() {
    for wall_expiry in [false, true] {
        let mut f = Fixture::new();
        assert!(f.cached(NOW + 1, f.now + Duration::from_millis(1)).unwrap());
        f.runtime.synchronize("instance", 1).unwrap();
        let (wall, instant) = if wall_expiry {
            (NOW + 5000, f.now + Duration::from_millis(2))
        } else {
            (NOW + 2, f.now + Duration::from_millis(5000))
        };
        assert!(!f.cached(wall, instant).unwrap());
    }
    let mut f = Fixture::new();
    assert!(f.cached(NOW + 10, f.now).unwrap());
    assert!(f.cached(NOW + 9, f.now).is_err());
    assert!(!f.cached(NOW + 10, f.now).unwrap());
}
