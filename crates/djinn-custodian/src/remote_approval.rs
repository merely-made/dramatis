// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Target-side verification of remote custody approval (custody plan VL-U).
//!
//! This portable gate takes protected owner policy and the authoritative
//! current revocation ledger. It needs no vault secret, SSH agent or unlocked
//! identity. It does not open storage, approve OS elevation, or execute a
//! petition. The target host must wire that separate commit barrier, recheck
//! context/revocation there, and support its backend before enabling a route.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use custody_wire::remote_approval::{
    ApprovalAction, ApprovalOperation, ApprovalProof, ApprovalRequest, DOMAIN, WEEK_SECONDS,
    enrollment_scope,
};
use insigne::delegation::{CapabilityScope, DelegationId, SignedDelegationCertificate};
use notochord::{RevocationLedger, TrustedRoot, validate_chain};

use crate::{Refusal, Result};

pub(crate) mod runtime;
pub mod storage;

/// Local owner policy, never a value accepted from a remote requester.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicy {
    pub root: TrustedRoot,
    pub target: [u8; 32],
    pub profile: String,
    pub actions: BTreeSet<ApprovalAction>,
    #[serde(default = "weekly_seconds")]
    pub max_grant_seconds: u64,
    #[serde(default = "weekly_seconds")]
    pub max_unlock_seconds: u64,
}

fn weekly_seconds() -> u64 {
    WEEK_SECONDS
}

impl ApprovalPolicy {
    pub(crate) fn validate_for_vault(
        &self,
        profile: Option<&str>,
        limit: Option<u64>,
    ) -> Result<()> {
        ApprovalGate::new(self.clone(), "policy-check".into(), 1)?;
        if profile != Some(self.profile.as_str())
            || limit.is_some_and(|seconds| self.max_unlock_seconds > seconds)
        {
            return Err(Refusal("remote-profile-or-limit"));
        }
        Ok(())
    }

    /// The selected one-week limits, with explicit operation permissions.
    /// A root pin without an action grants no remote custody authority.
    pub fn weekly(
        root: TrustedRoot,
        target: [u8; 32],
        profile: String,
        actions: impl IntoIterator<Item = ApprovalAction>,
    ) -> Self {
        Self {
            root,
            target,
            profile,
            actions: actions.into_iter().collect(),
            max_grant_seconds: WEEK_SECONDS,
            max_unlock_seconds: WEEK_SECONDS,
        }
    }
}

struct Pending {
    request: ApprovalRequest,
    started: Instant,
    deadline: Instant,
}

/// A local, single-use verification result. It contains no key or credential.
/// Hosts must complete the exact operation before its deadline and must not
/// cache this value as renewed authority across a lock, restart or revocation.
pub struct VerifiedApproval {
    request: ApprovalRequest,
    approver: [u8; 32],
    unlock_until_ms: Option<u64>,
}

/// A checked enrollment, not a completed pairing or an approval of any act.
pub struct CheckedEnrollment {
    device: [u8; 32],
    certificate: DelegationId,
    expires_at_ms: u64,
}

impl CheckedEnrollment {
    pub fn device(&self) -> [u8; 32] {
        self.device
    }
    pub fn certificate(&self) -> DelegationId {
        self.certificate
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl VerifiedApproval {
    pub fn request(&self) -> &ApprovalRequest {
        &self.request
    }
    pub fn approver(&self) -> [u8; 32] {
        self.approver
    }
    /// Effective absolute bound, capped by the signed root grant. Consent
    /// approves an existing petition and never renews its authorization.
    pub fn unlock_until_ms(&self) -> Option<u64> {
        self.unlock_until_ms
    }
}

/// Ephemeral request state. Restarts drop it; durable root pins and current
/// revocations are supplied by the protected host, not a proof's sender.
pub struct ApprovalGate {
    policy: ApprovalPolicy,
    instance: String,
    generation: u64,
    pending: HashMap<[u8; 32], Pending>,
    last_wall_ms: u64,
}

const REQUEST_SECONDS: u64 = custody_wire::limits::CONSENT.as_secs();
const MAX_PENDING: usize = custody_wire::limits::MAX_QUEUED_OPERATIONS;

impl ApprovalGate {
    /// Construct after loading the target's protected policy. A target key
    /// must be pinned/authenticated while locked; it is not an IP address.
    ///
    /// # Errors
    /// Refuses empty/oversized identities and zero or overflowing limits.
    pub fn new(policy: ApprovalPolicy, instance: String, generation: u64) -> Result<Self> {
        if policy.root.authority == [0; 32]
            || policy.root.issuer == [0; 32]
            || policy.target == [0; 32]
            || policy.profile.is_empty()
            || policy.profile.len() > 128
            || instance.is_empty()
            || instance.len() > 128
            || generation == 0
            || policy.max_grant_seconds == 0
            || policy.max_unlock_seconds == 0
            || policy.max_grant_seconds.checked_mul(1000).is_none()
            || policy.max_unlock_seconds.checked_mul(1000).is_none()
        {
            return Err(Refusal("remote-policy"));
        }
        Ok(Self {
            policy,
            instance,
            generation,
            pending: HashMap::new(),
            last_wall_ms: 0,
        })
    }

    /// Feed authoritative custody facts before processing network messages.
    /// A generation change, including lock/revocation, invalidates requests.
    ///
    /// # Errors
    /// Refuses invalid instance ids and regressing same-instance generations.
    pub fn synchronize(&mut self, instance: &str, generation: u64) -> Result<()> {
        if instance.is_empty()
            || instance.len() > 128
            || generation == 0
            || (instance == self.instance && generation < self.generation)
        {
            return Err(Refusal("remote-context"));
        }
        if instance != self.instance || generation != self.generation {
            self.pending.clear();
            self.instance = instance.into();
            self.generation = generation;
        }
        Ok(())
    }

    /// Check the root's enrollment before presenting/registering a device.
    /// The host persists the public certificate through its existing store;
    /// every subsequent approval still checks the current revocation ledger.
    ///
    /// # Errors
    /// Refuses malformed, untrusted, revoked, expired, oversized or excessive
    /// lifetime grants, and a scope outside this target/profile/action policy.
    pub fn check_enrollment(
        &self,
        grant: &SignedDelegationCertificate,
        ledger: &RevocationLedger,
        now_ms: u64,
    ) -> Result<CheckedEnrollment> {
        if !bounded_scope(&grant.certificate.scope)
            || grant.signature().len() != 64
            || grant.signer.signature().len() != 64
        {
            return Err(Refusal("remote-proof-size"));
        }
        validate_chain(
            std::slice::from_ref(grant),
            grant.certificate.subject,
            &[self.policy.root],
            ledger,
            1,
            now_ms,
        )
        .map_err(|_| Refusal("remote-chain"))?;
        let expires_at_ms = self.enrollment_scope_and_lifetime(grant, now_ms)?;
        Ok(CheckedEnrollment {
            device: grant.certificate.subject,
            certificate: grant.certificate.id(),
            expires_at_ms,
        })
    }

    /// Validate immutable history without treating it as current permission.
    /// Narrower owner settings must not erase signed withdrawals or make old
    /// enrollment records corrupt. Actual use still calls `check_enrollment`.
    pub(crate) fn check_stored_enrollment(
        &self,
        grant: &SignedDelegationCertificate,
    ) -> Result<()> {
        if !bounded_scope(&grant.certificate.scope)
            || grant.signature().len() != 64
            || grant.signer.signature().len() != 64
        {
            return Err(Refusal("remote-proof-size"));
        }
        validate_chain(
            std::slice::from_ref(grant),
            grant.certificate.subject,
            &[self.policy.root],
            &RevocationLedger::new(),
            1,
            grant.certificate.not_before_ms,
        )
        .map_err(|_| Refusal("remote-chain"))?;
        self.enrollment_shape(grant).map(|_| ())
    }

    /// Create a bounded challenge. This does not require the target vault to
    /// be open. The trusted host, not a remote frame, selects the operation.
    ///
    /// # Errors
    /// Refuses clock rollback, missing permission, invalid duration, full
    /// request capacity, arithmetic overflow or unavailable randomness.
    pub fn begin(
        &mut self,
        operation: ApprovalOperation,
        now_ms: u64,
        now: Instant,
    ) -> Result<ApprovalRequest> {
        self.expire(now_ms, now)?;
        if !self.policy.actions.contains(&operation.action()) {
            return Err(Refusal("remote-action"));
        }
        if matches!(&operation, ApprovalOperation::Unlock { seconds } if *seconds == 0 || *seconds > self.policy.max_unlock_seconds)
        {
            return Err(Refusal("remote-duration"));
        }
        if matches!(&operation, ApprovalOperation::Unlock { seconds } if now_ms.checked_add(seconds.saturating_mul(1000)).is_none())
        {
            return Err(Refusal("remote-time"));
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Refusal("remote-capacity"));
        }
        let expires_at_ms = now_ms
            .checked_add(REQUEST_SECONDS * 1000)
            .ok_or(Refusal("remote-time"))?;
        let deadline = now
            .checked_add(Duration::from_secs(REQUEST_SECONDS))
            .ok_or(Refusal("remote-time"))?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Refusal("randomness-unavailable"))?;
        if self.pending.contains_key(&nonce) {
            return Err(Refusal("remote-nonce"));
        }
        let request = ApprovalRequest {
            target: self.policy.target,
            profile: self.policy.profile.clone(),
            instance: self.instance.clone(),
            generation: self.generation,
            nonce,
            operation,
            issued_at_ms: now_ms,
            expires_at_ms,
        };
        self.pending.insert(
            nonce,
            Pending {
                request: request.clone(),
                started: now,
                deadline,
            },
        );
        Ok(request)
    }

    /// Verify and consume one exact approval, using the current ledger loaded
    /// by custody. No cached chain check survives revocation. Invalid proofs
    /// do not consume the legitimate request; a successful proof is one-use.
    ///
    /// # Errors
    /// Refuses missing/expired requests, invalid or revoked chains, any request
    /// binding mismatch, excessive grant lifetime and clock/arithmetic faults.
    pub fn accept(
        &mut self,
        nonce: [u8; 32],
        proof: &ApprovalProof,
        ledger: &RevocationLedger,
        now_ms: u64,
        now: Instant,
    ) -> Result<VerifiedApproval> {
        self.expire(now_ms, now)?;
        let request = &self
            .pending
            .get(&nonce)
            .ok_or(Refusal("remote-not-pending"))?
            .request;
        let grant_expires = self.check_proof(request, proof, ledger, now_ms)?;
        let unlock_until_ms = match request.operation {
            ApprovalOperation::Unlock { seconds } => {
                let until = now_ms
                    .checked_add(seconds * 1000)
                    .ok_or(Refusal("remote-time"))?;
                Some(grant_expires.map_or(until, |expires| until.min(expires)))
            },
            ApprovalOperation::Consent { .. } => None,
        };
        let approver = proof
            .chain
            .last()
            .ok_or(Refusal("remote-chain"))?
            .certificate
            .issuer;
        let pending = self
            .pending
            .remove(&nonce)
            .ok_or(Refusal("remote-not-pending"))?;
        Ok(VerifiedApproval {
            request: pending.request,
            approver,
            unlock_until_ms,
        })
    }

    /// Withdraw a request when its local petition or requesting session ends.
    pub fn cancel(&mut self, nonce: [u8; 32]) {
        self.pending.remove(&nonce);
    }

    fn expire(&mut self, now_ms: u64, now: Instant) -> Result<()> {
        if now_ms < self.last_wall_ms || self.pending.values().any(|p| now < p.started) {
            self.pending.clear();
            return Err(Refusal("remote-clock"));
        }
        self.last_wall_ms = now_ms;
        self.pending
            .retain(|_, p| now_ms < p.request.expires_at_ms && now < p.deadline);
        Ok(())
    }

    fn check_proof(
        &self,
        request: &ApprovalRequest,
        proof: &ApprovalProof,
        ledger: &RevocationLedger,
        now_ms: u64,
    ) -> Result<Option<u64>> {
        if proof.chain.is_empty() || proof.chain.len() > 2 {
            return Err(Refusal("remote-chain"));
        }
        // Bound allocations in Insigne's canonical signing bytes before checking.
        if proof.chain.iter().any(|signed| {
            !bounded_scope(&signed.certificate.scope)
                || signed.signature().len() != 64
                || signed.signer.signature().len() != 64
        }) {
            return Err(Refusal("remote-proof-size"));
        }
        let checked = validate_chain(
            &proof.chain,
            self.policy.target,
            &[self.policy.root],
            ledger,
            2,
            now_ms,
        )
        .map_err(|_| Refusal("remote-chain"))?;
        let leaf = checked.certificate();
        if leaf.scope != request.scope()
            || leaf.nonce != request.nonce
            || leaf.remaining_delegation_depth != 0
            || leaf.issued_at_ms < request.issued_at_ms
            || leaf.not_before_ms != leaf.issued_at_ms
            || leaf.issued_at_ms > now_ms
            || !leaf
                .expires_at_ms
                .is_some_and(|expires| expires > now_ms && expires <= request.expires_at_ms)
        {
            return Err(Refusal("remote-request-binding"));
        }
        if proof.chain.len() == 1 {
            return Ok(None);
        }
        self.enrollment_scope_and_lifetime(&proof.chain[0], now_ms)
            .map(Some)
    }

    fn enrollment_scope_and_lifetime(
        &self,
        signed: &SignedDelegationCertificate,
        now_ms: u64,
    ) -> Result<u64> {
        let expires = self.enrollment_shape(signed)?;
        let root_grant = &signed.certificate;
        let allowed = self
            .policy
            .actions
            .iter()
            .map(|action| action.as_str().to_string())
            .collect();
        if !root_grant.scope.actions.is_subset(&allowed) {
            return Err(Refusal("remote-enrollment-scope"));
        }
        if expires <= now_ms
            || expires.saturating_sub(root_grant.issued_at_ms)
                > self.policy.max_grant_seconds * 1000
        {
            return Err(Refusal("remote-grant-duration"));
        }
        Ok(expires)
    }

    fn enrollment_shape(&self, signed: &SignedDelegationCertificate) -> Result<u64> {
        let root_grant = &signed.certificate;
        let expected = enrollment_scope(
            self.policy.target,
            &self.policy.profile,
            [ApprovalAction::Unlock, ApprovalAction::Consent],
        );
        if root_grant.scope.domain != DOMAIN
            || root_grant.scope.resource != expected.resource
            || root_grant.scope.path_prefix != expected.path_prefix
            || !root_grant.scope.actions.is_subset(&expected.actions)
            || root_grant.remaining_delegation_depth != 1
        {
            return Err(Refusal("remote-enrollment-scope"));
        }
        let expires = root_grant
            .expires_at_ms
            .ok_or(Refusal("remote-grant-duration"))?;
        if expires <= root_grant.not_before_ms {
            return Err(Refusal("remote-grant-duration"));
        }
        Ok(expires)
    }
}

fn bounded_scope(scope: &CapabilityScope) -> bool {
    scope.domain.len() <= 64
        && scope.resource.len() == 32
        && scope.path_prefix.len() <= 2048
        && scope.actions.len() <= 2
        && scope.actions.iter().all(|action| action.len() <= 16)
}

#[cfg(test)]
mod tests;
