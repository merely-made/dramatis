// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Custody's live remote gate and revocation-bound per-generation consent.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use custody_wire::remote_approval::{
    ApprovalAction, ApprovalOperation, ApprovalProof, ApprovalRequest,
};
use insigne::delegation::{SignedDelegationCertificate, SignedDelegationRevocation};

use super::storage::EnrollmentStore;
use super::{ApprovalGate, ApprovalPolicy, VerifiedApproval};
use crate::{Refusal, Result};

type CacheKey = (String, usize, u64);

#[derive(Clone)]
pub(crate) struct Authority {
    enrollment: Option<SignedDelegationCertificate>,
    until_ms: u64,
}

impl Authority {
    pub fn valid_at(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }
}

#[cfg(test)]
mod tests;

struct Cached {
    authority: Authority,
    deadline: Instant,
}

pub(crate) struct RemoteRuntime {
    pub policy: ApprovalPolicy,
    store: EnrollmentStore,
    gate: ApprovalGate,
    context: (String, u64),
    cache: HashMap<CacheKey, Cached>,
    last_wall: u64,
}

impl RemoteRuntime {
    pub fn active_enrollments(&mut self, at_ms: u64) -> Result<Vec<SignedDelegationCertificate>> {
        let snapshot = self.store.snapshot()?;
        Ok(snapshot.enrollments.into_iter().filter(|grant| {
            self.gate.check_enrollment(grant, &snapshot.ledger, at_ms).is_ok()
        }).collect())
    }

    pub fn open(
        vault: &Path,
        policy: ApprovalPolicy,
        instance: String,
        generation: u64,
    ) -> Result<Self> {
        let store = EnrollmentStore::open(vault, &policy)?;
        let gate = ApprovalGate::new(policy.clone(), instance.clone(), generation)?;
        Ok(Self {
            policy,
            store,
            gate,
            context: (instance, generation),
            cache: HashMap::new(),
            last_wall: 0,
        })
    }

    pub fn synchronize(&mut self, instance: &str, generation: u64) -> Result<()> {
        self.gate.synchronize(instance, generation)?;
        if self.context != (instance.into(), generation) {
            self.cache.clear();
            self.context = (instance.into(), generation);
        }
        Ok(())
    }

    pub fn available(&self, profile: Option<&str>) -> bool {
        self.policy.actions.contains(&ApprovalAction::Consent)
            && profile == Some(self.policy.profile.as_str())
    }

    pub fn begin(
        &mut self,
        operation: ApprovalOperation,
        now_ms: u64,
        now: Instant,
    ) -> Result<ApprovalRequest> {
        self.check_clock(now_ms)?;
        self.store.snapshot()?;
        self.gate.begin(operation, now_ms, now)
    }

    pub fn accept(
        &mut self,
        nonce: [u8; 32],
        proof: &ApprovalProof,
        now_ms: u64,
        now: Instant,
    ) -> Result<(VerifiedApproval, Authority)> {
        self.check_clock(now_ms)?;
        let snapshot = self.store.snapshot()?;
        let enrollment = if proof.chain.len() == 2 {
            let presented = &proof.chain[0];
            if !snapshot
                .enrollments
                .iter()
                .any(|stored| stored == presented)
            {
                return Err(Refusal("remote-enrollment-missing"));
            }
            Some(presented.clone())
        } else {
            None
        };
        let verified = self
            .gate
            .accept(nonce, proof, &snapshot.ledger, now_ms, now)?;
        let maximum = now_ms
            .checked_add(self.policy.max_grant_seconds * 1000)
            .ok_or(Refusal("remote-time"))?;
        let until_ms = enrollment
            .as_ref()
            .and_then(|g| g.certificate.expires_at_ms)
            .unwrap_or(maximum)
            .min(maximum);
        Ok((
            verified,
            Authority {
                enrollment,
                until_ms,
            },
        ))
    }

    pub fn enroll(&mut self, grant: SignedDelegationCertificate, now_ms: u64) -> Result<()> {
        self.check_clock(now_ms)?;
        self.store.enroll(grant, now_ms)
    }

    pub fn revoke(&mut self, signed: SignedDelegationRevocation, now_ms: u64) -> Result<bool> {
        self.check_clock(now_ms)?;
        // Clear cached authority even if persistence fails. The store poisons
        // itself on a failed commit; no later lookup falls back to old trust.
        let result = self.store.revoke(signed, now_ms);
        if matches!(result, Ok(true))
            || result
                .as_ref()
                .is_err_and(|e| e.0.starts_with("remote-store"))
        {
            self.cache.clear();
        }
        result
    }

    pub fn remember(
        &mut self,
        key: CacheKey,
        authority: Authority,
        session_deadline: Option<Instant>,
        now_ms: u64,
        now: Instant,
    ) {
        if self.cache.len()
            >= custody_wire::limits::MAX_QUEUED_OPERATIONS * custody_wire::limits::MAX_CONNECTIONS
        {
            return;
        }
        let duration = Duration::from_millis(authority.until_ms.saturating_sub(now_ms));
        if let Some(deadline) = now.checked_add(duration) {
            let deadline = session_deadline.map_or(deadline, |session| session.min(deadline));
            self.cache.insert(
                key,
                Cached {
                    authority,
                    deadline,
                },
            );
        }
    }

    pub fn cached(
        &mut self,
        principal: &str,
        grant: usize,
        generation: u64,
        now_ms: u64,
        now: Instant,
    ) -> Result<bool> {
        self.check_clock(now_ms)?;
        let snapshot = self.store.snapshot()?;
        let key = (principal.to_string(), grant, generation);
        let Some(cached) = self.cache.get(&key) else {
            return Ok(false);
        };
        let current = now < cached.deadline
            && now_ms < cached.authority.until_ms
            && cached
                .authority
                .enrollment
                .as_ref()
                .is_none_or(|enrollment| {
                    snapshot.enrollments.iter().any(|g| g == enrollment)
                        && self
                            .gate
                            .check_enrollment(enrollment, &snapshot.ledger, now_ms)
                            .is_ok()
                });
        if !current {
            self.cache.remove(&key);
        }
        Ok(current)
    }

    fn check_clock(&mut self, now_ms: u64) -> Result<()> {
        if now_ms < self.last_wall {
            self.cache.clear();
            return Err(Refusal("remote-clock"));
        }
        self.last_wall = now_ms;
        Ok(())
    }
}
