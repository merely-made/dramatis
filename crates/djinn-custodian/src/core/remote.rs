// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Trusted host API and the independently granted public-only relay.

mod route;

use custody_wire::remote_approval::{ApprovalOperation, ApprovalProof, ApprovalRequest};
use insigne::delegation::{SignedDelegationCertificate, SignedDelegationRevocation};

use super::*;

fn wall_ms() -> Result<u64, Refusal> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|time| u64::try_from(time.as_millis()).ok())
        .ok_or(Refusal("remote-clock"))
}

#[cfg(test)]
mod tests;

impl Core {
    /// Persist a root-authorized public device enrollment. Root and action
    /// policy came from protected configuration; callers cannot replace it.
    ///
    /// # Errors
    /// Refuses disabled remote policy, invalid/revoked grants or unavailable state.
    pub fn enroll_remote_device(
        &mut self,
        grant: SignedDelegationCertificate,
    ) -> Result<(), Refusal> {
        self.remote
            .as_mut()
            .ok_or(Refusal("remote-disabled"))?
            .enroll(grant, wall_ms()?)
    }

    /// Persist a signed revocation before invalidating pending/cached consent.
    /// Replays are idempotent and cannot repeatedly cancel unrelated work.
    ///
    /// # Errors
    /// Refuses disabled policy, invalid revocations, failed storage or exhaustion.
    pub fn revoke_remote_device(
        &mut self,
        signed: SignedDelegationRevocation,
    ) -> (Result<(), Refusal>, Effects) {
        let mut effects = Effects::default();
        let result = self
            .remote
            .as_mut()
            .ok_or(Refusal("remote-disabled"))
            .and_then(|remote| remote.revoke(signed, wall_ms()?));
        let result = match result {
            Ok(false) => Ok(()),
            Ok(true) => {
                if !self.advance() {
                    self.lock(&mut effects);
                    Err(Refusal("generation-exhausted"))
                } else {
                    self.cancel(|_| true, &mut effects);
                    self.broadcast(FactCause::Revoke, None, None, &mut effects);
                    Ok(())
                }
            },
            Err(error) => Err(error),
        };
        (result, effects)
    }

    /// Read the exact active public petition for an authenticated remote UI.
    /// The future route must still authenticate/pin its target while locked.
    pub fn remote_petition(&self) -> Option<Petition> {
        let pending = self
            .queue
            .iter()
            .find(|p| self.active.as_deref() == Some(p.digest.as_str()))?;
        self.remote_available(&pending.summary.profile)
            .then(|| pending.summary.clone())
    }

    /// Create a proof challenge only for the actual active authorized petition.
    ///
    /// # Errors
    /// Refuses unavailable policy/state, wrong request/profile or an ended grant.
    pub fn request_remote_consent(
        &mut self,
        request: u64,
        digest: &str,
        now: Instant,
    ) -> (Result<ApprovalRequest, Refusal>, Effects) {
        let effects = self.expire(now);
        let result = self.begin_remote_consent(request, digest, now);
        (result, effects)
    }

    fn begin_remote_consent(
        &mut self,
        request: u64,
        digest: &str,
        now: Instant,
    ) -> Result<ApprovalRequest, Refusal> {
        let pending = self
            .queue
            .iter()
            .find(|p| {
                p.request == request && p.digest == digest && self.active.as_deref() == Some(digest)
            })
            .ok_or(Refusal("petition-not-active"))?;
        if !self.remote_available(&pending.summary.profile) || !self.pending_authorized(pending) {
            return Err(Refusal("remote-operation-denied"));
        }
        let digest = *blake3::Hash::from_hex(digest)
            .map_err(|_| Refusal("petition-binding"))?
            .as_bytes();
        let remote = self.remote.as_mut().ok_or(Refusal("remote-disabled"))?;
        remote.synchronize(&self.instance, self.generation)?;
        remote.begin(
            ApprovalOperation::Consent { request, digest },
            wall_ms()?,
            now,
        )
    }

    /// Verify and execute under the same mutable custody owner. Every current
    /// permission and revocation is checked; remote proof never becomes a local
    /// cached-consent bit and ordinary consent never renews the vault timer.
    ///
    /// # Errors
    /// Refuses missing/revoked enrollment, invalid proofs, stale context, expired
    /// or unauthorized petitions, unsupported opening and storage/clock faults.
    pub fn approve_remote_consent(
        &mut self,
        nonce: [u8; 32],
        proof: &ApprovalProof,
        now: Instant,
    ) -> (Result<(), Refusal>, Effects) {
        let mut effects = self.expire(now);
        let result = self.commit_remote_consent(nonce, proof, now, &mut effects);
        (result, effects)
    }

    fn commit_remote_consent(
        &mut self,
        nonce: [u8; 32],
        proof: &ApprovalProof,
        now: Instant,
        effects: &mut Effects,
    ) -> Result<(), Refusal> {
        let at_ms = wall_ms()?;
        let remote = self.remote.as_mut().ok_or(Refusal("remote-disabled"))?;
        remote.synchronize(&self.instance, self.generation)?;
        let (verified, authority) = remote.accept(nonce, proof, at_ms, now)?;
        // Resample after storage/signature work at the serialized commit barrier.
        let commit_now = now.max(Instant::now());
        let commit_ms = wall_ms()?;
        let expired = self.expire(commit_now);
        effects.messages.extend(expired.messages);
        effects.prompts.extend(expired.prompts);
        effects.close.extend(expired.close);
        let binding = verified.request();
        if commit_ms < at_ms
            || commit_ms >= binding.expires_at_ms
            || !authority.valid_at(commit_ms)
            || proof
                .chain
                .last()
                .and_then(|leaf| leaf.certificate.expires_at_ms)
                .is_none_or(|expires| commit_ms >= expires)
        {
            return Err(Refusal("remote-approval-expired"));
        }
        let ApprovalOperation::Consent { request, digest } = binding.operation else {
            return Err(Refusal("remote-unlock-backend-unsupported"));
        };
        if binding.instance != self.instance || binding.generation != self.generation {
            return Err(Refusal("petition-binding"));
        }
        let digest = blake3::Hash::from_bytes(digest).to_hex().to_string();
        let pending = self
            .queue
            .iter()
            .find(|p| p.request == request && p.digest == digest)
            .ok_or(Refusal("petition-not-pending"))?;
        if binding.profile != pending.summary.profile || !self.remote_available(&binding.profile) {
            return Err(Refusal("remote-operation-denied"));
        }
        let cache_key = (pending.principal.clone(), pending.grant, self.generation);
        let cache = pending.consent == Consent::PerGeneration;
        if !self.finish_petition(
            request,
            &digest,
            binding.generation,
            true,
            false,
            commit_now,
            effects,
        )? {
            return Err(Refusal("remote-operation-refused"));
        }
        if cache && self.generation == binding.generation {
            let deadline = self.unlock_deadline.map(|deadline| deadline.instant);
            self.remote
                .as_mut()
                .ok_or(Refusal("remote-disabled"))?
                .remember(cache_key, authority, deadline, commit_ms, commit_now);
        }
        Ok(())
    }

    /// No current passphrase backend can open from an approval alone. No
    /// passphrase is exported or retained as an automatic opening credential.
    ///
    /// # Errors
    /// Always reports the missing remote opening mechanism for this backend.
    pub fn request_remote_unlock(&self) -> Result<ApprovalRequest, Refusal> {
        Err(Refusal("remote-unlock-backend-unsupported"))
    }

    pub(super) fn remote_available(&self, profile: &str) -> bool {
        self.config.consent != ConsentMode::Deny
            && self.vault.profile() == Some(profile)
            && self
                .remote
                .as_ref()
                .is_some_and(|remote| remote.available(Some(profile)))
    }

    pub(super) fn remote_cached_consent(
        &mut self,
        principal: &str,
        grant: usize,
        profile: &str,
        now: Instant,
    ) -> Result<bool, Refusal> {
        if !self.remote_available(profile) {
            return Ok(false);
        }
        let remote = self.remote.as_mut().ok_or(Refusal("remote-disabled"))?;
        remote.synchronize(&self.instance, self.generation)?;
        remote.cached(principal, grant, self.generation, wall_ms()?, now)
    }
}
