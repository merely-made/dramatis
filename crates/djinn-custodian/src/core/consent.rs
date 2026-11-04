// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decide_into(
        &mut self,
        decider: Decider,
        request: u64,
        digest: &str,
        generation: u64,
        accept: bool,
        now: Instant,
        effects: &mut Effects,
    ) -> Result<(), Refusal> {
        let trusted = match decider {
            Decider::Session(id) => {
                self.config.consent == ConsentMode::Channel
                    && self
                        .sessions
                        .get(&id)
                        .is_some_and(|s| s.principal.consent_channel)
            },
            Decider::Mechanism => self.config.consent == ConsentMode::Polkit,
        };
        if !trusted {
            return Err(Refusal("not-consent-channel"));
        }
        self.finish_petition(request, digest, generation, accept, true, now, effects)
            .map(|_| ())
    }

    /// Both local and remote consent reach this one serialized commit barrier.
    /// Remote consent is cached separately, with its root grant and expiry.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_petition(
        &mut self,
        request: u64,
        digest: &str,
        generation: u64,
        accept: bool,
        local_cache: bool,
        now: Instant,
        effects: &mut Effects,
    ) -> Result<bool, Refusal> {
        if self.active.as_deref() != Some(digest) {
            return Err(Refusal("petition-not-active"));
        }
        let position = self
            .queue
            .iter()
            .position(|p| p.digest == digest)
            .ok_or(Refusal("petition-not-pending"))?;
        let head = &self.queue[position];
        if head.request != request || head.generation != generation || generation != self.generation
        {
            return Err(Refusal("petition-binding"));
        }
        let pending = self.queue.remove(position).expect("position is in range");
        self.active = None;
        let outcome = if !accept {
            self.withdraw(&pending);
            Outcome::refused("consent-denied")
        } else if now >= pending.deadline || !self.pending_authorized(&pending) {
            self.withdraw(&pending);
            Outcome::refused("invalidated")
        } else {
            if local_cache && pending.consent == Consent::PerGeneration {
                self.consented
                    .insert((pending.principal.clone(), pending.grant, self.generation));
            }
            self.execute(pending.deferred, effects)
        };
        let success = matches!(&outcome, Outcome::Success { .. });
        self.settle(pending.session, pending.request, outcome, effects);
        self.promote(effects);
        Ok(success)
    }

    pub(super) fn pending_authorized(&self, pending: &Pending) -> bool {
        if self.vault.is_locked() || self.revoked.contains(&pending.principal) {
            return false;
        }
        if pending.session != NO_SESSION && !self.sessions.contains_key(&pending.session) {
            return false;
        }
        let Some(principal) = self
            .config
            .principal(&pending.requester)
            .filter(|p| p.name == pending.principal)
        else {
            return false;
        };
        match &pending.deferred {
            Deferred::Operation(operation) => {
                self.authorize(&principal, operation)
                    .is_ok_and(|(index, consent, _)| {
                        index == pending.grant && consent == pending.consent
                    })
            },
            Deferred::Revoke { .. } => self
                .granted(&principal, |grant| matches!(grant, Grant::Revoke { .. }))
                .is_ok_and(|(index, _)| index == pending.grant),
            Deferred::Signing(id) => {
                principal.same_user
                    && self.sessions.values().any(|s| s.peer == pending.requester)
                    && self
                        .vault
                        .pending_signing()
                        .iter()
                        .any(|p| p.request.request_id == *id)
            },
        }
    }
}
