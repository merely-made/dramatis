// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl Core {
    /// Turn each new per-use SSH signing request into a consent petition.
    /// The requester the mechanism names is a session of the vault owner;
    /// with none connected, the request is denied rather than left waiting.
    pub fn petition_signing(&mut self, now: Instant) -> Effects {
        let mut effects = self.expire(now);
        let pending = self.vault.pending_signing();
        let live: HashSet<uuid::Uuid> = pending.iter().map(|p| p.request.request_id).collect();
        self.signing.retain(|id| live.contains(id));
        for pending in pending {
            let request = pending.request;
            if !self.signing.insert(request.request_id) {
                continue;
            }
            let owner = self
                .sessions
                .values()
                .find(|s| s.principal.same_user)
                .map(|s| (s.principal.clone(), s.peer.clone()));
            let Some((principal, requester)) =
                owner.filter(|_| self.config.consent != ConsentMode::Deny)
            else {
                let _ = self.vault.decide_signing(request.request_id, false);
                continue;
            };
            let summary: Summary = (
                "ssh-sign",
                self.vault.profile().unwrap_or_default().to_string(),
                request.public_key_fingerprint.chars().take(120).collect(),
                request.payload_digest.chars().take(64).collect(),
            );
            let _ = self.gate(
                NO_SESSION,
                0,
                &principal,
                requester,
                usize::MAX,
                Consent::PerOperation,
                summary,
                Deferred::Signing(request.request_id),
                now,
                &mut effects,
            );
        }
        effects
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn request(
        &mut self,
        session: SessionId,
        id: u64,
        instance: &str,
        generation: u64,
        operation: Operation,
        now: Instant,
        effects: &mut Effects,
    ) -> Option<Outcome> {
        let Some(state) = self.sessions.get(&session) else {
            return Some(Outcome::refused("session-closed"));
        };
        let principal = state.principal.clone();
        let requester = state.peer.clone();
        if self.revoked.contains(&principal.name) {
            effects.close.push(session);
            return Some(Outcome::refused("revoked"));
        }
        if instance != self.instance {
            return Some(Outcome::refused("stale-instance"));
        }
        let generation_free = matches!(operation, Operation::Status {} | Operation::Lock {});
        if self.exhausted && !generation_free {
            return Some(Outcome::refused("generation-exhausted"));
        }
        if !generation_free && generation != self.generation {
            return Some(Outcome::refused("stale-generation"));
        }
        match operation {
            Operation::RemoteApproval { command } => Some(
                match self.granted(&principal, |g| matches!(g, Grant::RemoteApprovalBridge)) {
                    Ok(_) => self.remote_route(*command, now, effects),
                    Err(error) => Outcome::refused(error.0),
                },
            ),
            Operation::Status {} => Some(
                self.granted(&principal, |g| matches!(g, Grant::Status))
                    .map_or_else(
                        |r| Outcome::refused(r.0),
                        |_| Outcome::Success {
                            answer: Answer::Status {
                                status: self.status(),
                            },
                        },
                    ),
            ),
            Operation::Lock {} => {
                if let Err(refusal) = self.granted(&principal, |g| matches!(g, Grant::Lock)) {
                    return Some(Outcome::refused(refusal.0));
                }
                let report = self.lock(effects);
                Some(lock_outcome(report))
            },
            Operation::Unlock { passphrase } => Some(self.unlock(&principal, passphrase, now, effects)),
            Operation::Revoke { principal: target } => {
                let (index, consent) =
                    match self.granted(&principal, |g| matches!(g, Grant::Revoke { .. })) {
                        Ok((index, Grant::Revoke { consent })) => (index, consent),
                        Ok(_) => unreachable!("matched a revoke grant"),
                        Err(refusal) => return Some(Outcome::refused(refusal.0)),
                    };
                if !self.config.principals.iter().any(|p| p.name == target) {
                    return Some(Outcome::refused("principal-unknown"));
                }
                let summary: Summary = (
                    "revoke",
                    String::new(),
                    target.clone(),
                    blake3::hash(target.as_bytes()).to_hex().to_string(),
                );
                self.gate(
                    session,
                    id,
                    &principal,
                    requester,
                    index,
                    consent,
                    summary,
                    Deferred::Revoke { principal: target },
                    now,
                    effects,
                )
            },
            operation => {
                if self.vault.is_locked()
                    && !matches!(
                        operation,
                        Operation::Snapshot {} | Operation::WalletPublic {}
                    )
                {
                    return Some(Outcome::refused("locked"));
                }
                let (index, consent, summary) = match self.authorize(&principal, &operation) {
                    Ok(found) => found,
                    Err(refusal) => return Some(Outcome::refused(refusal.0)),
                };
                self.gate(
                    session,
                    id,
                    &principal,
                    requester,
                    index,
                    consent,
                    summary,
                    Deferred::Operation(operation),
                    now,
                    effects,
                )
            },
        }
    }

    pub(super) fn release_grant(
        &self,
        source: Source,
        profile: &str,
        salts: &[Bytes],
        releasable: &dyn Fn(Source, &str, &[u8]) -> Option<(usize, Consent)>,
    ) -> Result<(usize, Consent), Refusal> {
        if salts.is_empty() || salts.len() > MAX_SALTS {
            return Err(Refusal("operation-or-scope"));
        }
        let mut found: Option<(usize, Consent)> = None;
        for salt in salts {
            let (index, consent) =
                releasable(source, profile, &salt.0).ok_or(Refusal("operation-or-scope"))?;
            // Every salt must come under one grant, so one consent covers them.
            if found.is_some_and(|(i, _)| i != index) {
                return Err(Refusal("operation-or-scope"));
            }
            found = Some((index, consent));
        }
        found.ok_or(Refusal("operation-or-scope"))
    }

    /// A grant without namespaces (host, wallet, payload, credentials).
    pub(super) fn coarse(
        &self,
        principal: &Principal,
        wanted: impl Fn(&Grant) -> bool,
        summary: Summary,
    ) -> Result<(usize, Consent, Summary), Refusal> {
        let (index, grant) = principal
            .grants
            .iter()
            .enumerate()
            .find(|(_, g)| wanted(g))
            .ok_or(Refusal("operation-denied"))?;
        let consent = match grant {
            Grant::Manage { consent }
            | Grant::Wallet { consent }
            | Grant::Payload { consent }
            | Grant::Credentials { consent }
            | Grant::Unassociated { consent } => *consent,
            _ => Consent::None,
        };
        Ok((index, consent, summary))
    }

    pub(super) fn granted(
        &self,
        principal: &Principal,
        wanted: impl Fn(&Grant) -> bool,
    ) -> Result<(usize, Grant), Refusal> {
        principal
            .grants
            .iter()
            .enumerate()
            .find(|(_, g)| wanted(g))
            .map(|(i, g)| (i, g.clone()))
            .ok_or(Refusal("operation-denied"))
    }
}

mod approval;
