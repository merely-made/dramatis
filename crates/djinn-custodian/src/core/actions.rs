// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl Core {
    pub(super) fn execute(&mut self, deferred: Deferred, effects: &mut Effects) -> Outcome {
        match deferred {
            Deferred::Operation(operation) => {
                let identity = if matches!(&operation, Operation::Intent { .. }) {
                    Some((
                        self.vault.profile().map(str::to_string),
                        self.vault.master_public_key(),
                    ))
                } else {
                    None
                };
                let outcome = self.perform(operation);
                if identity.is_some_and(|before| {
                    before
                        != (
                            self.vault.profile().map(str::to_string),
                            self.vault.master_public_key(),
                        )
                }) {
                    if !self.advance() {
                        self.lock(effects);
                        return Outcome::refused("generation-exhausted");
                    }
                    self.cancel(|_| true, effects);
                    self.broadcast(FactCause::ProfileChanged, None, None, effects);
                }
                outcome
            },
            Deferred::Signing(request) => match self.vault.decide_signing(request, true) {
                Ok(()) => Outcome::Success {
                    answer: Answer::Done {},
                },
                Err(refusal) => Outcome::refused(refusal.0),
            },
            Deferred::Revoke { principal } => {
                self.revoked.insert(principal.clone());
                if !self.advance() {
                    self.lock(effects);
                    return Outcome::refused("generation-exhausted");
                }
                self.cancel(|p| p.principal == principal, effects);
                let doomed: Vec<SessionId> = self
                    .sessions
                    .iter()
                    .filter(|(_, s)| s.principal.name == principal)
                    .map(|(id, _)| *id)
                    .collect();
                self.broadcast(FactCause::Revoke, None, Some(principal), effects);
                effects.close.extend(doomed);
                Outcome::Success {
                    answer: Answer::Revoked {
                        generation: self.generation,
                    },
                }
            },
        }
    }

    /// Run one authorized operation against the vault, wallet or catalog.
    pub(super) fn perform(&mut self, operation: Operation) -> Outcome {
        let success = |answer| Outcome::Success { answer };
        let refuse = |refusal: Refusal| Outcome::refused(refusal.0);
        let text = |prefix: &str, error: String| Outcome::Refused {
            code: format!("{prefix}: {}", error.chars().take(400).collect::<String>()),
        };
        let signature = |signed: crate::host::Signed| {
            success(Answer::Signature {
                public_key: signed.public_key,
                signature: signed.signature,
                attestation: signed.attestation,
            })
        };
        let released = |(master, keys): ([u8; 32], Vec<crate::host::Released>)| {
            success(Answer::Released {
                master_public_key: master,
                keys: keys
                    .into_iter()
                    .map(|r| ReleasedKey {
                        salt: Bytes(r.salt),
                        seed: Secret::copy_from(&*r.seed),
                        attestation: r.attestation,
                    })
                    .collect(),
            })
        };
        match operation {
            Operation::Sign {
                profile,
                salt,
                message,
                ..
            } => self
                .vault
                .sign(Source::Persona, Some(&profile), &salt.0, &message.0)
                .map_or_else(refuse, signature),
            Operation::Release { profile, salts } => {
                let salts: Vec<Vec<u8>> = salts.into_iter().map(|b| b.0).collect();
                self.vault
                    .release(Source::Persona, Some(&profile), &salts)
                    .map_or_else(refuse, released)
            },
            Operation::Derive {
                source,
                profile,
                salts,
            } => {
                let salts: Vec<Vec<u8>> = salts.into_iter().map(|b| b.0).collect();
                self.vault
                    .release(source, profile.as_deref(), &salts)
                    .map_or_else(refuse, released)
            },
            Operation::Attest {
                source,
                profile,
                salt,
            } => self
                .vault
                .attest(source, profile.as_deref(), &salt.0)
                .map_or_else(refuse, |attestation| {
                    success(Answer::Attestation { attestation })
                }),
            Operation::SignDerived {
                source,
                profile,
                salt,
                message,
            } => {
                if salt.0.is_empty() {
                    return Outcome::refused("operation-or-scope");
                }
                self.vault
                    .sign(source, profile.as_deref(), &salt.0, &message.0)
                    .map_or_else(refuse, signature)
            },
            Operation::Unassociated { action } => match action {
                UnassociatedAction::Create {} => self
                    .vault
                    .unassociated_create()
                    .map_or_else(refuse, |key| success(Answer::PublicKey { key })),
                UnassociatedAction::Sign { public_key, message } => self
                    .vault
                    .unassociated_sign(&public_key.0, &message.0)
                    .map_or_else(refuse, signature),
                UnassociatedAction::Release { public_key } => self
                    .vault
                    .unassociated_release(&public_key.0)
                    .map_or_else(refuse, |(public_key, seed)| {
                        success(Answer::Seed { public_key, seed: Secret::copy_from(&*seed) })
                    }),
            },
            Operation::Snapshot {} => self.vault.snapshot().map_or_else(refuse, |snapshot| {
                success(Answer::Snapshot {
                    snapshot: Box::new(snapshot),
                })
            }),
            Operation::WalletPublic {} => self
                .vault
                .wallet_public()
                .map_or_else(refuse, |(personas, roster)| {
                    success(Answer::WalletPublic { personas, roster })
                }),
            Operation::PublicKey { source, profile } => self
                .vault
                .public_key(source, profile.as_deref())
                .map_or_else(refuse, |key| success(Answer::PublicKey { key })),
            Operation::Intent { intent, payload } => self
                .vault
                .intent(&intent, &payload.0)
                .map_or_else(|e| text("intent-refused", e), |()| success(Answer::Done {})),
            Operation::HasProfile { profile } => self
                .vault
                .has_profile(&profile)
                .map_or_else(refuse, |value| success(Answer::Bool { value })),
            Operation::ChangePassphrase { old, new } => self
                .vault
                .change_passphrase(old.expose(), new.expose())
                .map_or_else(
                    |e| text("passphrase-change-refused", e),
                    |()| success(Answer::Done {}),
                ),
            Operation::ImportSshKey {
                key,
                passphrase,
                options,
            } => self
                .vault
                .import_ssh_key(
                    key.expose(),
                    passphrase.as_ref().map(Secret::expose),
                    &options.0,
                )
                .map_or_else(
                    |e| text("import-refused", e),
                    |value| success(Answer::Value { value }),
                ),
            Operation::VaultCommand {
                profile,
                command,
                args,
            } => match self.vault.vault_command(&profile, &command, &args) {
                Ok(CommandOutput::Text(text)) => success(Answer::VaultOutput { text }),
                Ok(CommandOutput::Enrollment {
                    target,
                    script,
                    confirmation,
                }) => success(Answer::VaultEnrollment {
                    target,
                    script,
                    confirmation,
                }),
                Err(refusal) => refuse(refusal),
            },
            Operation::EpochKeys {
                persona,
                device_label,
                keys,
            } => self
                .vault
                .epoch_keys(&persona, device_label.as_deref(), &keys)
                .map_or_else(refuse, |keys| success(Answer::EpochKeys { keys })),
            Operation::StationGrant {
                request,
                issuer_public_key,
            } => self
                .vault
                .station_grant(&request, &issuer_public_key.0)
                .map_or_else(
                    |e| text("station-grant-refused", e),
                    |value| success(Answer::Value { value }),
                ),
            Operation::RevokeDevice { device_id } => {
                self.vault.revoke_device(&device_id).map_or_else(
                    |e| text("revoke-refused", e),
                    |value| success(Answer::Value { value }),
                )
            },
            Operation::Payload {
                profile,
                persona,
                master,
                scope,
                content_hash,
                operation,
            } => self
                .vault
                .payload(
                    &profile,
                    &persona,
                    &master.0,
                    &scope.0,
                    &content_hash,
                    &operation,
                )
                .map_or_else(refuse, |(bytes, marker)| {
                    success(Answer::Payload {
                        bytes: Bytes(bytes),
                        marker,
                    })
                }),
            Operation::Credentials { operation } => self.vault.credentials(&operation).map_or_else(
                |e| text("credentials-refused", e),
                |value| success(Answer::Value { value }),
            ),
            Operation::RemoteApproval { .. }
            | Operation::Status {}
            | Operation::Lock {}
            | Operation::Unlock { .. }
            | Operation::Revoke { .. } => Outcome::refused("operation-or-scope"),
        }
    }

    pub(super) fn unlock(
        &mut self,
        principal: &Principal,
        passphrase: Secret,
        now: Instant,
        effects: &mut Effects,
    ) -> Outcome {
        if let Err(refusal) = self.granted(principal, |g| matches!(g, Grant::Unlock)) {
            return Outcome::refused(refusal.0);
        }
        if self.exhausted || self.generation == u64::MAX {
            self.lock(effects);
            return Outcome::refused("generation-exhausted");
        }
        if !self.vault.is_locked() {
            // An idempotent unlock request is not fresh owner authorization.
            // In particular it must not slide an existing absolute deadline.
            return Outcome::Success { answer: Answer::Unlocked { generation: self.generation } };
        }
        let deadline = match self.config.max_unlocked_seconds {
            Some(seconds) => match UnlockDeadline::new(now, SystemTime::now(), Duration::from_secs(seconds)) {
                Some(deadline) => Some(deadline),
                None => return Outcome::refused("unlock-duration-unrepresentable"),
            },
            None => None,
        };
        if let Err(refusal) = self.vault.unlock(passphrase.expose()) {
            return Outcome::refused(refusal.0);
        }
        drop(passphrase);
        self.unlock_deadline = deadline;
        let advanced = self.advance();
        debug_assert!(advanced);
        self.broadcast(FactCause::Unlock, None, None, effects);
        Outcome::Success {
            answer: Answer::Unlocked {
                generation: self.generation,
            },
        }
    }

    /// Close admission, drop the root and every grant, persist the barrier.
    pub(super) fn lock(&mut self, effects: &mut Effects) -> LockReport {
        self.unlock_deadline = None;
        let was_unlocked = !self.vault.is_locked();
        let durable = self.vault.lock();
        if !self.advance() {
            effects.close.extend(self.sessions.keys().copied());
        }
        self.cancel(|_| true, effects);
        let report = LockReport {
            generation: self.generation,
            memory_locked: true,
            // Operations run to completion under the custodian's lock before
            // this one starts; petitions were cancelled above.
            drained: true,
            durable,
        };
        let _ = was_unlocked;
        self.broadcast(FactCause::Lock, Some(report.clone()), None, effects);
        report
    }

    pub(super) fn advance(&mut self) -> bool {
        self.consented.clear();
        if self.exhausted {
            return false;
        }
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                true
            },
            None => {
                self.exhausted = true;
                false
            },
        }
    }

    pub(super) fn broadcast(
        &mut self,
        cause: FactCause,
        report: Option<LockReport>,
        revoked: Option<String>,
        effects: &mut Effects,
    ) {
        let fact = Fact {
            instance: self.instance.clone(),
            generation: self.generation,
            cause,
            locked: self.vault.is_locked(),
            report,
            revoked,
        };
        for id in self.sessions.keys() {
            effects
                .messages
                .push((*id, ServerMessage::Fact(fact.clone())));
        }
    }
}
