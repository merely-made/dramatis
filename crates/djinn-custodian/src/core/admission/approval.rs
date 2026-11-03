// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl Core {
    /// Which grant admits `operation`, its consent, and the petition summary.
    /// Purpose, audience, profile and namespace are all checked here, before
    /// any petition is shown.
    pub(super) fn authorize(
        &self,
        principal: &Principal,
        operation: &Operation,
    ) -> Result<(usize, Consent, Summary), Refusal> {
        let current = self.vault.profile().unwrap_or_default().to_string();
        let grants = || principal.grants.iter().enumerate();
        let digest = |bytes: &[u8]| blake3::hash(bytes).to_hex().to_string();
        let salts_digest = |salts: &[Bytes]| {
            let mut hasher = blake3::Hasher::new();
            for salt in salts {
                hasher.update(&(salt.0.len() as u64).to_le_bytes());
                hasher.update(&salt.0);
            }
            hasher.finalize().to_hex().to_string()
        };
        let open_master = self.vault.master_public_key();
        // A rule naming the open profile's own keys sees its master only for
        // the open profile's persona root.
        let master_for = |source: Source, profile: &str| {
            (matches!(source, Source::Persona) && profile == current)
                .then_some(open_master.as_ref())
                .flatten()
        };
        let releasable = |source: Source, profile: &str, salt: &[u8]| {
            grants().find_map(|(index, grant)| match grant {
                Grant::Release {
                    profile: scope,
                    salts: rules,
                    consent,
                    source: from,
                } if from.matches(source)
                    && scope.covers(profile, &current)
                    && rules
                        .iter()
                        .any(|r| r.allows_under(salt, master_for(source, profile))) =>
                {
                    Some((index, *consent))
                },
                _ => None,
            })
        };
        let refused = || Refusal("operation-or-scope");
        match operation {
            Operation::Sign {
                profile,
                purpose,
                salt,
                message,
            } => {
                if message.0.len() > MAX_SIGNED_BYTES {
                    return Err(Refusal("message-too-large"));
                }
                let (index, consent) = grants()
                    .find_map(|(index, grant)| match (grant, purpose) {
                        (
                            Grant::Sign {
                                profile: scope,
                                purpose: PurposeRule::Delegation { audience: granted },
                                consent,
                            },
                            Purpose::Delegation { audience },
                        ) if granted == audience && scope.covers(profile, &current) => {
                            Some((index, *consent))
                        },
                        (
                            Grant::Sign {
                                profile: scope,
                                purpose: PurposeRule::Root,
                                consent,
                            },
                            Purpose::Root {},
                        ) if scope.covers(profile, &current) => Some((index, *consent)),
                        _ => None,
                    })
                    .ok_or_else(refused)?;
                let master = self.vault.master_public_key().unwrap_or_default();
                match purpose {
                    Purpose::Delegation { audience } => {
                        crate::delegation::check(audience, &master, &salt.0, &message.0)?
                    },
                    Purpose::Root {} if salt.0.is_empty() => {},
                    Purpose::Root {} => return Err(Refusal("root-signature-takes-no-salt")),
                }
                let namespace = match purpose {
                    Purpose::Delegation { audience } => format!("delegation:{audience}"),
                    Purpose::Root {} => "root".into(),
                };
                Ok((
                    index,
                    consent,
                    ("sign", profile.clone(), namespace, digest(&message.0)),
                ))
            },
            Operation::Release { profile, salts }
            | Operation::Derive {
                source: Source::Persona,
                profile: Some(profile),
                salts,
            } => self
                .release_grant(Source::Persona, profile, salts, &releasable)
                .map(|(i, c)| {
                    (
                        i,
                        c,
                        (
                            "release",
                            profile.clone(),
                            "derived-keys".into(),
                            salts_digest(salts),
                        ),
                    )
                }),
            Operation::Derive {
                source,
                profile,
                salts,
            } => {
                let profile = profile.clone().unwrap_or_else(|| current.clone());
                let name = match source {
                    Source::Persona => "derived-keys",
                    Source::Wallet => "wallet-keys",
                };
                self.release_grant(*source, &profile, salts, &releasable)
                    .map(|(i, c)| {
                        (
                            i,
                            c,
                            ("release", profile.clone(), name.into(), salts_digest(salts)),
                        )
                    })
            },
            Operation::Attest {
                source,
                profile,
                salt,
            } => {
                let profile = profile.clone().unwrap_or_else(|| current.clone());
                let attestable = grants().find_map(|(index, grant)| match grant {
                    Grant::Attest {
                        profile: scope,
                        salts: rules,
                        consent,
                        source: from,
                    } if from.matches(*source)
                        && scope.covers(&profile, &current)
                        && rules
                            .iter()
                            .any(|r| r.allows_under(&salt.0, master_for(*source, &profile))) =>
                    {
                        Some((index, *consent))
                    },
                    _ => None,
                });
                let (index, consent) = attestable
                    .or_else(|| releasable(*source, &profile, &salt.0))
                    .ok_or_else(refused)?;
                Ok((
                    index,
                    consent,
                    ("attest", profile, "derived-key".into(), digest(&salt.0)),
                ))
            },
            Operation::SignDerived {
                source,
                profile,
                salt,
                message,
            } => {
                if message.0.len() > MAX_SIGNED_BYTES {
                    return Err(Refusal("message-too-large"));
                }
                let profile = profile.clone().unwrap_or_else(|| current.clone());
                let signable = grants().find_map(|(index, grant)| match grant {
                    Grant::Sign {
                        profile: scope,
                        purpose:
                            PurposeRule::Derived {
                                source: from,
                                salts: rules,
                            },
                        consent,
                    } if from.matches(*source)
                        && scope.covers(&profile, &current)
                        && rules
                            .iter()
                            .any(|r| r.allows_under(&salt.0, master_for(*source, &profile))) =>
                    {
                        Some((index, *consent))
                    },
                    _ => None,
                });
                let (index, consent) = signable
                    .or_else(|| releasable(*source, &profile, &salt.0))
                    .ok_or_else(refused)?;
                Ok((
                    index,
                    consent,
                    (
                        "sign-derived",
                        profile,
                        "derived-key".into(),
                        digest(&message.0),
                    ),
                ))
            },
            Operation::Snapshot {} => self.coarse(
                principal,
                |g| matches!(g, Grant::Snapshot),
                ("snapshot", String::new(), String::new(), String::new()),
            ),
            // The same disclosure class as the snapshot's carry view.
            Operation::WalletPublic {} => self.coarse(
                principal,
                |g| matches!(g, Grant::Snapshot),
                ("wallet-public", String::new(), String::new(), String::new()),
            ),
            Operation::PublicKey { source, profile } => {
                let profile = profile.clone().unwrap_or_else(|| current.clone());
                let found = grants().find_map(|(index, grant)| match grant {
                    Grant::Release {
                        profile: scope,
                        source: from,
                        ..
                    }
                    | Grant::Attest {
                        profile: scope,
                        source: from,
                        ..
                    } if from.matches(*source) && scope.covers(&profile, &current) => Some(index),
                    _ => None,
                });
                found
                    .map(|index| {
                        (
                            index,
                            Consent::None,
                            ("public-key", profile, String::new(), String::new()),
                        )
                    })
                    .ok_or_else(refused)
            },
            Operation::Intent { intent, payload } => self.coarse(
                principal,
                |g| matches!(g, Grant::Manage { .. }),
                (
                    "intent",
                    current.clone(),
                    intent.chars().take(64).collect(),
                    digest(&payload.0),
                ),
            ),
            Operation::HasProfile { profile } => self.coarse(
                principal,
                |g| matches!(g, Grant::Manage { .. }),
                ("has-profile", profile.clone(), String::new(), String::new()),
            ),
            Operation::ChangePassphrase { .. } => self.coarse(
                principal,
                |g| matches!(g, Grant::Manage { .. }),
                (
                    "change-passphrase",
                    current.clone(),
                    String::new(),
                    String::new(),
                ),
            ),
            Operation::ImportSshKey { options, .. } => self.coarse(
                principal,
                |g| matches!(g, Grant::Manage { .. }),
                (
                    "import-ssh-key",
                    current.clone(),
                    String::new(),
                    digest(&options.0),
                ),
            ),
            Operation::VaultCommand {
                profile,
                command,
                args,
            } => {
                let mut hasher = blake3::Hasher::new();
                for arg in args {
                    hasher.update(&(arg.len() as u64).to_le_bytes());
                    hasher.update(arg.as_bytes());
                }
                self.coarse(
                    principal,
                    |g| matches!(g, Grant::Manage { .. }),
                    (
                        "vault-command",
                        profile.clone(),
                        command.chars().take(64).collect(),
                        hasher.finalize().to_hex().to_string(),
                    ),
                )
            },
            Operation::EpochKeys { persona, keys, .. } => {
                let contexts = keys
                    .iter()
                    .map(|k| k.context.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                self.coarse(
                    principal,
                    |g| matches!(g, Grant::Wallet { .. }),
                    (
                        "epoch-keys",
                        persona.clone(),
                        contexts.chars().take(160).collect(),
                        String::new(),
                    ),
                )
            },
            Operation::StationGrant { request, .. } => self.coarse(
                principal,
                |g| matches!(g, Grant::Wallet { .. }),
                (
                    "station-grant",
                    String::new(),
                    String::new(),
                    digest(request.to_string().as_bytes()),
                ),
            ),
            Operation::RevokeDevice { device_id } => self.coarse(
                principal,
                |g| matches!(g, Grant::Wallet { .. }),
                (
                    "revoke-device",
                    String::new(),
                    device_id.clone(),
                    String::new(),
                ),
            ),
            Operation::Payload {
                profile,
                persona,
                content_hash,
                ..
            } => self.coarse(
                principal,
                |g| matches!(g, Grant::Payload { .. }),
                (
                    "payload",
                    profile.clone(),
                    persona.clone(),
                    content_hash.clone(),
                ),
            ),
            Operation::Credentials { operation } => {
                let kind = match operation {
                    custody_wire::CredentialOperation::Quarantine { .. } => "quarantine",
                    custody_wire::CredentialOperation::UnassignedImports {} => "unassigned-imports",
                    custody_wire::CredentialOperation::AssignImport { .. } => "assign-import",
                    custody_wire::CredentialOperation::Review { .. } => "review",
                    custody_wire::CredentialOperation::CxfPreview { .. } => "cxf-preview",
                    custody_wire::CredentialOperation::CxfImport { .. } => "cxf-import",
                };
                self.coarse(
                    principal,
                    |g| matches!(g, Grant::Credentials { .. }),
                    ("credentials", current.clone(), kind.into(), String::new()),
                )
            },
            Operation::Status {}
            | Operation::Lock {}
            | Operation::Unlock { .. }
            | Operation::Revoke { .. } => Err(refused()),
        }
    }

    /// Run now, or queue a petition, according to the grant's consent.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn gate(
        &mut self,
        session: SessionId,
        request: u64,
        principal: &Principal,
        requester: Peer,
        grant: usize,
        consent: Consent,
        summary: Summary,
        deferred: Deferred,
        now: Instant,
        effects: &mut Effects,
    ) -> Option<Outcome> {
        let approved = match consent {
            Consent::None => true,
            Consent::PerGeneration => {
                self.consented
                    .contains(&(principal.name.clone(), grant, self.generation))
            },
            Consent::PerOperation => false,
        };
        if approved {
            return Some(self.execute(deferred, effects));
        }
        if self.config.consent == ConsentMode::Deny {
            return Some(Outcome::refused("consent-unavailable"));
        }
        if self.config.consent == ConsentMode::Channel
            && !self.sessions.values().any(|s| s.principal.consent_channel)
        {
            return Some(Outcome::refused("consent-unavailable"));
        }
        if self.queue.len() >= limits::MAX_QUEUED_OPERATIONS
            || self.queue.iter().filter(|p| p.session == session).count()
                >= MAX_PETITIONS_PER_SESSION
        {
            return Some(Outcome::refused("consent-busy"));
        }
        let (operation, profile, namespace, payload_digest) = summary;
        let mut hasher = blake3::Hasher::new();
        for part in [
            self.instance.as_bytes(),
            &self.generation.to_le_bytes(),
            principal.name.as_bytes(),
            &request.to_le_bytes(),
            operation.as_bytes(),
            profile.as_bytes(),
            namespace.as_bytes(),
            payload_digest.as_bytes(),
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize().to_hex().to_string();
        let petition = Petition {
            request,
            digest: digest.clone(),
            generation: self.generation,
            principal: principal.name.clone(),
            operation: operation.to_string(),
            profile,
            namespace,
            payload_digest,
            expires_in_ms: limits::CONSENT.as_millis() as u64,
        };
        self.queue.push_back(Pending {
            session,
            request,
            digest,
            generation: self.generation,
            deadline: now + limits::CONSENT,
            principal: principal.name.clone(),
            grant,
            consent,
            requester,
            summary: petition,
            deferred,
        });
        self.promote(effects);
        None
    }
}
