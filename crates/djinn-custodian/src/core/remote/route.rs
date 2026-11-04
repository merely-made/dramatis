// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use custody_wire::remote_approval::route::{RemoteCommand, RemoteReply, RemoteState};

use super::*;

impl Core {
    pub(in crate::core) fn remote_route(
        &mut self,
        command: RemoteCommand,
        now: Instant,
        effects: &mut Effects,
    ) -> Outcome {
        let result = self.dispatch_remote(command, now, effects);
        let reply = result.unwrap_or_else(|error| RemoteReply::Refused {
            code: error.0.into(),
        });
        match serde_json::to_value(reply) {
            Ok(value) => Outcome::Success {
                answer: Answer::Value { value },
            },
            Err(_) => Outcome::refused("remote-reply-format"),
        }
    }

    fn dispatch_remote(
        &mut self,
        command: RemoteCommand,
        now: Instant,
        effects: &mut Effects,
    ) -> Result<RemoteReply, Refusal> {
        match command {
            RemoteCommand::State {} => {
                let remote = self.remote.as_mut().ok_or(Refusal("remote-disabled"))?;
                let enrollments = remote.active_enrollments(wall_ms()?)?;
                let policy = &remote.policy;
                Ok(RemoteReply::State {
                    state: RemoteState {
                        root_authority: policy.root.authority,
                        root_issuer: policy.root.issuer,
                        target: policy.target,
                        profile: policy.profile.clone(),
                        instance: self.instance.clone(),
                        generation: self.generation,
                        locked: self.vault.is_locked(),
                        actions: policy.actions.iter().copied().collect(),
                        max_grant_seconds: policy.max_grant_seconds,
                        enrollments,
                    },
                })
            },
            RemoteCommand::Challenge {} => {
                let petition = self
                    .remote_petition()
                    .ok_or(Refusal("remote-no-petition"))?;
                let (request, more) =
                    self.request_remote_consent(petition.request, &petition.digest, now);
                append(effects, more);
                Ok(RemoteReply::Challenge {
                    petition,
                    request: request?,
                })
            },
            RemoteCommand::Enroll { grant } => {
                self.enroll_remote_device(grant)?;
                Ok(RemoteReply::Done {})
            },
            RemoteCommand::Revoke { revocation } => {
                let (result, more) = self.revoke_remote_device(revocation);
                append(effects, more);
                result?;
                Ok(RemoteReply::Done {})
            },
            RemoteCommand::Approve { nonce, proof } => {
                let (result, more) = self.approve_remote_consent(nonce, &proof, now);
                append(effects, more);
                result?;
                Ok(RemoteReply::Done {})
            },
            RemoteCommand::Unlock {} => {
                self.request_remote_unlock()?;
                Err(Refusal("remote-unlock-backend-unsupported"))
            },
        }
    }
}

fn append(effects: &mut Effects, more: Effects) {
    effects.messages.extend(more.messages);
    effects.prompts.extend(more.prompts);
    effects.close.extend(more.close);
}
