// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The custodian's state machine, without I/O. Every transport and launcher
//! drives this one implementation of §5.3 to §5.6: the socket service on
//! Linux, macOS and Windows, and the signed macOS host through its C ABI.
//!
//! A session is opened for an OS peer the transport established; the
//! policy, not the hello, selects its principal. Each request is checked
//! for instance, generation, grant, profile, namespace and lock before it
//! runs or becomes a consent petition. A petition carries a digest the
//! custodian derived and is decided only by the trusted consent channel for
//! that digest, request and generation; the operation is rechecked when the
//! decision arrives. Lock, unlock and revocation advance one monotonic
//! generation, cancel every pending petition and broadcast a fact.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

mod lifetime;
use lifetime::UnlockDeadline;

use custody_wire::contract::{
    Answer, Fact, FactCause, Limits, LockReport, Outcome, Petition, Purpose, ReleasedKey,
    ServerMessage, Session, Source, Status,
};
use custody_wire::secret::{Bytes, Secret};
use custody_wire::{ClientMessage, Operation, Peer, limits};

use crate::Refusal;
use crate::host::{CommandOutput, HostCustody};
use crate::policy::{Config, Consent, ConsentMode, Grant, Principal, PurposeRule};

/// A session handle, unique per custodian start.
pub type SessionId = u64;

/// What the driver must do after a call.
#[derive(Default)]
pub struct Effects {
    /// Messages to deliver, in order.
    pub messages: Vec<(SessionId, ServerMessage)>,
    /// Petitions for a custodian-run consent mechanism (polkit, or the
    /// macOS host's own dialog). Decide them with [`Decider::Mechanism`].
    pub prompts: Vec<Prompt>,
    /// Sessions to close after delivery.
    pub close: Vec<SessionId>,
}

/// A petition for a custodian-run consent mechanism.
#[derive(Clone, Debug)]
pub struct Prompt {
    pub petition: Petition,
    /// The OS peer that asked, for the mechanism's own subject.
    pub requester: Peer,
}

/// Who is deciding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decider {
    /// A session; honoured only for a consent-channel principal.
    Session(SessionId),
    /// The mechanism the custodian itself ran for a [`Prompt`].
    Mechanism,
}

struct SessionState {
    principal: Principal,
    peer: Peer,
}

enum Deferred {
    Operation(Operation),
    Revoke {
        principal: String,
    },
    /// A per-use SSH signing request waiting in Castellan's broker.
    Signing(uuid::Uuid),
}

/// The session id internal petitions carry: no client waits on them.
const NO_SESSION: SessionId = 0;

/// What a consent petition shows: operation, profile, namespace and the
/// digest of the bytes or salts involved.
type Summary = (&'static str, String, String, String);

struct Pending {
    session: SessionId,
    request: u64,
    digest: String,
    generation: u64,
    deadline: Instant,
    principal: String,
    grant: usize,
    consent: Consent,
    requester: Peer,
    summary: Petition,
    deferred: Deferred,
}

/// The custodian.
pub struct Core {
    config: Config,
    vault: HostCustody,
    instance: String,
    generation: u64,
    exhausted: bool,
    sessions: HashMap<SessionId, SessionState>,
    next_session: SessionId,
    revoked: BTreeSet<String>,
    consented: HashSet<(String, usize, u64)>,
    queue: VecDeque<Pending>,
    active: Option<String>,
    signing: HashSet<uuid::Uuid>,
    unlock_deadline: Option<UnlockDeadline>,
    remote: Option<crate::remote_approval::runtime::RemoteRuntime>,
}

const MAX_SALTS: usize = 32;
const MAX_SIGNED_BYTES: usize = 64 * 1024;
const MAX_PETITIONS_PER_SESSION: usize = 4;

impl Core {
    /// Start locked, with a fresh instance id.
    pub fn start(config: Config) -> Result<Self, Refusal> {
        let instance = crate::nonce()?;
        let remote = config.remote_approval.as_ref().map(|policy| {
            crate::remote_approval::runtime::RemoteRuntime::open(
                &config.vault.directory, policy.clone(), instance.clone(), 1,
            )
        }).transpose()?;
        let vault = HostCustody::locked(
            &config.vault.directory,
            config.vault.profile.as_deref(),
            config.vault.data_root.as_deref(),
        )?;
        Ok(Self {
            config,
            vault,
            instance,
            generation: 1,
            exhausted: false,
            sessions: HashMap::new(),
            next_session: 1,
            revoked: BTreeSet::new(),
            consented: HashSet::new(),
            queue: VecDeque::new(),
            active: None,
            signing: HashSet::new(),
            unlock_deadline: None,
            remote,
        })
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn consent_mode(&self) -> ConsentMode {
        self.config.consent
    }

    /// Public status.
    pub fn status(&self) -> Status {
        let mut protection = self.vault.protection();
        if self.config.development {
            protection
                .push_str("; development mode: same-user principals may hold unattended grants");
        }
        Status {
            instance: self.instance.clone(),
            generation: self.generation,
            locked: self.vault.is_locked(),
            profile: self.vault.profile().map(str::to_string),
            master_public_key: self.vault.master_public_key(),
            protection,
            wallet_public_key: self.vault.wallet_public_key(),
        }
    }

    /// The vault, for the SSH agent and the signing-consent bridge.
    pub fn custody(&self) -> &HostCustody {
        &self.vault
    }

    /// Admit a session for `peer`. The first message must be a hello.
    pub fn open(
        &mut self,
        peer: Peer,
        hello: &ClientMessage,
    ) -> Result<(SessionId, ServerMessage), ServerMessage> {
        let refuse = |code: &str| ServerMessage::Refused { code: code.into() };
        let ClientMessage::Hello { version, nonce } = hello else {
            return Err(refuse("hello-required"));
        };
        if *version != custody_wire::VERSION {
            return Err(refuse("version"));
        }
        if nonce.len() > 128 {
            return Err(refuse("invalid-hello"));
        }
        let principal = self
            .config
            .principal(&peer)
            .ok_or_else(|| refuse("principal-unknown"))?;
        if self.revoked.contains(&principal.name) {
            return Err(refuse("revoked"));
        }
        if self.sessions.len() >= limits::MAX_CONNECTIONS {
            return Err(refuse("connection-capacity"));
        }
        // By principal, not by OS account: on Windows the consent helper and
        // Djinn are one SID and must not share a budget.
        if self
            .sessions
            .values()
            .filter(|s| s.principal.name == principal.name)
            .count()
            >= limits::MAX_CONNECTIONS_PER_PRINCIPAL
        {
            return Err(refuse("principal-connection-capacity"));
        }
        let id = self.next_session;
        self.next_session += 1;
        let session = Session {
            version: custody_wire::VERSION,
            instance: self.instance.clone(),
            generation: self.generation,
            locked: self.vault.is_locked(),
            principal: principal.name.clone(),
            peer: peer.clone(),
            scopes: principal.scopes(),
            consent_channel: principal.consent_channel,
            limits: Limits {
                max_frame_bytes: limits::MAX_FRAME_BYTES,
                max_queued_operations: limits::MAX_QUEUED_OPERATIONS as u32,
                noninteractive_ms: limits::NONINTERACTIVE.as_millis() as u64,
                consent_ms: limits::CONSENT.as_millis() as u64,
            },
            nonce: nonce.clone(),
        };
        self.sessions.insert(id, SessionState { principal, peer });
        Ok((id, ServerMessage::Opened(session)))
    }

    /// A session ended. Its pending petitions are withdrawn.
    pub fn close(&mut self, session: SessionId) -> Effects {
        self.sessions.remove(&session);
        let mut effects = Effects::default();
        let before = self.queue.len();
        self.queue.retain(|p| p.session != session);
        if self.queue.len() != before {
            if self
                .active
                .as_ref()
                .is_some_and(|d| !self.queue.iter().any(|p| &p.digest == d))
            {
                self.active = None;
            }
            self.promote(&mut effects);
        }
        effects
    }

    /// Handle one message from an open session.
    pub fn handle(&mut self, session: SessionId, message: ClientMessage, now: Instant) -> Effects {
        let mut effects = self.expire(now);
        match message {
            ClientMessage::Hello { .. } => {
                effects.close.push(session);
            },
            ClientMessage::Request {
                id,
                instance,
                generation,
                operation,
            } => {
                let outcome = self.request(
                    session,
                    id,
                    &instance,
                    generation,
                    operation,
                    now,
                    &mut effects,
                );
                if let Some(outcome) = outcome {
                    effects.messages.push((
                        session,
                        ServerMessage::Outcome {
                            request: id,
                            generation: self.generation,
                            outcome,
                        },
                    ));
                }
            },
            ClientMessage::Decide {
                request,
                digest,
                generation,
                accept,
            } => {
                let recorded = self.decide_into(
                    Decider::Session(session),
                    request,
                    &digest,
                    generation,
                    accept,
                    now,
                    &mut effects,
                );
                effects.messages.push((
                    session,
                    ServerMessage::Decided {
                        request,
                        recorded: recorded.is_ok(),
                        code: recorded.err().map(|r| r.0.to_string()),
                    },
                ));
            },
        }
        effects
    }

    /// A decision from the custodian's own consent mechanism.
    pub fn decide(
        &mut self,
        decider: Decider,
        request: u64,
        digest: &str,
        generation: u64,
        accept: bool,
        now: Instant,
    ) -> (Result<(), Refusal>, Effects) {
        let mut effects = self.expire(now);
        let recorded = self.decide_into(
            decider,
            request,
            digest,
            generation,
            accept,
            now,
            &mut effects,
        );
        (recorded, effects)
    }

    /// Expire petitions past their deadline.
    pub fn tick(&mut self, now: Instant) -> Effects {
        self.expire(now)
    }

    /// Lock from inside the custodian (a service stop or a platform event).
    pub fn lock_now(&mut self) -> (LockReport, Effects) {
        let mut effects = Effects::default();
        let report = self.lock(&mut effects);
        (report, effects)
    }

    /// Show the head of the queue if nothing is active.
    fn promote(&mut self, effects: &mut Effects) {
        if self.active.is_some() {
            return;
        }
        let Some(head) = self.queue.front() else {
            return;
        };
        self.active = Some(head.digest.clone());
        match self.config.consent {
            ConsentMode::Channel => {
                for (id, state) in &self.sessions {
                    if state.principal.consent_channel {
                        effects
                            .messages
                            .push((*id, ServerMessage::Petition(head.summary.clone())));
                    }
                }
            },
            ConsentMode::Polkit => effects.prompts.push(Prompt {
                petition: head.summary.clone(),
                requester: head.requester.clone(),
            }),
            ConsentMode::Deny => {},
        }
    }

    /// Answer the session that asked; a signing petition has none.
    fn settle(&self, session: SessionId, request: u64, outcome: Outcome, effects: &mut Effects) {
        if session != NO_SESSION {
            effects.messages.push((
                session,
                ServerMessage::Outcome {
                    request,
                    generation: self.generation,
                    outcome,
                },
            ));
        }
    }

    /// A petition that will not run: an SSH request is denied in the broker
    /// at once rather than left to Castellan's own timeout.
    fn withdraw(&self, pending: &Pending) {
        if let Deferred::Signing(request) = pending.deferred {
            let _ = self.vault.decide_signing(request, false);
        }
    }

    fn cancel(&mut self, which: impl Fn(&Pending) -> bool, effects: &mut Effects) {
        let mut kept = VecDeque::new();
        for pending in std::mem::take(&mut self.queue) {
            if which(&pending) {
                if self.active.as_deref() == Some(pending.digest.as_str()) {
                    self.active = None;
                }
                self.withdraw(&pending);
                self.settle(
                    pending.session,
                    pending.request,
                    Outcome::refused("invalidated"),
                    effects,
                );
            } else {
                kept.push_back(pending);
            }
        }
        self.queue = kept;
        if let Some(active) = &self.active
            && !self.queue.iter().any(|p| &p.digest == active)
        {
            self.active = None;
        }
        self.promote(effects);
    }

    fn expire(&mut self, now: Instant) -> Effects {
        let mut effects = Effects::default();
        if self.unlock_deadline.as_mut().is_some_and(|deadline| deadline.expired(now, SystemTime::now())) {
            self.lock(&mut effects);
        }
        let mut kept = VecDeque::new();
        for pending in std::mem::take(&mut self.queue) {
            if pending.deadline <= now {
                if self.active.as_deref() == Some(pending.digest.as_str()) {
                    self.active = None;
                }
                self.withdraw(&pending);
                self.settle(
                    pending.session,
                    pending.request,
                    Outcome::refused("consent-expired"),
                    &mut effects,
                );
            } else {
                kept.push_back(pending);
            }
        }
        self.queue = kept;
        self.promote(&mut effects);
        effects
    }

    /// The next petition or absolute unlock deadline, for a driver's timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.queue.iter().map(|p| p.deadline).chain(self.unlock_deadline.map(|deadline| deadline.instant)).min()
    }
}

fn lock_outcome(report: LockReport) -> Outcome {
    if report.durable {
        Outcome::Success {
            answer: Answer::Lock { report },
        }
    } else {
        Outcome::Degraded {
            code: "restart-barrier-not-durable".into(),
            answer: Some(Answer::Lock { report }),
        }
    }
}

/// How long a driver may sleep before the next expiry check.
pub fn tick_interval(core: &Core, now: Instant) -> Duration {
    core.next_deadline()
        .map(|d| d.saturating_duration_since(now))
        .unwrap_or(Duration::from_secs(60))
        .clamp(Duration::from_millis(50), Duration::from_secs(60))
}

#[cfg(test)]
mod exhaustion_tests;

mod admission;

mod actions;
mod consent;
mod remote;
