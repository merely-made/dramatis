// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A synchronous [`IdentityProvider`] over the custody route, for an
//! application whose code derives keys through a provider (dramatis repo
//! plan, DR-C; D11, D12).
//!
//! [`CustodyIdentity`] answers `derive_keypair` with a release djinn makes
//! under its policy, one salt at a time, and holds what it was given until
//! the vault locks: a watcher on the lock broadcast drops every held key the
//! moment djinn reports Locked or goes away. Attestations and signatures for
//! salts djinn will not release (root-level acts, D11) are made inside djinn
//! through [`CustodyIdentity::attest_derived_key`],
//! [`CustodyIdentity::sign`] and [`CustodyIdentity::issue_certificate`].
//!
//! Calls run on the provider's own thread, so the provider can be used from
//! inside or outside a tokio runtime. With djinn absent or Locked,
//! [`CustodyIdentity::connect`] fails with an error whose
//! [`is_pending`](CustodyClientError::is_pending) is true and every key
//! request answers [`IdentityError::Locked`]: the identity is pending, never
//! replaced by a key of the application's own (D12).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dramatis::roster::Roster;
use dramatis::view::VaultLockView;
use insigne::DerivedKeyAttestation;
use insigne::delegation::{
    DelegationCertificate, DelegationRevocation, SignedDelegationCertificate,
    SignedDelegationRevocation, delegation_signing_salt,
};
use personae::delegation::DelegationError;
use personae::{
    Ed25519Keypair, Ed25519PublicKey, IdentityError, IdentityProvider, ProfileId, RetainedKeys,
};

use crate::custody::{CustodyAnswer, CustodyCall, KeySource, ResidentStatus};
use crate::custody_client::{BlockingCustodyClient, CustodyClient, CustodyClientError};
use ostiary::app_admission::{AppId, configured_app_endpoint};
use ostiary::app_client::AppClientError;
use ostiary::declaration::AppDeclaration;

type JobCall = Box<dyn FnOnce(Option<&mut BlockingCustodyClient>) -> bool + Send>;
struct Job {
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
    call: JobCall,
}
impl Job {
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
    fn expired(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
            || self
                .remaining()
                .is_some_and(|remaining| remaining.is_zero())
    }
    fn run(self, client: Option<&mut BlockingCustodyClient>) -> bool {
        if self.expired() {
            return true;
        }
        (self.call)(client)
    }
}

/// Own the initializing actor until every fallible constructor step succeeds.
struct StartingActor {
    sender: Option<mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}
impl Drop for StartingActor {
    fn drop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The persona djinn speaks as, reached through the custody route.
pub struct CustodyIdentity {
    endpoint: String,
    app: AppId,
    declaration: Option<AppDeclaration>,
    requested_profile: Option<ProfileId>,
    master: Ed25519PublicKey,
    status: ResidentStatus,
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
    job_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    watch_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    call_timeout: Option<Duration>,
    held: Arc<Mutex<HashMap<Vec<u8>, RetainedKeys>>>,
    locked: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl CustodyIdentity {
    /// The status djinn answered when this connected.
    pub fn connected_status(&self) -> &ResidentStatus {
        &self.status
    }

    /// The persona in use when this connected.
    pub fn profile(&self) -> Option<&ProfileId> {
        self.status.profile.as_ref()
    }

    /// What protects the vault, as djinn reports it.
    pub fn protection(&self) -> String {
        format!("{:?} (held by djinn)", self.status.protection)
    }

    /// Whether djinn has reported the vault Locked (or gone) since this
    /// connected: every key request is pending until it unlocks.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// Monotonic local binding generation, including lock/loss followed by
    /// unlock between UI turns. It is not a wallet epoch or an authorization.
    pub fn custody_epoch(&self) -> Option<u64> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        (!self.is_locked() && epoch != 0 && self.epoch.load(Ordering::SeqCst) == epoch)
            .then_some(epoch)
    }

    /// The lock, the protection and the public roots, now.
    pub fn status(&self) -> Result<ResidentStatus, CustodyClientError> {
        self.ask(|client| client.status())
    }

    /// A bounded, read-only status check independent of the provider job queue.
    /// Timeout drops this fresh conversation; no consequential call is retried.
    pub fn status_timeout(&self, timeout: Duration) -> Result<ResidentStatus, CustodyClientError> {
        let endpoint = self.endpoint.clone();
        let app = self.app.clone();
        let declaration = self.declaration.clone();
        let profile = self.requested_profile.clone();
        let result = bounded_worker(move || {
            BlockingCustodyClient::status_at_timeout_with(
                &endpoint,
                app,
                declaration,
                profile,
                timeout,
            )
        });
        if self.status.custody_epoch.is_some()
            && !result
                .as_ref()
                .is_ok_and(|status| self.status_matches_binding(status))
        {
            self.invalidate_binding();
        }
        result
    }

    /// The vault's personas, for a picker. Answered while Locked too.
    pub fn roster(&self) -> Result<Roster, CustodyClientError> {
        self.ask(|client| client.roster())
    }

    /// Switch the persona djinn speaks as. Keys held for the old one are
    /// dropped; this provider keeps answering for the persona it connected
    /// as, so reconnect to speak as the new one.
    pub fn choose_profile(&self, profile: ProfileId) -> Result<(), CustodyClientError> {
        self.forget();
        self.ask(move |client| done(client.call(CustodyCall::ChooseProfile { profile })?))
    }

    /// Mint a persona in djinn's vault and switch to it.
    pub fn create_profile(
        &self,
        profile: ProfileId,
        display_name: impl Into<String>,
    ) -> Result<(), CustodyClientError> {
        let display_name = display_name.into();
        self.forget();
        self.ask(move |client| {
            done(client.call(CustodyCall::CreateProfile {
                profile,
                display_name,
            })?)
        })
    }

    /// Sign `message` inside djinn with the key `salt` derives: the signing
    /// key's public half and the signature (D11).
    pub fn sign(&self, salt: &[u8], message: &[u8]) -> Result<([u8; 32], Vec<u8>), IdentityError> {
        self.pending()?;
        let (salt, message) = (salt.to_vec(), message.to_vec());
        self.ask(move |client| client.sign(KeySource::Persona, salt, message))
            .map_err(identity_error)
    }

    /// Issue a delegation certificate as this persona, signed inside djinn:
    /// the scope's signing key never leaves it.
    pub fn issue_certificate(
        &self,
        certificate: DelegationCertificate,
    ) -> Result<SignedDelegationCertificate, DelegationError> {
        if !certificate.is_well_formed() {
            return Err(DelegationError::MalformedCertificate);
        }
        if certificate.issuer != self.master.to_bytes() {
            return Err(DelegationError::WrongIssuer);
        }
        let (signer, signature) = self.sign_scoped(
            &delegation_signing_salt(&certificate.scope),
            &certificate.signing_bytes(),
        )?;
        Ok(SignedDelegationCertificate::from_parts(
            certificate,
            signer,
            signature,
        ))
    }

    /// Issue a delegation revocation as this persona, signed inside djinn.
    pub fn issue_revocation(
        &self,
        revocation: DelegationRevocation,
    ) -> Result<SignedDelegationRevocation, DelegationError> {
        if !revocation.is_well_formed() {
            return Err(DelegationError::MalformedRevocation);
        }
        if revocation.issuer != self.master.to_bytes() {
            return Err(DelegationError::WrongIssuer);
        }
        let (signer, signature) = self.sign_scoped(
            &delegation_signing_salt(&revocation.scope),
            &revocation.signing_bytes(),
        )?;
        Ok(SignedDelegationRevocation::from_parts(
            revocation, signer, signature,
        ))
    }

    /// Drop every key held so far.
    pub fn forget(&self) {
        advance_epoch(&self.epoch);
        self.held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn sign_scoped(
        &self,
        salt: &[u8],
        message: &[u8],
    ) -> Result<(DerivedKeyAttestation, Vec<u8>), DelegationError> {
        let signer = self
            .attest_derived_key(salt)
            .map_err(|_| DelegationError::Identity)?;
        let (public_key, signature) = self
            .sign(salt, message)
            .map_err(|_| DelegationError::Identity)?;
        match signer.check(salt) {
            Ok(checked) if checked.derived() == &public_key => Ok((signer, signature)),
            _ => Err(DelegationError::Identity),
        }
    }

    fn pending(&self) -> Result<(), IdentityError> {
        match self.is_locked() {
            true => Err(IdentityError::Locked),
            false => Ok(()),
        }
    }

    fn ask<T: Send + 'static>(
        &self,
        call: impl FnOnce(&mut BlockingCustodyClient) -> Result<T, CustodyClientError> + Send + 'static,
    ) -> Result<T, CustodyClientError> {
        let jobs = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(closed)?;
        ask_on_bounded(&jobs, self.call_timeout, call)
    }
}

fn advance_epoch(epoch: &AtomicU64) {
    // Exhaustion permanently closes the generation instead of reusing one.
    let _ = epoch.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        Some(if value == 0 {
            0
        } else {
            value.checked_add(1).unwrap_or(0)
        })
    });
}

async fn wait_stopped(stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn timed_out() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "custody provider deadline elapsed",
    )))
}

fn invalidate_epoch(locked: &AtomicBool, epoch: &AtomicU64) {
    if !locked.swap(true, Ordering::SeqCst) {
        advance_epoch(epoch);
    }
}

#[cfg(test)]
mod epoch_tests;

impl Drop for CustodyIdentity {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.forget();
        if let Some(thread) = self
            .watch_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = thread.join();
        }
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(thread) = self
            .job_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = thread.join();
        }
    }
}

impl std::fmt::Debug for CustodyIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyIdentity")
            .field("profile", &self.status.profile)
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

impl IdentityProvider for CustodyIdentity {
    fn master_public_key(&self) -> Ed25519PublicKey {
        self.master
    }

    /// The key djinn releases for `salt` (D11); [`IdentityError::Locked`]
    /// while pending, and an error naming the refusal for a salt djinn keeps.
    fn derive_keypair(&self, salt: &[u8]) -> Result<Ed25519Keypair, IdentityError> {
        self.pending()?;
        if let Some(keys) = self
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(salt)
        {
            return keys.derive_keypair(salt);
        }
        let asked = salt.to_vec();
        let keys = self
            .ask(move |client| client.release(KeySource::Persona, vec![asked]))
            .map_err(identity_error)?;
        if keys.master_public_key() != self.master {
            return Err(IdentityError::DerivationFailed(
                "djinn now speaks as a different persona; reconnect".into(),
            ));
        }
        let keypair = keys.derive_keypair(salt)?;
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.insert(salt.to_vec(), keys);
        if self.is_locked() {
            held.clear();
            return Err(IdentityError::Locked);
        }
        Ok(keypair)
    }

    /// The master's attestation for `salt`'s key, signed inside djinn.
    fn attest_derived_key(&self, salt: &[u8]) -> Result<DerivedKeyAttestation, IdentityError> {
        self.pending()?;
        if let Some(keys) = self
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(salt)
        {
            return keys.attest_derived_key(salt);
        }
        let asked = salt.to_vec();
        let attestation = self
            .ask(move |client| client.attest(KeySource::Persona, asked))
            .map_err(identity_error)?;
        match attestation.check(salt) {
            Ok(checked) if checked.master() == &self.master.to_bytes() => Ok(attestation),
            _ => Err(IdentityError::DerivationFailed(
                "djinn's attestation does not name this persona".into(),
            )),
        }
    }
}

fn done(answer: CustodyAnswer) -> Result<(), CustodyClientError> {
    match answer {
        CustodyAnswer::Done => Ok(()),
        _ => Err(CustodyClientError::UnexpectedAnswer {
            asked: "profile",
            got: "another answer",
        }),
    }
}

fn closed() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Closed)
}

impl eidetic::PayloadSealer for CustodyIdentity {
    fn seal(
        &self,
        hash: &eidetic::Hash,
        cleartext: &[u8],
    ) -> eidetic::Result<(Vec<u8>, eidetic::SealedBlobRef)> {
        use super::custody_payload::{PayloadBytes, PayloadOperation, PayloadResult};
        if cleartext.len() > super::custody_payload::MAX_PAYLOAD_BYTES {
            return Err(eidetic::Error::new(
                "retained payload exceeds custody budget",
            ));
        }
        match self.retained_payload(
            hash,
            PayloadOperation::Seal {
                bytes: PayloadBytes(cleartext.to_vec()),
            },
        )? {
            PayloadResult::Sealed { bytes, marker } => Ok((bytes.0, marker)),
            _ => Err(eidetic::Error::new(
                "custody returned a different retained-payload operation",
            )),
        }
    }

    fn unseal(
        &self,
        hash: &eidetic::Hash,
        marker: &eidetic::SealedBlobRef,
        sealed: &[u8],
    ) -> eidetic::Result<Vec<u8>> {
        use super::custody_payload::{PayloadBytes, PayloadOperation, PayloadResult};
        if sealed.len() > super::custody_payload::MAX_PAYLOAD_BYTES + 40 {
            return Err(eidetic::Error::new(
                "retained payload exceeds custody budget",
            ));
        }
        match self.retained_payload(
            hash,
            PayloadOperation::Unseal {
                bytes: PayloadBytes(sealed.to_vec()),
                marker: marker.clone(),
            },
        )? {
            PayloadResult::Clear { bytes } if eidetic::Hash::of(&bytes.0) == *hash => Ok(bytes.0),
            _ => Err(eidetic::Error::new(
                "custody returned invalid retained-payload bytes",
            )),
        }
    }
}

impl CustodyIdentity {}

/// Isolate synchronous one-shot Tokio runtimes from any caller runtime.
/// The one-shot transport has its own deadline and is never retried.
fn bounded_worker<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, CustodyClientError> + Send + 'static,
) -> Result<T, CustodyClientError> {
    let thread = std::thread::Builder::new()
        .name("custody-bounded-call".into())
        .spawn(operation)
        .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
    thread.join().map_err(|_| closed())?
}

/// A pending identity reads as Locked; anything else keeps its reason.
fn identity_error(error: CustodyClientError) -> IdentityError {
    match error {
        error if error.is_pending() => IdentityError::Locked,
        CustodyClientError::Release(error) => error,
        other => IdentityError::Backend(other.to_string()),
    }
}

/// Run `call` on the provider's own thread and wait for its answer.
fn ask_on_bounded<T: Send + 'static>(
    jobs: &mpsc::Sender<Job>,
    timeout: Option<Duration>,
    call: impl FnOnce(&mut BlockingCustodyClient) -> Result<T, CustodyClientError> + Send + 'static,
) -> Result<T, CustodyClientError> {
    let (reply, answer) = mpsc::channel();
    let deadline = timeout
        .map(|duration| Instant::now().checked_add(duration).ok_or_else(timed_out))
        .transpose()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let check = cancelled.clone();
    let job = Job {
        deadline,
        cancelled: check.clone(),
        call: Box::new(move |client| {
            if check.load(Ordering::SeqCst) || deadline.is_some_and(|end| Instant::now() >= end) {
                return true;
            }
            match client {
                Some(client) => {
                    let result = call(client);
                    let healthy = !matches!(
                        result,
                        Err(CustodyClientError::Transport(_) | CustodyClientError::Absent(_))
                    );
                    let _ = reply.send(result);
                    healthy
                },
                None => {
                    let _ = reply.send(Err(CustodyClientError::Absent(AppClientError::Closed)));
                    false
                },
            }
        }),
    };
    jobs.send(job).map_err(|_| closed())?;
    let result = match deadline {
        Some(deadline) => answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => timed_out(),
                mpsc::RecvTimeoutError::Disconnected => closed(),
            }),
        None => answer.recv().map_err(|_| closed()),
    };
    cancelled.store(true, Ordering::SeqCst);
    result?
}

mod connection;

mod payload;

mod watcher;
