// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! [`ResidentCustody`] over the independently launched custodian: the only
//! implementation a production build has.
//!
//! Each method is one typed custody operation. The client verified the
//! custodian's OS identity before its first byte; a refusal maps to the
//! custody route's refusal and a lost custodian to "identity pending". A
//! follower thread turns the custodian's lock facts into the lock watch and
//! the holders' lock and re-derive, and treats a lost custodian as a lock:
//! honest holders forget their keys, and nothing local replaces it.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use castellan_client::custody::{
    CustodyRefusal, EpochKeyRequest, KeySource, ReleasedEpochKey, ReleasedKey, StationGrantRequest,
};
use castellan_client::custody_payload::{
    PayloadBytes, PayloadOperation as AppPayload, PayloadRequest, PayloadResult,
};
use custody_wire::contract::{
    Answer, CredentialOperation, Outcome, PayloadOperation, Purpose, Source,
};
use custody_wire::secret::{Bytes, Secret};
use custody_wire::{Client, Operation};
use dramatis::authentication::PassphraseChangeFailureV1;
use dramatis::intents::{
    CreateProfileIntentV1, ImportSshKeyNativeIntentV1, PROFILE_CREATE_INTENT,
    PROFILE_SWITCH_INTENT, SwitchProfileIntentV1,
};
use dramatis::view::{IdentitySurfaceSnapshot, VaultLockView};
use personae::{
    Ed25519Keypair, Ed25519PublicKey, IdentityError, IdentityProvider, PersonaId, ProfileId,
    RetainedKeys,
};

use super::{
    CredentialCall, ImportedSshKey, LockHolder, ResidentCustody, VaultOutput, WalletPublic, refusal,
};
use crate::custodian::InstalledCustodian;
use crate::native::NativeIdentityFailure;

const NONINTERACTIVE: Duration = Duration::from_secs(30);
/// Long enough for a consent petition the owner answers.
const PROMPTED: Duration = Duration::from_secs(150);

struct State {
    master: [u8; 32],
    profile: ProfileId,
    locked: bool,
}

/// Custody held by the custodian.
pub struct RemoteHost {
    installed: InstalledCustodian,
    client: Mutex<Option<Arc<Client>>>,
    state: Mutex<State>,
    lock: tokio::sync::watch::Sender<VaultLockView>,
    holders: Mutex<Vec<Arc<dyn LockHolder>>>,
    retained: Mutex<Vec<Arc<RetainedKeys>>>,
    /// The custodian instance, generation and lock last applied to the
    /// holders.
    applied: Mutex<Option<(String, u64, bool)>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn unavailable(reason: &str) -> CustodyRefusal {
    CustodyRefusal::Failed {
        reason: format!("the custodian is unavailable ({reason}); identity is pending"),
    }
}

fn unexpected() -> CustodyRefusal {
    CustodyRefusal::Failed {
        reason: "the custodian's answer did not check".into(),
    }
}

fn source(key: KeySource) -> Source {
    match key {
        KeySource::Persona => Source::Persona,
        KeySource::Wallet => Source::Wallet,
    }
}

impl RemoteHost {
    /// Connect to the installed custodian and learn its public state. The
    /// vault may be locked; `knows_identity` reports whether an identity is available.
    pub fn connect(installed: InstalledCustodian) -> Result<Arc<Self>, String> {
        let host = Arc::new(Self {
            installed,
            client: Mutex::new(None),
            state: Mutex::new(State {
                master: [0; 32],
                profile: ProfileId(String::new()),
                locked: true,
            }),
            lock: tokio::sync::watch::channel(VaultLockView::Locked).0,
            holders: Mutex::new(Vec::new()),
            retained: Mutex::new(Vec::new()),
            applied: Mutex::new(None),
        });
        host.client().map_err(|r| format!("{r:?}"))?;
        host.refresh().map_err(|r| format!("{r:?}"))?;
        let follower = Arc::clone(&host);
        std::thread::Builder::new()
            .name("custody-follower".into())
            .spawn(move || follower.follow())
            .map_err(|e| e.to_string())?;
        Ok(host)
    }

    /// Whether the custodian has opened the vault at least once, so the
    /// identity's public key is known.
    pub fn knows_identity(&self) -> bool {
        lock(&self.state).master != [0; 32]
    }

    fn client(&self) -> Result<Arc<Client>, CustodyRefusal> {
        let mut slot = lock(&self.client);
        if let Some(client) = slot.as_ref()
            && client.observed().alive
        {
            return Ok(Arc::clone(client));
        }
        #[cfg(unix)]
        let connector = custody_wire::transport::UnixSocketConnector::new(&self.installed.endpoint)
            .with_signed(self.installed.server.signed.clone());
        #[cfg(windows)]
        let connector = custody_wire::transport::NamedPipeConnector::new(&self.installed.endpoint);
        let client = Arc::new(
            Client::open(&connector, &self.installed.server)
                .map_err(|e| unavailable(&e.to_string()))?,
        );
        *slot = Some(Arc::clone(&client));
        Ok(client)
    }

    fn call(&self, operation: Operation, deadline: Duration) -> Result<Answer, CustodyRefusal> {
        let client = self.client()?;
        let seen = client.observed().generation;
        let mut outcome = client.call(operation.clone(), deadline);
        // A refusal ran nothing; if the generation moved before its fact
        // reached us, wait for the fact and ask once more.
        if outcome.code() == Some("stale-generation") {
            client.wait_for_change(seen, Duration::from_secs(2));
            outcome = client.call(operation, deadline);
        }
        match outcome {
            Outcome::Success { answer } => Ok(answer),
            Outcome::Refused { code } => Err(refusal(&code)),
            Outcome::Degraded { code, .. } => Err(CustodyRefusal::Failed {
                reason: format!("the custodian reported a degraded outcome: {code}"),
            }),
            Outcome::Unknown { code } => Err(unavailable(&code)),
        }
    }

    /// Re-read public status: lock, profile and master.
    fn refresh(&self) -> Result<(), CustodyRefusal> {
        let Answer::Status { status } = self.call(Operation::Status {}, NONINTERACTIVE)? else {
            return Err(unexpected());
        };
        let mut state = lock(&self.state);
        state.locked = status.locked;
        if let Some(master) = status.master_public_key {
            state.master = master;
        }
        if let Some(profile) = status.profile {
            state.profile = ProfileId(profile);
        }
        Ok(())
    }

    /// Follow lock facts and custodian loss for the lock watch and holders.
    fn follow(self: Arc<Self>) {
        loop {
            match self.client() {
                Ok(client) if client.observed().alive => {
                    self.sync(&client);
                    let seen = client.observed().generation;
                    client.wait_for_change(seen, Duration::from_secs(5));
                },
                _ => {
                    // Custodian loss is a lock: honest holders forget keys.
                    *lock(&self.applied) = None;
                    self.apply_locked();
                    std::thread::sleep(Duration::from_secs(2));
                },
            }
        }
    }

    /// Apply the custodian's current state once: refresh status, then lock
    /// the holders or re-derive them through the custodian. The status is
    /// read every time, because an outcome can reach this client before the
    /// fact that names its generation.
    fn sync(&self, client: &Client) {
        let mut applied = lock(&self.applied);
        if self.refresh().is_err() {
            return;
        }
        let observed = client.observed();
        let locked = lock(&self.state).locked;
        let key = (observed.instance.clone(), observed.generation, locked);
        if applied.as_ref() == Some(&key) {
            return;
        }
        match locked {
            true => self.apply_locked(),
            false => self.apply_unlocked(),
        }
        *applied = Some(key);
    }

    fn apply_locked(&self) {
        lock(&self.state).locked = true;
        for holder in lock(&self.holders).iter() {
            holder.lock();
        }
        self.lock.send_replace(VaultLockView::Locked);
    }

    fn apply_unlocked(&self) {
        let holders: Vec<_> = lock(&self.holders).clone();
        for holder in holders {
            if let Err(error) = holder.unlock(self) {
                tracing::warn!(holder = holder.name(), %error, "holder stayed locked after the custodian unlocked");
                holder.lock();
            }
        }
        self.lock.send_replace(VaultLockView::Unlocked);
    }

    fn released(
        &self,
        source: Source,
        profile: Option<&ProfileId>,
        salts: &[Vec<u8>],
    ) -> Result<
        (
            [u8; 32],
            Vec<(Vec<u8>, Ed25519Keypair, insigne::DerivedKeyAttestation)>,
        ),
        CustodyRefusal,
    > {
        let operation = Operation::Derive {
            source,
            profile: profile.map(|p| p.0.clone()),
            salts: salts.iter().map(|s| Bytes(s.clone())).collect(),
        };
        let Answer::Released {
            master_public_key,
            keys,
        } = self.call(operation, PROMPTED)?
        else {
            return Err(unexpected());
        };
        if keys.len() != salts.len() || keys.iter().zip(salts).any(|(k, s)| &k.salt.0 != s) {
            return Err(unexpected());
        }
        let master = Ed25519PublicKey::from_bytes(&master_public_key).map_err(|_| unexpected())?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let seed = zeroize::Zeroizing::new(
                <[u8; 32]>::try_from(key.seed.expose()).map_err(|_| unexpected())?,
            );
            let attestation = insigne::DerivedKeyAttestation::from_parts(
                key.attestation.master,
                key.attestation.derived,
                key.attestation.signature.0,
            );
            out.push((key.salt.0, Ed25519Keypair::from_seed(*seed), attestation));
        }
        // The same checks a retained release makes: every attestation checks
        // under its salt, names this master and names the key it came with.
        RetainedKeys::from_released(
            master,
            out.iter()
                .map(|(s, k, a)| (s.clone(), Ed25519Keypair::from_seed(k.to_seed()), a.clone())),
        )
        .map_err(|_| unexpected())?;
        Ok((master_public_key, out))
    }
}

impl IdentityProvider for RemoteHost {
    fn master_public_key(&self) -> Ed25519PublicKey {
        let master = lock(&self.state).master;
        Ed25519PublicKey::from_bytes(&master)
            .expect("composed only after the custodian opened the vault")
    }

    fn derive_keypair(&self, salt: &[u8]) -> Result<Ed25519Keypair, IdentityError> {
        match self.released(Source::Persona, None, &[salt.to_vec()]) {
            Ok((_, mut keys)) => Ok(keys.remove(0).1),
            Err(CustodyRefusal::Locked) => Err(IdentityError::Locked),
            Err(other) => Err(IdentityError::Backend(format!("{other:?}"))),
        }
    }

    fn attest_derived_key(
        &self,
        salt: &[u8],
    ) -> Result<insigne::DerivedKeyAttestation, IdentityError> {
        self.attest(KeySource::Persona, None, salt)
            .map_err(|refusal| match refusal {
                CustodyRefusal::Locked => IdentityError::Locked,
                other => IdentityError::Backend(format!("{other:?}")),
            })
    }
}

fn verify(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Result<(), CustodyRefusal> {
    let verified = Ed25519PublicKey::from_bytes(public_key)
        .map(|key| key.verify(message, &personae::Ed25519Signature::from_bytes(signature)))
        .unwrap_or(false);
    verified.then_some(()).ok_or_else(unexpected)
}

mod resident;
