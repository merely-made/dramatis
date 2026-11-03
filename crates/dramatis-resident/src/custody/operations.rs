// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Derive `requests` from `persona`'s current private epoch under
/// `data_root`, each checked against `policy`, in this process. Only builds
/// with `in-process-custody` (tests and receipt hosts) have it; a resident
/// with a custodian asks [`crate::custody_host::ResidentCustody::epoch_keys`].
#[cfg(feature = "in-process-custody")]
pub fn epoch_keys(
    policy: &ReleasePolicy,
    data_root: &Path,
    persona: personae::PersonaId,
    device_label: Option<&str>,
    requests: &[EpochKeyRequest],
) -> Result<Vec<ReleasedEpochKey>, CustodyRefusal> {
    if requests.is_empty() || requests.iter().any(|request| !policy.allows_epoch(request)) {
        return Err(CustodyRefusal::NotReleasable);
    }
    let wire: Vec<_> = requests
        .iter()
        .map(|r| custody_wire::EpochKeyRequest {
            context: r.context.clone(),
            device_bound: r.device_bound,
            public_only: r.public_only,
        })
        .collect();
    let keys = djinn_custodian::wallet::epoch_keys(data_root, persona, device_label, &wire)
        .map_err(|r| crate::custody_host::refusal(r.0))?;
    keys.into_iter()
        .zip(requests)
        .map(|(key, request)| {
            Ok(ReleasedEpochKey {
                request: request.clone(),
                key: <[u8; 32]>::try_from(key.key.expose()).map_err(failed)?,
            })
        })
        .collect()
}

/// Release `salts`' keys from `source`, each with its attestation (D11).
/// The declaration and grant admitted the salts; the floors hold here.
pub(super) async fn release(
    keeper: &Keeper,
    app: &AppId,
    authority: &AppAuthority,
    source: KeySource,
    profile: Option<ProfileId>,
    salts: Vec<Vec<u8>>,
) -> Result<CustodyAnswer, CustodyRefusal> {
    if salts.is_empty()
        || salts
            .iter()
            .any(|salt| salt.is_empty() || !station_floor(authority, salt))
    {
        return Err(CustodyRefusal::NotReleasable);
    }
    let host = Arc::clone(keeper.host());
    let (master, keys) =
        tokio::task::spawn_blocking(move || host.release(source, profile.as_ref(), &salts))
            .await
            .map_err(failed)??;
    tracing::info!(app = %app, keys = keys.len(), ?source, "released derived keys");
    Ok(CustodyAnswer::Released { master, keys })
}

/// The root's attestation of `salt`'s key; no key crosses.
pub(super) async fn attest(
    keeper: &Keeper,
    source: KeySource,
    profile: Option<ProfileId>,
    salt: Vec<u8>,
) -> Result<CustodyAnswer, CustodyRefusal> {
    if salt.is_empty() {
        return Err(CustodyRefusal::NotReleasable);
    }
    let host = Arc::clone(keeper.host());
    tokio::task::spawn_blocking(move || host.attest(source, profile.as_ref(), &salt))
        .await
        .map_err(failed)?
        .map(CustodyAnswer::Attestation)
}

/// Sign `message` with `salt`'s key where the key is; only the signature
/// crosses. A Graphshell guest delegation is decoded and checked for its
/// audience, issuer and scope key before it is signed.
pub(super) async fn sign(
    keeper: &Keeper,
    source: KeySource,
    profile: Option<ProfileId>,
    salt: Vec<u8>,
    message: Vec<u8>,
) -> Result<CustodyAnswer, CustodyRefusal> {
    if salt.is_empty() {
        return Err(CustodyRefusal::NotReleasable);
    }
    let host = Arc::clone(keeper.host());
    let delegation = source == KeySource::Persona
        && profile.is_none()
        && crate::custodian::is_graphshell_delegation(&salt);
    let (public_key, signature) = tokio::task::spawn_blocking(move || match delegation {
        true => host.sign_delegation(crate::custodian::GRAPHSHELL_AUDIENCE, &salt, &message),
        false => host.sign(source, profile.as_ref(), &salt, &message),
    })
    .await
    .map_err(failed)??;
    Ok(CustodyAnswer::Signature {
        public_key,
        signature,
    })
}

/// Refuse while the vault is Locked: every act and release waits for an
/// unlock (D12).
pub(super) fn unlocked(keeper: &Keeper) -> Result<(), CustodyRefusal> {
    match keeper.is_locked() {
        true => Err(CustodyRefusal::Locked),
        false => Ok(()),
    }
}

pub(super) fn status(keeper: &Keeper) -> Result<ResidentStatus, CustodyRefusal> {
    let custody_epoch = keeper.host().custody_epoch()?;
    let snapshot = keeper.snapshot().map_err(failed)?;
    let lock = snapshot.vault.lock;
    let profile = snapshot
        .profiles
        .iter()
        .find(|profile| profile.selected)
        .map(|profile| ProfileId(profile.id.clone()));
    let (persona_public_key, wallet_public_key) = match lock {
        VaultLockView::Locked => (None, None),
        VaultLockView::Unlocked => (
            Some(keeper.master_public_key().to_bytes()),
            keeper.host().root_public_key(KeySource::Wallet, None).ok(),
        ),
    };
    if keeper.host().custody_epoch()? != custody_epoch {
        return Err(refused("custody changed during status observation"));
    }
    Ok(ResidentStatus {
        lock,
        protection: snapshot.vault.protection,
        profile,
        persona_public_key,
        wallet_public_key,
        wallet_root: keeper.wallet_root().map(Into::into),
        custody_epoch,
    })
}

/// The roster from the keeper's public view, which it keeps while Locked
/// (vault lock ruling 11), so a picker draws either way.
pub(super) fn roster(keeper: &Keeper) -> Result<Roster, CustodyRefusal> {
    let snapshot = keeper.snapshot().map_err(failed)?;
    let mut entries: Vec<RosterEntry> = snapshot
        .profiles
        .iter()
        .map(|profile| RosterEntry {
            id: ProfileId(profile.id.clone()),
            display_name: profile.display_name.clone(),
            slot_count: profile.slot_count,
            chosen: profile.selected,
        })
        .collect();
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    let chosen = entries
        .iter()
        .find(|entry| entry.chosen)
        .map(|entry| entry.id.clone())
        .or_else(dramatis::authentication::env_profile)
        .unwrap_or_else(|| ProfileId("default".into()));
    Ok(Roster {
        entries,
        chosen,
        description: format!("{:?}", snapshot.vault.protection),
    })
}

pub(super) fn refused(error: impl std::fmt::Display) -> CustodyRefusal {
    CustodyRefusal::Refused {
        reason: error.to_string(),
    }
}

pub(super) fn failed(error: impl std::fmt::Display) -> CustodyRefusal {
    CustodyRefusal::Failed {
        reason: error.to_string(),
    }
}
