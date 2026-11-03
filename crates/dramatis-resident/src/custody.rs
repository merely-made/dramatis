// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The custody route's answers: what djinn does for an application that
//! asks instead of opening a vault, storage or wallet (dramatis repo plan,
//! D5, D11, D12, D17).
//!
//! - **Reads** (status, roster) answer Locked or not, so an app can show its
//!   identity as pending (D12).
//! - **Root-level acts** (attest, sign, issue a station grant, revoke a
//!   device) happen here; only their results cross (D11).
//! - **Releases** hand over the derived keys for salts the [`ReleasePolicy`]
//!   names, never the master, each with the master's attestation. A lock
//!   revokes them through the existing lock broadcast: `WatchLock` answers
//!   from the host's lock watch channel, and the app drops what it holds.
//! - **Epoch releases** hand over keys derived from a persona wallet's current
//!   private epoch, for the derivations the policy names, never the epoch.
//!   Knot's vault and writer keys are the first (DR-C): djinn derives them
//!   with the same `blake3::derive_key` Knot used, so stores keep their keys.

use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "in-process-custody")]
use castellan_client::custody::ReleasedEpochKey;
use castellan_client::custody::{
    CustodyAnswer, CustodyCall, CustodyRefusal, EpochKeyRequest, KeySource, ResidentStatus,
};
use dramatis::intents::{CreateProfileIntentV1, SwitchProfileIntentV1};
use dramatis::roster::{Roster, RosterEntry};
use dramatis::view::VaultLockView;
use ostiary::app_admission::AppId;
use ostiary::declaration::{AppAuthority, SaltPattern};
use personae::ProfileId;

use crate::custody_host::VaultOutput;
use crate::keeper::Keeper;
pub(crate) mod payload;

/// Which derived keys djinn releases, by root and salt (D11). Everything
/// else stays in djinn: the master always, the doors' keys, the records'
/// keys, any salt nobody named.
#[derive(Clone)]
pub struct ReleasePolicy {
    rules: Vec<(KeySource, SaltRule)>,
    epoch: Vec<EpochRule>,
    acts: Vec<(KeySource, SaltRule)>,
}

/// One epoch derivation a release may hand over: its context, whether it
/// mixes in the device root, and whether its secret may leave or only its
/// public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRule {
    pub context: String,
    pub device_bound: bool,
    pub secret: bool,
}

impl EpochRule {
    fn allows(&self, request: &EpochKeyRequest) -> bool {
        self.context == request.context
            && self.device_bound == request.device_bound
            && (self.secret || request.public_only)
    }
}

/// One namespace a release may draw from.
#[derive(Clone)]
pub enum SaltRule {
    /// Exactly this salt.
    Exact(Vec<u8>),
    /// Any salt beginning with these bytes (and longer than them).
    Prefix(Vec<u8>),
    /// Any salt the function accepts.
    Matches(fn(&[u8]) -> bool),
}

impl SaltRule {
    fn allows(&self, salt: &[u8]) -> bool {
        match self {
            Self::Exact(exact) => salt == exact.as_slice(),
            Self::Prefix(prefix) => salt.len() > prefix.len() && salt.starts_with(prefix),
            Self::Matches(test) => test(salt),
        }
    }
}

impl ReleasePolicy {
    /// Release nothing.
    pub fn none() -> Self {
        Self {
            rules: Vec::new(),
            epoch: Vec::new(),
            acts: Vec::new(),
        }
    }

    /// Sign and attest, but never release, salts matching `rule` from
    /// `source`: root-level acts done here on an app's behalf (D11).
    pub fn with_act(mut self, source: KeySource, rule: SaltRule) -> Self {
        self.acts.push((source, rule));
        self
    }

    /// Whether djinn may sign or attest with `salt`'s key for an app: any
    /// releasable salt, and the acts' salts. Never the master's place.
    pub fn allows_act(&self, source: KeySource, salt: &[u8]) -> bool {
        self.allows(source, salt)
            || (!salt.is_empty()
                && self
                    .acts
                    .iter()
                    .any(|(from, rule)| *from == source && rule.allows(salt)))
    }

    /// Release the epoch derivation `rule` names as well.
    pub fn with_epoch(mut self, rule: EpochRule) -> Self {
        self.epoch.push(rule);
        self
    }

    /// Release exactly the epoch derivations an application declares, for a
    /// resident that composes it in process.
    pub fn with_declared_epochs(self, uses: &[ostiary::declaration::EpochUse]) -> Self {
        uses.iter().fold(self, |policy, used| {
            policy.with_epoch(EpochRule {
                context: used.context.clone(),
                device_bound: used.device_bound,
                secret: used.secret,
            })
        })
    }

    /// Whether the epoch derivation `request` may leave djinn.
    pub fn allows_epoch(&self, request: &EpochKeyRequest) -> bool {
        !request.context.is_empty() && self.epoch.iter().any(|rule| rule.allows(request))
    }

    /// Release salts matching `rule` from `source` as well.
    pub fn with(mut self, source: KeySource, rule: SaltRule) -> Self {
        self.rules.push((source, rule));
        self
    }

    /// Whether `salt` from `source` may leave djinn. An empty salt is the
    /// master's place and never may.
    pub fn allows(&self, source: KeySource, salt: &[u8]) -> bool {
        !salt.is_empty()
            && self
                .rules
                .iter()
                .any(|(from, rule)| *from == source && rule.allows(salt))
    }
}

/// Answer one custody call for `app`.
///
/// Only a declared application (`authority`) is answered, and only the
/// calls, epoch derivations and salts its declaration names and its owner
/// grants (capability door D24). The floors hold for every caller: never the
/// master's place, a radio station's salts only under a grant naming that
/// station namespace itself, and a Graphshell delegation checked before it
/// is signed.
pub(crate) async fn answer(
    keeper: Arc<Keeper>,
    app: AppId,
    authority: Option<AppAuthority>,
    call: CustodyCall,
) -> Result<CustodyAnswer, CustodyRefusal> {
    tracing::debug!(app = %app, call = call_name(&call), declared = authority.is_some(), "custody call");
    let Some(authority) = authority else {
        return Err(CustodyRefusal::Undeclared {
            what: "a declaration".into(),
        });
    };
    call.admitted_by(&authority)?;
    match call {
        CustodyCall::Payload(request) => payload::answer(&keeper, &authority, request),
        CustodyCall::LockVault => {
            keeper.host().lock_vault().map_err(refused)?;
            Ok(CustodyAnswer::Done)
        },
        CustodyCall::ChangePassphraseNative(_) => {
            let receipt = tokio::task::spawn_blocking(move || keeper.change_passphrase_native())
                .await
                .map_err(failed)?;
            Ok(CustodyAnswer::PassphraseChange { receipt })
        },
        CustodyCall::UnlockNative => tokio::task::spawn_blocking(move || keeper.unlock_native())
            .await
            .map_err(failed)?,
        CustodyCall::UnassignedImports => {
            #[cfg(feature = "cxf")]
            {
                unlocked(&keeper)?;
                keeper
                    .unassigned_imports()
                    .map(|imports| CustodyAnswer::UnassignedImports { imports })
            }
            #[cfg(not(feature = "cxf"))]
            {
                Err(CustodyRefusal::NotServed)
            }
        },
        CustodyCall::AssignImport(request) => {
            #[cfg(feature = "cxf")]
            {
                unlocked(&keeper)?;
                tokio::task::spawn_blocking(move || keeper.assign_import(request))
                    .await
                    .map_err(failed)?
            }
            #[cfg(not(feature = "cxf"))]
            {
                let _ = request;
                Err(CustodyRefusal::NotServed)
            }
        },
        CustodyCall::Quarantine { profile } => {
            #[cfg(feature = "cxf")]
            {
                unlocked(&keeper)?;
                keeper
                    .quarantine(&profile)
                    .map(|cards| CustodyAnswer::Quarantine { cards })
            }
            #[cfg(not(feature = "cxf"))]
            {
                let _ = profile;
                Err(CustodyRefusal::NotServed)
            }
        },
        CustodyCall::ReviewQuarantine(request) => {
            #[cfg(feature = "cxf")]
            {
                unlocked(&keeper)?;
                tokio::task::spawn_blocking(move || keeper.review_quarantine(request))
                    .await
                    .map_err(failed)?
            }
            #[cfg(not(feature = "cxf"))]
            {
                let _ = request;
                Err(CustodyRefusal::NotServed)
            }
        },
        CustodyCall::VaultCommand {
            profile,
            command,
            args,
        } => {
            unlocked(&keeper)?;
            #[cfg(feature = "cxf")]
            if matches!(command.as_str(), "cxf-preview" | "cxf-import") {
                return tokio::task::spawn_blocking(move || {
                    keeper
                        .cxf_command(&command, &args)
                        .map(|text| CustodyAnswer::VaultOutput { text })
                        .map_err(refused)
                })
                .await
                .map_err(failed)?;
            }
            // File import and SSH commands are blocking. The keeper holds its
            // vault mutex for the act, so a lock cannot interleave with it.
            tokio::task::spawn_blocking(move || {
                keeper
                    .host()
                    .vault_command(&profile, &command, &args)
                    .map(|output| match output {
                        VaultOutput::Text(text) => CustodyAnswer::VaultOutput { text },
                        VaultOutput::Enrollment {
                            target,
                            script,
                            confirmation,
                        } => CustodyAnswer::VaultEnrollment {
                            target,
                            script,
                            confirmation,
                        },
                    })
            })
            .await
            .map_err(failed)?
        },
        CustodyCall::Status => status(&keeper).map(CustodyAnswer::Status),
        CustodyCall::Roster => roster(&keeper).map(CustodyAnswer::Roster),
        CustodyCall::ChooseProfile { profile } => {
            unlocked(&keeper)?;
            keeper
                .switch_profile(SwitchProfileIntentV1 { profile: profile.0 })
                .map_err(refused)?;
            Ok(CustodyAnswer::Done)
        },
        CustodyCall::CreateProfile {
            profile,
            display_name,
        } => {
            unlocked(&keeper)?;
            keeper
                .create_profile(CreateProfileIntentV1 {
                    id: profile.0.clone(),
                    display_name,
                })
                .map_err(refused)?;
            keeper
                .switch_profile(SwitchProfileIntentV1 { profile: profile.0 })
                .map_err(refused)?;
            Ok(CustodyAnswer::Done)
        },
        CustodyCall::Release { source, salts } => {
            unlocked(&keeper)?;
            release(&keeper, &app, &authority, source, None, salts).await
        },
        CustodyCall::Attest { source, salt } => {
            if !station_floor(&authority, &salt) {
                return Err(CustodyRefusal::NotReleasable);
            }
            unlocked(&keeper)?;
            attest(&keeper, source, None, salt).await
        },
        CustodyCall::Sign {
            source,
            salt,
            message,
        } => {
            if !station_floor(&authority, &salt) {
                return Err(CustodyRefusal::NotReleasable);
            }
            unlocked(&keeper)?;
            sign(&keeper, source, None, salt, message).await
        },
        CustodyCall::AsProfile { profile, inner } => {
            unlocked(&keeper)?;
            let source = KeySource::Persona;
            match *inner {
                CustodyCall::Status => {
                    let mut status = status(&keeper)?;
                    let host = Arc::clone(keeper.host());
                    let named = profile.clone();
                    status.persona_public_key = Some(
                        tokio::task::spawn_blocking(move || host.root_public_key(source, Some(&named)))
                            .await
                            .map_err(failed)??,
                    );
                    status.profile = Some(profile);
                    Ok(CustodyAnswer::Status(status))
                },
                CustodyCall::Release {
                    source: KeySource::Persona,
                    salts,
                } => release(&keeper, &app, &authority, source, Some(profile), salts).await,
                CustodyCall::Attest {
                    source: KeySource::Persona,
                    salt,
                } => attest(&keeper, source, Some(profile), salt).await,
                CustodyCall::Sign {
                    source: KeySource::Persona,
                    salt,
                    message,
                } => sign(&keeper, source, Some(profile), salt, message).await,
                _ => Err(CustodyRefusal::Refused {
                    reason: "only a status, or a persona release, attestation or signature, answers as a named persona".into(),
                }),
            }
        },
        CustodyCall::IssueStationGrant {
            request,
            issuer_public_key,
        } => {
            unlocked(&keeper)?;
            let root = keeper
                .wallet_root()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            let host = Arc::clone(keeper.host());
            tokio::task::spawn_blocking(move || {
                host.station_grant(&root, &request, issuer_public_key)
            })
            .await
            .map_err(failed)?
            .map(CustodyAnswer::StationGrant)
        },
        CustodyCall::RevokeDevice { device_id } => {
            unlocked(&keeper)?;
            let root = keeper
                .wallet_root()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            let host = Arc::clone(keeper.host());
            tokio::task::spawn_blocking(move || host.revoke_device(&root, device_id))
                .await
                .map_err(failed)?
                .map(CustodyAnswer::Revoked)
        },
        CustodyCall::ReleaseEpochKeys {
            persona,
            device_label,
            keys,
        } => {
            unlocked(&keeper)?;
            if keys.is_empty() {
                return Err(CustodyRefusal::NotReleasable);
            }
            let root = keeper
                .wallet_root()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            let host = Arc::clone(keeper.host());
            let released = tokio::task::spawn_blocking(move || {
                host.epoch_keys(
                    &root,
                    personae::PersonaId::from_uuid(persona),
                    device_label.as_deref(),
                    &keys,
                )
            })
            .await
            .map_err(failed)??;
            tracing::info!(app = %app, keys = released.len(), "released epoch keys");
            Ok(CustodyAnswer::EpochKeys { keys: released })
        },
        CustodyCall::WatchLock { seen } => {
            let mut lock = keeper.lock_state();
            loop {
                let now = *lock.borrow_and_update();
                if now != seen {
                    return Ok(CustodyAnswer::Lock(now));
                }
                if lock.changed().await.is_err() {
                    return Err(CustodyRefusal::Failed {
                        reason: "the resident is shutting down".into(),
                    });
                }
            }
        },
    }
}

fn call_name(call: &CustodyCall) -> &'static str {
    match call {
        CustodyCall::Payload(_) => "retained_payload",
        CustodyCall::VaultCommand { .. } => "vault_command",
        CustodyCall::UnlockNative => "unlock_native",
        CustodyCall::ChangePassphraseNative(_) => "change_passphrase_native",
        CustodyCall::UnassignedImports => "unassigned_imports",
        CustodyCall::AssignImport(_) => "assign_import",
        CustodyCall::LockVault => "lock_vault",
        CustodyCall::Quarantine { .. } => "quarantine",
        CustodyCall::ReviewQuarantine(_) => "review_quarantine",
        CustodyCall::Status => "status",
        CustodyCall::Roster => "roster",
        CustodyCall::ChooseProfile { .. } => "choose_profile",
        CustodyCall::CreateProfile { .. } => "create_profile",
        CustodyCall::Release { .. } => "release",
        CustodyCall::Attest { .. } => "attest",
        CustodyCall::Sign { .. } => "sign",
        CustodyCall::IssueStationGrant { .. } => "issue_station_grant",
        CustodyCall::RevokeDevice { .. } => "revoke_device",
        CustodyCall::WatchLock { .. } => "watch_lock",
        CustodyCall::ReleaseEpochKeys { .. } => "release_epoch_keys",
        CustodyCall::AsProfile { .. } => "as_profile",
    }
}

/// The radio station namespaces (`personae::tucket`, `personae::sennet`).
const STATION_NAMESPACES: [&str; 2] = [
    "mere.signalman.tucket.station/v1/",
    "mere.signalman.sennet.station/v1/",
];

/// A station's salt only under a grant naming that station namespace itself,
/// never under a broader pattern that happens to cover it.
fn station_floor(authority: &AppAuthority, salt: &[u8]) -> bool {
    if !(personae::tucket::is_station_salt(salt) || personae::sennet::is_station_salt(salt)) {
        return true;
    }
    let custody = &authority.grant().custody;
    custody.salts.iter().chain(&custody.acts).any(|used| {
        matches!(&used.name, SaltPattern::Prefix(prefix)
            if STATION_NAMESPACES.contains(&prefix.as_str()) && salt.starts_with(prefix.as_bytes()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostiary::declaration::{AppDeclaration, AppGrant, CustodyUse, SaltUse};

    fn wallet_authority(prefix: &str) -> AppAuthority {
        let used = SaltUse::wallet(SaltPattern::Prefix(prefix.into()));
        let declaration = AppDeclaration {
            custody: CustodyUse {
                salts: vec![used.clone()],
                ..CustodyUse::default()
            },
            ..AppDeclaration::default()
        };
        let mut grant = AppGrant::new(AppId::new("signalman"));
        grant.custody.salts.push(used);
        AppAuthority::new(declaration, grant)
    }

    #[test]
    fn a_station_salt_needs_a_grant_naming_its_station_namespace() {
        for (salt, namespace) in [
            (
                personae::tucket::station_salt(&[4; 16], "ridge").unwrap(),
                STATION_NAMESPACES[0],
            ),
            (
                personae::sennet::station_salt(&[4; 16], "ridge").unwrap(),
                STATION_NAMESPACES[1],
            ),
        ] {
            assert!(station_floor(&wallet_authority(namespace), &salt));
            assert!(
                !station_floor(&wallet_authority("mere.signalman."), &salt),
                "a broader grant does not reach a station's keys"
            );
        }
        assert!(
            station_floor(&wallet_authority("other/"), b"other/salt"),
            "the floor speaks only to station salts"
        );
    }
}

mod operations;

use operations::*;

#[cfg(feature = "in-process-custody")]
pub use operations::epoch_keys;
