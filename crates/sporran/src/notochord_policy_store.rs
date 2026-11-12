// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Persona-scoped persistence for Notochord owner policy.
//!
//! Path: `<settings_dir>/notochord.json`, where the caller supplies the
//! persona's settings directory (`<data_root>/personas/<persona_id>/settings`
//! in Graphshell). This module never learns a persona id.
//! The document contains owner rules and verified revocations. Live carrier
//! facts, principals, admitted streams, and session counters have no field in
//! [`OwnerPolicySet`] and therefore cannot survive a restart accidentally.

use std::path::{Path, PathBuf};
use std::{fs, io};

use notochord::OwnerPolicySet;


/// Persona-scoped Notochord policy filename.
pub const NOTOCHORD_POLICY_FILENAME: &str = "notochord.json";

/// Path to one persona's persisted owner policy, in its settings directory.
pub fn notochord_policy_path(settings_dir: &Path) -> PathBuf {
    settings_dir.join(NOTOCHORD_POLICY_FILENAME)
}

/// Load the owner's Notochord policy, or `None` for a fresh persona.
///
/// Malformed policy is an error. Silently replacing it with a closed default
/// would hide both owner intent and revocation state.
pub fn load_notochord_policy(settings_dir: &Path) -> io::Result<Option<OwnerPolicySet>> {
    let path = notochord_policy_path(settings_dir);
    match fs::read_to_string(path) {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Persist owner policy beside the persona's other settings.
///
/// The temporary file is fully written before it replaces the previous
/// document through Muniment's recoverable replacement mechanism.
pub fn save_notochord_policy(settings_dir: &Path, policies: &OwnerPolicySet) -> io::Result<()> {
    policies
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let target = notochord_policy_path(settings_dir);
    let json = serde_json::to_string_pretty(policies)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    muniment::atomic_file::write_bytes_with_backup(&target, json.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use notochord::{NetworkId, OwnerNetworkPolicy, OwnerPolicyEdit, ServiceAccess, ServiceRule};

    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mere-notochord-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn settings() -> OwnerPolicySet {
        let mut network = OwnerNetworkPolicy::closed(NetworkId([7; 32]));
        network.apply(OwnerPolicyEdit::Service {
            path: "/services/murm".to_string(),
            rule: ServiceRule::new(
                ServiceAccess::MemberOnly,
                "mere.network",
                ["connect"],
                true,
                Some(3),
            ),
        });
        network.apply(OwnerPolicyEdit::Transit(true));
        let mut policies = OwnerPolicySet::new();
        policies.upsert(network);
        policies
    }

    #[test]
    fn owner_policy_survives_restart_without_live_session_state() {
        let root = scratch("restart");
        let policies = settings();

        save_notochord_policy(&root, &policies).expect("first save");
        let restored = load_notochord_policy(&root)
            .expect("load")
            .expect("policy exists");
        assert_eq!(restored, policies);

        let json = fs::read_to_string(notochord_policy_path(&root)).expect("read policy");
        assert!(!json.contains("authenticated_initiator"));
        assert!(!json.contains("session_id"));
        assert!(!json.contains("AdmittedPrincipal"));
        assert!(!json.contains("SessionFacts"));

        fs::remove_dir_all(root).expect("remove scratch");
    }

    #[test]
    fn a_second_save_replaces_the_policy_document() {
        let root = scratch("replace");
        let mut policies = settings();
        save_notochord_policy(&root, &policies).expect("first save");

        policies
            .network_mut(NetworkId([7; 32]))
            .expect("network")
            .apply(OwnerPolicyEdit::Transit(false));
        save_notochord_policy(&root, &policies).expect("replacement save");

        let restored = load_notochord_policy(&root)
            .expect("load")
            .expect("policy exists");
        assert_eq!(restored, policies);
        assert!(
            !notochord_policy_path(&root)
                .with_extension("json.previous")
                .exists()
        );

        fs::remove_dir_all(root).expect("remove scratch");
    }

    #[test]
    fn an_unsupported_document_is_neither_loaded_nor_saved() {
        let root = scratch("version");
        let mut policies = settings();
        policies.version += 1;
        let error = save_notochord_policy(&root, &policies).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let path = notochord_policy_path(&root);
        fs::create_dir_all(path.parent().unwrap()).expect("settings directory");
        fs::write(&path, serde_json::to_string(&policies).unwrap()).expect("future policy");
        let error = load_notochord_policy(&root).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        fs::remove_dir_all(root).expect("remove scratch");
    }
}
