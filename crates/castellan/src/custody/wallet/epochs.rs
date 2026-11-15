// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The transitional per-persona private-epoch bridge: epoch material staged
//! for pairing-time wrapping, only ever at rest as a sealed record.

use std::io;
use std::path::Path;

use personae::{InMemoryProvider, PersonaId};

use super::at_rest::{no_sealed_store, refuse_raw};
use super::secrets::{io_backend_error, wallet_persona_secret_store};
use super::{KeyEpochId, PersonaEpochBridge, PrivateEpochRecord};
use sporran::wallet_store::load_persona_wallet;
use sporran::wallet_store::persona_epoch_bridge_path;

/// Load one persona epoch bridge, or `None` when absent.
pub fn load_persona_epoch_bridge(
    data_root: &Path,
    persona: PersonaId,
) -> io::Result<Option<PersonaEpochBridge>> {
    let path = persona_epoch_bridge_path(data_root, persona);
    if !path.is_file() {
        return Ok(None);
    }
    let relative = path
        .strip_prefix(data_root)
        .expect("wallet path under data root");
    // Custody D5: a raw legacy bridge is refused, a sealed-read failure returned.
    refuse_raw(&path)?;
    let Some(store) = wallet_persona_secret_store(data_root)? else {
        return Ok(None);
    };
    store.load_record(relative).map_err(io_backend_error)
}

/// Save one persona epoch bridge as a sealed record; with no sealed store
/// this is refused and nothing is written.
pub fn save_persona_epoch_bridge(data_root: &Path, bridge: &PersonaEpochBridge) -> io::Result<()> {
    let path = persona_epoch_bridge_path(data_root, bridge.persona_id);
    let store = wallet_persona_secret_store(data_root)?
        .ok_or_else(|| no_sealed_store("private-epoch bridge"))?;
    store
        .save_record(
            path.strip_prefix(data_root)
                .expect("wallet path under data root"),
            bridge,
        )
        .map_err(io_backend_error)
}

/// Ensure the temporary plaintext epoch bridge contains `epoch_id`.
pub fn ensure_persona_epoch_bridge(
    data_root: &Path,
    persona: PersonaId,
    epoch_id: KeyEpochId,
) -> io::Result<PersonaEpochBridge> {
    let mut bridge = load_persona_epoch_bridge(data_root, persona)?
        .unwrap_or_else(|| PersonaEpochBridge::new(persona));
    if !bridge.epochs.iter().any(|epoch| epoch.epoch_id == epoch_id) {
        bridge.epochs.push(PrivateEpochRecord {
            epoch_id,
            epoch_secret: InMemoryProvider::random()
                .master_keypair()
                .to_seed()
                .to_vec(),
        });
        save_persona_epoch_bridge(data_root, &bridge)?;
    }
    Ok(bridge)
}

/// Stage a known plaintext private epoch in the temporary host bridge.
pub fn stage_persona_private_epoch(
    data_root: &Path,
    persona: PersonaId,
    epoch_id: KeyEpochId,
    epoch_secret: &[u8],
) -> io::Result<PersonaEpochBridge> {
    let mut bridge = load_persona_epoch_bridge(data_root, persona)?
        .unwrap_or_else(|| PersonaEpochBridge::new(persona));
    let mut changed = false;
    match bridge
        .epochs
        .iter_mut()
        .find(|epoch| epoch.epoch_id == epoch_id)
    {
        Some(existing) => {
            if existing.epoch_secret != epoch_secret {
                existing.epoch_secret = epoch_secret.to_vec();
                changed = true;
            }
        },
        None => {
            bridge.epochs.push(PrivateEpochRecord {
                epoch_id,
                epoch_secret: epoch_secret.to_vec(),
            });
            changed = true;
        },
    }
    if changed {
        save_persona_epoch_bridge(data_root, &bridge)?;
    }
    Ok(bridge)
}

/// Load the current plaintext private epoch for `persona`, if the temporary
/// host bridge has one matching the wallet's `private_epoch_head`.
pub fn load_current_private_epoch(
    data_root: &Path,
    persona: PersonaId,
) -> io::Result<Option<PrivateEpochRecord>> {
    let Some(wallet) = load_persona_wallet(data_root, persona)? else {
        return Ok(None);
    };
    let Some(bridge) = load_persona_epoch_bridge(data_root, persona)? else {
        return Ok(None);
    };
    Ok(bridge
        .epochs
        .into_iter()
        .find(|epoch| epoch.epoch_id == wallet.private_epoch_head))
}

#[cfg(test)]
mod tests {
    use super::super::secrets::save_identity_seed;
    use super::super::store_test_support::*;
    use super::super::*;
    use super::*;
    use std::fs;

    #[test]
    fn persona_epoch_bridge_round_trips() {
        let root = temp_data_root("epoch-bridge");
        // A bridge is sealed under the seed's store (custody D5).
        save_identity_seed(&root, [0x45; 32]).unwrap();
        let bridge = PersonaEpochBridge {
            schema_version: WALLET_SCHEMA_VERSION,
            persona_id: fixture_persona(),
            epochs: vec![PrivateEpochRecord {
                epoch_id: fixture_epoch(),
                epoch_secret: vec![0x44; 32],
            }],
        };
        save_persona_epoch_bridge(&root, &bridge).unwrap();
        let restored = load_persona_epoch_bridge(&root, fixture_persona())
            .unwrap()
            .unwrap();
        assert_eq!(restored, bridge);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn copy_seeded_persona_epoch_bridge_round_trips_as_a_sealed_record() {
        let root = temp_data_root("epoch-bridge-sealed-copy");
        save_identity_seed(&root, [0x44; 32]).unwrap();
        let bridge = PersonaEpochBridge {
            schema_version: WALLET_SCHEMA_VERSION,
            persona_id: fixture_persona(),
            epochs: vec![PrivateEpochRecord {
                epoch_id: fixture_epoch(),
                epoch_secret: b"known-private-epoch".to_vec(),
            }],
        };

        save_persona_epoch_bridge(&root, &bridge).unwrap();
        let restored = load_persona_epoch_bridge(&root, fixture_persona())
            .unwrap()
            .unwrap();
        assert_eq!(restored, bridge);

        let text = fs::read_to_string(persona_epoch_bridge_path(&root, fixture_persona())).unwrap();
        assert!(!text.contains("\"epoch_secret\":["));
        assert!(!text.contains("known-private-epoch"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn delegated_persona_epoch_bridge_round_trips_as_a_sealed_record() {
        let root = temp_data_root("epoch-bridge-sealed-delegated");
        ensure_local_device_identity(&root, "Pocket Meerkat").unwrap();
        let bridge = PersonaEpochBridge {
            schema_version: WALLET_SCHEMA_VERSION,
            persona_id: fixture_persona(),
            epochs: vec![PrivateEpochRecord {
                epoch_id: fixture_epoch(),
                epoch_secret: b"known-private-epoch".to_vec(),
            }],
        };

        save_persona_epoch_bridge(&root, &bridge).unwrap();
        let restored = load_persona_epoch_bridge(&root, fixture_persona())
            .unwrap()
            .unwrap();
        assert_eq!(restored, bridge);

        let text = fs::read_to_string(persona_epoch_bridge_path(&root, fixture_persona())).unwrap();
        assert!(!text.contains("\"epoch_secret\":["));
        assert!(!text.contains("known-private-epoch"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_legacy_plaintext_persona_epoch_bridge_is_refused_until_the_explicit_migration() {
        let root = temp_data_root("epoch-bridge-migrate");
        save_identity_seed(&root, [0x51; 32]).unwrap();
        let bridge = PersonaEpochBridge {
            schema_version: WALLET_SCHEMA_VERSION,
            persona_id: fixture_persona(),
            epochs: vec![PrivateEpochRecord {
                epoch_id: fixture_epoch(),
                epoch_secret: b"known-private-epoch".to_vec(),
            }],
        };
        save_json_atomic(
            &persona_epoch_bridge_path(&root, fixture_persona()),
            &bridge,
        )
        .unwrap();

        let error = load_persona_epoch_bridge(&root, fixture_persona()).unwrap_err();
        assert!(matches!(
            WalletSecretRefusal::of(&error),
            Some(WalletSecretRefusal::LegacyRaw { .. })
        ));
        migrate_legacy_wallet_secrets(&root).unwrap();

        let restored = load_persona_epoch_bridge(&root, fixture_persona())
            .unwrap()
            .unwrap();
        assert_eq!(restored, bridge);

        let text = fs::read_to_string(persona_epoch_bridge_path(&root, fixture_persona())).unwrap();
        assert!(!text.contains("\"epoch_secret\":["));
        assert!(!text.contains("known-private-epoch"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_persona_epoch_bridge_is_idempotent_for_the_same_epoch() {
        let root = temp_data_root("ensure-epoch-bridge");
        // A bridge is sealed under the seed's store (custody D5).
        save_identity_seed(&root, [0x45; 32]).unwrap();
        let first = ensure_persona_epoch_bridge(&root, fixture_persona(), fixture_epoch()).unwrap();
        let second =
            ensure_persona_epoch_bridge(&root, fixture_persona(), fixture_epoch()).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.epochs.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_persona_private_epoch_replaces_existing_secret() {
        let root = temp_data_root("stage-epoch-bridge");
        // A bridge is sealed under the seed's store (custody D5).
        save_identity_seed(&root, [0x45; 32]).unwrap();
        ensure_persona_epoch_bridge(&root, fixture_persona(), fixture_epoch()).unwrap();

        stage_persona_private_epoch(
            &root,
            fixture_persona(),
            fixture_epoch(),
            b"known-private-epoch",
        )
        .unwrap();

        let bridge = load_persona_epoch_bridge(&root, fixture_persona())
            .unwrap()
            .expect("bridge should exist");
        assert_eq!(bridge.epochs.len(), 1);
        assert_eq!(bridge.epochs[0].epoch_id, fixture_epoch());
        assert_eq!(
            bridge.epochs[0].epoch_secret,
            b"known-private-epoch".to_vec()
        );
        let _ = fs::remove_dir_all(&root);
    }
}
