// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// In-memory [`IdentityStorage`] for tests and ephemeral runs.
///
/// Profiles are held in a `Mutex<HashMap>`; a clone of the storage shares
/// the same backing map so multiple consumers can see each other's
/// profile updates. Not for production — see plan §3.2 for the production
/// backends to come.
#[derive(Default, Clone)]
pub struct InMemoryStorage {
    inner: std::sync::Arc<std::sync::Mutex<HashMap<ProfileId, ProfileBytes>>>,
}

/// Wire-shaped representation of a profile for in-memory storage.
///
/// In a real backend this would be the at-rest encrypted form. Here we
/// keep it as a structural clone so tests can round-trip without
/// implementing serde plumbing yet.
struct ProfileBytes {
    display_name: String,
    master_seed: [u8; 32],
    slots: HashMap<ProtocolKey, SerializedSlot>,
}

/// Storage-shaped slot — same shape as [`IdentitySlot`] but with cloneable
/// payload bytes (so the storage map can hold and re-issue them).
struct SerializedSlot {
    kind: String,
    payload: Vec<u8>,
    bootstrap_state_dir: Option<PathBuf>,
    lineage: CredentialLineage,
    unlock_tier: UnlockTier,
    is_bootstrap: bool,
}

impl InMemoryStorage {
    /// Construct an empty in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }
}

fn serialize_slot(slot: &IdentitySlot) -> SerializedSlot {
    match slot {
        IdentitySlot::Direct {
            kind,
            payload,
            lineage,
            unlock_tier,
        } => SerializedSlot {
            kind: kind.clone(),
            payload: payload.as_slice().to_vec(),
            bootstrap_state_dir: None,
            lineage: *lineage,
            unlock_tier: *unlock_tier,
            is_bootstrap: false,
        },
        IdentitySlot::Bootstrap {
            kind,
            bootstrap,
            state_dir,
            lineage,
            unlock_tier,
        } => SerializedSlot {
            kind: kind.clone(),
            payload: bootstrap.as_slice().to_vec(),
            bootstrap_state_dir: Some(state_dir.clone()),
            lineage: *lineage,
            unlock_tier: *unlock_tier,
            is_bootstrap: true,
        },
    }
}

fn deserialize_slot(s: &SerializedSlot) -> IdentitySlot {
    if s.is_bootstrap {
        IdentitySlot::Bootstrap {
            kind: s.kind.clone(),
            bootstrap: SecretBytes::new(s.payload.clone()),
            state_dir: s
                .bootstrap_state_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".")),
            lineage: s.lineage,
            unlock_tier: s.unlock_tier,
        }
    } else {
        IdentitySlot::Direct {
            kind: s.kind.clone(),
            payload: SecretBytes::new(s.payload.clone()),
            lineage: s.lineage,
            unlock_tier: s.unlock_tier,
        }
    }
}

impl IdentityStorage for InMemoryStorage {
    fn load_profile(&self, id: &ProfileId) -> Result<Profile, IdentityError> {
        let guard = self.inner.lock().unwrap();
        let bytes = guard
            .get(id)
            .ok_or_else(|| IdentityError::Backend(format!("profile not found: {:?}", id)))?;
        let mut slots = SlotMap::with_capacity(bytes.slots.len());
        for (k, s) in &bytes.slots {
            slots.insert(k.clone(), deserialize_slot(s));
        }
        Ok(Profile {
            id: id.clone(),
            display_name: bytes.display_name.clone(),
            master: Ed25519Keypair::from_seed(bytes.master_seed),
            slots,
        })
    }

    fn save_profile(&self, profile: &Profile) -> Result<(), IdentityError> {
        let mut guard = self.inner.lock().unwrap();
        let mut slot_map = HashMap::with_capacity(profile.slots.len());
        for (k, s) in &profile.slots {
            slot_map.insert(k.clone(), serialize_slot(s));
        }
        guard.insert(
            profile.id.clone(),
            ProfileBytes {
                display_name: profile.display_name.clone(),
                master_seed: profile.master.to_seed(),
                slots: slot_map,
            },
        );
        Ok(())
    }

    fn delete_profile(&self, id: &ProfileId) -> Result<(), IdentityError> {
        self.inner.lock().unwrap().remove(id);
        Ok(())
    }

    fn list_profiles(&self) -> Result<Vec<ProfileSummary>, IdentityError> {
        let guard = self.inner.lock().unwrap();
        Ok(guard
            .iter()
            .map(|(id, bytes)| ProfileSummary {
                id: id.clone(),
                display_name: bytes.display_name.clone(),
                slot_count: bytes.slots.len(),
            })
            .collect())
    }

    /// None: the fixture holds plaintext and has no key to forget, so a
    /// vault over it refuses to lock.
    fn unlock_methods(&self) -> UnlockMethods {
        UnlockMethods::default()
    }

    fn lock(&self) {}

    fn is_locked(&self) -> bool {
        false
    }

    fn unlock(&self, _method: UnlockMethod<'_>) -> Result<(), IdentityError> {
        Ok(())
    }
}
