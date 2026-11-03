// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! [`PassphraseEncryptedStorage`] — passphrase-encrypted on-disk vault.
//!
//! Phase 2C v0 production-grade backend per
//! [`mere/design_docs/mere_docs/implementation_strategy/2026-05-05_protocol_architecture_plan.md`](../../../../../design_docs/archive_docs/2026-10-28/2026-05-05_protocol_architecture_plan.md)
//! §3.2.
//!
//! ## Wire format
//!
//! All profiles for one user live in a single JSON file. The file is
//! serde-shaped JSON of `EncryptedFile`: per-profile records with
//! ChaCha20-Poly1305 ciphertext + nonce + Argon2id parameters.
//!
//! ## Crypto
//!
//! - **Argon2id** derives a 32-byte KEK from passphrase + per-file salt.
//!   Memory-hard; resists GPU-accelerated brute-force.
//! - **ChaCha20-Poly1305** authenticated encryption per profile. A
//!   per-profile nonce is generated at save-time. The plaintext is the
//!   serde JSON of the in-memory profile shape. Version 2 binds the profile id
//!   as associated data. Version 1 is readable for existing vaults and upgraded
//!   on the next profile save.
//! - **The passphrase derives a *KEK* (key-encryption key); all profiles
//!   in the same file share the KEK.** Using a per-profile passphrase
//!   would force the user to remember N passphrases — bad UX. If a user
//!   wants partitioned profiles (work / personal), they can use two
//!   different files.
//!
//! ## Limitations (v0)
//!
//! - **Single file per backend instance.** Multi-file vaults are out of
//!   scope here; the user can construct multiple `PassphraseEncryptedStorage`
//!   over different paths to partition.
//! - **Whole-file rewrites on every save.** Atomic writes via tempfile
//!   + rename. Acceptable for the expected vault sizes (kilobytes).
//! Passphrase changes authenticate every profile and atomically replace the entire encrypted file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use argon2::{Argon2, Block};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::custody::profile_wire::{PlaintextProfile, plaintext_to_slot, slot_to_plaintext};
use crate::custody::unlock::{UnlockMethod, UnlockMethods};
use crate::custody::vault::{IdentityStorage, Profile, ProfileId, ProfileSummary};
use personae::{Ed25519Keypair, IdentityError};

const ARGON2_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const FILE_VERSION: u8 = 2;

/// On-disk file format. JSON-shaped.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFile {
    /// File-format version. Bump if the wire shape changes.
    version: u8,
    /// Argon2id salt — single salt per file, since all profiles share
    /// the same KEK derived from the passphrase.
    salt: Vec<u8>,
    /// Per-profile encrypted records.
    profiles: HashMap<String, EncryptedProfile>,
}

/// One profile's encrypted record.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedProfile {
    /// Per-profile ChaCha20-Poly1305 nonce.
    nonce: Vec<u8>,
    /// Authenticated ciphertext.
    ciphertext: Vec<u8>,
}

/// Argon2id-derived KEK.
///
/// Shared with [`crate::custody::passphrase_root`] so the passphrase profile vault and
/// the passphrase-wrapped vault root derive their key-encryption keys through
/// one KDF configuration (the "one unlock ladder" rule): same Argon2id
/// parameters, same zeroize discipline.
pub(crate) fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let argon = Argon2::default();
    let mut kek = Zeroizing::new([0u8; 32]);
    // argon2's own `hash_password_into` frees its working memory uncleared,
    // and the last blocks recompute the KEK; this buffer zeroizes on drop
    // (ruling 33).
    let mut blocks = Zeroizing::new(vec![Block::default(); argon.params().block_count()]);
    argon
        .hash_password_into_with_memory(passphrase, salt, kek.as_mut(), &mut blocks[..])
        .map_err(|e| IdentityError::Backend(format!("argon2 derive: {e}")))?;
    Ok(kek)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS randomness available");
    buf
}

/// Passphrase-encrypted on-disk storage backend.
///
/// Holds the file path + the in-memory KEK derived from the user's
/// passphrase at construction time. KEK lives in a [`Zeroizing<[u8; 32]>`]
/// and zeros on drop.
pub struct PassphraseEncryptedStorage {
    path: PathBuf,
    inner: Arc<Mutex<Inner>>,
    operations: Mutex<()>,
}

struct Inner {
    /// Argon2 salt for this file. Reused across saves of the same file
    /// (re-rolling would force a re-derive on every save).
    salt: Vec<u8>,
    /// Cached KEK; the file's salt + the original passphrase produced it.
    /// `None` while locked.
    kek: Option<Zeroizing<[u8; 32]>>,
}

impl PassphraseEncryptedStorage {
    /// Open or create a passphrase-encrypted vault file at `path`.
    ///
    /// If the file does not exist, a fresh random salt is held in memory;
    /// the first save creates the file. If the file exists, the salt is read
    /// from it and the supplied passphrase is verified by attempting
    /// to decrypt one of the profiles (or trusted-empty if no
    /// profiles).
    ///
    /// **Note**: with zero profiles, an incorrect passphrase is
    /// indistinguishable from a correct one — the file just appears
    /// empty. The first `save_profile` call commits the KEK to a
    /// decryption-checkable state.
    #[tracing::instrument(level = "info", skip_all, name = "passphrase_storage.open")]
    pub fn open(path: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self, IdentityError> {
        let path: PathBuf = path.into();
        let (salt, kek, _existing) = if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|e| IdentityError::Backend(format!("read vault file: {e}")))?;
            let file: EncryptedFile = serde_json::from_slice(&bytes)
                .map_err(|e| IdentityError::Backend(format!("parse vault file: {e}")))?;
            if !matches!(file.version, 1 | FILE_VERSION) {
                return Err(IdentityError::Backend(format!(
                    "unsupported vault file version {}",
                    file.version
                )));
            }
            let kek = derive_kek(passphrase, &file.salt)?;
            check_kek(&kek, &file)?;
            (file.salt, kek, file.profiles)
        } else {
            let salt = random_bytes(ARGON2_SALT_LEN);
            let kek = derive_kek(passphrase, &salt)?;
            (salt, kek, HashMap::new())
        };

        Ok(Self {
            path,
            operations: Mutex::new(()),
            inner: Arc::new(Mutex::new(Inner {
                salt,
                kek: Some(kek),
            })),
        })
    }

    /// Run `f` with the AEAD for the cached KEK, or [`IdentityError::Locked`].
    ///
    /// The key is borrowed where it lives, never copied out, so no stack
    /// copy of it outlives the call (see the no-residue test).
    fn with_cipher<R>(&self, f: impl FnOnce(&ChaCha20Poly1305) -> R) -> Result<R, IdentityError> {
        let inner = self.inner.lock().unwrap();
        let kek = inner.kek.as_ref().ok_or(IdentityError::Locked)?;
        let key = <&Key>::try_from(&kek[..]).expect("fixed-length key material");
        let cipher = ChaCha20Poly1305::new(key);
        Ok(f(&cipher))
    }

    fn ensure_unlocked(&self) -> Result<(), IdentityError> {
        self.with_cipher(|_| ())
    }

    fn load_file(&self) -> Result<EncryptedFile, IdentityError> {
        if !self.path.exists() {
            let salt = self.inner.lock().unwrap().salt.clone();
            return Ok(EncryptedFile {
                version: FILE_VERSION,
                salt,
                profiles: HashMap::new(),
            });
        }
        let bytes = std::fs::read(&self.path)
            .map_err(|e| IdentityError::Backend(format!("read vault file: {e}")))?;
        let file: EncryptedFile = serde_json::from_slice(&bytes)
            .map_err(|e| IdentityError::Backend(format!("parse vault file: {e}")))?;
        if !matches!(file.version, 1 | FILE_VERSION) {
            return Err(IdentityError::Backend(format!(
                "unsupported vault file version {}",
                file.version
            )));
        }
        if file.salt != self.inner.lock().unwrap().salt {
            return Err(IdentityError::Backend(
                "vault file salt changed since open; reopen the vault before accessing profiles"
                    .into(),
            ));
        }
        Ok(file)
    }

    fn save_file(&self, file: &EncryptedFile) -> Result<(), IdentityError> {
        super::atomic_secret_file::write_json(&self.path, file)
    }
}

/// Verify a KEK against one stored profile, if any; with none stored, any
/// passphrase is indistinguishable (see [`PassphraseEncryptedStorage::open`]).
fn check_kek(kek: &[u8; 32], file: &EncryptedFile) -> Result<(), IdentityError> {
    if let Some((id, p)) = file.profiles.iter().next() {
        let cipher =
            ChaCha20Poly1305::new(&Key::try_from(&kek[..]).expect("fixed-length key material"));
        let _checked = decrypt_profile(&cipher, file.version, id, p)?;
    }
    Ok(())
}

fn profile_aad(version: u8, id: &str) -> Vec<u8> {
    if version == 1 {
        Vec::new()
    } else {
        [b"mere.vault.profile.v2\0".as_slice(), id.as_bytes()].concat()
    }
}

fn decrypt_profile(
    cipher: &ChaCha20Poly1305,
    version: u8,
    id: &str,
    entry: &EncryptedProfile,
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let nonce = <&Nonce>::try_from(entry.nonce.as_slice())
        .map_err(|_| IdentityError::Backend("invalid profile nonce length".into()))?;
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &entry.ciphertext,
                aad: &profile_aad(version, id),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| IdentityError::Backend("incorrect passphrase or corrupt profile".into()))
}

fn encrypt_profile(
    cipher: &ChaCha20Poly1305,
    id: &str,
    plaintext: &[u8],
) -> Result<EncryptedProfile, IdentityError> {
    let nonce = random_bytes(NONCE_LEN);
    let ciphertext = cipher
        .encrypt(
            <&Nonce>::try_from(nonce.as_slice()).expect("generated nonce length"),
            Payload {
                msg: plaintext,
                aad: &profile_aad(FILE_VERSION, id),
            },
        )
        .map_err(|error| IdentityError::Backend(format!("encrypt profile: {error}")))?;
    Ok(EncryptedProfile { nonce, ciphertext })
}

impl IdentityStorage for PassphraseEncryptedStorage {
    fn load_profile(&self, id: &ProfileId) -> Result<Profile, IdentityError> {
        let _operation = self.operations.lock().unwrap();
        self.ensure_unlocked()?;
        let file = self.load_file()?;
        let entry = file
            .profiles
            .get(&id.0)
            .ok_or_else(|| IdentityError::Backend(format!("profile not found: {:?}", id)))?;
        let plaintext_bytes =
            self.with_cipher(|cipher| decrypt_profile(cipher, file.version, &id.0, entry))??;
        let mut plain: PlaintextProfile = serde_json::from_slice(&plaintext_bytes)
            .map_err(|e| IdentityError::Backend(format!("decode plaintext: {e}")))?;

        let mut slots = crate::custody::SlotMap::with_capacity(plain.slots.len());
        for s in &mut plain.slots {
            let (k, slot) = plaintext_to_slot(s);
            slots.insert(k, slot);
        }
        Ok(Profile {
            id: id.clone(),
            display_name: std::mem::take(&mut plain.display_name),
            master: Ed25519Keypair::from_seed(plain.master_seed),
            slots,
        })
    }

    fn save_profile(&self, profile: &Profile) -> Result<(), IdentityError> {
        let _operation = self.operations.lock().unwrap();
        self.ensure_unlocked()?;
        let plain = PlaintextProfile {
            display_name: profile.display_name.clone(),
            master_seed: profile.master.to_seed(),
            slots: profile
                .slots
                .iter()
                .map(|(k, s)| slot_to_plaintext(k, s))
                .collect(),
        };
        let plaintext_bytes = personae::zeroizing_json::to_vec(&plain)
            .map_err(|e| IdentityError::Backend(format!("encode plaintext: {e}")))?;
        drop(plain);

        let mut file = self.load_file()?;
        self.with_cipher(|cipher| -> Result<(), IdentityError> {
            if file.version == 1 {
                for (id, entry) in &mut file.profiles {
                    let plaintext = decrypt_profile(cipher, 1, id, entry)?;
                    *entry = encrypt_profile(cipher, id, &plaintext)?;
                }
                file.version = FILE_VERSION;
            }
            file.profiles.insert(
                profile.id.0.clone(),
                encrypt_profile(cipher, &profile.id.0, &plaintext_bytes)?,
            );
            Ok(())
        })??;
        self.save_file(&file)
    }

    fn delete_profile(&self, id: &ProfileId) -> Result<(), IdentityError> {
        let _operation = self.operations.lock().unwrap();
        self.ensure_unlocked()?;
        let mut file = self.load_file()?;
        file.profiles.remove(&id.0);
        self.save_file(&file)
    }

    fn list_profiles(&self) -> Result<Vec<ProfileSummary>, IdentityError> {
        let _operation = self.operations.lock().unwrap();
        self.ensure_unlocked()?;
        let file = self.load_file()?;
        let mut out = Vec::with_capacity(file.profiles.len());
        for (id_str, entry) in &file.profiles {
            // Decrypt to get display_name + slot count. This is N
            // decrypts per list call, fine for the expected profile
            // counts (handful) but worth caching if it ever matters.
            let bytes =
                self.with_cipher(|cipher| decrypt_profile(cipher, file.version, id_str, entry))??;
            let mut plain: PlaintextProfile = serde_json::from_slice(&bytes)
                .map_err(|e| IdentityError::Backend(format!("decode plaintext: {e}")))?;
            out.push(ProfileSummary {
                id: ProfileId(id_str.clone()),
                display_name: std::mem::take(&mut plain.display_name),
                slot_count: plain.slots.len(),
            });
        }
        Ok(out)
    }

    fn change_passphrase(
        &self,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), super::unlock::PassphraseChangeError> {
        use super::unlock::PassphraseChangeError as E;
        let _operation = self.operations.lock().unwrap();
        if new.is_empty() {
            return Err(E::InvalidNew);
        }
        if self.inner.lock().unwrap().kek.is_none() {
            return Err(E::Locked);
        }
        let mut file = self.load_file().map_err(|_| E::Storage)?;
        if file.profiles.is_empty() {
            return Err(E::Unsupported);
        }
        let old_key = derive_kek(old, &file.salt).map_err(|_| E::Storage)?;
        let held = self.inner.lock().unwrap();
        if !constant_time_eq::constant_time_eq(
            old_key.as_ref(),
            held.kek.as_ref().ok_or(E::Locked)?.as_ref(),
        ) {
            return Err(E::IncorrectCurrent);
        }
        drop(held);
        let old_cipher = ChaCha20Poly1305::new(<&Key>::try_from(old_key.as_slice()).unwrap());
        let salt = random_bytes(ARGON2_SALT_LEN);
        let new_key = derive_kek(new, &salt).map_err(|_| E::Storage)?;
        let new_cipher = ChaCha20Poly1305::new(<&Key>::try_from(new_key.as_slice()).unwrap());
        for (id, entry) in &mut file.profiles {
            let plaintext = decrypt_profile(&old_cipher, file.version, id, entry)
                .map_err(|_| E::IncorrectCurrent)?;
            *entry = encrypt_profile(&new_cipher, id, &plaintext).map_err(|_| E::Storage)?;
        }
        file.version = FILE_VERSION;
        file.salt = salt.clone();
        self.save_file(&file).map_err(|_| E::Storage)?;
        let mut inner = self.inner.lock().unwrap();
        inner.salt = salt;
        inner.kek = Some(new_key);
        Ok(())
    }

    fn unlock_methods(&self) -> UnlockMethods {
        UnlockMethods {
            passphrase: true,
            os_presence: false,
        }
    }

    fn lock(&self) {
        let _operation = self.operations.lock().unwrap();
        self.inner.lock().unwrap().kek = None;
    }

    fn is_locked(&self) -> bool {
        self.inner.lock().unwrap().kek.is_none()
    }

    /// Re-derives the KEK (Argon2id's cost is the only throttle, ruling 19)
    /// and checks it against a stored profile before keeping it.
    fn unlock(&self, method: UnlockMethod<'_>) -> Result<(), IdentityError> {
        let _operation = self.operations.lock().unwrap();
        let UnlockMethod::Passphrase(passphrase) = method else {
            return Err(IdentityError::Backend(
                "a passphrase vault unlocks only by its passphrase".to_string(),
            ));
        };
        let file = self.load_file()?;
        let kek = derive_kek(passphrase, &file.salt)?;
        check_kek(&kek, &file)?;
        self.inner.lock().unwrap().kek = Some(kek);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
