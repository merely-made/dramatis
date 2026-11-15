// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The padlock: the wallet root as a COSE_Encrypt profile,
//! `design_docs/2026-11-14_padlock_profile.md` (custody D8).
//!
//! One random 32-byte root is the content (ChaCha20-Poly1305, content type
//! `mere.padlock/1`); its CEK is wrapped once per slot with A256KW. A slot is a
//! passphrase (NFC, then Argon2id with stored parameters) or a 32-byte KEK the
//! caller supplies (the OS stores' glue is phase 2). Slots of kinds this reader
//! does not implement are skipped and kept byte for byte.
//!
//! Data only: no file I/O, no OS calls. Unlock hands the candidate root to a
//! caller-supplied verifier (the binding check, profile §4.2).

mod reader;
mod slot;
#[cfg(test)]
mod tests_profile;
#[cfg(test)]
mod tests_published;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use coset::{
    CoseEncrypt, CoseEncryptBuilder, HeaderBuilder, ProtectedHeader, TaggedCborSerializable,
};
use zeroize::Zeroizing;

use slot::Slot;

/// A root or CEK, cleared on drop.
type Key32 = Zeroizing<[u8; 32]>;

/// The protected `content type`: profile and version (profile §3.2).
pub const CONTENT_TYPE: &str = "mere.padlock/1";
/// R1: the largest file a reader parses.
pub const MAX_FILE_BYTES: usize = 16 * 1024;
/// R9: the most slots in one padlock.
pub const MAX_SLOTS: usize = 16;
/// R15: the largest opaque OS blob in a KEK slot.
pub const MAX_OS_BLOB_BYTES: usize = 2048;

/// Private-use header labels (profile §3.5, §3.6): the KDF, which must be 2.
pub const LABEL_KDF: i64 = -65537;
/// The Argon2 salt, 16 bytes.
pub const LABEL_KDF_SALT: i64 = -65538;
/// Argon2 memory, KiB.
pub const LABEL_KDF_M: i64 = -65539;
/// Argon2 passes.
pub const LABEL_KDF_T: i64 = -65540;
/// Argon2 lanes.
pub const LABEL_KDF_P: i64 = -65541;
/// Argon2 version, which must be 19 (0x13).
pub const LABEL_KDF_V: i64 = -65542;
/// An OS-KEK slot's opaque blob (a DPAPI blob, phase 2).
pub const LABEL_OS_BLOB: i64 = -65543;

/// `{1: 24, 3: "mere.padlock/1"}`, deterministically encoded.
const BODY_PROTECTED: &[u8] = b"\xa2\x01\x18\x18\x03\x6emere.padlock/1";

/// Argon2id costs (RFC 9106 §3.1): memory in KiB, passes, lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Params {
    /// RFC 9106 §4's second recommended set: the writer's default and the
    /// reader's floor (OP 5).
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };
    /// The reader's ceiling (OP 6): 1 GiB, 16 passes, 16 lanes.
    pub const CEILING: Self = Self {
        m_kib: 1024 * 1024,
        t: 16,
        p: 16,
    };

    fn check(self) -> Result<(), PadlockError> {
        let (lo, hi) = (Self::DEFAULT, Self::CEILING);
        let within = (lo.m_kib..=hi.m_kib).contains(&self.m_kib)
            && (lo.t..=hi.t).contains(&self.t)
            && (lo.p..=hi.p).contains(&self.p)
            && self.m_kib >= 8 * self.p;
        if within {
            Ok(())
        } else {
            Err(PadlockError::KdfBounds)
        }
    }
}

/// What a slot is, as far as this reader knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// `pass/…`: a passphrase through Argon2id.
    Passphrase,
    /// `dpapi/…`, `keychain/…`, `secsvc/…`: a 32-byte KEK the caller supplies.
    Kek,
    /// Anything else: never tried, kept byte for byte.
    Foreign,
}

/// A slot's public face: no secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotInfo {
    /// The slot's `kid`, `<method>/<id>`.
    pub kid: String,
    /// Its kind.
    pub kind: SlotKind,
    /// A KEK slot's opaque OS blob, if it carries one (not secret: OS ciphertext).
    pub os_blob: Option<Vec<u8>>,
}

/// The secret that opens one slot.
pub enum SlotInput<'a> {
    /// Tried against every passphrase slot.
    Passphrase(&'a str),
    /// Tried against the KEK slot named `kid`.
    Kek {
        /// The slot.
        kid: &'a str,
        /// Its key-wrap key.
        kek: &'a [u8; 32],
    },
}

/// A slot to write.
pub enum NewSlot<'a> {
    /// A passphrase slot; `kid` method `pass`.
    Passphrase {
        /// `pass/<id>`.
        kid: &'a str,
        /// Normalised to NFC before Argon2id.
        passphrase: &'a str,
        /// Within [`Argon2Params::DEFAULT`] and [`Argon2Params::CEILING`].
        params: Argon2Params,
    },
    /// A KEK slot; `kid` method `dpapi`, `keychain` or `secsvc`.
    Kek {
        /// `<method>/<id>`.
        kid: &'a str,
        /// A random 32-byte key the OS store holds; never the root or CEK.
        kek: &'a [u8; 32],
        /// An opaque OS blob kept in the slot, at most [`MAX_OS_BLOB_BYTES`].
        os_blob: Option<&'a [u8]>,
    },
}

/// Why a padlock was refused (rules R1 to R16) or an operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PadlockError {
    /// R1.
    TooLarge,
    /// R2, R16: not one well-formed CBOR item.
    Malformed,
    /// R2: bytes after the item.
    TrailingBytes,
    /// R3: not tag 96.
    NotTagged,
    /// R4, R17: not deterministically encoded.
    NotDeterministic,
    /// R5: a map key twice.
    DuplicateLabel,
    /// R6: a label in both buckets of one layer.
    LabelInBothBuckets,
    /// R7: a `crit` header.
    Critical,
    /// R8: not the COSE_Encrypt shape.
    Structure,
    /// R9: no recipients.
    NoSlots,
    /// R9: more than [`MAX_SLOTS`].
    TooManySlots,
    /// R10: content type is not [`CONTENT_TYPE`].
    Version,
    /// R10: body `alg` is not ChaCha20/Poly1305.
    WrongAlg,
    /// R10: any other body header.
    BodyHeader,
    /// R11.
    IvLength,
    /// R11.
    CiphertextLength,
    /// R12: an A256KW slot's protected bucket is not the empty bstr.
    SlotProtected,
    /// R12: a label the slot's kind does not allow.
    SlotLabel,
    /// R12: the wrapped CEK is not 40 bytes.
    WrappedKeyLength,
    /// R13: an Argon2 label is missing.
    KdfLabels,
    /// R13: Argon2 values outside the profile's bounds.
    KdfBounds,
    /// R13: the salt is not 16 bytes.
    SaltLength,
    /// R14: `kid` absent or not `<method>/<id>`.
    Kid,
    /// R14: two slots with one `kid`.
    DuplicateKid,
    /// R15.
    OsBlob,
    /// No slot of the input's kind (or `kid`).
    NoMatchingSlot,
    /// Every candidate slot failed its AES-KW integrity check.
    WrongSecret,
    /// A slot unwrapped but the body did not decrypt: damaged or forged.
    BodyAuthentication,
    /// The caller's verifier refused the root (profile §4.2 step 7).
    BindingRefused,
    /// Removing this slot would leave none this reader can open.
    LastSlot,
    /// No slot has that `kid`.
    UnknownKid,
    /// A slot with that `kid` exists already.
    KidExists,
    /// The OS random number generator failed.
    Randomness,
    /// A primitive refused its inputs.
    Kdf,
}

impl std::fmt::Display for PadlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "padlock: {self:?}")
    }
}

impl std::error::Error for PadlockError {}

/// A parsed, validated padlock. Holds no secret: ciphertexts and wraps only.
#[derive(Clone)]
pub struct Padlock {
    body: CoseEncrypt,
    slots: Vec<Slot>,
}

fn random<const N: usize>() -> Result<[u8; N], PadlockError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| PadlockError::Randomness)?;
    Ok(out)
}

impl Padlock {
    /// Strict decode (profile §5). Structural faults refuse the whole file.
    ///
    /// # Errors
    /// The rule the file breaks.
    pub fn parse(bytes: &[u8]) -> Result<Self, PadlockError> {
        let (body, slots) = reader::parse(bytes)?;
        Ok(Self { body, slots })
    }

    /// A new padlock around `root` with one slot (profile §4.1).
    ///
    /// # Errors
    /// An invalid slot, or the OS RNG failing.
    pub fn create(root: &[u8; 32], first: &NewSlot<'_>) -> Result<Self, PadlockError> {
        let cek = Zeroizing::new(random::<32>()?);
        Self::create_with(root, &cek, random()?, first, random()?)
    }

    pub(crate) fn create_with(
        root: &[u8; 32],
        cek: &[u8; 32],
        iv: [u8; 12],
        first: &NewSlot<'_>,
        salt: [u8; 16],
    ) -> Result<Self, PadlockError> {
        let cipher = ChaCha20Poly1305::new_from_slice(cek).map_err(|_| PadlockError::Kdf)?;
        let protected = ProtectedHeader {
            original_data: Some(BODY_PROTECTED.to_vec()),
            header: HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ChaCha20Poly1305)
                .content_type(CONTENT_TYPE.to_string())
                .build(),
        };
        let nonce = Nonce::from(iv);
        let body = CoseEncryptBuilder::new()
            .protected(protected.header.clone())
            .unprotected(HeaderBuilder::new().iv(iv.to_vec()).build())
            .try_create_ciphertext(root, b"", |msg, aad| {
                cipher
                    .encrypt(&nonce, Payload { msg, aad })
                    .map_err(|_| PadlockError::Kdf)
            })?
            .build();
        let body = CoseEncrypt { protected, ..body };
        let slot = slot::build(first, cek, salt)?;
        Self {
            body,
            slots: vec![slot],
        }
        .reparsed()
    }

    /// Opens one slot and the body, then asks `verify` whether the root is
    /// this wallet's (profile §4.2).
    ///
    /// # Errors
    /// No matching slot, a wrong secret, a damaged body or a refused binding.
    pub fn unlock(
        &self,
        input: &SlotInput<'_>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<Zeroizing<[u8; 32]>, PadlockError> {
        self.open(input, verify).map(|(root, _)| root)
    }

    fn open(
        &self,
        input: &SlotInput<'_>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<(Key32, Key32), PadlockError> {
        let cek = self.cek(input)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(cek.as_ref()).map_err(|_| PadlockError::Kdf)?;
        let nonce =
            Nonce::try_from(&self.body.unprotected.iv[..]).map_err(|_| PadlockError::IvLength)?;
        let plain = Zeroizing::new(self.body.decrypt_ciphertext(
            b"",
            || PadlockError::CiphertextLength,
            |msg, aad| {
                cipher
                    .decrypt(&nonce, Payload { msg, aad })
                    .map_err(|_| PadlockError::BodyAuthentication)
            },
        )?);
        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(plain.get(..32).ok_or(PadlockError::BodyAuthentication)?);
        if !verify(&root) {
            return Err(PadlockError::BindingRefused);
        }
        Ok((root, cek))
    }

    fn cek(&self, input: &SlotInput<'_>) -> Result<Zeroizing<[u8; 32]>, PadlockError> {
        let wrapped = |s: &Slot| s.recipient.ciphertext.clone().unwrap_or_default();
        match input {
            SlotInput::Passphrase(passphrase) => {
                let mut tried = false;
                for s in self.slots.iter().filter(|s| s.kind == SlotKind::Passphrase) {
                    tried = true;
                    let Some((salt, params)) = s.kdf else {
                        continue;
                    };
                    let kek = slot::passphrase_kek(passphrase, &salt, params)?;
                    if let Some(cek) = slot::unwrap(&kek, &wrapped(s)) {
                        return Ok(cek);
                    }
                }
                Err(if tried {
                    PadlockError::WrongSecret
                } else {
                    PadlockError::NoMatchingSlot
                })
            },
            SlotInput::Kek { kid, kek } => {
                let s = self
                    .slots
                    .iter()
                    .find(|s| s.kind == SlotKind::Kek && s.kid == *kid)
                    .ok_or(PadlockError::NoMatchingSlot)?;
                slot::unwrap(kek, &wrapped(s)).ok_or(PadlockError::WrongSecret)
            },
        }
    }

    /// Adds `new`, opening the CEK through `with` (profile §4.3). The body and
    /// every existing slot stay byte-identical.
    ///
    /// # Errors
    /// As [`Padlock::unlock`], or an invalid or duplicate slot.
    pub fn add_slot(
        &mut self,
        with: &SlotInput<'_>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
        new: &NewSlot<'_>,
    ) -> Result<(), PadlockError> {
        self.add_slot_with(with, verify, new, random()?)
    }

    pub(crate) fn add_slot_with(
        &mut self,
        with: &SlotInput<'_>,
        verify: impl FnOnce(&[u8; 32]) -> bool,
        new: &NewSlot<'_>,
        salt: [u8; 16],
    ) -> Result<(), PadlockError> {
        let kid = match new {
            NewSlot::Passphrase { kid, .. } | NewSlot::Kek { kid, .. } => *kid,
        };
        if self.slots.iter().any(|s| s.kid == kid) {
            return Err(PadlockError::KidExists);
        }
        if self.slots.len() >= MAX_SLOTS {
            return Err(PadlockError::TooManySlots);
        }
        let (_root, cek) = self.open(with, verify)?;
        let mut next = self.clone();
        next.slots.push(slot::build(new, &cek, salt)?);
        *self = next.reparsed()?;
        Ok(())
    }

    /// Removes the slot named `kid` (profile §4.4). Not revocation: an older
    /// copy of the file still opens with it.
    ///
    /// # Errors
    /// No such slot, or none this reader can open would remain.
    pub fn remove_slot(&mut self, kid: &str) -> Result<(), PadlockError> {
        let at = self
            .slots
            .iter()
            .position(|s| s.kid == kid)
            .ok_or(PadlockError::UnknownKid)?;
        let mut next = self.clone();
        next.slots.remove(at);
        if next.slots.iter().all(|s| s.kind == SlotKind::Foreign) {
            return Err(PadlockError::LastSlot);
        }
        *self = next.reparsed()?;
        Ok(())
    }

    /// Every slot's `kid` and kind, in file order.
    #[must_use]
    pub fn slots(&self) -> Vec<SlotInfo> {
        self.slots
            .iter()
            .map(|s| SlotInfo {
                kid: s.kid.clone(),
                kind: s.kind,
                os_blob: s.os_blob.clone(),
            })
            .collect()
    }

    /// The deterministic encoding (RFC 8949 §4.2.1).
    ///
    /// # Errors
    /// Only if coset cannot encode a structure it built, which the reparse
    /// after every change rules out.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PadlockError> {
        let mut cose = self.body.clone();
        cose.recipients = self.slots.iter().map(|s| s.recipient.clone()).collect();
        cose.to_tagged_vec().map_err(|_| PadlockError::Structure)
    }

    /// The writer's output must pass its own reader.
    fn reparsed(self) -> Result<Self, PadlockError> {
        Self::parse(&self.to_bytes()?)
    }
}
