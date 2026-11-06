// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Unassociated keys in custody (release log D3 and R7). A key is minted
//! here, stored sealed beside the vault under the open profile, and used only
//! through this module: signed with in place, or released as a seed for a
//! transport to bind. The master never reaches a transport, and the key is
//! derived from nothing, so nothing it publishes links to a persona.
//!
//! The store is sealed under a key the open persona derives for this purpose,
//! so a locked custodian opens nothing and a copied file is inert. A profile
//! switch hides the previous profile's keys rather than moving them.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use custody_wire::contract::Source;
use personae::UnassociatedKeypair;
use zeroize::Zeroizing;

use super::{HostCustody, Refusal, Signed};

const STORE_SALT: &[u8] = b"mere.custodian/unassociated-store/v1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn refused(_: impl std::fmt::Debug) -> Refusal {
    Refusal("unassociated-store")
}

impl HostCustody {
    /// The open profile's key directory and the key its files are sealed under.
    fn unassociated_store(&self) -> Result<(PathBuf, Zeroizing<[u8; 32]>), Refusal> {
        let profile = self.profile().ok_or(Refusal("locked"))?.to_string();
        let storage = self.provider(Source::Persona, None)?.derive_keypair(STORE_SALT).map_err(super::identity)?;
        Ok((self.directory.join("unassociated").join(profile), Zeroizing::new(storage.to_seed())))
    }

    fn unassociated_load(&self, public_key: &[u8]) -> Result<UnassociatedKeypair, Refusal> {
        let public: [u8; 32] = public_key.try_into().map_err(|_| Refusal("operation-or-scope"))?;
        let (dir, storage) = self.unassociated_store()?;
        let sealed = fs::read(dir.join(format!("{}.key", hex(&public)))).map_err(|_| Refusal("unassociated-unknown"))?;
        let key = UnassociatedKeypair::unseal(&storage, &sealed).map_err(refused)?;
        (key.public_key().to_bytes() == public).then_some(key).ok_or(Refusal("unassociated-store"))
    }

    /// Mint a key, store it sealed and answer its public half.
    pub fn unassociated_create(&self) -> Result<[u8; 32], Refusal> {
        let (dir, storage) = self.unassociated_store()?;
        let key = UnassociatedKeypair::generate();
        let public = key.public_key().to_bytes();
        let sealed = key.seal(&storage).map_err(refused)?;
        fs::create_dir_all(&dir).map_err(refused)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(dir.join(format!("{}.key", hex(&public)))).map_err(refused)?;
        file.write_all(&sealed).and_then(|()| file.sync_all()).map_err(refused)?;
        Ok(public)
    }

    /// Sign with a stored key; the key never leaves this call.
    pub fn unassociated_sign(&self, public_key: &[u8], message: &[u8]) -> Result<Signed, Refusal> {
        let key = self.unassociated_load(public_key)?;
        Ok(Signed { public_key: key.public_key().to_bytes(), signature: key.sign(message).to_bytes(), attestation: None })
    }

    /// The seed of a stored key, for a transport to bind in its own process.
    pub fn unassociated_release(&self, public_key: &[u8]) -> Result<([u8; 32], Zeroizing<[u8; 32]>), Refusal> {
        let key = self.unassociated_load(public_key)?;
        Ok((key.public_key().to_bytes(), Zeroizing::new(key.to_seed())))
    }
}
