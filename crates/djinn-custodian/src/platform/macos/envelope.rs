// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The data-protection Keychain envelope (custody plan H1): the 32-byte root
//! that seals the wallet's identity seed lives in a data-protection Keychain
//! item under the custodian's own access group, never in a file. This is the
//! macOS counterpart of Windows' DPAPI-wrapped auto-unlock root, installed
//! into Castellan through `AutoUnlockRootProvider`.
//!
//! The access group is an entitlement, and a restricted one: only the signed
//! bundle whose provisioning profile authorizes `keychain-access-groups` can
//! read or write the item, so an unrelated same-user process, an unsigned
//! copy or a differently signed one gets an error and no key. The item is
//! `WhenUnlockedThisDeviceOnly` and not synchronized: it never leaves this
//! Mac. Every failure, including a missing entitlement, a missing item and a
//! refused access, is an error and leaves the wallet locked. A new root is
//! never minted to replace one that cannot be read.
//!
//! Because the signed binary can be started by any process of the user, the
//! envelope is installed only from the root-owned installation
//! ([`require_installation`]): a caller-chosen configuration would let such a
//! process point the binary at the real wallet and read it back through
//! development-mode grants.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use castellan::custody::AutoUnlockRootProvider;
use personae::IdentityError;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use zeroize::Zeroizing;

use crate::policy::{Config, EnvelopeConfig};

/// Where the installer puts the signed custodian, its helper and its
/// configuration, all root-owned.
pub const INSTALL_ROOT: &str = "/Library/Application Support/Merely/djinn-custodian";

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
const PREFLIGHT_ACCOUNT: &str = "preflight";

/// The Keychain-backed root.
pub struct KeychainRoot {
    service: String,
    group: String,
}

impl KeychainRoot {
    pub fn new(config: &EnvelopeConfig) -> Self {
        Self {
            service: config.service.clone(),
            group: config.access_group.clone(),
        }
    }

    fn options(&self, account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(&self.service, account);
        options.use_protected_keychain();
        options.set_access_group(&self.group);
        options.set_access_synchronized(Some(false));
        options
    }

    fn lookup(
        &self,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, security_framework::base::Error> {
        match generic_password(self.options(account)) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Whether this process can use the group at all: a lookup of an item
    /// that is not there must say so, and anything else (above all a missing
    /// entitlement) means the envelope cannot work here.
    pub fn preflight(&self) -> Result<(), String> {
        match self.lookup(PREFLIGHT_ACCOUNT) {
            Ok(_) => Ok(()),
            Err(error) => Err(failure(
                "the data-protection Keychain is unavailable to this process",
                &error,
            )),
        }
    }
}

fn failure(what: &str, error: &security_framework::base::Error) -> String {
    let hint = if error.code() == ERR_SEC_MISSING_ENTITLEMENT {
        ": the binary lacks the keychain-access-groups entitlement and its provisioning profile (it must run from the signed bundle)"
    } else {
        ""
    };
    format!("{what}: OSStatus {}{hint}", error.code())
}

fn backend(text: String) -> IdentityError {
    IdentityError::Backend(text)
}

impl AutoUnlockRootProvider for KeychainRoot {
    fn backend(&self) -> &'static str {
        "data-protection-keychain"
    }

    fn create(&self, account: &str, root: &[u8; 32]) -> Result<(), IdentityError> {
        if self
            .lookup(account)
            .map_err(|e| backend(failure("read the envelope item", &e)))?
            .is_some()
        {
            return Err(backend("the envelope item already exists".into()));
        }
        let mut options = self.options(account);
        let protection = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(|e| backend(failure("build the item's protection", &e)))?;
        options.set_access_control(protection);
        set_generic_password_options(root, options)
            .map_err(|e| backend(failure("store the envelope item", &e)))
    }

    fn load(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, IdentityError> {
        let Some(bytes) = self
            .lookup(account)
            .map_err(|e| backend(failure("read the envelope item", &e)))?
        else {
            return Ok(None);
        };
        let mut root = Zeroizing::new([0u8; 32]);
        if bytes.len() != 32 {
            return Err(backend("the envelope item is not a 32-byte root".into()));
        }
        root.copy_from_slice(&bytes);
        Ok(Some(root))
    }

    fn discard(&self, account: &str) {
        let _ = delete_generic_password_options(self.options(account));
    }
}

/// Install the envelope into Castellan for this process, when the
/// configuration names one. Called before anything opens the wallet.
pub fn install(config: &Config, config_path: &Path) -> Result<(), String> {
    let Some(envelope) = &config.envelope else {
        return Ok(());
    };
    require_installation(config_path)?;
    let root = KeychainRoot::new(envelope);
    root.preflight()?;
    castellan::custody::install_auto_unlock_provider(Arc::new(root));
    Ok(())
}

/// The envelope's native round trip, for the receiving run: under the same
/// preconditions as service start, store a random throwaway item in the
/// custodian's group, read it back, compare, delete it and see it gone. Touches
/// no wallet and no real root.
pub fn self_test(config: &Config, config_path: &Path) -> Result<String, String> {
    let envelope = config.envelope.as_ref().ok_or("the configuration names no envelope")?;
    require_installation(config_path)?;
    let root = KeychainRoot::new(envelope);
    root.preflight()?;
    let mut value = Zeroizing::new([0u8; 32]);
    let mut id = [0u8; 8];
    getrandom::fill(&mut *value).and_then(|()| getrandom::fill(&mut id)).map_err(|e| e.to_string())?;
    let account = format!("selftest-{}", id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    root.create(&account, &value).map_err(|e| e.to_string())?;
    let read = root.load(&account);
    root.discard(&account);
    let gone = matches!(root.load(&account), Ok(None));
    match read {
        Ok(Some(read)) if *read == *value && gone => Ok(format!("stored, read back and removed a throwaway item in {}", envelope.access_group)),
        Ok(Some(_)) => Err("the item read back differently, or was not removed".into()),
        Ok(None) => Err("the item just stored was not found".into()),
        Err(error) => Err(error.to_string()),
    }
}

/// The configuration and the running executable are the installer's:
/// canonical paths under [`INSTALL_ROOT`], whose every ancestor is root's,
/// a real directory and writable by nobody else. A process of the desktop
/// user can start the signed binary, so this is what stops it choosing the
/// configuration the envelope is opened under.
pub fn require_installation(config_path: &Path) -> Result<(), String> {
    let root = std::fs::canonicalize(INSTALL_ROOT).map_err(|e| format!("{INSTALL_ROOT}: {e}"))?;
    let config = std::fs::canonicalize(config_path)
        .map_err(|e| format!("{}: {e}", config_path.display()))?;
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("the running executable: {e}"))?;
    for (what, path) in [("configuration", &config), ("executable", &exe)] {
        if !path.starts_with(&root) {
            return Err(format!(
                "the {what} {} is outside {INSTALL_ROOT}; a Keychain envelope is opened only by the installed custodian",
                path.display()
            ));
        }
        trusted_chain(path, 0).map_err(|why| format!("the {what} {}: {why}", path.display()))?;
    }
    Ok(())
}

/// Every component from `/` to `path` is a real file or directory owned by
/// `owner` that neither the group nor others can write.
pub fn trusted_chain(path: &Path, owner: u32) -> Result<(), String> {
    trusted_below(Path::new("/"), path, owner)
}

/// [`trusted_chain`] from `base` (itself checked) down to `path`.
fn trusted_below(base: &Path, path: &Path, owner: u32) -> Result<(), String> {
    let below = path
        .strip_prefix(base)
        .map_err(|_| format!("{} is not under {}", path.display(), base.display()))?;
    let mut current = base.to_path_buf();
    trusted_component(&current, owner)?;
    for part in below.components() {
        current.push(part);
        trusted_component(&current, owner)?;
    }
    Ok(())
}

fn trusted_component(path: &Path, owner: u32) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symbolic link", path.display()));
    }
    if meta.uid() != owner {
        return Err(format!("{} is not owned by uid {owner}", path.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by its group or others",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: getuid has no arguments or failure.
        unsafe { libc::getuid() }
    }

    #[test]
    fn a_chain_of_roots_unwritable_directories_is_trusted() {
        // SIP keeps these root's and unwritable by anyone else.
        trusted_chain(Path::new("/usr/bin/true"), 0).unwrap();
    }

    #[test]
    fn a_group_or_world_writable_or_foreign_component_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        let why = trusted_below(dir.path(), &open, me()).unwrap_err();
        assert!(
            why.contains("writable") || why.contains("not owned"),
            "{why}"
        );
        // Owned by someone other than the asked-for owner.
        let why = trusted_below(dir.path(), dir.path(), me().wrapping_add(1)).unwrap_err();
        assert!(why.contains("not owned"), "{why}");
    }

    #[test]
    fn a_symbolic_link_anywhere_in_the_chain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            trusted_below(dir.path(), &link, me())
                .unwrap_err()
                .contains("symbolic link")
        );
        assert!(
            trusted_below(dir.path(), &real, me()).is_ok(),
            "the real directory is the owner's, 0700 under a 0700 base"
        );
    }

    #[test]
    fn a_configuration_outside_the_installation_never_opens_the_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("attacker.json");
        std::fs::write(&config, b"{}").unwrap();
        let error = require_installation(&config).unwrap_err();
        assert!(
            error.contains("outside") || error.contains(INSTALL_ROOT),
            "{error}"
        );
    }

    #[test]
    fn a_configuration_naming_no_envelope_installs_nothing() {
        let config = crate::tests::config(tempfile::tempdir().unwrap().path(), "deny", "none");
        assert!(config.envelope.is_none());
        install(&config, Path::new("/nonexistent")).unwrap();
    }
}
