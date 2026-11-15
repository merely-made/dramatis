// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Adoption that never leaves a wallet adopted but unusable (custody D9; the
//! owner: "Adopt with a passphrase, or refuse").
//!
//! Before either side is touched, the adoption decides how the adopted
//! wallet will open:
//! - nothing raw: the files move as they are ([`super::adopt_files`]);
//! - raw legacy secrets and an OS store (or the macOS envelope) here: they
//!   are sealed under it;
//! - raw legacy secrets, no store, a passphrase: a passphrase padlock is made
//!   in the custodian's root and they are sealed under it;
//! - raw legacy secrets, no store, no passphrase: refused, nothing changed.
//!
//! The source is retired only after every sealed record has been read back
//! and compared with the raw bytes it came from. A rerun after a kill at any
//! step finishes or starts again from the untouched source.

use std::path::{Path, PathBuf};
use std::{fs, io};

use castellan::custody::os_kek::os_kek_store;
use castellan::custody::wallet::{
    WALLET_PADLOCK_FILENAME, WalletUnlock, create_wallet_padlock_with_passphrase,
    is_sealed_wallet_record, migrate_legacy_wallet_secrets, raw_legacy_wallet_secrets,
    relock_wallet_after_manual_unlock, sealed_secret_matches_raw, wallet_padlock_path,
    with_wallet_unlocked,
};
use sporran::wallet_store::identity_auto_unlock_root_path;
use zeroize::Zeroizing;

use super::adopt::{Adopted, adopt_files, carry_files, prune, wallet_files};

/// The flag a store-less custodian needs, named in its refusal.
pub const PASSPHRASE_FLAG: &str = "--passphrase stdin";

/// How the custodian's copy will be opened to seal it.
enum Opener<'a> {
    Os,
    Passphrase(&'a str),
    None,
}

impl Opener<'_> {
    fn unlock(&self) -> Option<WalletUnlock<'_>> {
        match self {
            Self::Os => Some(WalletUnlock::Os),
            Self::Passphrase(phrase) => Some(WalletUnlock::Passphrase(phrase)),
            Self::None => None,
        }
    }
}

/// Where an earlier, interrupted adoption into `dest` stopped.
#[derive(PartialEq)]
enum Prior {
    /// `dest` holds no wallet files.
    Fresh,
    /// `dest` holds only copies (or sealed forms) of a source that is still
    /// whole: they are cleared and the adoption starts again.
    Restart,
    /// The source was being retired: `dest` is the sealed wallet; finish.
    Finish,
}

fn described(error: io::Error) -> String {
    error.to_string()
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn is_padlock(relative: &Path) -> bool {
    relative
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(WALLET_PADLOCK_FILENAME))
}

/// Adopt the wallet and catalog under `source` into `dest`, sealing any raw
/// legacy secrets on the way, under an OS store here or, with none, a new
/// passphrase padlock made from `passphrase`.
///
/// # Errors
/// Refused before anything changes when raw secrets would have no sealed
/// home (it names [`PASSPHRASE_FLAG`]); any later failure clears the
/// custodian's copy and leaves the source whole.
pub fn adopt_wallet(
    source: &Path,
    dest: &Path,
    passphrase: Option<&str>,
) -> Result<Adopted, String> {
    let raw: Vec<(PathBuf, Zeroizing<Vec<u8>>)> = raw_legacy_wallet_secrets(source)
        .map_err(described)?
        .into_iter()
        .map(|path| fs::read(&path).map(|bytes| (relative(source, &path), Zeroizing::new(bytes))))
        .collect::<io::Result<_>>()
        .map_err(described)?;
    if wallet_files(source).map_err(described)?.is_empty() {
        return Err(format!(
            "no wallet or credential catalog under {}",
            source.display()
        ));
    }
    let has_dest_files = !wallet_files(dest).map_err(described)?.is_empty();
    if raw.is_empty() && !has_dest_files {
        return adopt_files(source, dest);
    }
    let opener = if os_kek_store(dest).is_some() {
        Opener::Os
    } else if let Some(phrase) = passphrase {
        Opener::Passphrase(phrase)
    } else {
        Opener::None
    };
    if !raw.is_empty() && matches!(opener, Opener::None) {
        return Err(format!(
            "{} holds raw legacy wallet secrets, and this custodian has no OS store to seal them \
             under; they are never kept raw (custody D5). Rerun with {PASSPHRASE_FLAG} to seal them \
             under a new passphrase padlock. Nothing was changed.",
            source.display()
        ));
    }
    if matches!(opener, Opener::Passphrase(_))
        && identity_auto_unlock_root_path(source).exists()
        && !wallet_padlock_path(source).exists()
    {
        return Err(
            "the wallet's legacy auto-unlock root opens only with the OS store it was made \
                    with, and this custodian has none. Nothing was changed."
                .into(),
        );
    }
    let prior = prior_state(source, dest, &opener)?;
    if prior == Prior::Restart {
        clear(dest)?;
    }
    if prior != Prior::Finish {
        carry_files(source, dest)?;
        if let Err(reason) = seal(dest, &opener, &raw) {
            clear(dest)?;
            return Err(format!(
                "the wallet was not adopted: {reason}; {} is untouched",
                source.display()
            ));
        }
    }
    let files = wallet_files(source).map_err(described)?;
    let left = retire(source, dest, &opener, &files, &raw)?;
    Ok(Adopted { files, left })
}

/// Seal the raw secrets in the custodian's copy and compare each sealed
/// record with the raw bytes it came from.
fn seal(
    dest: &Path,
    opener: &Opener<'_>,
    raw: &[(PathBuf, Zeroizing<Vec<u8>>)],
) -> Result<(), String> {
    if let Opener::Passphrase(phrase) = opener
        && !wallet_padlock_path(dest).exists()
    {
        create_wallet_padlock_with_passphrase(dest, phrase).map_err(described)?;
        relock_wallet_after_manual_unlock(dest);
    }
    let Some(unlock) = opener.unlock() else {
        return Ok(());
    };
    with_wallet_unlocked(dest, &unlock, || {
        migrate_legacy_wallet_secrets(dest)?;
        for (relative, bytes) in raw {
            if !sealed_secret_matches_raw(dest, &dest.join(relative), bytes)? {
                return Err(io::Error::other(format!(
                    "{} did not read back equal",
                    relative.display()
                )));
            }
        }
        Ok(())
    })
    .map_err(described)
}

/// Classify what `dest` already holds. Every file must be a copy of the
/// source's, a sealed form of one of its raw secrets, the padlock, or a staged
/// copy; anything else is another wallet and the adoption is refused.
fn prior_state(source: &Path, dest: &Path, opener: &Opener<'_>) -> Result<Prior, String> {
    let held = wallet_files(dest).map_err(described)?;
    if held.is_empty() {
        return Ok(Prior::Fresh);
    }
    let refused =
        || "the custodian's data root already holds a wallet or credential catalog".to_string();
    let (mut sealed, mut retired) = (Vec::new(), false);
    for rel in &held {
        let staged = rel.extension().is_some_and(|e| e == "adopting");
        if staged || is_padlock(rel) {
            continue;
        }
        match fs::read(source.join(rel)) {
            Ok(bytes) if fs::read(dest.join(rel)).is_ok_and(|copy| copy == bytes) => {},
            Ok(bytes) if is_sealed_wallet_record(&dest.join(rel)) => {
                sealed.push((rel.clone(), Zeroizing::new(bytes)))
            },
            Ok(_) => return Err(refused()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => retired = true,
            Err(error) => return Err(error.to_string()),
        }
    }
    if !sealed.is_empty() {
        let unlock = opener.unlock().ok_or_else(refused)?;
        let matches = with_wallet_unlocked(dest, &unlock, || {
            sealed.iter().try_fold(true, |all, (rel, bytes)| {
                Ok(all && sealed_secret_matches_raw(dest, &dest.join(rel), bytes)?)
            })
        });
        if !matches.unwrap_or(false) {
            return Err(refused());
        }
    }
    Ok(if retired {
        Prior::Finish
    } else {
        Prior::Restart
    })
}

/// Remove each source file only while it still equals what the custodian
/// verifiably holds: the same bytes, or (a raw secret) a sealed record that
/// reads back to them.
fn retire(
    source: &Path,
    dest: &Path,
    opener: &Opener<'_>,
    files: &[PathBuf],
    raw: &[(PathBuf, Zeroizing<Vec<u8>>)],
) -> Result<Vec<(PathBuf, String)>, String> {
    let verified = |rel: &Path, bytes: &[u8]| -> bool {
        if fs::read(dest.join(rel)).is_ok_and(|copy| copy == bytes) {
            return true;
        }
        let was_raw = raw.iter().any(|(r, b)| r == rel && b.as_slice() == bytes);
        let Some(unlock) = opener.unlock() else {
            return false;
        };
        was_raw
            && with_wallet_unlocked(dest, &unlock, || {
                sealed_secret_matches_raw(dest, &dest.join(rel), bytes)
            })
            .unwrap_or(false)
    };
    let mut left = Vec::new();
    for rel in files {
        let removed = match fs::read(source.join(rel)) {
            Ok(bytes) if verified(rel, &bytes) => {
                fs::remove_file(source.join(rel)).map_err(|e| e.to_string())
            },
            Ok(_) => Err("it changed after it was carried".to_string()),
            Err(error) => Err(error.to_string()),
        };
        if let Err(reason) = removed {
            left.push((rel.clone(), reason));
        }
    }
    prune(source, files);
    Ok(left)
}

/// Remove every wallet file from the custodian's root, staged copies
/// included (copies of a source that is still whole).
fn clear(dest: &Path) -> Result<(), String> {
    let mut held = wallet_files(dest).map_err(described)?;
    if let Ok(personas) = fs::read_dir(dest.join(sporran::PERSONAS_DIR)) {
        for persona in personas.flatten() {
            for staged in fs::read_dir(persona.path()).into_iter().flatten().flatten() {
                if staged.path().extension().is_some_and(|e| e == "adopting") {
                    held.push(relative(dest, &staged.path()));
                }
            }
        }
    }
    for rel in &held {
        fs::remove_file(dest.join(rel)).map_err(described)?;
    }
    prune(dest, &held);
    Ok(())
}
