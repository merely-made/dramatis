// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The padlock file (padlock profile §4.7): bounded before it is parsed,
//! verified before and after it is written, the previous bytes put back on
//! any mismatch, and never a `.prev` copy left behind.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sporran::wallet_store::save_bytes_atomic;

use crate::custody::padlock::{MAX_FILE_BYTES, Padlock, PadlockError};

pub(super) fn padlock_error(error: PadlockError) -> io::Error {
    let kind = match error {
        PadlockError::WrongSecret | PadlockError::BindingRefused => io::ErrorKind::PermissionDenied,
        PadlockError::NoMatchingSlot | PadlockError::UnknownKid => io::ErrorKind::NotFound,
        PadlockError::Randomness | PadlockError::Kdf => io::ErrorKind::Other,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

/// The sibling the house's atomic replace moves the old file to while it
/// swaps in the new one (`muniment::atomic_file`); present only if a
/// replacement was interrupted.
fn interrupted_backup(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".previous");
    path.with_file_name(name)
}

/// Bytes of the padlock at `path`, at most [`MAX_FILE_BYTES`] (R1 before any
/// parse). An interrupted replacement leaves only the backup, which is read.
fn read_bounded(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let backup = interrupted_backup(path);
    let source = if path.exists() {
        path
    } else if backup.exists() {
        backup.as_path()
    } else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(source)?
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(padlock_error(PadlockError::TooLarge));
    }
    Ok(Some(bytes))
}

/// The padlock at `path`, strictly decoded, or `None` when there is none.
pub(super) fn read_padlock(path: &Path) -> io::Result<Option<Padlock>> {
    read_bounded(path)?
        .map(|bytes| Padlock::parse(&bytes).map_err(padlock_error))
        .transpose()
}

/// Write `padlock` to `path`. `check` runs on the staged bytes before the write
/// and on the file read back after it; on any failure after the write the
/// previous bytes (or no file) are put back and the error returned.
pub(super) fn write_padlock(
    path: &Path,
    padlock: &Padlock,
    check: impl Fn(&Padlock) -> io::Result<()>,
) -> io::Result<()> {
    let bytes = padlock.to_bytes().map_err(padlock_error)?;
    check(&Padlock::parse(&bytes).map_err(padlock_error)?)?;
    let previous = read_bounded(path)?;
    #[cfg(test)]
    fail_point::hit()?;
    save_bytes_atomic(path, &bytes)?;
    let outcome = read_bounded(path).and_then(|back| match back {
        Some(back) if back == bytes => check(&Padlock::parse(&back).map_err(padlock_error)?),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the padlock at {path:?} did not read back equal"),
        )),
    });
    if let Err(error) = outcome {
        match previous {
            Some(previous) => save_bytes_atomic(path, &previous)?,
            None => std::fs::remove_file(path)?,
        }
        return Err(error);
    }
    Ok(())
}

/// Remove the padlock at `path` (a rolled-back migration).
pub(super) fn remove_padlock(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// A test hook that fails the next write before it replaces the file.
#[cfg(test)]
pub(super) mod fail_point {
    use std::cell::Cell;
    use std::io;

    thread_local!(static ARMED: Cell<bool> = const { Cell::new(false) });

    pub(in crate::custody::wallet) fn arm() {
        ARMED.with(|armed| armed.set(true));
    }

    pub(super) fn hit() -> io::Result<()> {
        if ARMED.with(|armed| armed.replace(false)) {
            return Err(io::Error::other("interrupted before the replacement"));
        }
        Ok(())
    }
}
