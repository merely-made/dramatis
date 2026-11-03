// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// A directory in canonical form, so two of them compare soundly by prefix
/// (the record and freshness roots must not overlap).
///
/// [`Self::resolve`] canonicalizes once, where that is allowed; [`Self::child`]
/// descends without resolving again, refusing any component that is not a
/// plain directory, so the result stays canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedDirectory(pub(super) PathBuf);

impl ResolvedDirectory {
    /// Create `path` if missing and resolve it to its canonical form.
    pub fn resolve(path: impl Into<PathBuf>) -> Result<Self, IdentityError> {
        let path = path.into();
        std::fs::create_dir_all(&path).map_err(|error| {
            IdentityError::Backend(format!("create directory {path:?}: {error}"))
        })?;
        path.canonicalize()
            .map(Self)
            .map_err(|error| IdentityError::Backend(format!("resolve directory {path:?}: {error}")))
    }

    /// The directory `relative` below this one, created if missing. Only plain
    /// components are accepted, and each must be a directory, never a link.
    pub fn child(&self, relative: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let relative = relative.as_ref();
        let mut path = self.0.clone();
        for component in relative.components() {
            match component {
                Component::Normal(part) => path.push(part),
                Component::CurDir => continue,
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(IdentityError::Backend(format!(
                        "resolved child must be relative and traversal-free: {relative:?}"
                    )));
                },
            }
            match std::fs::create_dir(&path) {
                Ok(()) => {},
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => {
                    return Err(IdentityError::Backend(format!(
                        "create directory {path:?}: {error}"
                    )));
                },
            }
            let kind = std::fs::symlink_metadata(&path)
                .map_err(|error| {
                    IdentityError::Backend(format!("inspect directory {path:?}: {error}"))
                })?
                .file_type();
            if !kind.is_dir() {
                return Err(IdentityError::Backend(format!(
                    "{path:?} is not a plain directory"
                )));
            }
        }
        Ok(Self(path))
    }

    /// The canonical path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

pub(super) fn resolve_record_path(
    root: &Path,
    relative: &Path,
) -> Result<(PathBuf, String), IdentityError> {
    let mut normalized = PathBuf::new();
    let mut aad = String::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                if !aad.is_empty() {
                    aad.push('/');
                }
                aad.push_str(&part.to_string_lossy());
                normalized.push(part);
            },
            Component::CurDir => {},
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(IdentityError::Backend(format!(
                    "sealed record path must be relative and traversal-free: {:?}",
                    relative
                )));
            },
        }
    }
    if aad.is_empty() {
        return Err(IdentityError::Backend(
            "sealed record path must not be empty".to_string(),
        ));
    }
    Ok((root.join(normalized), aad))
}

pub(super) fn save_json_atomic<T>(path: &Path, value: &T) -> Result<(), IdentityError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|err| IdentityError::Backend(format!("serialize {:?}: {err}", path)))?;
    save_bytes_atomic(path, &bytes)
}

pub(super) fn save_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let parent = path.parent().ok_or_else(|| {
        IdentityError::Backend(format!("sealed record path has no parent: {:?}", path))
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|err| IdentityError::Backend(format!("create dir {:?}: {err}", parent)))?;
    let tmp = tempfile_in_dir(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|err| IdentityError::Backend(format!("create tmp {:?}: {err}", tmp)))?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(IdentityError::Backend(format!(
            "write and flush tmp {:?}: {err}",
            tmp
        )));
    }
    drop(file);
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(IdentityError::Backend(format!(
            "rename tmp {:?} -> {:?}: {err}",
            tmp, path
        )));
    }
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| IdentityError::Backend(format!("flush dir {:?}: {err}", parent)))?;
    Ok(())
}

pub(super) fn tempfile_in_dir(dir: &Path) -> Result<PathBuf, IdentityError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| IdentityError::Backend(format!("time: {err}")))?
        .as_nanos();
    let mut rand = [0u8; 8];
    getrandom::fill(&mut rand).expect("OS randomness available");
    let mut hex = String::with_capacity(16);
    for byte in rand {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Ok(dir.join(format!(".sealed-record-{now}-{hex}.tmp")))
}
