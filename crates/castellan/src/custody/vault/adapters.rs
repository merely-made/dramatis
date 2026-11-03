// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Borrowed storage delegates, so a vault can be opened over a backend
/// the caller keeps (`IdentityVault<&dyn IdentityStorage>`) without
/// giving up ownership.
impl<T: IdentityStorage + ?Sized> IdentityStorage for &T {
    fn load_profile(&self, id: &ProfileId) -> Result<Profile, IdentityError> {
        (**self).load_profile(id)
    }

    fn save_profile(&self, profile: &Profile) -> Result<(), IdentityError> {
        (**self).save_profile(profile)
    }

    fn delete_profile(&self, id: &ProfileId) -> Result<(), IdentityError> {
        (**self).delete_profile(id)
    }

    fn list_profiles(&self) -> Result<Vec<ProfileSummary>, IdentityError> {
        (**self).list_profiles()
    }

    fn unlock_methods(&self) -> UnlockMethods {
        (**self).unlock_methods()
    }

    fn lock(&self) {
        (**self).lock()
    }

    fn is_locked(&self) -> bool {
        (**self).is_locked()
    }

    fn unlock(&self, method: UnlockMethod<'_>) -> Result<(), IdentityError> {
        (**self).unlock(method)
    }

    fn change_passphrase(
        &self,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), super::super::unlock::PassphraseChangeError> {
        (**self).change_passphrase(old, new)
    }

    fn enroll_passphrase(&self, passphrase: &[u8]) -> Result<(), IdentityError> {
        (**self).enroll_passphrase(passphrase)
    }
}

/// Boxed storage delegates, so callers can pick a backend at runtime
/// (`IdentityVault<Box<dyn IdentityStorage>>`).
impl<T: IdentityStorage + ?Sized> IdentityStorage for Box<T> {
    fn load_profile(&self, id: &ProfileId) -> Result<Profile, IdentityError> {
        (**self).load_profile(id)
    }

    fn save_profile(&self, profile: &Profile) -> Result<(), IdentityError> {
        (**self).save_profile(profile)
    }

    fn delete_profile(&self, id: &ProfileId) -> Result<(), IdentityError> {
        (**self).delete_profile(id)
    }

    fn list_profiles(&self) -> Result<Vec<ProfileSummary>, IdentityError> {
        (**self).list_profiles()
    }

    fn unlock_methods(&self) -> UnlockMethods {
        (**self).unlock_methods()
    }

    fn lock(&self) {
        (**self).lock()
    }

    fn is_locked(&self) -> bool {
        (**self).is_locked()
    }

    fn unlock(&self, method: UnlockMethod<'_>) -> Result<(), IdentityError> {
        (**self).unlock(method)
    }

    fn change_passphrase(
        &self,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), super::super::unlock::PassphraseChangeError> {
        (**self).change_passphrase(old, new)
    }

    fn enroll_passphrase(&self, passphrase: &[u8]) -> Result<(), IdentityError> {
        (**self).enroll_passphrase(passphrase)
    }
}
