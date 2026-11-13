// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native identity callbacks and command execution; host-owned dialogs are injected.

use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;
#[cfg(feature = "in-process-custody")]
use castellan::custody::OsPresence;
use crate::custody_host::ResidentCustody;
use crate::native::{NativeIdentityAction, NativeIdentityResult, NativeIdentityFailure};
use dramatis::intents::ImportSshKeyNativeIntentV1;

const MAX_SSH_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;

/// Secret-bearing desktop interactions required by native identity actions.
///
/// Implementations own the selected path and passphrase. Neither appears in
/// the browser request or response types.
pub trait NativeIdentityUi: Send + Sync {
    /// Confirm facts obtained from the authority, never text or an answer
    /// supplied by the requesting app. Absence of a native UI refuses.
    fn confirm_signing(
        &self,
        _pending: &personae::signing::PendingSigningRequest,
        _decision: personae::signing::SigningDecision,
    ) -> Result<bool, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }
    /// Resident-owned confirmation; apps cannot supply the answer.
    fn confirm_quarantine(
        &self,
        _profile: &str,
        _title: &str,
        _action: &str,
    ) -> Result<bool, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }
    /// Ask the owner whether `app` may have what `grant` describes, the
    /// first time it connects (capability door D25). Djinn writes the text;
    /// the application supplies only its name and declaration.
    fn confirm_application(&self, _app: &str, _grant: &str) -> Result<bool, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }
    fn pick_ssh_private_key(&self) -> Result<Option<PathBuf>, NativeIdentityFailure>;

    fn prompt_ssh_private_key_passphrase(
        &self,
    ) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure>;

    /// Ask the OS to verify the user (Windows Hello). `Ok(None)` when it is
    /// unavailable, cancelled or not verified: the passphrase box follows.
    /// Only an in-process, OS-sealed vault takes this proof.
    #[cfg(feature = "in-process-custody")]
    fn verify_presence(&self) -> Result<Option<OsPresence>, NativeIdentityFailure> {
        Ok(None)
    }

    /// Ask for the vault passphrase in a native box; `Ok(None)` if cancelled.
    fn prompt_vault_passphrase(&self) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }

    /// The same box in the host's own words: a resident's start prompt, a
    /// first-run choice, a retry after an error (vault lock rulings 63, 64).
    fn ask_vault_passphrase(
        &self,
        _message: &str,
    ) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableNativeIdentityUi;

impl NativeIdentityUi for UnavailableNativeIdentityUi {
    fn pick_ssh_private_key(&self) -> Result<Option<PathBuf>, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }

    fn prompt_ssh_private_key_passphrase(
        &self,
    ) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure> {
        Err(NativeIdentityFailure::UiUnavailable)
    }
}

/// Apply one fixed native interaction against custody.
pub fn apply_native_identity_action<U>(
    host: &dyn ResidentCustody,
    ui: &U,
    action: NativeIdentityAction,
) -> NativeIdentityResult
where
    U: NativeIdentityUi + ?Sized,
{
    match action {
        NativeIdentityAction::ImportSshPrivate { unlock_policy } => {
            import_ssh_private(host, ui, ImportSshKeyNativeIntentV1 { unlock_policy })
        },
        NativeIdentityAction::UnlockVault => unlock_vault(host, ui),
    }
}

/// Local owner action. No caller supplies a credential, path, or prompt text.
pub(crate) fn change_passphrase<U: NativeIdentityUi + ?Sized>(
    host: &dyn ResidentCustody,
    ui: &U,
) -> dramatis::authentication::PassphraseChangeReceiptV1 {
    use dramatis::authentication::{
        PassphraseChangeFailureV1 as F, PassphraseChangeReceiptV1 as R,
    };
    let rejected = |reason| R::Rejected { reason };
    if host.is_locked() {
        return rejected(F::Locked);
    }
    let prompt = |message| match ui.ask_vault_passphrase(message) {
        Ok(Some(secret)) => Ok(secret),
        Ok(None) => Err(R::Cancelled),
        Err(_) => Err(rejected(F::UiUnavailable)),
    };
    let old = match prompt("Change vault passphrase: enter the current passphrase.") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let new = match prompt("Enter the new vault passphrase.") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if new.is_empty() {
        return rejected(F::InvalidNewPassphrase);
    }
    let confirmation = match prompt("Enter the new vault passphrase again.") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if *new != *confirmation {
        return rejected(F::ConfirmationMismatch);
    }
    match host.change_passphrase(old.as_bytes(), new.as_bytes()) {
        Ok(()) => R::Changed,
        Err(failure) => rejected(failure),
    }
}

/// OS presence first where an in-process vault takes it, then the
/// passphrase box. Toward a custodian the passphrase is sent once over the
/// checked channel (the documented terminal-unlock exception) and dropped.
fn unlock_vault<U>(host: &dyn ResidentCustody, ui: &U) -> NativeIdentityResult
where
    U: NativeIdentityUi + ?Sized,
{
    if !host.is_locked() {
        return NativeIdentityResult::UnlockedVault;
    }
    let ui_object: &dyn NativeIdentityUi = &Delegate(ui);
    match host.unlock_with_presence(ui_object) {
        Some(Ok(())) => return NativeIdentityResult::UnlockedVault,
        Some(Err(error)) => tracing::warn!(%error, "presence unlock refused; asking for the passphrase"),
        None => {},
    }
    let passphrase = match ui.prompt_vault_passphrase() {
        Ok(Some(passphrase)) => passphrase,
        Ok(None) => return NativeIdentityResult::Cancelled,
        Err(reason) => return NativeIdentityResult::Rejected { reason },
    };
    let unlocked = host.unlock_with_passphrase(passphrase.as_bytes());
    drop(passphrase);
    match unlocked {
        Ok(()) => NativeIdentityResult::UnlockedVault,
        Err(_) if host.is_locked() => NativeIdentityResult::Rejected {
            reason: NativeIdentityFailure::IncorrectPassphrase,
        },
        Err(_) => NativeIdentityResult::Rejected {
            reason: NativeIdentityFailure::UnlockRejected,
        },
    }
}

fn import_ssh_private<U>(
    host: &dyn ResidentCustody,
    ui: &U,
    options: ImportSshKeyNativeIntentV1,
) -> NativeIdentityResult
where
    U: NativeIdentityUi + ?Sized,
{
    let path = match ui.pick_ssh_private_key() {
        Ok(Some(path)) => path,
        Ok(None) => return NativeIdentityResult::Cancelled,
        Err(reason) => return NativeIdentityResult::Rejected { reason },
    };
    let metadata = match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            return NativeIdentityResult::Rejected {
                reason: NativeIdentityFailure::SelectedFileUnreadable,
            };
        },
    };
    if metadata.len() > MAX_SSH_PRIVATE_KEY_BYTES {
        return NativeIdentityResult::Rejected {
            reason: NativeIdentityFailure::SelectedFileTooLarge,
        };
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_) => {
            return NativeIdentityResult::Rejected {
                reason: NativeIdentityFailure::SelectedFileUnreadable,
            };
        },
    };
    if bytes.len() as u64 > MAX_SSH_PRIVATE_KEY_BYTES {
        return NativeIdentityResult::Rejected {
            reason: NativeIdentityFailure::SelectedFileTooLarge,
        };
    }
    let encrypted = match ssh_key::PrivateKey::from_openssh(bytes.as_slice()) {
        Ok(private) => private.is_encrypted(),
        Err(_) => {
            return NativeIdentityResult::Rejected {
                reason: NativeIdentityFailure::InvalidPrivateKey,
            };
        },
    };
    let passphrase = match encrypted {
        true => match ui.prompt_ssh_private_key_passphrase() {
            Ok(Some(passphrase)) => Some(passphrase),
            Ok(None) => return NativeIdentityResult::Cancelled,
            Err(reason) => return NativeIdentityResult::Rejected { reason },
        },
        false => None,
    };
    // The key file's bytes go to custody once; the key is opened and stored
    // there, not here.
    match host.import_ssh_key(bytes.as_slice(), passphrase.as_ref().map(|p| p.as_bytes()), options) {
        Ok(receipt) => NativeIdentityResult::ImportedSshPrivate {
            fingerprint: receipt.fingerprint,
            comment: receipt.comment,
            unlock_policy: receipt.unlock_policy,
            replaced_existing: receipt.replaced_existing,
        },
        Err(reason) => NativeIdentityResult::Rejected { reason },
    }
}

/// A sized native surface as a trait object.
struct Delegate<'a, U: NativeIdentityUi + ?Sized>(&'a U);

impl<U: NativeIdentityUi + ?Sized> NativeIdentityUi for Delegate<'_, U> {
    fn pick_ssh_private_key(&self) -> Result<Option<PathBuf>, NativeIdentityFailure> {
        self.0.pick_ssh_private_key()
    }

    fn prompt_ssh_private_key_passphrase(&self) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure> {
        self.0.prompt_ssh_private_key_passphrase()
    }

    #[cfg(feature = "in-process-custody")]
    fn verify_presence(&self) -> Result<Option<OsPresence>, NativeIdentityFailure> {
        self.0.verify_presence()
    }
}

#[cfg(all(test, feature = "in-process-custody"))]
mod tests {
    use std::sync::{Arc, Mutex};
    use castellan::authority::PersonaeHost;
    use castellan::custody::{IdentityVault, InMemoryStorage, Profile};
    use dramatis::intents::SshUnlockPolicyIntentV1;
    use dramatis::view::VaultProtectionView;
    use personae::{Ed25519Keypair, ProfileId};
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use super::*;
    struct ScriptedUi {
        path: PathBuf,
        passphrases: Mutex<Vec<String>>,
    }

    impl NativeIdentityUi for ScriptedUi {
        fn pick_ssh_private_key(&self) -> Result<Option<PathBuf>, NativeIdentityFailure> {
            Ok(Some(self.path.clone()))
        }

        fn prompt_ssh_private_key_passphrase(
            &self,
        ) -> Result<Option<Zeroizing<String>>, NativeIdentityFailure> {
            Ok(self.passphrases.lock().unwrap().pop().map(Zeroizing::new))
        }
    }

    fn host() -> Arc<PersonaeHost<InMemoryStorage>> {
        let profile = Profile::new(
            ProfileId("native-ui".to_string()),
            "Native UI",
            Ed25519Keypair::from_seed([0x81; 32]),
        );
        Arc::new(PersonaeHost::new(
            IdentityVault::with_profile(InMemoryStorage::new(), profile),
            None,
            VaultProtectionView::Ephemeral,
        ))
    }

    fn scratch_key(tag: &str, passphrase: &str) -> (PathBuf, String) {
        let mut private = PrivateKey::random(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        private.set_comment("native picker receipt");
        let fingerprint = private.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let private = private
            .encrypt(&mut rand_core::UnwrapErr(getrandom::SysRng), passphrase)
            .unwrap();
        let encoded = private.to_openssh(LineEnding::LF).unwrap();
        let path = std::env::temp_dir().join(format!(
            "graphshell-native-import-{tag}-{}",
            std::process::id()
        ));
        fs::write(&path, encoded.as_bytes()).unwrap();
        (path, fingerprint)
    }

    #[test]
    fn encrypted_key_is_unlocked_and_imported_without_a_serialized_secret() {
        let (path, fingerprint) = scratch_key("ok", "correct horse");
        let ui = ScriptedUi {
            path: path.clone(),
            passphrases: Mutex::new(vec!["correct horse".to_string()]),
        };
        let host = host();
        let result = apply_native_identity_action(
            host.as_ref(),
            &ui,
            NativeIdentityAction::ImportSshPrivate {
                unlock_policy: SshUnlockPolicyIntentV1::PerUse,
            },
        );
        assert!(matches!(
            &result,
            NativeIdentityResult::ImportedSshPrivate {
                fingerprint: imported,
                ..
            } if imported == &fingerprint
        ));
        assert_eq!(host.snapshot().unwrap().ssh_keys.len(), 1);

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("correct horse"));
        assert!(!serialized.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!serialized.contains(path.to_string_lossy().as_ref()));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn wrong_passphrase_imports_nothing_and_returns_a_bounded_reason() {
        let (path, _) = scratch_key("wrong", "correct horse");
        let ui = ScriptedUi {
            path: path.clone(),
            passphrases: Mutex::new(vec!["wrong horse".to_string()]),
        };
        let host = host();
        let result = apply_native_identity_action(
            host.as_ref(),
            &ui,
            NativeIdentityAction::ImportSshPrivate {
                unlock_policy: SshUnlockPolicyIntentV1::ShortTtl { idle_seconds: 90 },
            },
        );
        assert_eq!(
            result,
            NativeIdentityResult::Rejected {
                reason: NativeIdentityFailure::IncorrectPassphrase
            }
        );
        assert!(host.snapshot().unwrap().ssh_keys.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unavailable_ui_cannot_downgrade_to_browser_secret_input() {
        let result = apply_native_identity_action(
            host().as_ref(),
            &UnavailableNativeIdentityUi,
            NativeIdentityAction::ImportSshPrivate {
                unlock_policy: SshUnlockPolicyIntentV1::Session,
            },
        );
        assert_eq!(
            result,
            NativeIdentityResult::Rejected {
                reason: NativeIdentityFailure::UiUnavailable
            }
        );
    }
}
