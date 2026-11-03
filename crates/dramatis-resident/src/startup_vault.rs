// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! How the resident reaches its custody without the environment (vault lock
//! rulings 42 and 62 to 66; custody isolation plan, H2).
//!
//! With an installed custodian (every production build), the resident opens
//! no vault: [`open_custody`] connects to the custodian and, while it is
//! locked, asks for the passphrase on the same native box or terminal and
//! sends it once over the checked channel. Builds with
//! `in-process-custody` (tests and receipt hosts) keep the in-process open
//! below when no custodian is installed.
//!
//! A passphrase vault starts locked: the resident asks before it builds any
//! storage key, profile, door or lane (ruling 66), first in a native box and
//! else at its terminal (ruling 63). A cancel, a mismatch or a refused open
//! asks again after a backoff; with neither a box nor a terminal there is
//! nothing to ask with, and the start fails naming both. With no vault the
//! prompt creates one, asking twice (ruling 64). The OS-rooted vault (DPAPI)
//! still opens unattended, unless its vault carries the persisted lock: then
//! the start waits at the same prompt, Hello first (rulings 5, 76, 80). The
//! environment is never read (ruling 7).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "in-process-custody")]
use castellan::custody::bootstrap::{self, OpenedStorage, PASSPHRASE_VAULT_FILE, Unlock};
#[cfg(feature = "in-process-custody")]
use castellan::custody::{
    AUTO_UNLOCK_ROOT_FILE, IdentityStorage, OsPresence, SealedProfileStorage, UnlockMethod,
};
use zeroize::Zeroizing;

use crate::custody_host::ResidentCustody;

/// Which vault a start opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultChoice {
    /// The OS-held root opens it unattended (DPAPI).
    AutoOs,
    /// The passphrase vault, which starts locked.
    Passphrase,
}

/// The passphrase vault when the platform holds no root, when the directory
/// already holds one, or when a passphrase was handed over and no OS-rooted
/// vault is there yet; else the OS's (whose persisted lock a handed-over
/// passphrase then answers).
#[cfg(feature = "in-process-custody")]
pub fn choose(vault_dir: &Path, passphrase_given: bool) -> VaultChoice {
    let os_root = cfg!(windows);
    let os_vault = vault_dir.join(AUTO_UNLOCK_ROOT_FILE).exists();
    if !os_root || vault_dir.join(PASSPHRASE_VAULT_FILE).exists() || (passphrase_given && !os_vault)
    {
        VaultChoice::Passphrase
    } else {
        VaultChoice::AutoOs
    }
}

/// What a prompt is for, so each source can word it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    /// Unlock the existing vault; `retry` carries why the last try failed.
    Unlock { retry: Option<String> },
    /// First run: choose the new vault's passphrase.
    Create { retry: Option<String> },
    /// First run: type it again.
    Confirm,
}

impl Ask {
    /// The words a box or a terminal shows.
    pub fn message(&self) -> String {
        let (base, retry) = match self {
            Ask::Unlock { retry } => ("Enter the vault passphrase to start.", retry),
            Ask::Create { retry } => (
                "No identity vault yet. Choose a passphrase for a new one.",
                retry,
            ),
            Ask::Confirm => return "Type the new vault passphrase again.".into(),
        };
        match retry {
            Some(reason) => format!("{reason} {base}"),
            None => base.into(),
        }
    }
}

/// One answer from a prompt.
pub enum Answer {
    /// What was typed.
    Passphrase(Zeroizing<String>),
    /// Closed without an answer.
    Cancelled,
}

/// A source of passphrases: the native box, the terminal, or a script.
pub trait Prompt {
    /// Ask once. `Err` when this source cannot ask at all.
    fn ask(&mut self, ask: &Ask) -> Result<Answer, String>;

    /// The OS's own check of the user (Windows Hello), where this source
    /// offers one; `None` when unavailable, cancelled or not verified.
    #[cfg(feature = "in-process-custody")]
    fn presence(&mut self) -> Option<OsPresence> {
        None
    }
}

/// The native box where the desktop has one, else the terminal (ruling 63).
pub struct NativeOrTerminal<U> {
    /// The native identity UI.
    pub native: U,
}

impl<U: crate::identity_ui::NativeIdentityUi> Prompt for NativeOrTerminal<U> {
    #[cfg(feature = "in-process-custody")]
    fn presence(&mut self) -> Option<OsPresence> {
        self.native.verify_presence().ok().flatten()
    }

    fn ask(&mut self, ask: &Ask) -> Result<Answer, String> {
        let message = ask.message();
        match self.native.ask_vault_passphrase(&message) {
            Ok(Some(passphrase)) => return Ok(Answer::Passphrase(passphrase)),
            Ok(None) => return Ok(Answer::Cancelled),
            Err(_) => {},
        }
        match crate::enrollment::read_from_terminal(&format!("{message} ")) {
            Ok(passphrase) => Ok(Answer::Passphrase(passphrase)),
            Err(error) => Err(format!(
                "no native passphrase box and no terminal to ask at ({error})"
            )),
        }
    }
}

/// The opened vault, in a build with `in-process-custody`.
#[cfg(feature = "in-process-custody")]
pub struct Started {
    /// The opened storage.
    pub opened: OpenedStorage,
    /// Which vault it is.
    pub choice: VaultChoice,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

#[cfg(feature = "in-process-custody")]
impl Started {
    /// The storage and the choice; the passphrase is dropped with this.
    pub fn into_parts(self) -> (OpenedStorage, VaultChoice) {
        drop(self.passphrase);
        (self.opened, self.choice)
    }
}

/// What a start reports while it waits, for the event file.
pub trait Waiting {
    /// One event and its fields.
    fn emit(&mut self, event: &str, fields: serde_json::Value);
}

impl<F: FnMut(&str, serde_json::Value)> Waiting for F {
    fn emit(&mut self, event: &str, fields: serde_json::Value) {
        self(event, fields)
    }
}

/// The wait before asking again, after `misses` misses: 1 s doubling to 30 s.
pub fn backoff(misses: u32) -> Duration {
    Duration::from_secs((1u64 << misses.min(5)).min(30))
}

/// Open the vault for a start, in this process. A passphrase vault waits on
/// `prompt`; `sleep` is the backoff (injected for tests).
#[cfg(feature = "in-process-custody")]
pub fn open(
    vault_dir: &Path,
    choice: VaultChoice,
    prompt: &mut dyn Prompt,
    waiting: &mut dyn Waiting,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Started, String> {
    if choice == VaultChoice::AutoOs && castellan::custody::lock_persisted(vault_dir) {
        return open_under_persisted_lock(vault_dir, prompt, waiting, sleep);
    }
    if choice == VaultChoice::AutoOs {
        let opened = bootstrap::open_storage(vault_dir, Unlock::AutoOs)
            .map_err(|error| error.to_string())?;
        return Ok(Started {
            opened,
            choice,
            passphrase: None,
        });
    }
    let exists = vault_dir.join(PASSPHRASE_VAULT_FILE).exists();
    waiting.emit(
        "waiting-for-unlock",
        serde_json::json!({ "creating": !exists }),
    );
    let mut misses = 0u32;
    let mut retry: Option<String> = None;
    loop {
        let ask = match exists {
            true => Ask::Unlock {
                retry: retry.take(),
            },
            false => Ask::Create {
                retry: retry.take(),
            },
        };
        let passphrase = match prompt.ask(&ask)? {
            Answer::Passphrase(passphrase) if passphrase.is_empty() => {
                Some((passphrase, "An empty passphrase is not accepted."))
            },
            Answer::Passphrase(passphrase) => Some((passphrase, "")),
            Answer::Cancelled => None,
        };
        let Some((passphrase, refused)) = passphrase else {
            waiting.emit("unlock-cancelled", serde_json::json!({ "misses": misses }));
            sleep(backoff(misses));
            misses += 1;
            continue;
        };
        if !refused.is_empty() {
            retry = Some(refused.into());
            continue;
        }
        if !exists {
            let Answer::Passphrase(again) = prompt.ask(&Ask::Confirm)? else {
                waiting.emit("unlock-cancelled", serde_json::json!({ "misses": misses }));
                sleep(backoff(misses));
                misses += 1;
                continue;
            };
            if again.as_bytes() != passphrase.as_bytes() {
                retry = Some("The two passphrases did not match.".into());
                continue;
            }
        }
        let bytes = Zeroizing::new(passphrase.as_bytes().to_vec());
        match bootstrap::open_storage(vault_dir, Unlock::Passphrase(bytes.clone())) {
            Ok(opened) => {
                let event = if exists {
                    "unlocked-at-start"
                } else {
                    "vault-created"
                };
                waiting.emit(event, serde_json::json!({}));
                return Ok(Started {
                    opened,
                    choice,
                    passphrase: Some(bytes),
                });
            },
            // Argon2id's cost is the throttle on a wrong passphrase (ruling
            // 19); any refusal is shown and asked again.
            Err(error) => {
                waiting.emit(
                    "unlock-refused",
                    serde_json::json!({ "reason": error.to_string() }),
                );
                retry = Some(format!("That did not open the vault ({error})."));
            },
        }
    }
}

/// An OS-rooted vault whose lock persisted: open it locked and wait for a
/// user act, Hello once and then the passphrase box, before anything else
/// exists (rulings 5, 76). The marker clears with the unlock.
#[cfg(feature = "in-process-custody")]
fn open_under_persisted_lock(
    vault_dir: &Path,
    prompt: &mut dyn Prompt,
    waiting: &mut dyn Waiting,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Started, String> {
    waiting.emit(
        "waiting-for-unlock",
        serde_json::json!({ "persisted_lock": true }),
    );
    let storage = SealedProfileStorage::open_locked(vault_dir);
    let mut unlocked = match prompt.presence() {
        Some(verified) => storage.unlock(UnlockMethod::OsPresence(verified)).is_ok(),
        None => false,
    };
    let mut misses = 0u32;
    let mut retry: Option<String> = None;
    while !unlocked {
        let passphrase = match prompt.ask(&Ask::Unlock {
            retry: retry.take(),
        })? {
            Answer::Passphrase(passphrase) if passphrase.is_empty() => {
                retry = Some("An empty passphrase is not accepted.".into());
                continue;
            },
            Answer::Passphrase(passphrase) => passphrase,
            Answer::Cancelled => {
                waiting.emit("unlock-cancelled", serde_json::json!({ "misses": misses }));
                sleep(backoff(misses));
                misses += 1;
                continue;
            },
        };
        match storage.unlock(UnlockMethod::Passphrase(passphrase.as_bytes())) {
            Ok(()) => unlocked = true,
            Err(error) => {
                waiting.emit(
                    "unlock-refused",
                    serde_json::json!({ "reason": error.to_string() }),
                );
                retry = Some(format!("That did not open the vault ({error})."));
            },
        }
    }
    castellan::custody::clear_persisted_lock(vault_dir).map_err(|error| error.to_string())?;
    waiting.emit(
        "unlocked-at-start",
        serde_json::json!({ "persisted_lock": true }),
    );
    Ok(Started {
        opened: OpenedStorage {
            storage: Box::new(storage),
            description: format!(
                "OS auto-unlock sealed records at {} (DPAPI-wrapped root), opened by a user act \
                 under the persisted lock",
                vault_dir.display()
            ),
        },
        choice: VaultChoice::AutoOs,
        passphrase: None,
    })
}

/// Custody for a start: the installed custodian, waited on until it holds an
/// unlocked identity; else, in a build with `in-process-custody`, the vault
/// opened here. Without either the start fails: nothing falls back.
pub fn open_custody(
    vault_dir: &Path,
    profile: Option<&personae::ProfileId>,
    data_root: Option<std::path::PathBuf>,
    passphrase_given: bool,
    prompt: &mut dyn Prompt,
    waiting: &mut dyn Waiting,
    sleep: &mut dyn FnMut(Duration),
) -> Result<OpenedCustody, String> {
    if let Some(installed) = crate::custodian::InstalledCustodian::load()? {
        let host = crate::custody_host::remote::RemoteHost::connect(installed)?;
        unlock_custodian(host.as_ref(), prompt, waiting, sleep)?;
        let held = host.current_profile_id();
        if let Some(wanted) = profile
            && *wanted != held
        {
            return Err(format!(
                "the custodian holds profile {:?}, not {:?}; switch it with the profile intent",
                held.0, wanted.0
            ));
        }
        return Ok(OpenedCustody {
            host,
            protection: dramatis::view::VaultProtectionView::Passphrase,
            #[cfg(feature = "in-process-custody")]
            in_process: None,
        });
    }
    #[cfg(feature = "in-process-custody")]
    {
        let choice = choose(vault_dir, passphrase_given);
        let started = open(vault_dir, choice, prompt, waiting, sleep)?;
        let (opened, choice) = started.into_parts();
        let profile_id =
            crate::profile::resolve_selected_profile(&*opened.storage, vault_dir, profile)
                .map_err(|e| e.to_string())?;
        let (record, created) = bootstrap::load_or_create_profile(&*opened.storage, &profile_id)
            .map_err(|e| e.to_string())?;
        if created {
            tracing::warn!(profile = %profile_id.0, "selected profile was created");
        }
        let protection = match choice {
            VaultChoice::Passphrase => dramatis::view::VaultProtectionView::Passphrase,
            VaultChoice::AutoOs => dramatis::view::VaultProtectionView::OsProtected,
        };
        let host = Arc::new(
            castellan::authority::PersonaeHost::new(
                castellan::custody::IdentityVault::with_profile(opened.storage, record),
                data_root,
                protection,
            )
            .with_vault_dir(vault_dir.to_path_buf())
            .with_persisted_lock(vault_dir.to_path_buf()),
        );
        return Ok(OpenedCustody {
            host: host.clone(),
            protection,
            in_process: Some(host),
        });
    }
    #[cfg(not(feature = "in-process-custody"))]
    {
        let _ = (vault_dir, profile, data_root, passphrase_given);
        Err(format!(
            "no custodian is installed (expected {}); install djinn-custodian, which holds the vault",
            crate::custodian::installed_path().display()
        ))
    }
}

/// Custody a start reached.
pub struct OpenedCustody {
    pub host: Arc<dyn ResidentCustody>,
    /// How the vault is protected: a custodian's is always a passphrase vault.
    pub protection: dramatis::view::VaultProtectionView,
    /// Castellan's host itself, when the vault was opened in this process (a
    /// test or receipt build); it serves the SSH agent there. A custodian
    /// serves its own.
    #[cfg(feature = "in-process-custody")]
    pub in_process: Option<Arc<castellan::authority::PersonaeHost<Box<dyn IdentityStorage>>>>,
}

/// Wait until the custodian holds an unlocked identity, asking for its
/// passphrase while it is locked. A cancel asks again after a backoff; a
/// refusal says why and asks again.
pub fn unlock_custodian(
    host: &dyn ResidentCustody,
    prompt: &mut dyn Prompt,
    waiting: &mut dyn Waiting,
    sleep: &mut dyn FnMut(Duration),
) -> Result<(), String> {
    if !host.is_locked() {
        return Ok(());
    }
    waiting.emit(
        "waiting-for-unlock",
        serde_json::json!({ "custodian": true }),
    );
    let mut misses = 0u32;
    let mut retry: Option<String> = None;
    loop {
        let passphrase = match prompt.ask(&Ask::Unlock {
            retry: retry.take(),
        })? {
            Answer::Passphrase(passphrase) if passphrase.is_empty() => {
                retry = Some("An empty passphrase is not accepted.".into());
                continue;
            },
            Answer::Passphrase(passphrase) => passphrase,
            Answer::Cancelled => {
                waiting.emit("unlock-cancelled", serde_json::json!({ "misses": misses }));
                sleep(backoff(misses));
                misses += 1;
                continue;
            },
        };
        let unlocked = host.unlock_with_passphrase(passphrase.as_bytes());
        drop(passphrase);
        match unlocked {
            Ok(()) => {
                waiting.emit(
                    "unlocked-at-start",
                    serde_json::json!({ "custodian": true }),
                );
                return Ok(());
            },
            Err(error) => {
                waiting.emit("unlock-refused", serde_json::json!({ "reason": error }));
                retry = Some(format!("The custodian did not unlock ({error})."));
            },
        }
    }
}

/// One passphrase from standard input, for the harness (ruling 65): one
/// line, read once, never the environment. Only fd 0 exists everywhere.
#[cfg(feature = "passphrase-fd")]
pub fn read_passphrase_fd(fd: u32) -> Result<Zeroizing<String>, String> {
    use std::io::BufRead;
    if fd != 0 {
        return Err(format!(
            "--passphrase-fd {fd}: only 0 (standard input) is read"
        ));
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| format!("--passphrase-fd 0: {error}"))?;
    let trimmed = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(trimmed);
    Ok(line)
}

/// A handed-over passphrase: one try at unlocking or creating (it answers
/// the confirmation too), so a refused passphrase ends the start.
pub struct Given {
    passphrase: Zeroizing<String>,
    tried: bool,
}

impl Given {
    /// A prompt that answers with `passphrase`.
    pub fn new(passphrase: Zeroizing<String>) -> Self {
        Self {
            passphrase,
            tried: false,
        }
    }
}

impl Prompt for Given {
    fn ask(&mut self, ask: &Ask) -> Result<Answer, String> {
        if *ask != Ask::Confirm {
            if self.tried {
                return Err("the handed-over passphrase did not open the vault".into());
            }
            self.tried = true;
        }
        Ok(Answer::Passphrase(self.passphrase.clone()))
    }
}

#[cfg(all(test, feature = "in-process-custody"))]
mod tests;
