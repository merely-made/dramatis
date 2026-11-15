// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! `djinn-custodian wallet-root`: the owner's acts on the wallet's padlock
//! (custody D8, D9 step one). Passphrases come on stdin, never the command
//! line. The padlock's passphrase is its own, not the vault's: step two of
//! custody D9 unifies them.

use std::io::{BufRead, Write};
use std::path::Path;

use castellan::custody::wallet::{self, WalletUnlock};
use zeroize::Zeroizing;

/// What `wallet-root` was asked to do.
pub struct Request<'a> {
    /// `slots`, `create`, `migrate`, `seal-legacy`, `add-passphrase`, `add-os`,
    /// `change-passphrase` or `remove`.
    pub action: &'a str,
    /// The slot to remove.
    pub kid: Option<&'a str>,
    /// `os` (the default) or `passphrase`: how the padlock is opened first.
    pub with: Option<&'a str>,
    /// `migrate` only: `stdin` adds a passphrase slot read from stdin.
    pub passphrase: Option<&'a str>,
}

fn line(input: &mut impl BufRead, what: &str) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::new());
    input.read_line(&mut text).map_err(|e| e.to_string())?;
    let keep = text.trim_end_matches(['\r', '\n']).len();
    text.truncate(keep);
    if text.is_empty() {
        return Err(format!("an empty {what} is not accepted"));
    }
    Ok(text)
}

/// A new padlock passphrase from stdin, typed twice.
///
/// # Errors
/// Empty, unreadable, or the two lines differ.
pub fn new_passphrase(input: &mut impl BufRead) -> Result<Zeroizing<String>, String> {
    let first = line(input, "padlock passphrase")?;
    if *first != *line(input, "padlock passphrase")? {
        return Err("the two padlock passphrases did not match".into());
    }
    Ok(first)
}

/// Run `request` against the wallet under `data_root`.
///
/// # Errors
/// The request is malformed or the wallet refuses it; nothing is changed then.
pub fn run(
    data_root: &Path,
    request: &Request<'_>,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<(), String> {
    let fail = |e: std::io::Error| e.to_string();
    // How add-passphrase and add-os open the padlock first.
    let current = match (request.action, request.with.unwrap_or("os")) {
        ("add-passphrase" | "add-os" | "seal-legacy", "passphrase") => {
            Some(line(input, "current padlock passphrase")?)
        },
        (_, "os" | "passphrase") => None,
        (_, other) => return Err(format!("--with is os or passphrase, not {other}")),
    };
    let with = current
        .as_deref()
        .map_or(WalletUnlock::Os, |p| WalletUnlock::Passphrase(p));
    let say =
        |out: &mut dyn Write, text: String| writeln!(out, "{text}").map_err(|e| e.to_string());
    match request.action {
        "slots" => {
            for slot in wallet::wallet_padlock_slots(data_root).map_err(fail)? {
                say(out, format!("{}\t{:?}", slot.kid, slot.kind))?;
            }
            Ok(())
        },
        "create" => {
            let phrase = new_passphrase(input)?;
            wallet::create_wallet_padlock_with_passphrase(data_root, &phrase).map_err(fail)?;
            say(out, "created a padlock with one passphrase slot, pass/1; it is the padlock's passphrase, not the vault's".into())
        },
        "migrate" => {
            let phrase = match request.passphrase {
                None => None,
                Some("stdin") => Some(new_passphrase(input)?),
                Some(other) => return Err(format!("--passphrase takes only stdin, not {other}")),
            };
            wallet::migrate_wallet_root_to_padlock(
                data_root,
                phrase.as_deref().map(String::as_str),
            )
            .map_err(fail)?;
            say(
                out,
                "the wallet's root is under its padlock; the legacy root file is retired".into(),
            )
        },
        "seal-legacy" => {
            let sealed = wallet::seal_legacy_wallet_secrets(data_root, &with).map_err(fail)?;
            say(
                out,
                format!(
                    "sealed {} raw legacy wallet secrets under the padlock",
                    sealed.len()
                ),
            )
        },
        "add-passphrase" => {
            let phrase = new_passphrase(input)?;
            let kid =
                wallet::add_wallet_passphrase_slot(data_root, &with, &phrase).map_err(fail)?;
            say(
                out,
                format!("added {kid}; it is the padlock's passphrase, not the vault's"),
            )
        },
        "add-os" => {
            let kid = wallet::add_wallet_os_slot(data_root, &with).map_err(fail)?;
            say(out, format!("added {kid}"))
        },
        "change-passphrase" => {
            let old = line(input, "current padlock passphrase")?;
            let new = new_passphrase(input)?;
            wallet::change_wallet_passphrase(data_root, &old, &new).map_err(fail)?;
            say(
                out,
                "changed; an older copy of the padlock file still opens with the old passphrase"
                    .into(),
            )
        },
        "remove" => {
            let kid = request.kid.ok_or("remove needs --kid")?;
            wallet::remove_wallet_padlock_slot(data_root, kid).map_err(fail)?;
            say(
                out,
                format!(
                    "removed {kid}. This is not revocation: a copy of the padlock file taken before still opens with it"
                ),
            )
        },
        other => Err(format!("unknown wallet-root action {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_text(root: &Path, request: &Request<'_>, stdin: &str) -> Result<String, String> {
        let mut out = Vec::new();
        run(root, request, &mut stdin.as_bytes(), &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn request<'a>(action: &'a str) -> Request<'a> {
        Request {
            action,
            kid: None,
            with: None,
            passphrase: None,
        }
    }

    #[test]
    fn admin_acts_on_a_padlock() {
        let root = tempfile::tempdir().unwrap();
        castellan::custody::os_kek::install_os_kek_store(
            root.path(),
            std::sync::Arc::new(castellan::custody::os_kek::MemoryOsKek::default()),
        );
        let persona = personae::PersonaId::new();
        wallet::ensure_wallet_state(root.path(), persona, "admin test").unwrap();
        assert!(
            run_text(root.path(), &request("add-passphrase"), "one\ntwo\n")
                .unwrap_err()
                .contains("did not match")
        );
        assert!(
            run_text(root.path(), &request("add-passphrase"), "one\none\n")
                .unwrap()
                .contains("pass/1")
        );
        let change = run_text(
            root.path(),
            &request("change-passphrase"),
            "one\nthree\nthree\n",
        );
        assert!(change.unwrap().contains("older copy"));
        let slots = run_text(root.path(), &request("slots"), "").unwrap();
        assert!(slots.contains("pass/2"), "{slots}");
        let removed = run_text(
            root.path(),
            &Request {
                kid: Some("pass/2"),
                ..request("remove")
            },
            "",
        )
        .unwrap();
        assert!(removed.contains("not revocation"));
        castellan::custody::os_kek::remove_os_kek_store(root.path());
    }
}
