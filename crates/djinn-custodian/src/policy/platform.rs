// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use serde::Deserialize;

/// The data-protection Keychain envelope (custody plan H1): where the
/// custodian's sealing root lives, and under which access group.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeConfig {
    /// The custodian's own Keychain access group, `TEAMID.identifier`; the
    /// signed bundle's entitlement and provisioning profile must carry it.
    pub access_group: String,
    /// The Keychain service the sealing root is filed under.
    #[serde(default = "default_envelope_service")]
    pub service: String,
}

fn default_envelope_service() -> String {
    "com.merely.djinn.custodian.envelope".into()
}

impl EnvelopeConfig {
    /// Why this envelope is refused in a configuration, if it is.
    pub(super) fn check(&self, development: bool) -> Result<(), String> {
        let plain = |text: &str| {
            !text.is_empty()
                && text.len() <= 128
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        };
        if !(plain(&self.service)
            && self
                .access_group
                .split_once('.')
                .is_some_and(|(team, id)| plain(team) && plain(id)))
        {
            return Err("the envelope names an invalid Keychain access group or service".into());
        }
        if development {
            return Err("a custodian with a Keychain envelope is never a development one: its configuration would be caller-chosen".into());
        }
        Ok(())
    }
}

/// The vault owner's desktop account.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    #[serde(default)]
    pub unix_uid: Option<u32>,
    #[serde(default)]
    pub windows_sid: Option<String>,
}

/// Which channel decides petitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsentMode {
    /// Nobody: every petition is refused.
    Deny,
    /// A session admitted as `consent_channel`.
    Channel,
    /// Linux polkit with an interactive authentication of the requester's
    /// session (`auth_self`), run by the custodian itself.
    Polkit,
}
