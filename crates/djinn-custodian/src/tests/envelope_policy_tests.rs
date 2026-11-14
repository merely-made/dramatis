// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The macOS envelope's configuration: a valid group and service, a refusal of
//! anything that could be a Keychain query's injection, and no development
//! custodian holding an envelope (its configuration would be caller-chosen).

use crate::policy::Config;

fn with(envelope: &str, development: bool) -> Result<Config, crate::policy::PolicyError> {
    let json = format!(
        r#"{{"vault": {{"directory": "/Library/x/vault"}}, "owner": {{"unix_uid": 501}}, "consent": "deny",
            "development": {development}, "envelope": {envelope}, "principals": []}}"#
    );
    Config::parse(json.as_bytes())
}

#[test]
fn a_team_prefixed_group_parses_with_the_default_service() {
    let config = with(
        r#"{"access_group": "HWVZ5S7ACJ.com.merely.djinn.custodian"}"#,
        false,
    )
    .unwrap();
    let envelope = config.envelope.unwrap();
    assert_eq!(
        envelope.access_group,
        "HWVZ5S7ACJ.com.merely.djinn.custodian"
    );
    assert_eq!(envelope.service, "com.merely.djinn.custodian.envelope");
}

#[test]
fn a_malformed_group_or_service_is_refused() {
    for bad in [
        r#"{"access_group": ""}"#,
        r#"{"access_group": "NoTeamDot"}"#,
        r#"{"access_group": "TEAM.id with space"}"#,
        r#"{"access_group": "TEAM.id", "service": ""}"#,
        r#"{"access_group": "TEAM.id", "service": "a/b"}"#,
        r#"{"access_group": "TEAM.id", "extra": 1}"#,
    ] {
        assert!(with(bad, false).is_err(), "{bad}");
    }
}

#[test]
fn a_development_custodian_cannot_hold_an_envelope() {
    assert!(with(r#"{"access_group": "TEAM.id"}"#, true).is_err());
    assert!(with(r#"{"access_group": "TEAM.id"}"#, false).is_ok());
}
