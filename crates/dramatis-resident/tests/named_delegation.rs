// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

#![cfg(any(unix, windows))]

use castellan_client::custody::{CustodyAnswer, CustodyCall, CustodyRefusal, KeySource};
use djinn_custodian::fixture::{self, Spec};
use dramatis_resident::custodian::{GRAPHSHELL_AUDIENCE, InstalledCustodian};
use dramatis_resident::custody_host::{ResidentCustody, remote::RemoteHost};
use dramatis_resident::keeper::Keeper;
use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
    delegation_signing_salt,
};
use ostiary::app_admission::AppId;
use ostiary::declaration::{
    AppAuthority, AppDeclaration, AppGrant, CustodyOperation, CustodyUse, SaltPattern, SaltUse,
};
use personae::{Ed25519Keypair, ProfileId};
use std::sync::Arc;

#[tokio::test]
async fn named_graphshell_invitation_uses_the_checked_remote_signer() {
    let root = tempfile::tempdir().unwrap();
    let profiles = [("owner", "Owner", [7; 32]), ("guest", "Guest", [8; 32])];
    let grants = fixture::DJINN_GRANTS_TEMPLATE
        .replace("@CONSENT@", "none")
        .replace("@SIGN_CONSENT@", "none");
    let custodian = fixture::start(
        root.path(),
        Spec {
            passphrase: "fixture-passphrase",
            profiles: &profiles,
            grants: serde_json::from_str(&grants).unwrap(),
            consent: "deny",
            mechanism: None,
            agent: false,
        },
    )
    .unwrap();
    let remote =
        RemoteHost::connect(InstalledCustodian::from_path(&custodian.client_file, false).unwrap())
            .unwrap();
    remote
        .unlock_with_passphrase(b"fixture-passphrase")
        .unwrap();
    let keeper = Arc::new(Keeper::new(remote));

    let app = AppId::new("isocosm");
    let usage = CustodyUse {
        operations: [CustodyOperation::Attest, CustodyOperation::Sign].into(),
        acts: vec![SaltUse::persona(SaltPattern::DelegationScope(
            GRAPHSHELL_AUDIENCE.into(),
        ))],
        ..Default::default()
    };
    let mut grant = AppGrant::new(app.clone());
    grant.custody.operations = usage.operations.clone();
    grant.custody.acts = usage.acts.clone();
    let authority = AppAuthority::new(
        AppDeclaration {
            custody: usage,
            ..Default::default()
        },
        grant,
    );
    let named = |profile: &str, inner: CustodyCall| {
        Arc::clone(&keeper).answer_custody(
            app.clone(),
            Some(authority.clone()),
            CustodyCall::AsProfile {
                profile: ProfileId(profile.into()),
                inner: Box::new(inner),
            },
        )
    };

    let key = |seed| Ed25519Keypair::from_seed(seed).public_key().to_bytes();
    let statement = DelegationCertificate::new(
        DelegationParent::Root([3; 32]),
        key(profiles[0].2),
        key(profiles[1].2),
        CapabilityScope {
            domain: GRAPHSHELL_AUDIENCE.into(),
            resource: vec![4; 32],
            path_prefix: "/".into(),
            actions: ["view".into()].into(),
        },
        10,
        10,
        Some(20),
        0,
        [5; 32],
    );
    let salt = delegation_signing_salt(&statement.scope);
    let sign = |statement: &DelegationCertificate| CustodyCall::Sign {
        source: KeySource::Persona,
        salt: salt.clone(),
        message: statement.signing_bytes(),
    };
    let CustodyAnswer::Attestation(attestation) = named(
        "owner",
        CustodyCall::Attest {
            source: KeySource::Persona,
            salt: salt.clone(),
        },
    )
    .await
    .unwrap() else {
        panic!("expected the owner's delegation-key attestation")
    };
    let CustodyAnswer::Signature {
        public_key,
        signature,
    } = named("owner", sign(&statement)).await.unwrap()
    else {
        panic!("expected a checked delegation signature")
    };
    assert_eq!(attestation.check(&salt).unwrap().derived(), &public_key);
    let signed = SignedDelegationCertificate::from_parts(statement.clone(), attestation, signature);
    assert_eq!(signed.check().unwrap().signer().master(), &statement.issuer);

    let mut wrong_issuer = statement.clone();
    wrong_issuer.issuer = key(profiles[1].2);
    assert!(matches!(named("owner", sign(&wrong_issuer)).await,
        Err(CustodyRefusal::Refused { reason }) if reason.ends_with("issuer-not-profile")));
    assert!(matches!(
        named("guest", sign(&statement)).await,
        Err(CustodyRefusal::NotReleasable)
    ));
}
