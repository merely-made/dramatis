// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

fn admit(authority: &AppAuthority, call: &CustodyCall) -> Result<(), CustodyRefusal> {
    call.admitted_by(authority)
}

#[test]
fn a_call_and_its_answer_round_trip_as_json() {
    let call = CustodyCall::Release {
        source: KeySource::Persona,
        salts: vec![b"mesh-author".to_vec()],
    };
    let text = serde_json::to_string(&call).unwrap();
    assert_eq!(serde_json::from_str::<CustodyCall>(&text).unwrap(), call);

    let status = CustodyAnswer::Status(ResidentStatus {
        custody_epoch: None,
        lock: VaultLockView::Locked,
        protection: VaultProtectionView::Ephemeral,
        profile: Some(ProfileId("default".into())),
        persona_public_key: None,
        wallet_public_key: Some([3; 32]),
        wallet_root: None,
    });
    let text = serde_json::to_string(&status).unwrap();
    assert_eq!(
        serde_json::from_str::<CustodyAnswer>(&text).unwrap(),
        status
    );
}

#[test]
fn a_released_seed_never_prints() {
    let provider = personae::InMemoryProvider::from_seed([9; 32]);
    let key = ReleasedKey {
        salt: b"mesh-author".to_vec(),
        seed: [0x5a; 32],
        attestation: personae::IdentityProvider::attest_derived_key(&provider, b"mesh-author")
            .unwrap(),
    };
    assert!(!format!("{key:?}").contains("90"));
}

#[test]
fn an_epoch_release_round_trips_and_never_prints_its_key() {
    let call = CustodyCall::ReleaseEpochKeys {
        persona: Uuid::from_u128(7),
        device_label: Some("study".into()),
        keys: vec![EpochKeyRequest::secret("ctx", true)],
    };
    let text = serde_json::to_string(&call).unwrap();
    assert_eq!(serde_json::from_str::<CustodyCall>(&text).unwrap(), call);
    let answer = CustodyAnswer::EpochKeys {
        keys: vec![ReleasedEpochKey {
            request: EpochKeyRequest::public("ctx", false),
            key: [0x5a; 32],
        }],
    };
    let text = serde_json::to_string(&answer).unwrap();
    assert_eq!(
        serde_json::from_str::<CustodyAnswer>(&text).unwrap(),
        answer
    );
    assert!(!format!("{answer:?}").contains("90"));
}

#[test]
fn a_declared_app_is_refused_what_it_did_not_declare_or_was_not_granted() {
    use ostiary::app_admission::AppId;
    use ostiary::declaration::{AppDeclaration, AppGrant, CustodyUse, EpochUse, NamePattern};
    let declaration = AppDeclaration {
        custody: CustodyUse {
            operations: [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys].into(),
            epoch: vec![EpochUse::secret("app.vault", false)],
            ..CustodyUse::default()
        },
        ..AppDeclaration::default()
    };
    let mut grant = AppGrant::new(AppId::new("app"));
    grant.custody.operations = [
        CustodyOperation::Status,
        CustodyOperation::ReleaseEpochKeys,
        CustodyOperation::LockVault,
    ]
    .into();
    grant.custody.epoch = vec![NamePattern::prefix("app.")];
    let authority = AppAuthority::new(declaration, grant);
    let release = |context: &str| CustodyCall::ReleaseEpochKeys {
        persona: Uuid::from_u128(7),
        device_label: None,
        keys: vec![EpochKeyRequest::secret(context, false)],
    };
    assert!(admit(&authority, &CustodyCall::Status).is_ok());
    assert!(
        admit(
            &authority,
            &CustodyCall::AsProfile {
                profile: ProfileId("p".into()),
                inner: Box::new(CustodyCall::Status),
            }
        )
        .is_ok()
    );
    assert!(admit(&authority, &release("app.vault")).is_ok());
    assert!(matches!(
        admit(&authority, &CustodyCall::LockVault),
        Err(CustodyRefusal::Undeclared { .. })
    ));
    assert!(matches!(
        admit(&authority, &release("app.other")),
        Err(CustodyRefusal::Undeclared { .. })
    ));
    let mut salted = AppDeclaration::default();
    salted.custody.operations = [CustodyOperation::Release, CustodyOperation::Sign].into();
    salted.custody.salts = vec![ostiary::declaration::SaltUse::persona(
        ostiary::declaration::SaltPattern::Prefix("app.place.".into()),
    )];
    let mut salt_grant = AppGrant::new(AppId::new("app"));
    salt_grant.custody.operations = salted.custody.operations.clone();
    salt_grant.custody.salts = salted.custody.salts.clone();
    let salted = AppAuthority::new(salted, salt_grant);
    let release = |salt: &[u8]| CustodyCall::Release {
        source: KeySource::Persona,
        salts: vec![b"app.place.a".to_vec(), salt.to_vec()],
    };
    assert!(admit(&salted, &release(b"app.place.b")).is_ok());
    assert!(
        matches!(
            admit(&salted, &release(b"other")),
            Err(CustodyRefusal::Undeclared { .. })
        ),
        "every salt in a release is checked"
    );
    assert!(
        admit(
            &salted,
            &CustodyCall::Sign {
                source: KeySource::Persona,
                salt: b"app.place.a".to_vec(),
                message: vec![]
            }
        )
        .is_ok()
    );
    assert!(matches!(
        admit(
            &salted,
            &CustodyCall::Sign {
                source: KeySource::Wallet,
                salt: b"app.place.a".to_vec(),
                message: vec![]
            }
        ),
        Err(CustodyRefusal::Undeclared { .. })
    ));
    let refusal = admit(&authority, &CustodyCall::Roster).unwrap_err();
    assert_eq!(
        refusal,
        CustodyRefusal::Undeclared {
            what: "the custody operation roster".into()
        }
    );
    let text = serde_json::to_string(&refusal).unwrap();
    assert_eq!(
        serde_json::from_str::<CustodyRefusal>(&text).unwrap(),
        refusal
    );
}

#[test]
fn the_delegation_scope_prefix_is_insignes() {
    for domain in ["moot", "mere.knot", "mere.graphshell", ""] {
        assert_eq!(
            ostiary::declaration::delegation_scope_prefix(domain),
            insigne::delegation::delegation_signing_prefix(domain)
        );
    }
}
