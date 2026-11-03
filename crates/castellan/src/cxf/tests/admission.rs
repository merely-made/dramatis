// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[test]
fn account_choices_are_complete_before_writes_and_cross_persona_links_are_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let (host, resident) = fixture(dir.path());
    let left = PersonaId::new();
    let right = PersonaId::new();
    let input = || {
        document(vec![
            account(
                "YQ",
                vec![item(
                    "aQ",
                    "Left",
                    vec![
                        json!({"type":"note","content":field(SECRET)}),
                        json!({"type":"item-reference","reference":{"account":"Yg","item":"ag"}}),
                    ],
                )],
            ),
            account(
                "Yg",
                vec![item(
                    "ag",
                    "Right",
                    vec![json!({"type":"note","content":field(SECRET)})],
                )],
            ),
        ])
    };
    let failed = Import::read(input())
        .unwrap()
        .commit(choices(&["YQ"], left), &resident, &host)
        .unwrap_err();
    assert_eq!(failed.receipt.items, 0);
    assert!(resident.items(left).list().unwrap().is_empty());
    let mut destinations = choices(&["YQ"], left);
    destinations.extend(choices(&["Yg"], right));
    let receipt = Import::read(input())
        .unwrap()
        .commit(destinations, &resident, &host)
        .unwrap();
    assert!(
        receipt
            .notices
            .iter()
            .any(|n| n.reason == "cross-persona link omitted")
    );
    assert!(
        !resident.items(left).list().unwrap()[0]
            .credentials
            .iter()
            .any(|c| matches!(c.kind, CredentialKind::ItemReference(_)))
    );
    let same = PersonaId::new();
    let receipt = Import::read(input())
        .unwrap()
        .commit(choices(&["YQ", "Yg"], same), &resident, &host)
        .unwrap();
    assert!(
        !receipt
            .notices
            .iter()
            .any(|n| n.reason == "cross-persona link omitted")
    );
    assert!(
        resident
            .items(same)
            .list()
            .unwrap()
            .iter()
            .flat_map(|i| &i.credentials)
            .any(|c| matches!(c.kind, CredentialKind::ItemReference(_)))
    );
}

#[test]
fn invalid_version_or_missing_string_type_refuses_the_document() {
    let mut v: Value = serde_json::from_slice(&document(vec![account("YQ", vec![])])).unwrap();
    v["version"]["major"] = json!(2);
    assert!(Import::read(serde_json::to_vec(&v).unwrap()).is_err());
    for credential in [json!({}), json!({"type":17})] {
        assert!(
            Import::read(document(vec![account(
                "YQ",
                vec![item("aQ", "Bad", vec![credential])]
            )]))
            .is_err()
        );
    }
}

#[test]
fn custom_fields_are_recovered_element_by_element_and_known_extra_fields_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (host, resident) = fixture(dir.path());
    let persona = PersonaId::new();
    let input = document(vec![account(
        "YQ",
        vec![item(
            "aQ",
            "Fields",
            vec![
                json!({"type":"custom-fields","label":"Section","fields":[{"fieldType":"string","label":"Good","value":SECRET},{"fieldType":"future-field","value":SECRET},{"fieldType":"date","value":"nonsense"}]}),
                json!({"type":"generated-password","password":SECRET,"futureField":SECRET}),
            ],
        )],
    )]);
    let import = Import::read(input).unwrap();
    assert_eq!(import.preview().accounts[0].dispositions["stored"], 2);
    assert_eq!(import.preview().notices.len(), 2);
    import
        .commit(choices(&["YQ"], persona), &resident, &host)
        .unwrap();
    let store = resident.items(persona);
    let item = store.list().unwrap().remove(0);
    assert!(item.credentials.iter().any(|c|matches!(&c.kind,CredentialKind::CustomFields{field_labels,..} if field_labels==&vec![Some("Good".into())])));
    let password = item
        .credentials
        .iter()
        .find(|c| matches!(c.kind, CredentialKind::GeneratedPassword))
        .unwrap();
    let payload: Value = SealedRecordStorage::open_with_key(dir.path().join("records"), [0x61; 32])
        .load_record(store.payload_path(password.id))
        .unwrap()
        .unwrap();
    let bytes: Vec<u8> =
        serde_json::from_value(payload["payload"]["Secret"]["bytes"].clone()).unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("futureField"));
}

#[tokio::test]
async fn pkcs8_keys_join_native_slots_preserve_existing_keys_and_reimport_is_a_noop() {
    use crate::custody::{IdentitySlot, ssh_slot};
    use dramatis::intents::{ImportSshKeyNativeIntentV1, SshUnlockPolicyIntentV1};
    use signature::Verifier;
    use ssh_agent_lib::agent::Session;
    use ssh_agent_lib::proto::SignRequest;
    let dir = tempfile::tempdir().unwrap();
    let (host, resident) = fixture(dir.path());
    let persona = PersonaId::new();
    let existing: ssh_key::PrivateKey =
        ssh_key::private::Ed25519Keypair::from(ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]))
            .into();
    let existing_key = ssh_slot::protocol_key_for(&existing);
    host.import_ssh_private(
        existing,
        ImportSshKeyNativeIntentV1 {
            unlock_policy: SshUnlockPolicyIntentV1::Session,
        },
    )
    .unwrap();
    let load = || {
        SealedProfileStorage::open_with_key(dir.path().join("vault"), [0x29; 32])
            .load_profile(&ProfileId("family".into()))
            .unwrap()
    };
    let slot_bytes = |profile: &Profile| match &profile.slots[&existing_key] {
        IdentitySlot::Direct { payload, .. } => payload.as_slice().to_vec(),
        _ => panic!("native SSH slot"),
    };
    let before = slot_bytes(&load());
    let ed = ed25519_dalek::SigningKey::from_bytes(&[0x41; 32])
        .to_pkcs8_der()
        .unwrap();
    let rsa = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let p256 = p256::SecretKey::from_slice(&[0x12; 32])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let p384 = p384::SecretKey::from_slice(&[0x13; 48])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let credentials=vec![("ssh-ed25519",ed),("ssh-rsa",rsa),("ecdsa-sha2-nistp256",p256),("ecdsa-sha2-nistp384",p384)].into_iter().map(|(algorithm,der)|json!({"type":"ssh-key","keyType":algorithm,"privateKey":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.as_bytes()),"keyComment":"Imported"})).collect();
    let input = document(vec![account("YQ", vec![item("aQ", "SSH", credentials)])]);
    let first = Import::read(input.clone())
        .unwrap()
        .commit(choices(&["YQ"], persona), &resident, &host)
        .unwrap();
    assert_eq!(first.ssh_keys, 4);
    assert_eq!(first.items, 0);
    assert_eq!(slot_bytes(&load()), before);
    let files_before = file_bytes(&dir.path().join("vault"));
    let mut agent = host.agent_session();
    let identities = agent.request_identities().await.unwrap();
    assert_eq!(
        identities
            .iter()
            .filter(|identity| matches!(
                identity.credential,
                ssh_agent_lib::proto::PublicCredential::Key(_)
            ))
            .count(),
        5
    );
    assert_eq!(
        identities
            .iter()
            .filter(|identity| matches!(
                identity.credential,
                ssh_agent_lib::proto::PublicCredential::Cert(_)
            ))
            .count(),
        5
    );
    for identity in identities {
        let public = identity.credential.key_data().clone();
        let flags = if matches!(public, ssh_key::public::KeyData::Rsa(_)) {
            2
        } else {
            0
        };
        let signature = agent
            .sign(SignRequest {
                credential: identity.credential,
                data: b"CXF signing receipt".to_vec(),
                flags,
            })
            .await
            .unwrap();
        assert!(public.verify(b"CXF signing receipt", &signature).is_ok());
    }
    let mut repeat_choices = choices(&["YQ"], persona);
    repeat_choices.get_mut("YQ").unwrap().ssh_unlock_policy = SshUnlockPolicyIntentV1::PerUse;
    Import::read(input)
        .unwrap()
        .commit(repeat_choices, &resident, &host)
        .unwrap();
    assert_eq!(slot_bytes(&load()), before);
    assert_eq!(file_bytes(&dir.path().join("vault")), files_before);
}
