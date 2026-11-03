// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// The wire receipt: lock by message 22 over an isolated pipe, message 23
/// refused, then a native unlock restores the same identities, a verifying
/// signature, and byte-identical items.
#[cfg(windows)]
#[tokio::test]
async fn over_an_isolated_pipe_the_agent_locks_by_the_wire_and_unlocks_only_natively() {
    use signature::Verifier;
    use ssh_agent_lib::client::Client;
    use tokio::net::windows::named_pipe::ClientOptions;

    let dir = tempdir().unwrap();
    let fixture = lockable(dir.path());
    let persona = PersonaId::new();
    fixture
        .resident
        .otp_items(persona)
        .import_otpauth_uri(TOTP)
        .unwrap();
    let items = || serde_json::to_vec(&fixture.resident.items(persona).list().unwrap()).unwrap();
    let items_before = items();

    let endpoint = format!(r"\\.\pipe\castellan-lock-receipt-{}", Uuid::new_v4());
    let listener = fixture.host.bind_receipt_listener(&endpoint).unwrap();
    let server = tokio::spawn(ssh_agent_lib::agent::listen(
        listener,
        fixture.host.agent_session(),
    ));
    let mut client = Client::new(ClientOptions::new().open(&endpoint).unwrap());
    let public = PublicKey::from(&fixture.key);
    let listed = client.request_identities().await.unwrap();
    assert_eq!(listed.len(), 2);
    sign_over(&mut client, &public).await.unwrap();

    client.lock(String::from("pw")).await.unwrap();
    assert!(fixture.host.is_locked() && fixture.resident.is_locked());
    assert!(client.request_identities().await.unwrap().is_empty());
    assert!(sign_over(&mut client, &public).await.is_err());
    assert!(client.unlock(String::from("pw")).await.is_err());
    assert!(
        client.lock(String::from("pw")).await.is_err(),
        "already locked"
    );
    assert!(fixture.host.is_locked());

    unlock(&fixture.host);
    let again = client.request_identities().await.unwrap();
    assert_eq!(
        again
            .iter()
            .map(|i| i.credential.key_data())
            .collect::<Vec<_>>(),
        listed
            .iter()
            .map(|i| i.credential.key_data())
            .collect::<Vec<_>>()
    );
    let signature = sign_over(&mut client, &public).await.unwrap();
    public
        .key_data()
        .verify(b"lock receipt", &signature)
        .unwrap();
    assert_eq!(items(), items_before);

    server.abort();
    let _ = server.await;
}

#[cfg(windows)]
async fn sign_over(
    client: &mut impl Session,
    public: &PublicKey,
) -> Result<ssh_key::Signature, ssh_agent_lib::error::AgentError> {
    client
        .sign(SignRequest {
            credential: public.key_data().clone().into(),
            data: b"lock receipt".to_vec(),
            flags: 0,
        })
        .await
}
