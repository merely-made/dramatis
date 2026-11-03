// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

// Moved from the door client's tests (djinn-slimming S2): a custody
// release in an unexpected or mismatched answer leaks nothing.
use ostiary::app_admission::{AppHello, AppId};
use ostiary::app_client::{AppClientError, AppConnection};
use ostiary::frame::{read_native_message_async, write_native_message_async};
use ostiary::wire::{AppHostMessage, AppMessage, BrowserChallenge};

/// The host's side of the handshake, run before a test host's exchange.
async fn admit(server: &mut tokio::io::DuplexStream) {
    let hello: AppHello = read_native_message_async(server).await.unwrap().unwrap();
    let challenge = AppHostMessage::<(), (), ()>::Challenge {
        challenge: BrowserChallenge::fresh(),
    };
    write_native_message_async(server, &challenge)
        .await
        .unwrap();
    let _: AppMessage<(), ()> = read_native_message_async(server).await.unwrap().unwrap();
    let connected = AppHostMessage::<(), (), ()>::Connected {
        app: hello.app,
        session: "fixture".into(),
    };
    write_native_message_async(server, &connected)
        .await
        .unwrap();
}

async fn connection(client: tokio::io::DuplexStream) -> AppConnection {
    AppConnection::open_over(Box::new(client), AppHello::new(AppId::new("fixture")))
        .await
        .unwrap()
}

fn released_answer() -> crate::custody::CustodyAnswer {
    use crate::custody::{CustodyAnswer, ReleasedKey};
    use personae::IdentityProvider;
    let salt = b"test-release-key".to_vec();
    let provider = personae::InMemoryProvider::from_seed([9; 32]);
    let attestation = provider.attest_derived_key(&salt).unwrap();
    CustodyAnswer::Released {
        master: [0x5a; 32],
        keys: vec![ReleasedKey {
            salt,
            seed: [0x6b; 32],
            attestation,
        }],
    }
}

fn assert_release_secrets_absent(error: &AppClientError) {
    let sentinels = [
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
        "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
        "107, 107, 107",
        "90, 90, 90",
    ];
    let mut errors: Vec<&dyn std::error::Error> = vec![error];
    while let Some(cause) = errors.pop() {
        let description = format!("{cause:?} {cause}");
        for sentinel in sentinels {
            assert!(!description.contains(sentinel));
        }
        if let Some(source) = cause.source() {
            errors.push(source);
        }
    }
}

#[tokio::test]
async fn unexpected_real_custody_release_does_not_leak_in_error_chain() {
    use crate::custody::CustodyRefusal;
    let (client, mut server) = tokio::io::duplex(4096);
    let host = tokio::spawn(async move {
        admit(&mut server).await;
        let _: Option<AppMessage<String, ()>> =
            read_native_message_async(&mut server).await.unwrap();
        let answer = AppHostMessage::<(), (), _>::Answer {
            id: 1,
            answer: Ok::<_, CustodyRefusal>(released_answer()),
        };
        write_native_message_async(&mut server, &answer)
            .await
            .unwrap();
    });
    let mut connection = connection(client).await;
    let error = connection
        .request::<_, String, ()>("request")
        .await
        .unwrap_err();
    assert!(matches!(error, AppClientError::UnexpectedAnswer { .. }));
    assert_release_secrets_absent(&error);
    host.await.unwrap();
}

#[tokio::test]
async fn mismatched_custody_release_does_not_leak_key_material() {
    use crate::custody::{CustodyAnswer, CustodyRefusal};
    let (client, mut server) = tokio::io::duplex(4096);
    let host = tokio::spawn(async move {
        admit(&mut server).await;
        let call: AppMessage<(), String> = read_native_message_async(&mut server)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(call, AppMessage::Call { id: 1, .. }));
        let answer = AppHostMessage::<(), (), _>::Answer {
            id: 99,
            answer: Ok::<_, CustodyRefusal>(released_answer()),
        };
        write_native_message_async(&mut server, &answer)
            .await
            .unwrap();
    });
    let mut connection = connection(client).await;
    let error = connection
        .call::<_, Result<CustodyAnswer, CustodyRefusal>>("release")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AppClientError::MismatchedResponse {
            expected: 1,
            got: 99
        }
    ));
    assert_release_secrets_absent(&error);
    host.await.unwrap();
}
