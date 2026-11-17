// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Native receiving fixture. Sign two copies with different certificates
//! and the same code identifier, then pair `listen` and `connect` on a
//! temporary socket. `observe` sends no bytes and can inspect a live peer.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use custody_wire::{Peer, ServerExpectation, SignedIdentity, peer};
    use custody_wire::transport::Connector;

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        return Err("usage: macos_certificate_peer listen|connect|observe|handshake SOCKET TEAM IDENTIFIER CERT-SHA1".into());
    }
    let identity = SignedIdentity {
        team: args[2].clone(),
        identifier: args[3].clone(),
        certificate_sha1: Some(args[4].clone()),
    };
    let expectation = ServerExpectation { signed: vec![identity.clone()], ..Default::default() };
    if args[0] == "handshake" {
        let connector = custody_wire::transport::UnixSocketConnector::new(&args[1]).with_signed(vec![identity]);
        let result = match connector.connect() {
            Ok(connection) => custody_wire::Client::over(connection, &expectation).map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        println!("{}", serde_json::json!({"hello_accepted": result.is_ok(),
            "error": result.err()}));
        return Ok(());
    }
    let (mut stream, listener) = if args[0] == "listen" {
        let listener = UnixListener::bind(&args[1])?;
        println!("listening");
        std::io::stdout().flush()?;
        let (stream, _) = listener.accept()?;
        (stream, Some(listener))
    } else if args[0] == "connect" || args[0] == "observe" {
        (UnixStream::connect(&args[1])?, None)
    } else {
        return Err("unknown fixture mode".into());
    };
    let unpinned = SignedIdentity {
        certificate_sha1: None, ..identity.clone()
    };
    let mut observed = peer::signed_peer(stream.as_raw_fd(), std::slice::from_ref(&unpinned))
        .unwrap_or(peer::unix_peer(stream.as_raw_fd())?);
    if matches!(observed, Peer::Unix { uid: 0, .. }) {
        // The manager hands its socket to the live service. Observe that
        // service before comparing two signature requirements on it.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Some(signed) = peer::signed_peer(stream.as_raw_fd(), std::slice::from_ref(&unpinned)) {
                observed = signed;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let pinned = peer::signed_peer(stream.as_raw_fd(), &[identity]);
    let accepted = expectation.admits(&observed);
    assert_eq!(accepted, pinned.is_some(), "OS certificate requirement and peer fact must agree");
    let mut bytes = 0;
    if args[0] == "connect" && accepted {
        // A public fixture byte, never a custody request or secret.
        if stream.write_all(&[1]).is_ok() { bytes = 1; }
    } else if args[0] == "listen" {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut byte = [0u8; 1];
        if let Ok(count) = stream.read(&mut byte) { bytes = count; }
    }
    println!("{}", serde_json::json!({
        "accepted": accepted, "peer": observed, "bytes": bytes,
        "signed_fact": matches!(pinned, Some(Peer::Signed { .. }))
    }));
    drop(stream);
    if listener.is_some() { std::fs::remove_file(&args[1])?; }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This receiving fixture requires macOS.");
    std::process::exit(2);
}
