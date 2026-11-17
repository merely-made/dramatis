// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Sign as an untrusted custodian and count what a pinned client sends.
//! No peer lookup after EOF: the rejecting client may already have exited.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    let path = std::env::args().nth(1).ok_or("usage: macos_wrong_server SOCKET")?;
    let listener = UnixListener::bind(&path)?;
    println!("listening");
    std::io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut bytes = [0u8; 1];
    let count = stream.read(&mut bytes)?;
    println!("{{\"bytes\":{count}}}");
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This receiving fixture requires macOS.");
    std::process::exit(2);
}
