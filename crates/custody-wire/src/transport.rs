// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The transport trait the contract runs over, and its two OS transports:
//! a Unix-domain socket (0600, or a systemd-activated socket owned by the
//! desktop user at 0600) and a Windows named pipe whose DACL admits only
//! the vault owner and whose peers are checked by token SID. Each accepted
//! or connected stream carries its OS-established [`Peer`]. Blocking I/O
//! with a watchdog that shuts the stream down replaces read timeouts, so
//! one deadline mechanism serves both platforms.

use std::io::{Read, Write};

use crate::peer::Peer;

/// One full-duplex local stream.
pub trait Duplex: Read + Write + Send + Sync {
    /// A second handle on the same stream, for a reader thread.
    fn try_clone_duplex(&self) -> std::io::Result<Box<dyn Duplex>>;
    /// End both directions now; a blocked read on any handle returns.
    fn shutdown_both(&self);
}

/// An accepted or connected stream and who is on the other end.
pub struct Connection {
    pub stream: Box<dyn Duplex>,
    pub peer: Peer,
}

/// The server side: accept one connection at a time.
pub trait Listener: Send {
    fn accept(&self) -> std::io::Result<Connection>;
}

/// The client side: connect, reporting the server's OS identity.
pub trait Connector: Send + Sync {
    fn connect(&self) -> std::io::Result<Connection>;
}

#[cfg(unix)]
pub use unix::{UnixSocketConnector, UnixSocketListener};

#[cfg(unix)]
mod unix {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use super::{Connection, Connector, Duplex, Listener};
    use crate::peer::{effective_uid, unix_peer};

    impl Duplex for UnixStream {
        fn try_clone_duplex(&self) -> std::io::Result<Box<dyn Duplex>> {
            Ok(Box::new(self.try_clone()?))
        }

        fn shutdown_both(&self) {
            let _ = self.shutdown(std::net::Shutdown::Both);
        }
    }

    /// A Unix-domain listener at an owner-only path.
    pub struct UnixSocketListener {
        listener: UnixListener,
        path: Option<PathBuf>,
        signed: Vec<crate::peer::SignedIdentity>,
    }

    impl UnixSocketListener {
        /// Bind `path` at 0600. A stale socket owned by this user with no
        /// listener is replaced; anything else at the path is refused, so a
        /// second custodian fails loudly instead of orphaning the first.
        pub fn bind(path: &Path) -> std::io::Result<Self> {
            if let Some(parent) = path.parent() {
                let meta = std::fs::metadata(parent)?;
                if meta.uid() != effective_uid() || meta.mode() & 0o022 != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "the socket directory must be owned by the custodian and not group- or world-writable",
                    ));
                }
            }
            match std::fs::symlink_metadata(path) {
                Ok(meta) => {
                    if !meta.file_type().is_socket() || meta.uid() != effective_uid() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "the endpoint path holds something other than this user's socket",
                        ));
                    }
                    match UnixStream::connect(path) {
                        Ok(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AddrInUse,
                                "another custodian serves this endpoint",
                            ));
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                            std::fs::remove_file(path)?;
                        },
                        Err(error) => return Err(error),
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
            let listener = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                listener,
                path: Some(path.to_path_buf()),
                signed: Vec::new(),
            })
        }

        /// On macOS, report a peer satisfying one of these signing
        /// requirements as that signed identity rather than its uid.
        pub fn with_signed(mut self, signed: Vec<crate::peer::SignedIdentity>) -> Self {
            self.signed = signed;
            self
        }

        /// The socket systemd passed (`LISTEN_PID`/`LISTEN_FDS`, fd 3), if
        /// this process was socket-activated. The unit owns its path and
        /// mode; the custodian does not need to reach the path at all.
        pub fn from_systemd() -> std::io::Result<Option<Self>> {
            let pid_matches = std::env::var("LISTEN_PID")
                .ok()
                .and_then(|pid| pid.parse::<u32>().ok())
                == Some(std::process::id());
            let one_fd = std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
            if !pid_matches || !one_fd {
                return Ok(None);
            }
            const SD_LISTEN_FDS_START: i32 = 3;
            let mut kind: libc::c_int = 0;
            let mut accepting: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: valid out-pointers of the stated sizes on an fd systemd
            // promised to this pid.
            let ok = unsafe {
                libc::getsockopt(SD_LISTEN_FDS_START, libc::SOL_SOCKET, libc::SO_TYPE, (&mut kind as *mut libc::c_int).cast(), &mut len) == 0
                    && libc::getsockopt(SD_LISTEN_FDS_START, libc::SOL_SOCKET, libc::SO_ACCEPTCONN, (&mut accepting as *mut libc::c_int).cast(), &mut len) == 0
                    && libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            };
            if !ok || kind != libc::SOCK_STREAM || accepting == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the activated descriptor is not a listening stream socket",
                ));
            }
            // SAFETY: systemd transferred ownership of fd 3 to this process.
            let listener = unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };
            Ok(Some(Self {
                listener,
                path: None,
                signed: Vec::new(),
            }))
        }

        /// Every socket systemd passed, by `FileDescriptorName` (`LISTEN_FDNAMES`),
        /// for a unit that listens on more than one.
        pub fn systemd_named() -> std::io::Result<Vec<(String, UnixListener)>> {
            let pid_matches = std::env::var("LISTEN_PID").ok().and_then(|pid| pid.parse::<u32>().ok()) == Some(std::process::id());
            let count = std::env::var("LISTEN_FDS").ok().and_then(|n| n.parse::<i32>().ok()).unwrap_or(0);
            if !pid_matches || !(1..=8).contains(&count) {
                return Ok(Vec::new());
            }
            let names: Vec<String> = std::env::var("LISTEN_FDNAMES").unwrap_or_default().split(':').map(str::to_string).collect();
            let mut listeners = Vec::new();
            for index in 0..count {
                let fd = 3 + index;
                // SAFETY: systemd transferred these descriptors to this pid.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                // SAFETY: as above; each descriptor is taken exactly once.
                let listener = unsafe { UnixListener::from_raw_fd(fd) };
                listeners.push((names.get(index as usize).cloned().unwrap_or_default(), listener));
            }
            Ok(listeners)
        }

        /// Wrap an already-bound listener (tests).
        pub fn from_listener(listener: UnixListener) -> Self {
            Self {
                listener,
                path: None,
                signed: Vec::new(),
            }
        }
    }

    impl Drop for UnixSocketListener {
        fn drop(&mut self) {
            if let Some(path) = &self.path {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    impl Listener for UnixSocketListener {
        fn accept(&self) -> std::io::Result<Connection> {
            loop {
                let (stream, _) = self.listener.accept()?;
                // A client that cannot be identified is dropped, not the listener.
                match identify(stream.as_raw_fd(), &self.signed) {
                    Ok(peer) => {
                        return Ok(Connection {
                            stream: Box::new(stream),
                            peer,
                        });
                    }
                    Err(error) => eprintln!("djinn-custodian: refused an unidentified socket client: {error}"),
                }
            }
        }
    }

    fn identify(fd: std::os::fd::RawFd, signed: &[crate::peer::SignedIdentity]) -> std::io::Result<crate::peer::Peer> {
        #[cfg(target_os = "macos")]
        if let Some(peer) = crate::peer::signed_peer(fd, signed) {
            return Ok(peer);
        }
        let _ = signed;
        unix_peer(fd)
    }

    /// Connect to a custodian's Unix-domain socket.
    pub struct UnixSocketConnector {
        path: PathBuf,
        signed: Vec<crate::peer::SignedIdentity>,
    }

    impl UnixSocketConnector {
        pub fn new(path: impl Into<PathBuf>) -> Self {
            Self {
                path: path.into(),
                signed: Vec::new(),
            }
        }

        /// On macOS, identify a server satisfying one of these signing
        /// requirements by that identity.
        pub fn with_signed(mut self, signed: Vec<crate::peer::SignedIdentity>) -> Self {
            self.signed = signed;
            self
        }
    }

    impl Connector for UnixSocketConnector {
        fn connect(&self) -> std::io::Result<Connection> {
            let stream = UnixStream::connect(&self.path)?;
            let peer = identify(stream.as_raw_fd(), &self.signed)?;
            Ok(Connection {
                stream: Box::new(stream),
                peer,
            })
        }
    }
}

#[cfg(windows)]
pub use windows::{NamedPipeConnector, NamedPipeListener, admit_identification, impersonated_client_sid};

#[cfg(windows)]
pub(crate) mod windows;
