// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<S: IdentityStorage + 'static> PersonaeHost<S> {
    /// Bind an isolated Windows named pipe for acceptance testing.
    ///
    /// The standard OpenSSH endpoint is rejected here. Taking it over requires
    /// a separate cutover path with restart and real-login receipts.
    #[cfg(windows)]
    pub fn bind_receipt_listener(
        &self,
        endpoint: &str,
    ) -> std::io::Result<ssh_agent_lib::agent::NamedPipeListener> {
        if endpoint.eq_ignore_ascii_case(STANDARD_WINDOWS_AGENT_ENDPOINT) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "receipt listener cannot bind the standard SSH agent endpoint",
            ));
        }
        let listener = ssh_agent_lib::agent::NamedPipeListener::bind(endpoint)?;
        *self.listener.lock().unwrap() = AgentListenerView::ReceiptEndpoint {
            endpoint: endpoint.to_string(),
        };
        Ok(listener)
    }

    /// Bind an isolated Unix socket for acceptance testing.
    ///
    /// The user's own `SSH_AUTH_SOCK` is refused, as the OpenSSH pipe is on
    /// Windows: it belongs to the agent the user already runs.
    #[cfg(not(windows))]
    pub fn bind_receipt_listener(
        &self,
        endpoint: &str,
    ) -> std::io::Result<tokio::net::UnixListener> {
        if endpoint.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the receipt SSH agent socket path is empty",
            ));
        }
        if is_standard_unix_agent(endpoint) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "receipt listener cannot bind the standard SSH agent endpoint",
            ));
        }
        let listener = tokio::net::UnixListener::bind(endpoint)?;
        *self.listener.lock().unwrap() = AgentListenerView::ReceiptEndpoint {
            endpoint: endpoint.to_string(),
        };
        Ok(listener)
    }

    /// Bind the standard Windows OpenSSH endpoint for the resident host.
    ///
    /// This is deliberately distinct from [`Self::bind_receipt_listener`]:
    /// only a lifecycle-managed device host should call it.
    #[cfg(windows)]
    pub fn bind_standard_listener(
        &self,
        endpoint: &str,
    ) -> std::io::Result<ssh_agent_lib::agent::NamedPipeListener> {
        if !endpoint.eq_ignore_ascii_case(STANDARD_WINDOWS_AGENT_ENDPOINT) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the Windows standard listener must use the OpenSSH agent pipe",
            ));
        }
        let listener = ssh_agent_lib::agent::NamedPipeListener::bind(endpoint)?;
        *self.listener.lock().unwrap() = AgentListenerView::StandardEndpoint {
            endpoint: endpoint.to_string(),
        };
        Ok(listener)
    }

    /// Bind the configured Unix `SSH_AUTH_SOCK` for the resident host.
    #[cfg(not(windows))]
    pub fn bind_standard_listener(
        &self,
        endpoint: &str,
    ) -> std::io::Result<tokio::net::UnixListener> {
        if endpoint.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the standard SSH agent socket path is empty",
            ));
        }
        let listener = tokio::net::UnixListener::bind(endpoint)?;
        *self.listener.lock().unwrap() = AgentListenerView::StandardEndpoint {
            endpoint: endpoint.to_string(),
        };
        Ok(listener)
    }
}
