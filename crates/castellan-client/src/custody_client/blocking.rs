// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// [`CustodyClient`] on its own current-thread runtime, for synchronous
/// callers. Never call it from inside a tokio runtime.
pub struct BlockingCustodyClient {
    runtime: tokio::runtime::Runtime,
    client: CustodyClient,
    timeout: Option<std::time::Duration>,
}

fn deadline_error() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "custody operation deadline elapsed",
    )))
}

impl BlockingCustodyClient {
    /// Bound connection, handshake and one read-only status operation together.
    /// The client is dropped on timeout so a late frame can never answer a later
    /// request on a reused sequential connection. Call outside a Tokio runtime.
    pub fn status_at_timeout(
        endpoint: &str,
        app: AppId,
        profile: Option<ProfileId>,
        timeout: std::time::Duration,
    ) -> Result<ResidentStatus, CustodyClientError> {
        Self::status_at_timeout_with(endpoint, app, None, profile, timeout)
    }

    /// [`Self::status_at_timeout`], carrying `declaration` when there is one.
    pub fn status_at_timeout_with(
        endpoint: &str,
        app: AppId,
        declaration: Option<AppDeclaration>,
        profile: Option<ProfileId>,
        timeout: std::time::Duration,
    ) -> Result<ResidentStatus, CustodyClientError> {
        expect_status(Self::call_at_timeout_with(
            endpoint,
            app,
            declaration,
            profile,
            CustodyCall::Status,
            timeout,
        )?)
    }

    /// One bounded independent conversation. Timeout discards its transport;
    /// callers decide uncertainty/reconciliation and this never retries a call.
    pub fn call_at_timeout(
        endpoint: &str,
        app: AppId,
        profile: Option<ProfileId>,
        call: CustodyCall,
        timeout: std::time::Duration,
    ) -> Result<CustodyAnswer, CustodyClientError> {
        Self::call_at_timeout_with(endpoint, app, None, profile, call, timeout)
    }

    /// [`Self::call_at_timeout`], carrying `declaration` when there is one.
    pub fn call_at_timeout_with(
        endpoint: &str,
        app: AppId,
        declaration: Option<AppDeclaration>,
        profile: Option<ProfileId>,
        call: CustodyCall,
        timeout: std::time::Duration,
    ) -> Result<CustodyAnswer, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        runtime.block_on(async {
            tokio::time::timeout(timeout, async {
                let mut client = CustodyClient::open_at_with(endpoint, app, declaration).await?;
                client.speak_as(profile);
                client.call(call).await
            })
            .await
            .map_err(|_| {
                CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "custody status deadline elapsed",
                )))
            })?
        })
    }

    /// Connect to the configured first-party endpoint as `app`.
    pub fn open(app: AppId) -> Result<Self, CustodyClientError> {
        Self::open_at(&configured_app_endpoint(), app)
    }

    /// The same, at an explicit endpoint.
    pub fn open_at(endpoint: &str, app: AppId) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(CustodyClient::open_at(endpoint, app))?;
        Ok(Self {
            runtime,
            client,
            timeout: None,
        })
    }

    /// Connect to the configured endpoint as `app`, carrying its declaration.
    pub fn open_declared(
        app: AppId,
        declaration: AppDeclaration,
    ) -> Result<Self, CustodyClientError> {
        Self::open_declared_at(&configured_app_endpoint(), app, declaration)
    }

    /// The same, at an explicit endpoint.
    pub fn open_declared_at(
        endpoint: &str,
        app: AppId,
        declaration: AppDeclaration,
    ) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(CustodyClient::open_at_with(
            endpoint,
            app,
            Some(declaration),
        ))?;
        Ok(Self {
            runtime,
            client,
            timeout: None,
        })
    }

    /// Bounded transport for a provider whose actor must be joinable. Every
    /// later call also has this deadline; a transport timeout retires the client.
    pub fn open_at_timeout(
        endpoint: &str,
        app: AppId,
        timeout: std::time::Duration,
    ) -> Result<Self, CustodyClientError> {
        Self::open_at_timeout_with(endpoint, app, None, timeout)
    }

    /// [`Self::open_at_timeout`], carrying `declaration` when there is one.
    pub fn open_at_timeout_with(
        endpoint: &str,
        app: AppId,
        declaration: Option<AppDeclaration>,
        timeout: std::time::Duration,
    ) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(async {
            tokio::time::timeout(
                timeout,
                CustodyClient::open_at_with(endpoint, app, declaration),
            )
            .await
            .map_err(|_| deadline_error())?
        })?;
        Ok(Self {
            runtime,
            client,
            timeout: Some(timeout),
        })
    }

    pub(crate) fn set_call_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.timeout = timeout;
    }

    /// See [`CustodyClient::speak_as`].
    pub fn speak_as(&mut self, profile: Option<ProfileId>) {
        self.client.speak_as(profile);
    }

    /// One raw call.
    pub fn call(&mut self, call: CustodyCall) -> Result<CustodyAnswer, CustodyClientError> {
        match self.timeout {
            Some(timeout) => self.runtime.block_on(async {
                tokio::time::timeout(timeout, self.client.call(call))
                    .await
                    .map_err(|_| deadline_error())?
            }),
            None => self.runtime.block_on(self.client.call(call)),
        }
    }

    /// See [`CustodyClient::status`].
    pub fn status(&mut self) -> Result<ResidentStatus, CustodyClientError> {
        expect_status(self.call(CustodyCall::Status)?)
    }

    /// See [`CustodyClient::roster`].
    pub fn roster(&mut self) -> Result<Roster, CustodyClientError> {
        expect_roster(self.call(CustodyCall::Roster)?)
    }

    /// See [`CustodyClient::release`].
    pub fn release(
        &mut self,
        source: KeySource,
        salts: Vec<Vec<u8>>,
    ) -> Result<RetainedKeys, CustodyClientError> {
        expect_released(self.call(CustodyCall::Release { source, salts })?)
    }

    /// See [`CustodyClient::attest`].
    pub fn attest(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
    ) -> Result<DerivedKeyAttestation, CustodyClientError> {
        expect_attestation(self.call(CustodyCall::Attest { source, salt })?)
    }

    /// See [`CustodyClient::sign`].
    pub fn sign(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<([u8; 32], Vec<u8>), CustodyClientError> {
        expect_signature(self.call(CustodyCall::Sign {
            source,
            salt,
            message,
        })?)
    }

    /// See [`CustodyClient::issue_station_grant`].
    pub fn issue_station_grant(
        &mut self,
        request: StationGrantRequest,
        issuer_public_key: [u8; 32],
    ) -> Result<DeviceGrantSet, CustodyClientError> {
        expect_grant(self.call(CustodyCall::IssueStationGrant {
            request,
            issuer_public_key,
        })?)
    }

    /// See [`CustodyClient::release_epoch_keys`].
    pub fn release_epoch_keys(
        &mut self,
        persona: uuid::Uuid,
        device_label: Option<String>,
        keys: Vec<EpochKeyRequest>,
    ) -> Result<Vec<ReleasedEpochKey>, CustodyClientError> {
        expect_epoch_keys(self.call(CustodyCall::ReleaseEpochKeys {
            persona,
            device_label,
            keys,
        })?)
    }

    /// See [`CustodyClient::revoke_device`].
    pub fn revoke_device(
        &mut self,
        device_id: DeviceId,
    ) -> Result<RemoteAuthRevocationOutcome, CustodyClientError> {
        expect_revoked(self.call(CustodyCall::RevokeDevice {
            device_id: *device_id.as_uuid(),
        })?)
    }
}
