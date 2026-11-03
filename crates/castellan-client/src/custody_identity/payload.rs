// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl CustodyIdentity {
    pub(super) fn invalidate_binding(&self) {
        invalidate_epoch(&self.locked, &self.epoch);
        self.held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(super) fn status_matches_binding(&self, status: &ResidentStatus) -> bool {
        status.lock == VaultLockView::Unlocked
            && status.profile == self.status.profile
            && status.persona_public_key == Some(self.master.to_bytes())
            && status.custody_epoch == self.status.custody_epoch
    }

    pub(super) fn check_fresh_payload_binding(&self, timeout: Duration) -> eidetic::Result<()> {
        let status = self.status_timeout(timeout);
        if status
            .as_ref()
            .is_ok_and(|status| self.status_matches_binding(status))
            && self.custody_epoch().is_some()
        {
            return Ok(());
        }
        self.invalidate_binding();
        Err(eidetic::Error::new(
            "custody binding unavailable or changed",
        ))
    }

    pub(super) fn retained_payload(
        &self,
        hash: &eidetic::Hash,
        operation: super::super::custody_payload::PayloadOperation,
    ) -> eidetic::Result<super::super::custody_payload::PayloadResult> {
        self.pending()
            .map_err(|e| eidetic::Error::new(e.to_string()))?;
        let request = super::super::custody_payload::PayloadRequest {
            profile: self.profile().cloned().ok_or_else(|| {
                eidetic::Error::new("custody disclosed no retained-content profile")
            })?,
            master: self.master.to_bytes(),
            content_hash: *hash,
            custody_epoch: self.status.custody_epoch.clone(),
            operation,
        };
        request.validate().map_err(eidetic::Error::new)?;
        let timeout = self.call_timeout.unwrap_or(Duration::from_secs(5));
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| eidetic::Error::new("custody deadline invalid"))?;
        let local_epoch = self
            .custody_epoch()
            .ok_or_else(|| eidetic::Error::new("custody binding unavailable"))?;
        let remaining = || deadline.saturating_duration_since(Instant::now());
        if request.custody_epoch.is_some() {
            self.check_fresh_payload_binding(remaining())?;
        }
        let endpoint = self.endpoint.clone();
        let app = self.app.clone();
        let declaration = self.declaration.clone();
        let profile = self.requested_profile.clone();
        let payload_timeout = remaining();
        let result = bounded_worker(move || {
            match BlockingCustodyClient::call_at_timeout_with(
                &endpoint,
                app,
                declaration,
                profile,
                CustodyCall::Payload(request),
                payload_timeout,
            ) {
                Ok(CustodyAnswer::Payload { result }) => Ok(result),
                Ok(_) => Err(CustodyClientError::UnexpectedAnswer {
                    asked: "retained payload",
                    got: "another operation",
                }),
                Err(error) => Err(error),
            }
        });
        if self.status.custody_epoch.is_some() {
            self.check_fresh_payload_binding(remaining())?;
        }
        if self.custody_epoch() != Some(local_epoch) {
            return Err(eidetic::Error::new(
                "custody binding changed during payload",
            ));
        }
        result.map_err(|e| eidetic::Error::new(e.to_string()))
    }
}
