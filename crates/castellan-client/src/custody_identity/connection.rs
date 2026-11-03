// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl CustodyIdentity {
    /// Connect to djinn at the configured first-party endpoint as `app`.
    /// Pending (see [`CustodyClientError::is_pending`]) when djinn is absent
    /// or Locked.
    pub fn connect(app: &str) -> Result<Self, CustodyClientError> {
        Self::connect_at(&configured_app_endpoint(), app)
    }

    /// A provider with bounded connection/status stages and bounded actor RPCs.
    /// Intended for cancellable off-thread setup; it never retries an operation.
    pub fn connect_timeout(app: &str, timeout: Duration) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(&configured_app_endpoint(), app, None, None, Some(timeout))
    }

    pub fn connect_at_timeout(
        endpoint: &str,
        app: &str,
        timeout: Duration,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, None, None, Some(timeout))
    }

    /// [`Self::connect_timeout`] carrying `declaration` on every conversation,
    /// so djinn answers only the custody it names and the owner grants.
    pub fn connect_declared_timeout(
        app: &str,
        declaration: AppDeclaration,
        timeout: Duration,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_declared_at_timeout(&configured_app_endpoint(), app, declaration, timeout)
    }

    /// [`Self::connect_declared_timeout`] at an explicit endpoint.
    pub fn connect_declared_at_timeout(
        endpoint: &str,
        app: &str,
        declaration: AppDeclaration,
        timeout: Duration,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, Some(declaration), None, Some(timeout))
    }

    /// The same, at an explicit endpoint.
    pub fn connect_at(endpoint: &str, app: &str) -> Result<Self, CustodyClientError> {
        Self::connect_as_at(endpoint, app, None)
    }

    /// Connect as `app` speaking as persona `profile` without switching djinn
    /// to it (D13); `None` is the persona in use.
    pub fn connect_as(app: &str, profile: Option<ProfileId>) -> Result<Self, CustodyClientError> {
        Self::connect_as_at(&configured_app_endpoint(), app, profile)
    }

    /// [`Self::connect_as`] at an explicit endpoint.
    pub fn connect_as_at(
        endpoint: &str,
        app: &str,
        profile: Option<ProfileId>,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, None, profile, None)
    }

    /// [`Self::connect_as`] carrying `declaration` on every conversation: an
    /// application that speaks as a chosen persona and is admitted by its
    /// declaration (capability door D22).
    pub fn connect_declared_as(
        app: &str,
        declaration: AppDeclaration,
        profile: Option<ProfileId>,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_declared_as_at(&configured_app_endpoint(), app, declaration, profile)
    }

    /// [`Self::connect_declared_as`] at an explicit endpoint.
    pub fn connect_declared_as_at(
        endpoint: &str,
        app: &str,
        declaration: AppDeclaration,
        profile: Option<ProfileId>,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, Some(declaration), profile, None)
    }

    pub(super) fn connect_as_at_bounded(
        endpoint: &str,
        app: &str,
        declaration: Option<AppDeclaration>,
        profile: Option<ProfileId>,
        timeout: Option<Duration>,
    ) -> Result<Self, CustodyClientError> {
        let deadline = timeout
            .map(|duration| Instant::now().checked_add(duration).ok_or_else(timed_out))
            .transpose()?;
        let remaining = || deadline.map(|end| end.saturating_duration_since(Instant::now()));
        let app = AppId::new(app);
        let requested_profile = profile.clone();
        let opened_declaration = declaration.clone();
        let open = move |endpoint: &str, app: AppId, limit: Option<Duration>| {
            let declaration = opened_declaration.clone();
            let opened = match (limit, declaration) {
                (Some(timeout), declaration) => {
                    BlockingCustodyClient::open_at_timeout_with(endpoint, app, declaration, timeout)
                },
                (None, Some(declaration)) => {
                    BlockingCustodyClient::open_declared_at(endpoint, app, declaration)
                },
                (None, None) => BlockingCustodyClient::open_at(endpoint, app),
            };
            opened.map(|mut client| {
                client.speak_as(profile.clone());
                client
            })
        };
        let (jobs, received) = mpsc::channel::<Job>();
        let (ready, opened) = mpsc::channel();
        let actor_endpoint = endpoint.to_string();
        let actor_app = app.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let actor_stop = stop.clone();
        let job_thread = std::thread::Builder::new()
            .name(format!("custody-{app}"))
            .spawn(move || {
                let initial_timeout =
                    deadline.map(|end| end.saturating_duration_since(Instant::now()));
                let mut client = match open(&actor_endpoint, actor_app.clone(), initial_timeout) {
                    Ok(client) => {
                        let _ = ready.send(Ok(()));
                        Some(client)
                    },
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    },
                };
                while let Ok(job) = received.recv() {
                    if actor_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if job.expired() {
                        continue;
                    }
                    if client.is_none() {
                        client = open(&actor_endpoint, actor_app.clone(), job.remaining()).ok();
                    }
                    if actor_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if job.expired() {
                        continue;
                    }
                    if let Some(client) = client.as_mut() {
                        client.set_call_timeout(job.remaining());
                    }
                    if !job.run(client.as_mut()) {
                        client = None;
                    }
                }
            })
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let mut starting = StartingActor {
            sender: Some(jobs),
            thread: Some(job_thread),
            stop: stop.clone(),
        };
        match timeout {
            Some(_) => opened
                .recv_timeout(remaining().expect("bounded startup"))
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => timed_out(),
                    mpsc::RecvTimeoutError::Disconnected => closed(),
                })??,
            None => opened.recv().map_err(|_| closed())??,
        }

        let status = ask_on_bounded(
            starting.sender.as_ref().expect("startup sender"),
            remaining(),
            |client| client.status(),
        )?;
        let Some(master) = status
            .persona_public_key
            .filter(|_| status.lock == VaultLockView::Unlocked)
        else {
            return Err(CustodyClientError::Refused(
                crate::custody::CustodyRefusal::Locked,
            ));
        };
        let master = Ed25519PublicKey::from_bytes(&master).map_err(CustodyClientError::Release)?;
        let this = Self {
            endpoint: endpoint.to_owned(),
            app: app.clone(),
            declaration: declaration.clone(),
            requested_profile,
            master,
            status,
            jobs: Mutex::new(starting.sender.take()),
            job_thread: Mutex::new(starting.thread.take()),
            watch_thread: Mutex::new(None),
            call_timeout: timeout,
            held: Arc::default(),
            locked: Arc::new(AtomicBool::new(false)),
            epoch: Arc::new(AtomicU64::new(1)),
            stop,
        };
        this.watch(endpoint.to_string(), app, declaration);
        Ok(this)
    }
}
