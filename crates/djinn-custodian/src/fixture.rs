// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A custodian served from a thread of the caller over a new synthetic
//! passphrase vault, for test suites and receipt hosts. Only the `fixture`
//! feature builds it; an installed custodian never does. Everything lives
//! under the directory the caller hands over, which must be new.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use castellan::custody::bootstrap::{self, Unlock};
use castellan::custody::{IdentityStorage, Profile};
use personae::{Ed25519Keypair, ProfileId};

use crate::consent::Mechanism;
use crate::core::Core;
use crate::driver::Service;
use crate::policy::Config;

/// The installed Djinn grant template, shared with synthetic receiving hosts.
pub const DJINN_GRANTS_TEMPLATE: &str = include_str!("../packaging/djinn-grants.json.in");

/// A served custodian and where a client finds it.
pub struct Fixture {
    pub vault: PathBuf,
    pub data_root: PathBuf,
    /// The client file a Djinn reads in place of the installed one.
    pub client_file: PathBuf,
    /// Where the SSH agent is served, when asked for.
    pub agent: Option<PathBuf>,
    pub service: Arc<Service>,
}

/// What the fixture serves.
pub struct Spec<'a> {
    pub passphrase: &'a str,
    /// `(id, display name, master seed)`; the first is the one opened.
    pub profiles: &'a [(&'a str, &'a str, [u8; 32])],
    /// The grants of the one principal: this process's own account.
    pub grants: serde_json::Value,
    pub consent: &'a str,
    pub mechanism: Option<Arc<dyn Mechanism>>,
    /// Serve the SSH agent beside the custody socket, as an installed
    /// custodian does (the service bridges its per-use requests to consent).
    pub agent: bool,
}

/// Create the vault under `root` and serve it: on a socket there on Unix, on
/// a named pipe of the fixture's own on Windows.
#[cfg(any(unix, windows))]
pub fn start(root: &Path, spec: Spec<'_>) -> Result<Fixture, String> {
    start_inner(root, spec, true, root.join("run"), None)
}

/// Open a marked receipt fixture on a fresh runtime directory. The caller
/// holds an exclusive lease for every service clone; the existing vault is never reseeded.
#[cfg(unix)]
pub fn receipt(root: &Path, spec: Spec<'_>, create: bool) -> Result<Fixture, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !root.is_absolute() || root == Path::new("/") || root.canonicalize().map_err(|e| e.to_string())? != root
        || !meta.is_dir() || meta.uid() != custody_wire::peer::effective_uid() || meta.mode() & 0o077 != 0 {
        return Err("receipt fixture root must be private, owned, and canonical".into());
    }
    fn reject_symlinks(path: &Path) -> Result<(), String> {
        for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            if ty.is_symlink() { return Err("symlink in receipt fixture root".into()); }
            if ty.is_dir() { reject_symlinks(&entry.path())?; }
        }
        Ok(())
    }
    reject_symlinks(root)?;
    if std::fs::read(root.join("fixture-marker")).map_err(|e| e.to_string())? != b"eidetic-retention-20261019\n" {
        return Err("receipt fixture marker mismatch".into());
    }
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true)
        .open(root.join("fixture.lock")).map_err(|e| e.to_string())?;
    lock.try_lock().map_err(|e| format!("fixture root already in use: {e}"))?;
    let lock = Arc::new(lock);
    let state = root.join("custodian");
    if create {
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let name = entry.map_err(|e| e.to_string())?.file_name();
            if name != "fixture-marker" && name != "fixture.lock" {
                return Err("unrecognized content in new fixture root".into());
            }
        }
        std::fs::create_dir(&state).map_err(|e| e.to_string())?;
    } else if !state.is_dir() || state.is_symlink() {
        return Err("receipt fixture state missing or unsafe".into());
    }
    if !create && (!state.join("vault").join(bootstrap::PASSPHRASE_VAULT_FILE).is_file()
        || std::fs::read(state.join("initialized")).ok().as_deref() != Some(b"receipt-fixture-v1\n")) {
        return Err("incomplete receipt fixture state".into());
    }
    let run = state.join(format!("run-{}", uuid::Uuid::new_v4()));
    start_inner(&state, spec, create, run, Some(lock))
}

#[cfg(any(unix, windows))]
fn start_inner(root: &Path, spec: Spec<'_>, create: bool, run: PathBuf, lease: Option<Arc<std::fs::File>>) -> Result<Fixture, String> {
    let vault = root.join("vault");
    let data_root = root.join("data");
    if create {
        std::fs::create_dir_all(&data_root).map_err(|e| e.to_string())?;
        let opened = bootstrap::open_storage(&vault, Unlock::passphrase(spec.passphrase)).map_err(|e| e.to_string())?;
        for (id, name, seed) in spec.profiles {
            let profile = Profile::new(ProfileId((*id).into()), *name, Ed25519Keypair::from_seed(*seed));
            opened.storage.save_profile(&profile).map_err(|e| e.to_string())?;
        }
    } else if !vault.is_dir() || vault.is_symlink() || !data_root.is_dir() || data_root.is_symlink() {
        return Err("receipt fixture vault or wallet root missing or unsafe".into());
    }
    let account = Account::current()?;
    let first = spec.profiles.first().ok_or("a fixture needs a profile")?.0;
    let config = serde_json::json!({
        "vault": {"directory": vault, "profile": first, "data_root": data_root},
        "owner": account.owner(), "consent": spec.consent, "development": true,
        "principals": [{"name": "djinn", "match": account.principal(), "grants": spec.grants}]
    });
    let config = Config::parse(&serde_json::to_vec(&config).map_err(|e| e.to_string())?).map_err(|e| e.0)?;
    let (listener, endpoint) = account.listen(&run)?;
    let service = Arc::new(Service::new(Core::start(config).map_err(|r| r.to_string())?, spec.mechanism)
        .with_fixture_lease(lease));
    let serving = Arc::clone(&service);
    std::thread::Builder::new()
        .name("fixture-custodian".into())
        .spawn(move || serving.serve(&*listener))
        .map_err(|e| e.to_string())?;
    account.ready(&endpoint)?;
    let agent = match spec.agent {
        true => Some(account.agent(&service, &run, &endpoint)?),
        false => None,
    };
    let client_file = root.join("client.json");
    let client = serde_json::json!({"endpoint": endpoint, "server": account.server(), "agent": agent});
    std::fs::write(&client_file, serde_json::to_vec(&client).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(Fixture {
        vault,
        data_root,
        client_file,
        agent,
        service,
    })
}

/// The caller's own account: the fixture's owner, its one principal and
/// the server a client expects.
#[cfg(unix)]
struct Account(u32);

#[cfg(unix)]
impl Account {
    fn current() -> Result<Self, String> {
        Ok(Self(custody_wire::peer::effective_uid()))
    }
    fn owner(&self) -> serde_json::Value {
        serde_json::json!({"unix_uid": self.0})
    }
    fn principal(&self) -> serde_json::Value {
        serde_json::json!({"unix-uid": self.0})
    }
    fn server(&self) -> serde_json::Value {
        serde_json::json!({"unix_uids": [self.0]})
    }
    fn listen(&self, run: &Path) -> Result<(Box<dyn custody_wire::transport::Listener + Send>, PathBuf), String> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(run).map_err(|e| e.to_string())?;
        std::fs::set_permissions(run, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let socket = run.join("custody.sock");
        let listener = custody_wire::transport::UnixSocketListener::bind(&socket).map_err(|e| e.to_string())?;
        Ok((Box::new(listener), socket))
    }
    /// A bound socket already accepts.
    fn ready(&self, _: &Path) -> Result<(), String> {
        Ok(())
    }
    fn agent(&self, service: &Service, run: &Path, _: &Path) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt;
        let path = run.join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        crate::agent::spawn(Service::clone(service), listener, Some(self.0)).map_err(|e| e.to_string())?;
        Ok(path)
    }
}

#[cfg(windows)]
struct Account(String);

#[cfg(windows)]
impl Account {
    fn current() -> Result<Self, String> {
        custody_wire::peer::current_user_sid().map(Self).map_err(|e| e.to_string())
    }
    fn owner(&self) -> serde_json::Value {
        serde_json::json!({"windows_sid": self.0})
    }
    fn principal(&self) -> serde_json::Value {
        serde_json::json!({"windows-sid": self.0})
    }
    fn server(&self) -> serde_json::Value {
        serde_json::json!({"windows_sids": [self.0]})
    }
    /// The installed custodian's pipe and admission, under a name of the
    /// fixture's own so it never meets an installed custodian.
    fn listen(&self, _: &Path) -> Result<(Box<dyn custody_wire::transport::Listener + Send>, PathBuf), String> {
        let name = format!(r"\\.\pipe\djinn-custodian-fixture-{}", uuid::Uuid::new_v4());
        custody_wire::transport::admit_identification(std::slice::from_ref(&self.0)).map_err(|e| format!("admit the owner: {e}"))?;
        Ok((Box::new(custody_wire::transport::NamedPipeListener::new(&name, &self.0)), name.into()))
    }
    /// The listener makes its first instance on the serving thread; wait
    /// for it without connecting, as a client finding none fails at once.
    fn ready(&self, endpoint: &Path) -> Result<(), String> {
        use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
        let name: Vec<u16> = endpoint.as_os_str().to_string_lossy().encode_utf16().chain([0]).collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // SAFETY: a live NUL-terminated pipe name.
        while unsafe { WaitNamedPipeW(name.as_ptr(), 50) } == 0 {
            if std::time::Instant::now() > deadline {
                return Err("the fixture pipe never appeared".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }
    fn agent(&self, service: &Service, _: &Path, endpoint: &Path) -> Result<PathBuf, String> {
        let name = format!("{}-agent", endpoint.display());
        crate::agent_pipe::spawn(Service::clone(service), name.clone(), self.0.clone()).map_err(|e| e.to_string())?;
        Ok(name.into())
    }
}

#[cfg(all(test, any(unix, windows)))]
mod transport_tests {
    use super::*;
    use custody_wire::contract::{Answer, Outcome};
    use custody_wire::secret::Secret;
    use custody_wire::{Client, Operation, ServerExpectation};
    use std::time::Duration;

    const PASSPHRASE: &str = "public transport fixture";

    fn connector(endpoint: &str) -> Box<dyn custody_wire::transport::Connector> {
        #[cfg(unix)]
        return Box::new(custody_wire::transport::UnixSocketConnector::new(endpoint));
        #[cfg(windows)]
        return Box::new(custody_wire::transport::NamedPipeConnector::new(endpoint));
    }

    /// Djinn's way in: the client file, the platform transport and the
    /// owner's admission, then an operation only the principal's grant allows.
    #[test]
    fn a_client_file_reaches_the_fixture_and_a_wrong_server_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let fixture = start(root.path(), Spec {
            passphrase: PASSPHRASE,
            profiles: &[("family", "Family", [0x52; 32])],
            grants: serde_json::json!([{"operation": "status"}, {"operation": "unlock"}]),
            consent: "deny",
            mechanism: None,
            agent: false,
        }).unwrap();
        let file = crate::helper::ClientFile::read(&fixture.client_file).unwrap();
        let wrong = ServerExpectation { unix_uids: vec![u32::MAX], windows_sids: vec!["S-1-5-18".into()], ..ServerExpectation::default() };
        assert!(Client::open(&*connector(&file.endpoint), &wrong).is_err(), "only the owner's own server is admitted");
        let client = Client::open(&*connector(&file.endpoint), &file.server).unwrap();
        let status = client.call(Operation::Status {}, Duration::from_secs(10));
        assert!(matches!(status, Outcome::Success { answer: Answer::Status { .. } }), "{status:?}");
        let unlocked = client.call(Operation::Unlock { passphrase: Secret::copy_from(PASSPHRASE.as_bytes()) }, Duration::from_secs(30));
        assert!(matches!(unlocked, Outcome::Success { answer: Answer::Unlocked { .. } }), "{unlocked:?}");
    }
}

impl Fixture {
    /// The vault opened directly, to check what the custodian answered.
    pub fn direct(&self, passphrase: &str, profile: &str) -> Result<castellan::custody::IdentityVault<Box<dyn IdentityStorage>>, String> {
        let opened = bootstrap::open_storage(&self.vault, Unlock::passphrase(passphrase)).map_err(|e| e.to_string())?;
        castellan::custody::IdentityVault::open(opened.storage, &ProfileId(profile.into())).map_err(|e| e.to_string())
    }
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;
    use custody_wire::transport::{Connection, Listener};
    use std::time::{Duration, Instant};

    struct FailedListener;
    impl Listener for FailedListener {
        fn accept(&self) -> std::io::Result<Connection> {
            Err(std::io::Error::other("synthetic accept failure"))
        }
    }

    /// Child process lets the parent check both retained and released lease
    /// without leaving an unjoinable ticker behind in the test process.
    #[test]
    #[ignore]
    fn failing_listener_child() {
        let root = PathBuf::from(std::env::var_os("CUSTODIAN_LEASE_TEST_ROOT").unwrap());
        let lease = std::fs::OpenOptions::new().read(true).write(true).create(true)
            .open(root.join("fixture.lock")).unwrap();
        lease.try_lock().unwrap();
        let vault = root.join("vault");
        let opened = bootstrap::open_storage(&vault, Unlock::passphrase("public lease fixture")).unwrap();
        opened.storage.save_profile(&Profile::new(
            ProfileId("family".into()), "Family", Ed25519Keypair::from_seed([0x51; 32]),
        )).unwrap();
        drop(opened);
        let uid = custody_wire::peer::effective_uid();
        let config = serde_json::json!({
            "vault": {"directory": vault, "profile": "family"},
            "owner": {"unix_uid": uid}, "consent": "deny", "development": true,
            "principals": [{"name": "djinn", "match": {"unix-uid": uid}, "grants": []}]
        });
        let config = Config::parse(&serde_json::to_vec(&config).unwrap()).unwrap();
        let service = Service::new(Core::start(config).unwrap(), None)
            .with_fixture_lease(Some(Arc::new(lease)));
        assert!(service.serve(&FailedListener).is_err());
        drop(service);
        std::fs::write(root.join("ready"), b"failed listener returned").unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join("stop").exists() {
            assert!(Instant::now() < deadline, "parent did not stop child");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }

    #[test]
    fn lease_survives_accept_failure_until_service_workers_exit() {
        let root = tempfile::tempdir().unwrap();
        let mut child = ChildGuard(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["fixture::lease_tests::failing_listener_child", "--ignored", "--exact", "--nocapture"])
            .env("CUSTODIAN_LEASE_TEST_ROOT", root.path()).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.path().join("ready").exists() {
            assert!(child.0.try_wait().unwrap().is_none(), "child exited before reporting listener failure");
            assert!(Instant::now() < deadline, "child did not report listener failure");
            std::thread::sleep(Duration::from_millis(10));
        }
        let contender = std::fs::OpenOptions::new().read(true).write(true)
            .open(root.path().join("fixture.lock")).unwrap();
        assert!(contender.try_lock().is_err(), "worker must retain lease after listener exits");
        std::fs::write(root.path().join("stop"), b"stop").unwrap();
        assert!(child.0.wait().unwrap().success());
        contender.try_lock().expect("process exit releases the lease");
    }
}
