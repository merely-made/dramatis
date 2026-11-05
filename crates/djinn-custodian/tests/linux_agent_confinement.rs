// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use castellan::custody::bootstrap::{self, Unlock};
use djinn_custodian::core::Core;
use djinn_custodian::driver::Service;
use djinn_custodian::platform::{self, Confinement};
use djinn_custodian::policy::Config;
use personae::ProfileId;

const CHILD: &str = "DJINN_AGENT_CONFINEMENT_FIXTURE";

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "native Linux gate: requires Landlock ABI >= 6 and seccomp"]
fn agent_runs_inside_linux_confinement() {
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let config_path = root.join("config.json");
        let config = Config::parse(&std::fs::read(&config_path).unwrap()).unwrap();
        let listener = UnixListener::bind(root.join("agent.sock")).unwrap();
        let core = Core::start(config.clone()).unwrap();
        let applied = platform::confine(&Confinement {
            state: config.vault.directory.clone(),
            config: config_path,
            required: true,
        })
        .unwrap();
        assert!(
            applied
                .notes
                .iter()
                .any(|note| note == "seccomp allowlist enforcing")
        );
        djinn_custodian::agent::spawn(Service::new(core, None), listener, config.owner.unix_uid)
            .unwrap();
        std::fs::write(
            config.vault.directory.join("ready"),
            b"confined agent spawned",
        )
        .unwrap();
        std::thread::sleep(Duration::from_secs(10));
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("vault");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let opened = bootstrap::open_storage(
        &state,
        Unlock::passphrase(b"synthetic-agent-fixture".to_vec()),
    )
    .unwrap();
    bootstrap::load_or_create_profile(&*opened.storage, &ProfileId("fixture".into())).unwrap();
    drop(opened);
    let uid = custody_wire::peer::effective_uid();
    std::fs::write(root.join("config.json"), serde_json::to_vec(&serde_json::json!({
        "vault":{"directory":state,"profile":"fixture"}, "owner":{"unix_uid":uid},
        "consent":"deny", "principals":[{"name":"fixture","match":{"unix-uid":uid},"grants":[{"operation":"status"}]}]
    })).unwrap()).unwrap();
    // A separate executable avoids inheriting a test runner's threads or
    // confining the parent. The lease reaps it before the fixture is removed.
    let mut child = Running(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent_runs_inside_linux_confinement",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, root)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !state.join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "confined agent child exited before readiness"
        );
        assert!(
            Instant::now() < deadline,
            "confined agent did not become ready"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = UnixStream::connect(root.join("agent.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        stream.read(&mut byte).unwrap(),
        0,
        "the running agent must accept and close an owner's connection while the vault is locked"
    );
}
