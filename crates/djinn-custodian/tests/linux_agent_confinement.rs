// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use castellan::custody::bootstrap::{self, Unlock};
use custody_wire::contract::{Answer, Outcome, ServerMessage};
use custody_wire::secret::Secret;
use custody_wire::{ClientMessage, Operation, Peer};
use djinn_custodian::core::Core;
use djinn_custodian::driver::Service;
use djinn_custodian::platform::{self, Confinement};
use djinn_custodian::policy::Config;
use personae::ProfileId;

const CHILD: &str = "DJINN_AGENT_CONFINEMENT_FIXTURE";
const OMIT_DATA: &str = "DJINN_AGENT_FIXTURE_OMIT_DATA";

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "native Linux gate: requires Landlock ABI >= 6 and seccomp"]
fn agent_and_unlock_run_inside_linux_confinement() {
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let config_path = root.join("config.json");
        let config = Config::parse(&std::fs::read(&config_path).unwrap()).unwrap();
        let omit_data = std::env::var(OMIT_DATA).as_deref() == Ok("1");
        let listener = UnixListener::bind(root.join("agent.sock")).unwrap();
        let core = Core::start(config.clone()).unwrap();
        let applied = platform::confine(&Confinement {
            state: config.vault.directory.clone(),
            data_root: if omit_data {
                None
            } else {
                config.vault.data_root.clone()
            },
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
        let service = Service::new(core, None);
        djinn_custodian::agent::spawn(service.clone(), listener, config.owner.unix_uid).unwrap();
        std::fs::write(
            config.vault.directory.join("ready"),
            b"confined agent spawned",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while !config.vault.directory.join("unlock-now").exists() {
            assert!(
                Instant::now() < deadline,
                "parent did not finish the locked-agent check"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut core = service.core().lock().unwrap();
        let uid = config.owner.unix_uid.unwrap();
        let (session, _) = core
            .open(
                Peer::Unix {
                    uid,
                    gid: uid,
                    pid: Some(std::process::id() as i32),
                },
                &ClientMessage::Hello {
                    version: custody_wire::VERSION,
                    nonce: "native-fixture".into(),
                },
            )
            .unwrap();
        let message = ClientMessage::Request {
            id: 1,
            instance: core.instance().into(),
            generation: core.generation(),
            operation: Operation::Unlock {
                passphrase: Secret::copy_from(b"synthetic-agent-fixture"),
            },
        };
        let effects = core.handle(session, message, Instant::now());
        let data = config.vault.data_root.as_ref().unwrap();
        if omit_data {
            assert!(effects.messages.iter().any(|(_, message)| matches!(message,
                ServerMessage::Outcome { request: 1, outcome, .. } if outcome.code() == Some("vault-storage"))),
                "omitting the catalog root must reproduce the native storage refusal");
            assert_eq!(
                std::fs::write(data.join("forbidden-write"), b"fixture")
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        } else {
            assert!(
                effects.messages.iter().any(|(_, message)| matches!(
                    message,
                    ServerMessage::Outcome {
                        request: 1,
                        outcome: Outcome::Success {
                            answer: Answer::Unlocked { .. }
                        },
                        ..
                    }
                )),
                "unlock, including credential catalog initialization, must work under confinement"
            );
            std::fs::write(data.join("allowed-write"), b"fixture").unwrap();
        }
        assert_eq!(
            std::fs::read(root.join("outside.txt")).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::write(root.join("config.json"), b"forbidden")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::write(
            config.vault.directory.join("finished"),
            if omit_data {
                "vault-storage"
            } else {
                "unlocked"
            },
        )
        .unwrap();
        drop(core);
        std::thread::sleep(Duration::from_secs(10));
        return;
    }
    run_fixture(true);
    run_fixture(false);
}

fn run_fixture(omit_data: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("vault");
    let data = root.join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("outside.txt"), b"must remain outside the sandbox").unwrap();
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
        "vault":{"directory":state,"data_root":data,"profile":"fixture"}, "owner":{"unix_uid":uid},
        "consent":"deny", "principals":[{"name":"fixture","match":{"unix-uid":uid},"grants":[{"operation":"status"},{"operation":"unlock"}]}]
    })).unwrap()).unwrap();
    // A separate executable avoids inheriting a test runner's threads or
    // confining the parent. The lease reaps it before the fixture is removed.
    let mut child = Running(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent_and_unlock_run_inside_linux_confinement",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, root)
            .env(OMIT_DATA, if omit_data { "1" } else { "0" })
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
    std::fs::write(state.join("unlock-now"), b"continue").unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while !state.join("finished").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "confined unlock child exited"
        );
        assert!(Instant::now() < deadline, "confined unlock did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        std::fs::read_to_string(state.join("finished")).unwrap(),
        if omit_data {
            "vault-storage"
        } else {
            "unlocked"
        }
    );
}
