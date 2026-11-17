#!/usr/bin/python3 -I
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Apply a Luggage-verified custodian binary to an existing Linux installation."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time


CONFIG = Path("/etc/djinn-custodian/upgrade.json")
PROGRAM = Path("/usr/local/libexec/djinn-custodian")
HELPER = "/usr/local/libexec/djinn-approval"
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?")
MAX_BINARY = 128 * 1024 * 1024


def command(*args, data=None):
    return subprocess.run(
        args, input=data, capture_output=True, check=True, timeout=30,
        env={"PATH": PATH, "LC_ALL": "C"},
    ).stdout


def digest(path):
    with path.open("rb") as binary:
        return hashlib.file_digest(binary, "sha256").hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Upgrade:
    def __init__(self, policy, program=PROGRAM):
        self.owner = policy["owner"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.owner):
            raise ValueError("invalid custodian owner")
        self.baseline_sha = policy["baseline_sha256"]
        self.baseline_version = policy["baseline_version"]
        if not SHA256.fullmatch(self.baseline_sha) or not VERSION.fullmatch(self.baseline_version):
            raise ValueError("invalid baseline release")
        self.unit = f"djinn-custodian@{self.owner}.service"
        self.program = program
        self.state = program.parent / ".djinn-custodian-upgrade"
        self.pending = self.state / "pending.json"
        self.previous = self.state / "previous"

    def write_state(self, name, data):
        fd, temp = tempfile.mkstemp(dir=self.state)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.state / name)
            sync_dir(self.state)
        finally:
            Path(temp).unlink(missing_ok=True)

    def version(self, sha):
        if sha == self.baseline_sha:
            return self.baseline_version
        record = self.state / f"{sha}.json"
        if not record.is_file():
            raise RuntimeError("running binary is absent from the release records")
        return json.loads(record.read_text())

    def service_identity(self):
        uid = pwd.getpwnam(self.owner).pw_uid
        response = json.loads(command(
            "runuser", "-u", self.owner, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
            HELPER, "relay", data=b'{"command":"state"}',
        ))
        if response["reply"] != "state":
            raise RuntimeError("custodian did not return relay state")
        state = response["state"]
        return {key: state[key] for key in ("root_authority", "root_issuer", "target", "profile")}

    def check_service_scope(self):
        user = command("systemctl", "show", self.unit, "-p", "User", "--value").decode().strip()
        if user != f"djinn-custodian-{self.owner}":
            raise RuntimeError("custodian unit must run under its dedicated account")
        configs = {path.name for path in CONFIG.parent.glob("*.json")} - {CONFIG.name}
        if configs != {f"{self.owner}.json"}:
            raise RuntimeError("expected one configured custodian instance for the shared binary")
        for kind in ("service", "socket"):
            units = command(
                "systemctl", "list-units", f"djinn-custodian@*.{kind}", "--no-legend", "--plain",
            ).decode().splitlines()
            if [line.split()[0] for line in units if line.strip()] != [f"djinn-custodian@{self.owner}.{kind}"]:
                raise RuntimeError("expected one active custodian service and socket")

    def running_pid(self):
        pid = int(command("systemctl", "show", self.unit, "-p", "MainPID", "--value"))
        if pid <= 1 or not Path(f"/proc/{pid}/exe").samefile(self.program):
            raise RuntimeError("custodian service is not running the installed binary")
        return pid

    def restart_verified(self, identity):
        command("systemctl", "restart", self.unit)
        deadline = time.monotonic() + 15
        while True:
            try:
                pid = self.running_pid()
                found = self.service_identity()
                if found != identity:
                    raise ValueError("custodian identity or relay authority changed")
                if self.running_pid() == pid:
                    return
            except (OSError, RuntimeError, subprocess.SubprocessError):
                if time.monotonic() >= deadline:
                    raise
            if time.monotonic() >= deadline:
                raise RuntimeError("custodian did not hold a stable process")
            time.sleep(0.25)

    def keep_label(self, path):
        getenforce = Path("/usr/sbin/getenforce")
        if getenforce.is_file() and command(getenforce).strip() != b"Disabled":
            command("chcon", f"--reference={self.program}", path)

    def stage(self, stream):
        target = self.state / "candidate"
        target.unlink(missing_ok=True)
        with target.open("xb") as output:
            header = stream.read(20)
            with self.program.open("rb") as current:
                installed_header = current.read(20)
            # ELF class, data encoding and architecture must match the installed program.
            if (len(header) != 20 or header[:4] != b"\x7fELF"
                    or header[4:6] != installed_header[4:6]
                    or header[18:20] != installed_header[18:20]):
                raise ValueError("package is not an ELF binary for the installed architecture")
            output.write(header)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                output.write(chunk)
                if output.tell() > MAX_BINARY:
                    raise ValueError("custodian binary exceeds size limit")
            os.fchmod(output.fileno(), 0o755)
            self.keep_label(target)
            output.flush()
            os.fsync(output.fileno())
        return target

    def recover(self):
        if not self.pending.exists():
            return
        journal = json.loads(self.pending.read_text())
        if digest(self.previous) != journal["sha256"]:
            raise RuntimeError("saved custodian failed rollback verification")
        restore = self.state / "restore"
        restore.unlink(missing_ok=True)
        os.link(self.previous, restore)
        os.replace(restore, self.program)
        sync_dir(self.program.parent)
        self.restart_verified(journal["identity"])
        self.pending.unlink()
        sync_dir(self.state)

    def install(self, version, stream):
        if not VERSION.fullmatch(version):
            raise ValueError("invalid package release version")
        self.check_service_scope()
        self.running_pid()
        identity = self.service_identity()
        installed = digest(self.program)
        self.version(installed)
        stage = self.state / "candidate"
        try:
            stage = self.stage(stream)
            sha = digest(stage)
            if sha == installed or sha == self.baseline_sha:
                raise ValueError("package would install the current or original binary")
            record = self.state / f"{sha}.json"
            if record.exists() and self.version(sha) != version:
                raise ValueError("package bytes already have a different release version")
            self.write_state(record.name, version)
            self.previous.unlink(missing_ok=True)
            os.link(self.program, self.previous)
            self.write_state(self.pending.name, {"sha256": installed, "identity": identity})
            os.replace(stage, self.program)
            sync_dir(self.program.parent)
            self.restart_verified(identity)
            self.pending.unlink()
            sync_dir(self.state)
        except BaseException:
            self.recover()
            raise
        finally:
            stage.unlink(missing_ok=True)


def main(args):
    if os.geteuid() != 0:
        raise RuntimeError("the custodian update adapter must run as root")
    if args != ["running-version"] and not (len(args) == 2 and args[0] == "install"):
        raise ValueError("usage: djinn-custodian-upgrade running-version | install VERSION")
    # A lost SSH session should leave the transaction free to finish or roll back.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.umask(0o077)
    policy = json.loads(CONFIG.read_text())
    update = Upgrade(policy)
    mode = update.program.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0 or mode.st_mode & 0o022:
        raise RuntimeError("installed custodian must be a root-owned regular file")
    update.state.mkdir(mode=0o700, exist_ok=True)
    with (update.state / "lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        update.recover()
        if args == ["running-version"]:
            update.running_pid()
            print(update.version(digest(update.program)))
        else:
            update.install(args[1], sys.stdin.buffer)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"djinn-custodian-upgrade: {error}", file=sys.stderr)
        sys.exit(1)
