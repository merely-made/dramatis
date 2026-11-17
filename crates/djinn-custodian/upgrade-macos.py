#!/usr/bin/python3 -I
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

"""Apply a Luggage-verified Developer ID bundle to an installed custodian."""

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time


ROOT = Path("/Library/Application Support/Merely/djinn-custodian")
POLICY = Path("/etc/djinn-custodian/upgrade.json")
APP = "djinn-custodian.app"
EXECUTABLE = Path("Contents/MacOS/djinn-custodian")
IDENTIFIER = "com.merely.djinn.custodian"
MAX_BUNDLE_BYTES = 128 * 1024 * 1024


def command(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=15,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})


def provisioning_profile(path):
    # security cms imports certificates into the default Keychain while
    # decoding. The root updater has no login Keychain. Verify the CMS
    # signature against macOS's public system roots without importing it.
    roots = command("/usr/bin/security", "find-certificate", "-a", "-p",
                    "/System/Library/Keychains/SystemRootCertificates.keychain")
    decoded = subprocess.run(
        ["/usr/bin/openssl", "cms", "-verify", "-inform", "DER", "-in", path,
         "-CAfile", "/dev/stdin", "-purpose", "any"],
        input=roots, capture_output=True, check=True, timeout=15,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    return plistlib.loads(decoded.stdout)


def version_parts(text):
    if not isinstance(text, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", text):
        raise ValueError("expected a three-part bundle version")
    return tuple(map(int, text.split(".")))


def trusted(path, kind):
    info = path.lstat()
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f"unsafe administrator-owned path: {path}")


def exchange(left, right):
    rename = ctypes.CDLL(None, use_errno=True).renamex_np
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(left), os.fsencode(right), 0x00000002) != 0:  # RENAME_SWAP
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(left), str(right))


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def unpack(stream, destination):
    total = 0
    seen = set()
    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            relative = PurePosixPath(member.name)
            if (not relative.parts or relative.parts[0] != APP or ".." in relative.parts
                    or relative.as_posix() != member.name.rstrip("/") or relative in seen
                    or not (member.isdir() or member.isfile())):
                raise ValueError(f"unexpected archive entry: {member.name!r}")
            seen.add(relative)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("unpacked bundle exceeds size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
                os.fchmod(output.fileno(), 0o755 if member.mode & 0o111 else 0o644)
                output.flush()
                os.fsync(output.fileno())
    for directory, _, _ in os.walk(destination / APP, topdown=False):
        os.chmod(directory, 0o755)
        sync_dir(directory)
    sync_dir(destination)


def identity(bundle):
    with (bundle / "Contents/Info.plist").open("rb") as stream:
        plist = plistlib.load(stream)
    version = plist["CFBundleShortVersionString"]
    version_parts(version)
    return {"version": version, "sha256": hashlib.sha256((bundle / EXECUTABLE).read_bytes()).hexdigest()}


class Upgrade:
    def __init__(self, policy, root=ROOT):
        self.owner = policy["owner"]
        self.team = policy["team"]
        self.arch = policy["arch"]
        certificate = policy["certificate_sha1"]
        if (not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.owner)
                or not re.fullmatch(r"[A-Z0-9]+", self.team)
                or not re.fullmatch(r"[A-Fa-f0-9]{40}", certificate)
                or self.arch not in {"x86_64", "arm64"}):
            raise ValueError("invalid macOS update policy")
        self.requirement = f'anchor apple generic and identifier "{IDENTIFIER}" and certificate leaf = H"{certificate}"'
        self.uid = int(command("/usr/bin/id", "-u", self.owner))
        self.domain = f"gui/{self.uid}"
        self.root = root
        self.app = root / APP
        self.state = root / ".djinn-custodian-upgrade"
        self.pending = self.state / "pending.json"
        self.candidate = self.state / APP
        client = root / "clients" / f"{self.uid}.json"
        trusted(client, stat.S_ISREG)
        expected = json.loads(client.read_text())
        server = expected["server"]
        if len(server.get("signed", [])) == 1:
            signer = server["signed"][0]
            if isinstance(signer.get("certificate_sha1"), str):
                signer["certificate_sha1"] = signer["certificate_sha1"].upper()
        if server != {"signed": [{"team": self.team, "identifier": IDENTIFIER, "certificate_sha1": certificate.upper()}]}:
            raise ValueError("update policy and installed client expect different signers")
        self.endpoint = expected["endpoint"]

    def verify(self, bundle):
        trusted(bundle, stat.S_ISDIR)
        trusted(bundle / EXECUTABLE, stat.S_ISREG)
        command("/usr/bin/codesign", "--verify", "--strict", "--deep", f"-R={self.requirement}", bundle)
        if command("/usr/bin/lipo", "-archs", bundle / EXECUTABLE).decode().strip() != self.arch:
            raise ValueError("bundle architecture differs from the upgrade policy")
        details = command("/usr/bin/codesign", "-d", "--verbose=4", bundle)
        if not re.search(rb"^CodeDirectory.*flags=.*runtime", details, re.M) or not re.search(rb"^Timestamp=", details, re.M):
            raise ValueError("bundle requires hardened runtime and a secure timestamp")
        exported = command("/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", bundle)
        # codesign writes commentary to stderr before its entitlement plist.
        start = exported.index(b"<?xml")
        claims = plistlib.loads(exported[start:])
        group = f"{self.team}.{IDENTIFIER}"
        if (claims.get("com.apple.application-identifier") != group or claims.get("keychain-access-groups") != [group]
                or "get-task-allow" in claims or "com.apple.security.get-task-allow" in claims):
            raise ValueError("bundle entitlements differ from the installed Keychain policy")
        profile = provisioning_profile(bundle / "Contents/embedded.provisionprofile")
        authorized = profile["Entitlements"]
        if (authorized.get("com.apple.application-identifier") != group
                or not {group, f"{self.team}.*"}.intersection(authorized.get("keychain-access-groups", []))):
            raise ValueError("embedded profile does not authorize the custodian’s Keychain group")
        return identity(bundle)

    def job_pid(self, label, program):
        status = command("/bin/launchctl", "print", f"{self.domain}/{label}").decode()
        state = re.search(r"^\s*state = running$", status, re.M)
        executable = re.search(r"^\s*program = (.*)$", status, re.M)
        pid = re.search(r"^\s*pid = (\d+)$", status, re.M)
        if not (state and pid and executable and Path(executable[1]) == program):
            raise RuntimeError(f"{label} is not running from {program}")
        return int(pid[1])

    def running_pid(self):
        pid = self.job_pid(IDENTIFIER, self.app / EXECUTABLE)
        # A launchd socket can initially report PID 1. Observe the kernel's
        # audit token after accept, without sending a custody request.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(self.endpoint)
            for _ in range(20):
                token = struct.unpack("=8I", connection.getsockopt(0, 6, 32))  # SOL_LOCAL, LOCAL_PEERTOKEN
                if (token[5], token[1]) == (pid, self.uid):
                    return pid
                time.sleep(0.01)
        raise RuntimeError("custody socket did not identify the running launchd job")

    def restart(self):
        command("/bin/launchctl", "kickstart", "-k", f"{self.domain}/{IDENTIFIER}")
        deadline = time.monotonic() + 15
        while True:
            try:
                self.running_pid()
                break
            except (OSError, RuntimeError, subprocess.SubprocessError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        # Do not hold the update while the owner responds to the unlock UI.
        for label in (f"{IDENTIFIER}.consent", "org.merely.djinn"):
            command("/bin/launchctl", "kickstart", "-k", f"{self.domain}/{label}")

    def write_pending(self, previous):
        journal = self.state / "pending.new"
        with journal.open("w", encoding="utf-8") as stream:
            json.dump(previous, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(journal, self.pending)
        sync_dir(self.state)

    def recover(self):
        if not self.pending.exists():
            return
        previous = json.loads(self.pending.read_text())
        if identity(self.app) != previous:
            if self.verify(self.candidate) != previous:
                raise RuntimeError("saved bundle does not match the rollback journal")
            exchange(self.app, self.candidate)
            sync_dir(self.root)
            sync_dir(self.state)
        if self.verify(self.app) != previous:
            raise RuntimeError("restored bundle does not match the rollback journal")
        self.restart()
        self.pending.unlink()
        sync_dir(self.state)

    def install(self, version, stream):
        old_pid = self.running_pid()
        previous = self.verify(self.app)
        if version_parts(version) <= version_parts(previous["version"]):
            raise ValueError("release must be newer than the installed bundle")
        for label, program in ((f"{IDENTIFIER}.consent", "djinn-custodian-consent"), ("org.merely.djinn", "djinn")):
            self.job_pid(label, self.root / program)
        if self.candidate.exists():
            shutil.rmtree(self.candidate)
        try:
            unpack(stream, self.state)
            if self.verify(self.candidate)["version"] != version:
                raise ValueError("manifest and signed bundle versions differ")
            self.write_pending(previous)
            exchange(self.app, self.candidate)
            sync_dir(self.root)
            sync_dir(self.state)
            self.restart()
            if self.running_pid() == old_pid:
                raise RuntimeError("launchd did not replace the custodian process")
            self.pending.unlink()
            sync_dir(self.state)
        except BaseException:
            self.recover()
            raise
        finally:
            if not self.pending.exists() and self.candidate.is_dir():
                shutil.rmtree(self.candidate)


def main(args):
    if os.geteuid() != 0:
        raise RuntimeError("the macOS custodian update adapter must run as root")
    if args != ["running-version"] and not (len(args) == 2 and args[0] == "install"):
        raise ValueError("usage: djinn-custodian-upgrade running-version | install VERSION")
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    trusted(POLICY, stat.S_ISREG)
    trusted(ROOT, stat.S_ISDIR)
    update = Upgrade(json.loads(POLICY.read_text()))
    update.state.mkdir(mode=0o700, exist_ok=True)
    trusted(update.state, stat.S_ISDIR)
    with (update.state / "lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        update.recover()
        if args == ["running-version"]:
            update.running_pid()
            print(update.verify(update.app)["version"])
        else:
            update.install(args[1], sys.stdin.buffer)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, ValueError, RuntimeError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            diagnostic = error.stderr or error.output or b""
            print(diagnostic.decode(errors="replace").strip(), file=sys.stderr)
        print(f"djinn-custodian-upgrade: {error}", file=sys.stderr)
        sys.exit(1)
