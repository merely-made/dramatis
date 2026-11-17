#!/usr/bin/python3 -I
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

"""Administrator bootstrap for the certificate-pinned macOS runtime cohort.

Keeps vault data and grants, journals a compressed rollback, and narrows the
existing peer requirements. Normal app updates continue through Luggage.
"""

import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path("/Library/Application Support/Merely/djinn-custodian")
ADAPTER = Path("/usr/local/libexec/djinn-custodian-upgrade")
UPDATE_POLICY = Path("/private/etc/djinn-custodian/upgrade.json")
APP = "djinn-custodian.app"
IDENTIFIER = "com.merely.djinn.custodian"
LIMIT = 160_000_000


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def command(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=20)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def trusted(path):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f"administrator ownership required: {path}")


def write(path, data, mode=0o644):
    fd, name = tempfile.mkstemp(prefix=".cohort-", dir=path.parent)
    candidate = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(candidate, path)
        sync_dir(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def unpack(archive, destination, allowed):
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as stream:
        for entry in stream:
            path = PurePosixPath(entry.name)
            if (not path.parts or path.parts[0] not in allowed or ".." in path.parts
                    or path.as_posix() != entry.name.rstrip("/") or path in seen
                    or not (entry.isdir() or entry.isfile())):
                raise ValueError(f"unexpected cohort entry: {entry.name!r}")
            seen.add(path)
            output = destination.joinpath(*path.parts)
            if entry.isdir():
                output.mkdir(parents=True, exist_ok=True)
            else:
                total += entry.size
                if total > LIMIT:
                    raise ValueError("cohort exceeds its unpacked size bound")
                output.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(entry) as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
                output.chmod(0o755 if entry.mode & 0o111 else 0o644)
    if {path.name for path in destination.iterdir()} != set(allowed):
        raise ValueError("cohort does not contain the complete component set")
    for directory, _, _ in os.walk(destination, topdown=False):
        if Path(directory) != destination:
            os.chmod(directory, 0o755)
        sync_dir(directory)


def snapshot(objects):
    result = {}
    for name, path in objects.items():
        for item in ([path] if path.is_file() else path.rglob("*")):
            if item.is_symlink():
                raise ValueError("cohort objects cannot contain links")
            if item.is_file():
                key = name if item == path else name + "/" + str(item.relative_to(path))
                result[key] = digest(item)
    return result


class Cohort:
    def __init__(self, policy, root=ROOT, adapter=ADAPTER):
        self.policy, self.root, self.adapter = policy, root, adapter
        self.owner = policy["owner"]
        self.uid = int(command("/usr/bin/id", "-u", self.owner))
        self.domain = f"gui/{self.uid}"
        self.objects = {APP: root / APP, "djinn": root / "djinn",
                        "djinn-custodian-consent": root / "djinn-custodian-consent",
                        "policy.json": root / f"{self.owner}.json",
                        "client.json": root / "clients" / f"{self.uid}.json", "adapter": adapter}
        self.recovery = root / ".certificate-pin-recovery"
        self.recovery.mkdir(mode=0o700, exist_ok=True)
        trusted(self.recovery)
        self.journal = self.recovery / "journal.json"
        self.backup = self.recovery / "cohort.tar.gz"

    def services(self, start):
        labels = [IDENTIFIER, IDENTIFIER + ".consent", "org.merely.djinn"]
        if not start:
            pids = []
            for label in reversed(labels):
                try:
                    status = command("/bin/launchctl", "print", f"{self.domain}/{label}")
                    match = re.search(rb"^\s*pid = (\d+)$", status, re.M)
                    if match:
                        pids.append(int(match[1]))
                except subprocess.CalledProcessError:
                    pass
                subprocess.run(["/bin/launchctl", "disable", f"{self.domain}/{label}"], check=True)
                subprocess.run(["/bin/launchctl", "bootout", f"{self.domain}/{label}"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 15
            for pid in pids:
                while True:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("a prior cohort process has not stopped")
                    time.sleep(0.05)
            return
        home = Path(command("/usr/bin/dscl", ".", "-read", f"/Users/{self.owner}", "NFSHomeDirectory").decode().split(": ", 1)[1].strip())
        for label in labels:
            plist = (home / "Library/LaunchAgents" if label == "org.merely.djinn" else Path("/Library/LaunchAgents")) / f"{label}.plist"
            command("/bin/launchctl", "enable", f"{self.domain}/{label}")
            command("/bin/launchctl", "asuser", str(self.uid), "/usr/bin/sudo", "-n", "-u", self.owner,
                    "/bin/launchctl", "bootstrap", self.domain, str(plist))

    def verify_program(self, path, identifier):
        requirement = (f'anchor apple generic and identifier "{identifier}" and '
                       f'certificate leaf[subject.OU] = "{self.policy["team"]}" and '
                       f'certificate leaf = H"{self.policy["certificate_sha1"]}"')
        command("/usr/bin/codesign", "--verify", "--strict", "--deep", f"-R={requirement}", str(path))
        info = command("/usr/bin/codesign", "-d", "--verbose=4", str(path))
        claims = command("/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(path))
        if (not re.search(rb"^CodeDirectory.*flags=.*runtime", info, re.M)
                or not re.search(rb"^Timestamp=", info, re.M) or b"get-task-allow" in claims):
            raise ValueError("cohort programs need hardened runtime, secure timestamp and no debug entitlement")
        binary = path / "Contents/MacOS/djinn-custodian" if path.is_dir() else path
        if command("/usr/bin/lipo", "-archs", str(binary)).decode().strip() != self.policy["arch"]:
            raise ValueError("cohort architecture differs from the installed update policy")

    def narrow(self):
        certificate, team = self.policy["certificate_sha1"], self.policy["team"]
        config = json.loads(self.objects["policy.json"].read_text())
        for rule in config["principals"]:
            signed = rule["match"].get("signed")
            if signed is not None:
                if signed["team"] != team or signed["identifier"] not in {IDENTIFIER + ".consent", "com.merely.djinn"}:
                    raise ValueError("additional signed principals require an explicit migration")
                signed["certificate_sha1"] = certificate
        client = json.loads(self.objects["client.json"].read_text())
        signers = client["server"].get("signed", [])
        if len(signers) != 1 or signers[0]["team"] != team or signers[0]["identifier"] != IDENTIFIER:
            raise ValueError("unexpected installed server expectation")
        signers[0]["certificate_sha1"] = certificate
        return {"policy.json": json.dumps(config, indent=2).encode(),
                "client.json": json.dumps(client, indent=2).encode()}

    def save(self):
        current = snapshot(self.objects)
        if self.journal.exists():
            journal = json.loads(self.journal.read_text())
            if journal["previous"] != current or journal["phase"] not in {"saved", "restored"}:
                raise RuntimeError("a previous migration still needs recovery or acceptance")
            return current
        with tarfile.open(self.backup, "w:gz") as archive:
            for name, path in self.objects.items():
                archive.add(path, arcname=name)
        with self.backup.open("rb") as stream:
            os.fsync(stream.fileno())
        sync_dir(self.recovery)
        # Verify every saved file without expanding a second runtime copy.
        with tarfile.open(self.backup, "r:gz") as archive:
            restored = {entry.name: hashlib.sha256(archive.extractfile(entry).read()).hexdigest()
                        for entry in archive if entry.isfile()}
        if current != restored:
            raise RuntimeError("cohort rollback verification failed")
        write(self.journal, json.dumps({"phase": "saved", "previous": current}).encode(), 0o600)
        return current

    def place(self, source, target):
        if target.is_dir():
            shutil.rmtree(target)
        os.replace(source, target)
        sync_dir(source.parent)
        sync_dir(target.parent)

    def restore(self):
        journal = json.loads(self.journal.read_text())
        self.services(False)
        with tempfile.TemporaryDirectory(prefix="restore-", dir=self.recovery) as temporary:
            restored = Path(temporary)
            unpack(self.backup, restored, self.objects)
            for name, target in self.objects.items():
                self.place(restored / name, target)
        if snapshot(self.objects) != journal["previous"]:
            raise RuntimeError("restored cohort differs from its journal")
        self.services(True)
        journal["phase"] = "restored"
        write(self.journal, json.dumps(journal).encode(), 0o600)

    def verify_app(self, incoming, replacement_adapter):
        loader = importlib.machinery.SourceFileLoader("cohort_adapter", str(replacement_adapter))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(module)
        verifier = object.__new__(module.Upgrade)
        verifier.team, verifier.arch = self.policy["team"], self.policy["arch"]
        verifier.requirement = (f'anchor apple generic and identifier "{IDENTIFIER}" and '
                                f'certificate leaf = H"{self.policy["certificate_sha1"]}"')
        previous = verifier.verify(self.root / APP)
        candidate = verifier.verify(incoming / APP)
        if module.version_parts(candidate["version"]) <= module.version_parts(previous["version"]):
            raise ValueError("cohort must be newer than the installed bundle")

    def validate(self):
        command(str(self.root / APP / "Contents/MacOS/djinn-custodian"), "validate-config",
                "--config", str(self.objects["policy.json"]))

    def apply(self, incoming, replacement_adapter):
        self.verify_app(incoming, replacement_adapter)
        for path, identifier in ((incoming / APP, IDENTIFIER),
                                 (incoming / "djinn-custodian-consent", IDENTIFIER + ".consent"),
                                 (incoming / "djinn", "com.merely.djinn")):
            self.verify_program(path, identifier)
        narrowed = self.narrow()
        previous = self.save()
        write(self.journal, json.dumps({"phase": "pending", "previous": previous}).encode(), 0o600)
        try:
            self.services(False)
            for name in (APP, "djinn-custodian-consent", "djinn"):
                self.place(incoming / name, self.objects[name])
            for name, content in narrowed.items():
                write(self.objects[name], content)
            write(self.adapter, replacement_adapter.read_bytes(), 0o755)
            self.validate()
            self.services(True)
            write(self.journal, json.dumps({"phase": "applied", "previous": previous,
                                           "installed": snapshot(self.objects)}).encode(), 0o600)
        except BaseException:
            # Remaining candidates are generated delivery, never live code.
            # Release them before expanding the compressed rollback cohort.
            if incoming.exists():
                shutil.rmtree(incoming)
            self.restore()
            raise

    def accept(self):
        journal = json.loads(self.journal.read_text())
        if journal["phase"] != "applied" or snapshot(self.objects) != journal["installed"]:
            raise RuntimeError("the applied cohort changed before acceptance")
        journal["phase"] = "accepted"
        write(self.root / "certificate-pin-accepted.json", json.dumps(journal).encode())
        # This is the marker-identified generated rollback, after the
        # operator's native consent and identity gate. Personal data is outside it.
        shutil.rmtree(self.recovery)


def main(args):
    if os.geteuid() != 0 or not (len(args) == 2 or args == ["accept"]):
        raise ValueError("run as administrator: replace-fleet-cohort.py STAGED-DIRECTORY CHECKSUM-SHA256 | accept")
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    trusted(ROOT)
    trusted(UPDATE_POLICY)
    policy = json.loads(UPDATE_POLICY.read_text())
    if (not re.fullmatch(r"[a-z_][a-z0-9_-]*", policy["owner"])
            or not re.fullmatch(r"[A-Z0-9]+", policy["team"])
            or not re.fullmatch(r"[A-Fa-f0-9]{40}", policy["certificate_sha1"])
            or policy["arch"] not in {"arm64", "x86_64"}):
        raise ValueError("invalid installed update policy")
    if command("/usr/bin/stat", "-f", "%Su", "/dev/console").decode().strip() != policy["owner"]:
        raise ValueError("run this bootstrap in the vault owner's GUI session")
    cohort = Cohort(policy)
    state = ROOT / ".djinn-custodian-upgrade"
    state.mkdir(mode=0o700, exist_ok=True)
    trusted(state)
    # Serialize the bootstrap with the installed Luggage adapter, too.
    with (state / "lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args == ["accept"]:
            cohort.accept()
            print("Native cohort accepted; temporary rollback cleared.")
            return
        if (state / "pending.json").exists():
            raise RuntimeError("recover the prior app update before replacing the cohort")
        if cohort.journal.exists():
            journal = json.loads(cohort.journal.read_text())
            if journal["phase"] == "pending":
                cohort.restore()
            elif journal["phase"] == "applied":
                if snapshot(cohort.objects) != journal["installed"]:
                    raise RuntimeError("applied cohort differs from its journal")
                print("Certificate-pinned cohort is already applied; continue owner acceptance.")
                return
        receive(cohort, Path(args[0]), args[1])


def receive(cohort, source, checksum):
    with tempfile.TemporaryDirectory(prefix=".cohort-receive-", dir=ROOT) as temporary:
        private = Path(temporary)
        for name in ("SHA256SUMS", "cohort.tar.gz", "djinn-custodian-upgrade"):
            shutil.copyfile(source / name, private / name)
        if digest(private / "SHA256SUMS") != checksum:
            raise ValueError("cohort checksum list differs from the pinned receipt")
        entries = {}
        for line in (private / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ", 1)
            if name not in {"cohort.tar.gz", "djinn-custodian-upgrade"} or name in entries:
                raise ValueError("unexpected pinned cohort file")
            entries[name] = expected
            if digest(private / name) != expected:
                raise ValueError("cohort input digest differs")
        if len(entries) != 2:
            raise ValueError("incomplete cohort checksum list")
        incoming = private / "cohort"
        incoming.mkdir()
        unpack(private / "cohort.tar.gz", incoming, {APP, "djinn-custodian-consent", "djinn"})
        cohort.apply(incoming, private / "djinn-custodian-upgrade")
        print("Certificate-pinned cohort applied; owner unlock and identity acceptance remain.")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"replace-fleet-cohort: {error}", file=sys.stderr)
        sys.exit(1)
