#!/usr/bin/env python3
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Reviewed administrator activation of existing custody, without vault adoption.

Run with sudo on the target. Inputs are public pins and hash-checked binaries.
The service stays network-isolated. Its own account creates the enrollment DB.
The first activation refuses existing remote policy or authority storage.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_binary(path, expected):
    data = Path(path).read_bytes()
    if digest(data).lower() != expected.lower():
        raise ValueError("candidate binary differs from reviewed hash")
    return data


def atomic(path, data, mode, uid=0, gid=0):
    if path.is_symlink():
        raise ValueError("refusing indirect installed path")
    fd, name = tempfile.mkstemp(prefix=".approval-stage-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.chown(name, uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)  # Only this tool's uncommitted generated temp file.


def run(*args):
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["user", "binary", "binary-sha256", "helper", "helper-sha256", "root", "target", "profile"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("administrator authentication is required; run this reviewed command with sudo")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", args.user):
        raise ValueError("invalid service instance")
    root = list(bytes.fromhex(args.root))
    target = list(bytes.fromhex(args.target))
    if len(root) != 32 or len(target) != 32:
        raise ValueError("public root and target must each be 32 bytes")
    unit = "djinn-custodian@" + args.user + ".service"
    sockets = ["djinn-custodian@" + args.user + ".socket",
               "djinn-custodian-agent@" + args.user + ".socket"]
    config_path = Path("/etc/djinn-custodian") / (args.user + ".json")
    binary_path = Path("/usr/local/libexec/djinn-custodian")
    helper_path = Path("/usr/local/libexec/djinn-approval")
    owner = pwd.getpwnam(args.user)
    service = pwd.getpwnam("djinn-custodian-" + args.user)
    for path in [config_path, config_path.parent, binary_path, binary_path.parent]:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("installed paths must be direct, root-owned and protected")
    before = config_path.read_bytes()
    policy = json.loads(before)
    if policy.get("remote_approval") or any(p["name"] == "approval-bridge" for p in policy["principals"]):
        raise ValueError("remote approval is already configured; refusing a reset")
    if policy["owner"].get("unix_uid") != owner.pw_uid:
        raise ValueError("configured owner differs from target service instance")
    if policy["vault"].get("profile", args.profile) != args.profile:
        raise ValueError("profile differs from existing fixed policy")
    vault = Path(policy["vault"]["directory"])
    if (vault / "remote-approval.redb").exists():
        raise ValueError("existing authority storage preserved; inspect before activation")
    receiving = checked_binary(args.binary, args.binary_sha256)
    helper = checked_binary(args.helper, args.helper_sha256)
    policy["vault"]["profile"] = args.profile
    policy["max_unlocked_seconds"] = 604800
    policy["remote_approval"] = dict(root=dict(authority=root, issuer=root), target=target,
                                      profile=args.profile, actions=["consent"],
                                      max_grant_seconds=604800, max_unlock_seconds=604800)
    # Linux admission currently distinguishes UIDs, not executable paths.
    # Preserve that existing boundary; signing still requires per-use polkit.
    principal = next(p for p in policy["principals"] if p["match"] == {"unix-uid": owner.pw_uid})
    principal["grants"].extend([
        {"operation": "remote-approval-bridge"},
        {"operation": "attest", "profile": {"named": args.profile},
         "salts": [{"delegation": "merely.custody.remote-approval/v1"}], "consent": "per-operation"},
        {"operation": "sign", "profile": {"named": args.profile},
         "purpose": {"purpose": "delegation", "audience": "merely.custody.remote-approval/v1"},
         "consent": "per-operation"},
    ])
    updated = json.dumps(policy, indent=2).encode()
    backup = Path("/var/lib/djinn-custodian") / args.user / "approval-backup"
    backup.mkdir(mode=0o700, exist_ok=True)
    info = backup.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("backup directory is not protected")
    old_binary = binary_path.read_bytes()
    if helper_path.exists():
        info = helper_path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("existing helper is not protected")
    old_helper = helper_path.read_bytes() if helper_path.exists() else None
    for name, data in [("policy", before), ("binary", old_binary)]:
        path = backup / (name + "-" + digest(data))
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(data)
        if path.read_bytes() != data:
            raise ValueError("existing rollback copy differs")
    meta = config_path.stat()
    run("systemctl", "is-active", "--quiet", unit)
    active_sockets = [socket for socket in sockets if subprocess.run(
        ["systemctl", "is-active", "--quiet", socket]).returncode == 0]
    stopped = False
    try:
        run("systemctl", "stop", *active_sockets, unit)
        stopped = True
        atomic(binary_path, receiving, 0o755)
        atomic(helper_path, helper, 0o755)
        atomic(config_path, updated, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        run(str(binary_path), "validate-config", "--config", str(config_path))
        # Keep this public setup record in the already protected service state.
        setup_owned = vault.parent / "approval-setup.json"
        if setup_owned.exists():
            raise ValueError("existing setup config preserved")
        atomic(setup_owned, updated, 0o400, service.pw_uid, service.pw_gid)
        run("runuser", "-u", service.pw_name, "--", str(binary_path), "remote-init", "--config", str(setup_owned))
        run("systemctl", "start", *active_sockets, unit)
        for _ in range(60):
            run("systemctl", "is-active", "--quiet", unit)
            time.sleep(0.25)
        print(json.dumps(dict(status="activated-awaiting-unlock-and-enrollment", unit=unit,
                              binary_sha256=digest(receiving), helper_sha256=digest(helper))))
    except Exception:
        if stopped:
            run("systemctl", "stop", *active_sockets, unit)
            atomic(binary_path, old_binary, 0o755)
            atomic(config_path, before, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
            if old_helper is not None:
                atomic(helper_path, old_helper, 0o755)
            run("systemctl", "start", *active_sockets, unit)
        raise


if __name__ == "__main__":
    main()
