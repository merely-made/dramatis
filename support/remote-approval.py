#!/usr/bin/env python3
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
"""Public custody approval over owner-pinned SSH and the local custody bridge.

The private operator config pins root_authority, root_issuer and devices. Each
device has public_key (hex), profile, helper (absolute path), and optional ssh
(an existing pinned SSH alias). Omitting ssh means local execution. SSH's host
key check is mandatory; the returned custody pins must match independently.
No passphrase or general custody operation is accepted by this tool.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading

LIMIT = 1024 * 1024


def key(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("expected a pinned 32-byte public key in hex")
    return list(bytes.fromhex(value))


def invoke(device, args, value=None):
    helper = device["helper"]
    if device.get("ssh"):
        host = device["ssh"]
        # SSH joins remote argv using a shell. Admit only these literal tokens.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host):
            raise ValueError("invalid SSH alias")
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", helper) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:/-]+", arg) for arg in args
        ):
            raise ValueError("remote helper and arguments must be literal shell-safe tokens")
        command = ["ssh", "-T", "-o", "StrictHostKeyChecking=yes", "-o",
                   "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, helper, *args]
    else:
        if not os.path.isabs(helper):
            raise ValueError("local helper path must be absolute")
        command = [helper, *args]
    payload = json.dumps(value).encode() if value is not None else b""
    if len(payload) > LIMIT:
        raise ValueError("public request exceeds route limit")
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    watchdog = threading.Timer(180, child.kill)
    watchdog.start()
    try:
        child.stdin.write(payload)
        child.stdin.close()
        result = child.stdout.read(LIMIT + 1)
        if len(result) > LIMIT:
            raise ValueError("public reply exceeds route limit")
        if child.wait() != 0:
            raise ValueError("approval helper did not complete; no success assumed")
        return json.loads(result)
    finally:
        watchdog.cancel()
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()


def relay(device, command):
    result = invoke(device, ["relay"], command)
    if result.get("reply") == "refused":
        raise ValueError("target refused: " + result["code"])
    return result


def state(config, device):
    result = relay(device, {"command": "state"})
    current = result.get("state", {})
    for field, expected in {
        "root_authority": key(config["root_authority"]),
        "root_issuer": key(config["root_issuer"]),
        "target": key(device["public_key"]),
        "profile": device["profile"],
    }.items():
        if current.get(field) != expected:
            raise ValueError("authenticated host returned an unpinned custody " + field)
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("action", choices=["state", "enroll", "approve"])
    parser.add_argument("target")
    parser.add_argument("device", nargs="?")
    parser.add_argument("--seconds", type=int, default=604800)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8-sig") as stream:
        config = json.load(stream)
    target = config["devices"][args.target]
    current = state(config, target)
    if args.action == "state":
        print(json.dumps(current))
        return
    if args.device is None:
        parser.error("enroll and approve require an approving device")
    device = config["devices"][args.device]
    if args.action == "enroll":
        root = config["devices"][config["root_device"]]
        if key(root["public_key"]) != key(config["root_issuer"]):
            raise ValueError("root signing device does not match the root pin")
        signed = invoke(root, ["enroll", root["profile"], device["public_key"], str(args.seconds)], current)
        reply = relay(target, {"command": "enroll", "grant": signed})
        after = state(config, target)
        if reply.get("reply") != "done" or signed not in after["enrollments"]:
            raise ValueError("enrollment was not read back from protected storage")
        print(json.dumps({"enrolled": args.device, "target": args.target,
                          "expires_at_ms": signed["certificate"]["expires_at_ms"]}))
        return
    challenge = relay(target, {"command": "challenge"})
    if challenge.get("reply") != "challenge":
        raise ValueError("no pending target challenge")
    subject = key(device["public_key"])
    enrollment = next((grant for grant in current["enrollments"]
                       if grant["certificate"]["subject"] == subject), None)
    if enrollment is None and subject != key(config["root_issuer"]):
        raise ValueError("approving device is not enrolled for this target")
    proof = invoke(device, ["approve", device["profile"]], {
        "state": current, "petition": challenge["petition"],
        "request": challenge["request"], "enrollment": enrollment,
    })
    reply = relay(target, {"command": "approve", "nonce": challenge["request"]["nonce"], "proof": proof})
    if reply.get("reply") != "done":
        raise ValueError("target did not commit the approval")
    print(json.dumps({"approved_by": args.device, "target": args.target,
                      "request": challenge["petition"]["request"]}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print("remote-approval: " + str(error), file=sys.stderr)
        sys.exit(2)
