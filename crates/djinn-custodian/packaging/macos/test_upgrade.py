# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

import importlib.util
import io
import json
from pathlib import Path
import plistlib
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("upgrade_macos", Path(__file__).resolve().parents[2] / "upgrade-macos.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def archive(version):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        for path, content, mode in (
            ("Contents/Info.plist", plistlib.dumps({"CFBundleShortVersionString": version}), 0o644),
            (str(upgrade.EXECUTABLE), version.encode(), 0o755),
        ):
            entry = tarfile.TarInfo(f"{upgrade.APP}/{path}")
            entry.size = len(content)
            entry.mode = mode
            bundle.addfile(entry, io.BytesIO(content))
    stream.seek(0)
    return stream


class Fixture(upgrade.Upgrade):
    def __init__(self, root):
        self.root = root
        self.state = root / "state"
        self.state.mkdir()
        self.app = root / upgrade.APP
        self.candidate = self.state / upgrade.APP
        self.pending = self.state / "pending.json"
        self.pid = 1
        self.fail_restart = False
        upgrade.unpack(archive("0.0.1"), self.root)

    def verify(self, bundle):
        return upgrade.identity(bundle)

    def running_pid(self):
        return self.pid

    def job_pid(self, label, program):
        return self.pid

    def restart(self):
        if self.fail_restart:
            self.fail_restart = False
            raise RuntimeError("fixture launch failed")
        self.pid += 1


class ProfileVerification(unittest.TestCase):
    def test_installed_client_must_pin_the_release_certificate(self):
        certificate = "AB" * 20
        policy = {"owner": "markik", "team": "TEAM", "arch": "arm64", "certificate_sha1": certificate}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "clients").mkdir()
            client = root / "clients/501.json"
            for pin, accepted in ((certificate.lower(), True), ("CD" * 20, False), (None, False)):
                signer = {"team": "TEAM", "identifier": upgrade.IDENTIFIER}
                if pin is not None:
                    signer["certificate_sha1"] = pin
                client.write_text(json.dumps({"endpoint": "custody.sock", "server": {"signed": [signer]}}))
                with patch.object(upgrade, "command", return_value=b"501"), patch.object(upgrade, "trusted"):
                    if accepted:
                        upgrade.Upgrade(policy, root)
                    else:
                        with self.assertRaisesRegex(ValueError, "different signers"):
                            upgrade.Upgrade(policy, root)

    def test_profile_check_uses_system_roots_and_checks_the_signature(self):
        roots = b"system root certificates"
        profile = Path("embedded.provisionprofile")
        payload = {"Entitlements": {"com.apple.application-identifier": "TEAM.custodian"}}
        with patch.object(upgrade, "command", return_value=roots) as command, \
                patch.object(upgrade.subprocess, "run") as decode:
            decode.return_value.stdout = plistlib.dumps(payload)
            self.assertEqual(upgrade.provisioning_profile(profile), payload)
            command.assert_called_once_with(
                "/usr/bin/security", "find-certificate", "-a", "-p",
                "/System/Library/Keychains/SystemRootCertificates.keychain",
            )
            self.assertEqual(decode.call_args.args[0], [
                "/usr/bin/openssl", "cms", "-verify", "-inform", "DER", "-in", profile,
                "-CAfile", "/dev/stdin", "-purpose", "any",
            ])
            self.assertIs(decode.call_args.kwargs["check"], True)
            self.assertEqual(decode.call_args.kwargs["input"], roots)


@unittest.skipUnless(sys.platform == "darwin", "uses the native atomic bundle exchange")
class BundleUpdate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.adapter = Fixture(Path(temporary.name))

    def test_darwin_exchange_and_replay(self):
        self.adapter.install("0.0.2", archive("0.0.2"))
        self.assertEqual(upgrade.identity(self.adapter.app)["version"], "0.0.2")
        self.assertEqual(self.adapter.pid, 2)
        with self.assertRaisesRegex(ValueError, "newer"):
            self.adapter.install("0.0.2", archive("0.0.2"))

    def test_restart_failure_restores_the_old_bundle(self):
        previous = upgrade.identity(self.adapter.app)
        self.adapter.fail_restart = True
        with self.assertRaisesRegex(RuntimeError, "fixture launch failed"):
            self.adapter.install("0.0.2", archive("0.0.2"))
        self.assertEqual(upgrade.identity(self.adapter.app), previous)
        self.assertFalse(self.adapter.pending.exists())
        self.assertEqual(self.adapter.pid, 2)

    def test_signed_version_must_match_manifest_version(self):
        with self.assertRaisesRegex(ValueError, "versions differ"):
            self.adapter.install("0.0.3", archive("0.0.2"))
        self.assertEqual(upgrade.identity(self.adapter.app)["version"], "0.0.1")
        self.assertEqual(self.adapter.pid, 1)

    def test_archive_rejects_links_and_paths_outside_the_bundle(self):
        for name, kind in ((f"{upgrade.APP}/Contents/link", tarfile.SYMTYPE),
                           (f"{upgrade.APP}/../unexpected", tarfile.REGTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as staging:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    bundle.addfile(entry)
                stream.seek(0)
                with self.assertRaisesRegex(ValueError, "unexpected archive entry"):
                    upgrade.unpack(stream, Path(staging))
                self.assertEqual(list(Path(staging).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
