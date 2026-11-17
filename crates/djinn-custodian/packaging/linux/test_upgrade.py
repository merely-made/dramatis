# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[2] / "upgrade-linux.py"
SPEC = importlib.util.spec_from_file_location("custodian_upgrade", PATH)
if sys.platform == "linux":
    upgrade = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(upgrade)


@unittest.skipUnless(sys.platform == "linux", "requires Linux directory fsync and an ELF fixture")
class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.binary = Path(workspace.name) / "djinn-custodian"
        self.baseline = Path("/usr/bin/true").read_bytes()
        self.binary.write_bytes(self.baseline)
        self.original_sha = upgrade.digest(self.binary)
        self.candidate = self.baseline + b"candidate"
        self.starts = []
        self.healthy = True
        self.identity = {"target": [7] * 32, "profile": "default"}
        policy = {
            "owner": "test",
            "baseline_sha256": self.original_sha,
            "baseline_version": "0.0.1",
        }
        self.adapter = upgrade.Upgrade(policy, self.binary)
        self.adapter.state.mkdir()
        self.adapter.check_service_scope = lambda: None
        self.adapter.running_pid = lambda: 5
        self.adapter.service_identity = lambda: dict(self.identity)
        self.adapter.keep_label = lambda path: None
        self.adapter.restart_verified = self.restart

    def restart(self, identity):
        binary = self.binary.read_bytes()
        self.starts.append(binary)
        self.assertEqual(identity, self.identity)
        if binary != self.baseline and not self.healthy:
            raise RuntimeError("candidate was unhealthy")

    def test_success_keeps_original_for_recovery_and_resolves_exact_version(self):
        self.adapter.install("0.0.2", io.BytesIO(self.candidate))
        self.assertEqual(self.starts, [self.candidate])
        self.assertEqual(self.binary.read_bytes(), self.candidate)
        self.assertEqual(self.adapter.previous.read_bytes(), self.baseline)
        self.assertEqual(self.adapter.version(upgrade.digest(self.binary)), "0.0.2")
        self.assertFalse(self.adapter.pending.exists())

    def test_failed_restart_restores_the_original(self):
        self.healthy = False
        with self.assertRaisesRegex(RuntimeError, "candidate was unhealthy"):
            self.adapter.install("0.0.2", io.BytesIO(self.candidate))
        self.assertEqual(self.starts, [self.candidate, self.baseline])
        self.assertEqual(self.adapter.version(upgrade.digest(self.binary)), "0.0.1")
        self.assertFalse(self.adapter.pending.exists())

    def test_interrupted_swap_is_recovered_on_the_next_call(self):
        self.adapter.previous.hardlink_to(self.binary)
        self.adapter.write_state(
            "pending.json", {"sha256": self.original_sha, "identity": self.identity},
        )
        self.adapter.stage(io.BytesIO(self.candidate)).replace(self.binary)
        self.adapter.recover()
        self.assertEqual(self.starts, [self.baseline])
        self.assertEqual(self.binary.read_bytes(), self.baseline)
        self.assertFalse(self.adapter.pending.exists())

    def test_invalid_payload_leaves_the_service_alone(self):
        with self.assertRaisesRegex(ValueError, "not an ELF binary"):
            self.adapter.install("0.0.2", io.BytesIO(b"invalid"))
        self.assertEqual(self.starts, [])
        self.assertEqual(self.binary.read_bytes(), self.baseline)
        self.assertFalse((self.adapter.state / "candidate").exists())


if __name__ == "__main__":
    unittest.main()
