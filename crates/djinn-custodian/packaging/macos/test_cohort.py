# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

import getpass
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("cohort", Path(__file__).with_name("replace-fleet-cohort.py"))
cohort = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cohort)
CERTIFICATE = "AB" * 20


class Fixture(cohort.Cohort):
    """Real file transactions with fake programs; native signing has its own gate."""

    def __init__(self, root):
        policy = {"owner": getpass.getuser(), "team": "TEAM", "arch": "arm64", "certificate_sha1": CERTIFICATE}
        with patch.object(cohort, "trusted"):
            super().__init__(policy, root, root / "adapter")
        self.calls = []
        self.fail_validate = self.fail_start = False

    def verify_program(self, path, identifier):
        pass

    def verify_app(self, incoming, replacement_adapter):
        pass

    def validate(self):
        if self.fail_validate:
            raise RuntimeError("fixture policy check failed")

    def services(self, start):
        self.calls.append(start)
        if start and self.fail_start:
            self.fail_start = False
            raise RuntimeError("fixture restart failed")


class CohortTransactions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "installed"
        self.root.mkdir()
        self.adapter = Fixture(self.root)
        self.stage = self.directory / "incoming"
        self.stage.mkdir()
        for directory, content in ((self.root, b"old program"), (self.stage, b"new program")):
            app = directory / cohort.APP / "Contents/MacOS"
            app.mkdir(parents=True)
            (app / "djinn-custodian").write_bytes(content)
            for name in ("djinn", "djinn-custodian-consent"):
                (directory / name).write_bytes(content)
        self.replacement = self.directory / "new-adapter"
        self.replacement.write_bytes(b"new adapter")
        self.adapter.adapter.write_bytes(b"old adapter")
        self.adapter.objects["client.json"].parent.mkdir()
        self.config = {
            "max_unlocked_seconds": 1234, "vault": {"directory": "/retained/vault"},
            "principals": [{"name": "djinn", "match": {"signed": {"team": "TEAM", "identifier": "com.merely.djinn"}},
                            "grants": [{"operation": "status"}]}],
        }
        self.adapter.objects["policy.json"].write_text(json.dumps(self.config))
        self.adapter.objects["client.json"].write_text(json.dumps({"endpoint": "unchanged.sock", "server": {
            "signed": [{"team": "TEAM", "identifier": cohort.IDENTIFIER}]}}))
        self.personal = self.root / "personal-vault"
        self.personal.write_bytes(b"synthetic private state must stay unchanged")
        self.previous = cohort.snapshot(self.adapter.objects)

    def test_cohort_and_peer_policies_move_together_without_changing_grants_or_data(self):
        self.adapter.apply(self.stage, self.replacement)
        config = json.loads(self.adapter.objects["policy.json"].read_text())
        self.assertEqual(config["max_unlocked_seconds"], 1234)
        self.assertEqual(config["principals"][0]["grants"], self.config["principals"][0]["grants"])
        self.assertEqual(config["principals"][0]["match"]["signed"]["certificate_sha1"], CERTIFICATE)
        client = json.loads(self.adapter.objects["client.json"].read_text())
        self.assertEqual(client["server"]["signed"][0]["certificate_sha1"], CERTIFICATE)
        self.assertEqual(client["endpoint"], "unchanged.sock")
        self.assertEqual(self.adapter.adapter.read_bytes(), b"new adapter")
        self.assertEqual(self.adapter.calls, [False, True])
        self.assertEqual(self.personal.read_bytes(), b"synthetic private state must stay unchanged")

    def test_policy_failure_restores_every_prior_component_and_configuration(self):
        self.adapter.fail_validate = True
        with self.assertRaisesRegex(RuntimeError, "policy check failed"):
            self.adapter.apply(self.stage, self.replacement)
        self.assertEqual(cohort.snapshot(self.adapter.objects), self.previous)
        self.assertEqual(json.loads(self.adapter.journal.read_text())["phase"], "restored")
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.personal.read_bytes(), b"synthetic private state must stay unchanged")

    def test_restart_failure_restores_both_programs_and_certificate_policy(self):
        self.adapter.fail_start = True
        with self.assertRaisesRegex(RuntimeError, "restart failed"):
            self.adapter.apply(self.stage, self.replacement)
        self.assertEqual(cohort.snapshot(self.adapter.objects), self.previous)
        self.assertEqual(self.adapter.calls, [False, True, False, True])

    def test_interrupted_transaction_recovers_from_its_verified_rollback(self):
        previous = self.adapter.save()
        cohort.write(self.adapter.journal, json.dumps({"phase": "pending", "previous": previous}).encode())
        self.adapter.objects["djinn"].write_bytes(b"interrupted replacement")
        self.adapter.restore()
        self.assertEqual(cohort.snapshot(self.adapter.objects), self.previous)
        self.assertEqual(self.adapter.save(), self.previous)

    def test_acceptance_preserves_personal_data_and_refuses_a_changed_cohort(self):
        self.adapter.apply(self.stage, self.replacement)
        self.adapter.objects["djinn"].write_bytes(b"tampered after application")
        with self.assertRaisesRegex(RuntimeError, "changed before acceptance"):
            self.adapter.accept()
        self.assertTrue(self.adapter.backup.exists())
        self.adapter.objects["djinn"].write_bytes(b"new program")
        self.adapter.accept()
        self.assertFalse(self.adapter.recovery.exists())
        self.assertTrue((self.root / "certificate-pin-accepted.json").is_file())
        self.assertEqual(self.personal.read_bytes(), b"synthetic private state must stay unchanged")

    def test_archive_refuses_links_duplicate_names_and_outside_paths(self):
        for name, kind, duplicate in (("djinn", tarfile.SYMTYPE, False),
                                      (cohort.APP + "/../outside", tarfile.REGTYPE, False),
                                      ("djinn", tarfile.REGTYPE, True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "cohort.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    for _ in range(2 if duplicate else 1):
                        item = tarfile.TarInfo(name)
                        item.type = kind
                        stream.addfile(item, io.BytesIO())
                output = root / "output"
                output.mkdir()
                with self.assertRaisesRegex(ValueError, "unexpected cohort entry"):
                    cohort.unpack(archive, output, {cohort.APP, "djinn", "djinn-custodian-consent"})


if __name__ == "__main__":
    unittest.main()
