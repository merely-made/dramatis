#!/usr/bin/env python3
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("approval", Path(__file__).with_name("remote-approval.py"))
approval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(approval)


class AdmissionControls(unittest.TestCase):
    def test_authenticated_host_does_not_substitute_custody_pins(self):
        config = {"root_authority": "01" * 32, "root_issuer": "02" * 32}
        device = {"public_key": "03" * 32, "profile": "default"}
        state = {"root_authority": [1] * 32, "root_issuer": [2] * 32,
                 "target": [3] * 32, "profile": "default"}
        with patch.object(approval, "relay", return_value={"state": state}):
            self.assertEqual(approval.state(config, device), state)
        for field in state:
            wrong = dict(state)
            wrong[field] = "other" if field == "profile" else [4] * 32
            with patch.object(approval, "relay", return_value={"state": wrong}):
                with self.assertRaises(ValueError):
                    approval.state(config, device)

    def test_remote_shell_arguments_are_checked_before_launch(self):
        for device, args in [
            ({"ssh": "-oProxyCommand=bad", "helper": "/usr/local/libexec/djinn-approval"}, ["relay"]),
            ({"ssh": "T-PC", "helper": "/tmp/helper;touch /tmp/bad"}, ["relay"]),
            ({"ssh": "T-PC", "helper": "/usr/local/libexec/djinn-approval"}, ["sign", "$(bad)"]),
        ]:
            with patch.object(approval.subprocess, "Popen") as process:
                with self.assertRaises(ValueError):
                    approval.invoke(device, args)
                process.assert_not_called()

    def test_incomplete_route_is_not_reported_as_success(self):
        with patch.object(approval, "invoke", return_value={"reply": "refused", "code": "remote-chain"}):
            with self.assertRaisesRegex(ValueError, "remote-chain"):
                approval.relay({}, {"command": "enroll"})


if __name__ == "__main__":
    unittest.main()
