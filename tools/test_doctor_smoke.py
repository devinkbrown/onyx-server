#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial capture tests; mocked output does not prove native CLI behavior."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import doctor_smoke as smoke


class DoctorSmokeTests(unittest.TestCase):
    def test_malformed_private_child_output_stays_out_of_failure(self):
        secret = b"PRIVATE_CHILD_OUTPUT_MUST_NOT_REACH_TEST_FAILURES"

        def child(*args, **kwargs):
            kwargs["stdout"].write(secret)
            kwargs["stderr"].write(secret)
            return subprocess.CompletedProcess([], 0)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.write_bytes(b"")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                with patch.object(smoke.subprocess, "run", side_effect=child):
                    with self.assertRaises(smoke.SmokeFailure) as failure:
                        smoke.invoke(root / "unused", root, candidate, "case")
            self.assertTrue(str(failure.exception) == "doctor JSON is malformed", "failure reason changed")
            self.assertTrue(secret.decode() not in str(failure.exception) + captured.getvalue(),
                            "private output reached failure diagnostics")
            self.assertTrue(captured.getvalue() == "", "fixture emitted captured output")

    def test_capture_limit_rejected_before_json_decode(self):
        def child(*args, **kwargs):
            kwargs["stdout"].write(b"x" * smoke.LIMIT)
            return subprocess.CompletedProcess([], 0)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(smoke.subprocess, "run", side_effect=child):
                with self.assertRaisesRegex(smoke.SmokeFailure, "doctor capture reached bound"):
                    smoke.invoke(root / "unused", root, root / "candidate", "case")


if __name__ == "__main__":
    unittest.main()
