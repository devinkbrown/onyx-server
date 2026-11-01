#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial fixture tests; mocked child behavior is not native acceptance."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import alpine_diagnostics_smoke as smoke


class DiagnosticsFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "artifact"
        self.source.write_bytes(b"fake artifact, never executed")
        self.child = None
        self.fixture_root = None
        self.secret = None

    def child_start(self, argv, **kwargs):
        self.assertIs(kwargs["preexec_fn"], smoke.limit_fixture_files)
        self.assertTrue(kwargs["start_new_session"])
        self.fixture_root = kwargs["cwd"]
        self.child = kwargs["stdout"]
        return object()

    def invoke(self, exchange):
        def command(argv, **kwargs):
            kwargs["stdout"].write(b"Onyx Server 0.8.1\n")
            return subprocess.CompletedProcess([], 0)
        with patch.object(smoke.os, "geteuid", return_value=1002), \
             patch.object(smoke.subprocess, "run", side_effect=command), \
             patch.object(smoke.subprocess, "Popen", side_effect=self.child_start), \
             patch.object(smoke, "registered_ping", side_effect=exchange), \
             patch.object(smoke, "budget_probe", return_value={}), \
             patch.object(smoke, "stop") as stop:
            try:
                return smoke.run(self.source)
            finally:
                stop.assert_called_once()

    def test_budget_oracle_requires_post_window_summary_and_counters(self):
        proof = {"accepted_delta": 200, "suppressed_delta": 72, "summary_offset": 42}
        prefix = b"onyx-server: connection suppressed=72\n".ljust(42, b"x")
        line = b"onyx-server: connection suppressed=72\n"
        smoke.verify_budget(prefix + line, b"private-canary", proof)
        with self.assertRaisesRegex(smoke.FixtureFailure, "summary missing"):
            smoke.verify_budget(prefix, b"private-canary", proof)
        with self.assertRaisesRegex(smoke.FixtureFailure, "counters did not advance"):
            smoke.verify_budget(prefix + line, b"private-canary", {**proof, "suppressed_delta": 0})
        with self.assertRaisesRegex(smoke.FixtureFailure, "private payload leaked"):
            smoke.verify_budget(prefix + line + b"private-canary", b"private-canary", proof)

    def test_private_marker_leak_fails_without_printing_child_output(self):
        def malicious_child(process, port, *, quit_marker):
            self.secret = quit_marker
            self.child.write(b"untrusted-log-prefix\n" + quit_marker + b"\n")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
            with self.assertRaises(smoke.FixtureFailure) as failure:
                self.invoke(malicious_child)
        self.assertEqual(str(failure.exception), "private QUIT text leaked into fixture log")
        self.assertTrue(self.secret.decode() not in str(failure.exception) + printed.getvalue(), "private marker appeared in failure diagnostics")
        self.assertTrue("untrusted-log-prefix" not in printed.getvalue(), "untrusted child output reached diagnostics")
        self.assertTrue(printed.getvalue() == "", "fixture emitted unexpected diagnostics")
        self.assertFalse(self.fixture_root.exists(), "private fixture was not cleaned up")

    def test_missing_diagnostics_is_failure_with_private_cleanup(self):
        def silent_child(process, port, *, quit_marker):
            self.child.write(b"untrusted-content\n")
        with self.assertRaisesRegex(smoke.FixtureFailure, "no typed connection diagnostics"):
            self.invoke(silent_child)
        self.assertFalse(self.fixture_root.exists())

    def test_exchange_failure_always_stops_child_and_cleans_up(self):
        def broken_child(process, port, *, quit_marker):
            raise smoke.FixtureFailure("fixture IRC exchange failed")
        with self.assertRaisesRegex(smoke.FixtureFailure, "fixture IRC exchange failed"):
            self.invoke(broken_child)
        self.assertFalse(self.fixture_root.exists())

    def test_log_at_kernel_bound_is_not_accepted(self):
        def noisy_child(process, port, *, quit_marker):
            self.child.write(b"x" * smoke.LOG_LIMIT)
        with self.assertRaisesRegex(smoke.FixtureFailure, "fixture log reached observation bound"):
            self.invoke(noisy_child)
        self.assertFalse(self.fixture_root.exists())


if __name__ == "__main__":
    unittest.main()
