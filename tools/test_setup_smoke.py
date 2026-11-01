#!/usr/bin/env python3
"""Failure-output secrecy regressions for the setup acceptance harness.

Set ONYX_SETUP_SMOKE_TEST_BINARY to a current artifact to enable the PTY case.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MARKER = b"PRIVATE_FIXTURE_SECRET_MUST_NOT_BE_LOGGED"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux setup harness")
class FailureSecrecy(unittest.TestCase):
    def setUp(self):
        parent = ROOT / ".zig-cache/setup-smoke-tests"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def exercise(self, code, exit_code, expected):
        wrapper = self.work / "fixture"
        wrapper.write_text("#!/usr/bin/env python3\n" + code + "\n")
        wrapper.chmod(0o700)
        probe = subprocess.run([str(wrapper), "--interactive"], capture_output=True, timeout=5)
        self.assertEqual(exit_code, probe.returncode)
        self.assertTrue(MARKER in probe.stdout + probe.stderr, "negative fixture did not emit marker")
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/setup_smoke.py"), "--binary", str(wrapper)],
            cwd=ROOT, capture_output=True, timeout=30,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(MARKER not in result.stdout + result.stderr, "captured fixture secret escaped")
        self.assertTrue(expected in result.stderr, "intended diagnostic path was not exercised")

    def test_child_stderr_never_appears_in_failure_diagnostics(self):
        self.exercise(
            f"import sys; sys.stderr.buffer.write({MARKER!r}); sys.exit(7)",
            7, b"CLI status mismatch",
        )

    def test_pty_capture_never_appears_in_failure_diagnostics(self):
        configured = os.environ.get("ONYX_SETUP_SMOKE_TEST_BINARY")
        if not configured:
            self.skipTest("set ONYX_SETUP_SMOKE_TEST_BINARY for the real setup prerequisite")
        binary = str(Path(configured).resolve(strict=True))
        code = (
            "import os, sys, time\n"
            "if '--interactive' in sys.argv:\n"
            f"    os.write(1, b'Profile selection\\n' + {MARKER!r})\n"
            "    time.sleep(.2)\n"
            "    sys.exit(17)\n"
            f"os.execv({binary!r}, [{binary!r}] + sys.argv[1:])\n"
        )
        self.exercise(code, 17, b"PTY status mismatch")


if __name__ == "__main__":
    unittest.main()
