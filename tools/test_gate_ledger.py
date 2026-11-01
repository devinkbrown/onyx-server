#!/usr/bin/env python3
"""Evidence invalidation tests; these do not run Onyx or installed services."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gate_ledger", Path(__file__).with_name("gate_ledger.py"))
ledger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src/a").write_text("initial")
        self.record = self.root / "evidence/gate.json"
        self.command = [sys.executable, "-c", "print('3 passed, 1 skipped')"]
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)

    def run_gate(self, command=None):
        return ledger.run(self.root, self.record, ["src"], command or self.command)

    def test_success_and_private_evidence(self):
        self.assertEqual(0, self.run_gate())
        self.assertEqual(0, ledger.status(self.root, self.record))
        self.assertEqual(0o600, self.record.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.record.with_suffix(".log").stat().st_mode & 0o777)
        self.assertIn("1 skipped", self.record.with_suffix(".log").read_text())
        with self.assertRaises(FileExistsError):
            self.run_gate()

    def test_changed_added_deleted_source_and_environment_invalidate(self):
        self.run_gate()
        source = self.root / "src/a"
        source.write_text("changed")
        self.assertEqual(1, ledger.status(self.root, self.record))
        source.write_text("initial")
        added = self.root / "src/new"
        added.write_text("added")
        self.assertEqual(1, ledger.status(self.root, self.record))
        added.unlink()
        source.unlink()
        self.assertEqual(1, ledger.status(self.root, self.record))
        source.write_text("initial")
        with patch.dict(os.environ, {"ONYX_LEDGER_TEST": "changed"}):
            self.assertEqual(1, ledger.status(self.root, self.record))
        self.assertEqual(0, ledger.status(self.root, self.record))

    def test_nonzero_gate_never_current(self):
        self.assertEqual(1, self.run_gate([sys.executable, "-c", "raise SystemExit(4)"]))
        self.assertEqual(1, ledger.status(self.root, self.record))

    def test_gate_mutating_dependency_never_current(self):
        self.assertEqual(1, self.run_gate([sys.executable, "-c",
            "from pathlib import Path; Path('src/a').write_text('changed')"]))
        self.assertFalse(json.loads(self.record.read_text())["unchanged"])
        self.assertEqual(1, ledger.status(self.root, self.record))

    def test_log_tampering_invalidates(self):
        self.run_gate()
        self.record.with_suffix(".log").write_text("changed")
        self.assertEqual(1, ledger.status(self.root, self.record))

    def test_missing_or_symlink_dependency_refused(self):
        with self.assertRaises(ValueError):
            ledger.snapshot(self.root, ["missing"], self.command)
        (self.root / "src/link").symlink_to(self.root / "src/a")
        with self.assertRaises(ValueError):
            ledger.snapshot(self.root, ["src"], self.command)

    def test_explicit_external_dependency_is_content_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "dependency"
            external.write_text("initial")
            before = ledger.snapshot(self.root, ["src", str(external)], self.command)
            external.write_text("changed")
            self.assertNotEqual(before, ledger.snapshot(
                self.root, ["src", str(external)], self.command))

    def test_orchestrator_call_id_does_not_invalidate_evidence(self):
        self.run_gate()
        with patch.dict(os.environ, {"CODEX_TOOL_CALL_ID": "another-call"}):
            self.assertEqual(0, ledger.status(self.root, self.record))

    def test_explicit_cli_root_controls_command_and_evidence(self):
        command = [sys.executable, "-c", "from pathlib import Path; print(Path.cwd()); print(Path('src/a').read_text())"]
        arguments = ["gate_ledger.py", "run", "--root", str(self.root),
                     "--record", str(self.record), "--input", "src", "--", *command]
        with patch.object(sys, "argv", arguments):
            self.assertEqual(0, ledger.main())
        self.assertEqual(str(self.root), json.loads(self.record.read_text())["root"])
        self.assertEqual([str(self.root), "initial"], self.record.with_suffix(".log").read_text().splitlines())
        arguments = ["gate_ledger.py", "status", "--root", str(self.root), "--record", str(self.record)]
        with patch.object(sys, "argv", arguments):
            self.assertEqual(0, ledger.main())
        with tempfile.TemporaryDirectory() as other:
            other_root = Path(other)
            (other_root / "src").mkdir()
            (other_root / "src/a").write_text("initial")
            arguments[arguments.index(str(self.root))] = str(other_root)
            with patch.object(sys, "argv", arguments):
                self.assertEqual(1, ledger.main())

    def test_cli_root_rejects_file_before_running_command(self):
        arguments = ["gate_ledger.py", "run", "--root", str(self.root / "src/a"),
                     "--record", str(self.record), "--input", "src", "--", *self.command]
        with patch.object(sys, "argv", arguments), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                ledger.main()
        self.assertFalse(self.record.exists())


class ContinuationDecisions(unittest.TestCase):
    setUp = LedgerTests.setUp
    run_gate = LedgerTests.run_gate
    def test_unchanged_failure_requires_diagnosis(self):
        self.run_gate([sys.executable, "-c", "raise SystemExit(4)"])
        self.assertEqual({"action": "diagnose", "reason": "unchanged_failure_do_not_repeat"},
                         ledger.decision(self.root, self.record))
        (self.root / "src/a").write_text("relevant correction")
        self.assertEqual("run_changed_context", ledger.decision(self.root, self.record)["action"])

    def test_success_reuses_only_intact_evidence(self):
        self.run_gate()
        self.assertEqual("reuse", ledger.decision(self.root, self.record)["action"])
        self.record.with_suffix(".log").write_text("changed")
        (self.root / "src/a").write_text("also changed")
        self.assertEqual({"action": "investigate", "reason": "evidence_log_changed"},
                         ledger.decision(self.root, self.record))

    def test_unstable_inputs_are_not_a_retry_permission(self):
        self.run_gate([sys.executable, "-c", "from pathlib import Path; Path('src/a').write_text('changed')"])
        self.assertEqual({"action": "investigate", "reason": "inputs_changed_during_gate"},
                         ledger.decision(self.root, self.record))

    def test_boolean_exit_cannot_authorize_reuse(self):
        self.run_gate();data = json.loads(self.record.read_text());data["exit_code"] = False
        self.record.write_text(json.dumps(data))
        with self.assertRaises(ValueError): ledger.decision(self.root, self.record)

    def test_cli_decision_does_not_execute_or_create_receipts(self):
        self.run_gate();before = self.record.read_bytes()
        arguments = ["gate_ledger.py", "decision", "--root", str(self.root), "--record", str(self.record)]
        with patch.object(sys, "argv", arguments), patch.object(ledger.subprocess, "run") as execute:
            self.assertEqual(0, ledger.main());execute.assert_not_called()
        self.assertEqual(before, self.record.read_bytes())


class TestCountEvidence(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            path.write_bytes(data.encode())
            return ledger.test_counts(path)

    def test_debug_and_safe_aggregate_and_overlap(self):
        verbose = "verbose test summary: 87 passed; 0 skipped; 0 failed; 0 leaked; 0 log errors; elapsed 847us\n"
        line = "Build Summary: 9/9 steps succeeded; 10526/10850 tests passed (324 skipped)\n"
        result = self.parse(verbose + line)
        self.assertEqual((10526, 10850, 324, 0, 0), tuple(result[k] for k in ("passed", "total", "skipped", "failed", "crashed")))
        self.assertEqual("build_aggregate", result["scope"])
        safe = self.parse("Build Summary: 4/4 steps succeeded; 85/85 tests passed\n")
        self.assertEqual((85, 0), (safe["passed"], safe["skipped"]))

    def test_failure_crash_and_single_verbose(self):
        result = self.parse("Build Summary: 6/9 steps succeeded (1 failed); 10521/10850 tests passed (324 skipped, 5 crashed)\n")
        self.assertEqual((10521, 324, 5, 0), tuple(result[k] for k in ("passed", "skipped", "crashed", "failed")))
        result = self.parse("verbose test summary: 87 passed; 2 skipped; 1 failed; 0 leaked; 1 log errors; elapsed 65ms\n")
        self.assertEqual((87, 2, 1, None, 1), tuple(result[k] for k in ("passed", "skipped", "failed", "crashed", "log_errors")))
        self.assertEqual("single_verbose_runner", result["scope"])

    def test_unknown_duplicate_malformed_and_inconsistent(self):
        aggregate = "Build Summary: 4/4 steps succeeded; 85/85 tests passed\n"
        verbose = "verbose test summary: 85 passed; 0 skipped; 0 failed; 0 leaked; 0 log errors; elapsed 1s\n"
        for text in ("", "Build Summary: 4/4 steps succeeded\n", aggregate + aggregate,
                     verbose + verbose, "Build Summary: 4/4 steps succeeded; 85/90 tests passed (4 skipped)\n",
                     "Build Summary: 4/4 steps succeeded; 85/86 tests passed (1 mystery)\n"):
            self.assertIsNone(self.parse(text))

    def test_oversized_log_is_unknown(self):
        self.assertIsNone(self.parse("x" * (ledger.COUNT_LOG_LIMIT + 1)))

    def test_malformed_and_valid_aggregate_is_unknown(self):
        text = ("Build Summary: malformed; 1/1 tests passed\n"
                "Build Summary: 4/4 steps succeeded; 85/85 tests passed\n")
        self.assertIsNone(self.parse(text))

    def test_count_cannot_override_gate_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "src").mkdir(); (root / "src/x").write_text("x")
            record = root / "gate.json"
            command = [sys.executable, "-c", "print('Build Summary: 4/4 steps succeeded; 85/85 tests passed'); raise SystemExit(1)"]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, ledger.run(root, record, ["src"], command))
                self.assertEqual(1, ledger.status(root, record))
            self.assertEqual(85, json.loads(record.read_text())["test_counts"]["passed"])


if __name__ == "__main__":
    unittest.main()
