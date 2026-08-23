#!/usr/bin/env python3
"""Focused unit tests for upgrade-smoke's private setup and launch helpers."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "upgrade_smoke", Path(__file__).with_name("upgrade_smoke.py")
)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


TEST_SCRATCH = Path(__file__).resolve().parents[1] / ".upgrade-smoke-tests"


class SmokeSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        TEST_SCRATCH.mkdir(mode=0o700, exist_ok=True)
        os.chmod(TEST_SCRATCH, 0o700)
        self.root = Path(tempfile.mkdtemp(prefix="test-", dir=TEST_SCRATCH))

    def tearDown(self) -> None:
        smoke.cleanup()
        shutil.rmtree(self.root, ignore_errors=True)
        try:
            TEST_SCRATCH.rmdir()
        except OSError:
            pass

    def test_private_run_reserves_distinct_loopback_ports_and_cleans_up(self) -> None:
        scratch_parent = self.root / ".upgrade-smoke"
        scratch_parent.mkdir(mode=0o755)
        run = smoke.make_private_run(self.root)
        try:
            self.assertEqual(3, len(set(run.ports)))
            self.assertEqual(0o700, run.directory.stat().st_mode & 0o777)
            self.assertEqual(0o700, run.scratch_parent.stat().st_mode & 0o777)
            for port in run.ports:
                contender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                with self.assertRaises(OSError):
                    contender.bind((smoke.HOST, port))
                contender.close()
        finally:
            run.release_ports()
            smoke.remove_private_run(run)
        self.assertFalse(run.directory.exists())
        self.assertTrue(run.scratch_parent.exists())
        self.assertEqual(0o700, run.scratch_parent.stat().st_mode & 0o777)

    def test_private_text_and_log_are_owner_only_under_a_permissive_umask(self) -> None:
        old_umask = os.umask(0)
        try:
            config = self.root / "generated.toml"
            log = self.root / "daemon.log"
            smoke.write_private_text(config, "secret = 'value'\n")
            with smoke.open_private_log(log) as file:
                file.write("private log\n")
        finally:
            os.umask(old_umask)
        self.assertEqual("secret = 'value'\n", config.read_text())
        self.assertEqual(0o600, config.stat().st_mode & 0o777)
        self.assertEqual(0o600, log.stat().st_mode & 0o777)
        with self.assertRaises(FileExistsError):
            smoke.write_private_text(config, "replacement")

    def test_gated_launch_releases_reservation_before_exec_and_preserves_exit_status(self) -> None:
        run = smoke.make_private_run(self.root)
        port = run.ports[0]
        code = (
            "import socket, sys; "
            "s = socket.socket(); s.bind(('127.0.0.1', int(sys.argv[1]))); "
            "sys.exit(23)"
        )
        with smoke.open_private_log(run.log) as log_file:
            proc = smoke.launch_gated(
                run, [sys.executable, "-c", code, str(port)], log_file, None
            )
        self.assertEqual(23, proc.wait(timeout=3))
        self.assertEqual([], run.reservations)
        smoke.remove_private_run(run)

    def test_cleanup_is_idempotent_resets_global_and_contains_removal(self) -> None:
        run = smoke.make_private_run(self.root)
        smoke.RUN = run
        smoke.cleanup()
        smoke.cleanup()
        self.assertIsNone(smoke.RUN)
        self.assertFalse(run.directory.exists())

        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        invalid = smoke.SmokeRun(
            directory=unrelated,
            scratch_parent=self.root / ".upgrade-smoke",
            config=unrelated / "onyx.toml",
            database=unrelated / "accounts.db",
            log=unrelated / "daemon.log",
            ports=(1, 2, 3),
            reservations=[],
        )
        with self.assertRaises(RuntimeError):
            smoke.remove_private_run(invalid)
        self.assertTrue(unrelated.exists())

    def test_concurrent_runs_keep_the_shared_private_parent(self) -> None:
        first = smoke.make_private_run(self.root)
        second = smoke.make_private_run(self.root)
        self.assertEqual(first.scratch_parent, second.scratch_parent)
        first.release_ports()
        smoke.remove_private_run(first)
        self.assertTrue(second.directory.exists())
        self.assertTrue(second.scratch_parent.exists())
        second.release_ports()
        smoke.remove_private_run(second)
        self.assertTrue(second.scratch_parent.exists())

    def test_interrupt_after_gate_write_leaves_child_owned_for_cleanup(self) -> None:
        run = smoke.make_private_run(self.root)
        smoke.RUN = run
        original_write = os.write

        def write_then_interrupt(fd: int, data: bytes) -> int:
            original_write(fd, data)
            raise KeyboardInterrupt

        with smoke.open_private_log(run.log) as log_file, mock.patch.object(
            smoke.os, "write", side_effect=write_then_interrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                smoke.launch_gated(
                    run,
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    log_file,
                    None,
                )
        proc = run.process
        self.assertIsNotNone(proc)
        smoke.cleanup()
        assert proc is not None
        self.assertIsNotNone(proc.poll())
        self.assertFalse(run.directory.exists())

    def test_cleanup_kills_and_reaps_a_terminate_resistant_child(self) -> None:
        run = smoke.make_private_run(self.root)
        smoke.RUN = run
        ready = run.directory / "ready"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import pathlib, signal, sys, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)",
                str(ready),
            ]
        )
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(0.01)
        self.assertTrue(ready.exists())
        run.process = proc
        smoke.cleanup()
        self.assertEqual(-9, proc.poll())
        self.assertFalse(run.directory.exists())

    def test_main_cleans_unexpected_post_spawn_error(self) -> None:
        run = smoke.make_private_run(self.root)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        run.process = proc

        def raise_after_spawn() -> int:
            smoke.RUN = run
            raise RuntimeError("post-spawn fixture failure")

        with mock.patch.object(smoke, "_run_smoke", side_effect=raise_after_spawn), mock.patch(
            "sys.stderr", new_callable=io.StringIO
        ):
            self.assertEqual(1, smoke.main())
        self.assertIsNone(smoke.RUN)
        self.assertFalse(run.directory.exists())
        self.assertIsNotNone(proc.poll())


if __name__ == "__main__":
    unittest.main()
