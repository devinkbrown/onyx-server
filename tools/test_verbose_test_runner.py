#!/usr/bin/env python3
"""Real compiled runner controls; tiny immutable fixture, no daemon compilation.

ONYX_TEST_ZIG=/path/to/pinned/zig python3 -B tools/test_verbose_test_runner.py
"""
import hashlib
import json
import signal
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

import gate_ledger


class RunnerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="onyx-runner-")
        cls.root = Path(cls.tmp.name)
        cls.zig = os.environ.get("ONYX_TEST_ZIG", "zig")
        runner = Path(__file__).resolve().with_name("verbose_test_runner.zig")
        shutil.copyfile(runner, cls.root / "runner.zig")
        (cls.root / "fixture.zig").write_text('''const std = @import("std");
test "alpha pass" { try std.testing.expect(true); }
test "beta skip" { return error.SkipZigTest; }
test "gamma fail" { return error.DeliberateControl; }
''')
        # Passthrough args must affect only Run, never the compile cache key.
        (cls.root / "build.zig").write_text('''const std = @import("std");
pub fn build(b: *std.Build) void {
    const t = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("fixture.zig"),
        .target = b.graph.host,
    }), .test_runner = .{ .path = b.path("runner.zig"), .mode = .simple } });
    const r = b.addRunArtifact(t);
    r.addPassthruArgs();
    b.step("test-cached", "Runner controls").dependOn(&r.step);
}
''')
        cls.cold = cls.build("--test-filter=alpha")
        if cls.cold.returncode:
            raise AssertionError(cls.cold.stdout)
        cls.binary = next((cls.root / ".zig-cache" / "o").glob("*/test"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def build(cls, *args):
        return subprocess.run([cls.zig, "build", "test-cached", "--summary", "all", "--", *args],
                              cwd=cls.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def run_case(self, *args):
        return subprocess.run([str(self.binary), *args], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_substring(self):
        r = self.run_case("--test-filter=alpha")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 discovered; 1 matched; 2 excluded", r.stdout)
        self.assertIn("executed 1 tests", r.stdout)
        self.assertIn("1 passed; 0 skipped; 0 failed", r.stdout)

    def test_multiple_filters_union_deduplicates(self):
        r = self.run_case("--test-filter=alpha", "--test-filter=alpha", "--test-filter=beta")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 discovered; 2 matched; 1 excluded", r.stdout)
        self.assertIn("1 passed; 1 skipped; 0 failed", r.stdout)
        self.assertIn("executed 2 tests", r.stdout)

    def test_no_match_fails(self):
        r = self.run_case("--test-filter=absent")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("no tests matched", r.stdout)

    def test_empty_filter_fails(self):
        self.assertEqual(self.run_case("--test-filter=").returncode, 2)

    def test_default_runs_all_and_reports_failure(self):
        r = self.run_case()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("1 passed; 1 skipped; 1 failed", r.stdout)
        self.assertIn("executed 3 tests", r.stdout)
        self.assertIn("DeliberateControl", r.stdout)
        self.assertIn("slowest tests:", r.stdout)

    def test_list_does_not_execute_failure(self):
        r = self.run_case("--list-tests", "--test-filter=gamma")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("gamma fail", r.stdout)
        self.assertIn("listed 1 tests; executed 0", r.stdout)
        self.assertNotIn("FAIL", r.stdout)

    def test_shards_disjoint_exhaustive_deterministic(self):
        def names(*args):
            r = self.run_case("--list-tests", *args)
            if r.returncode == 2:
                self.assertIn("no tests matched", r.stdout)
                return []
            self.assertEqual(r.returncode, 0, r.stdout)
            return r.stdout.splitlines()[1:-1]
        all_names = names()
        shards = [names("--test-shard-count=3", f"--test-shard-index={i}") for i in range(3)]
        self.assertEqual(sorted(all_names), sorted(name for shard in shards for name in shard))
        self.assertEqual(shards, [names("--test-shard-count=3", f"--test-shard-index={i}") for i in range(3)])
        self.assertEqual(sorted(all_names), sorted(names("--test-group=parallel") + names("--test-group=serial")))

    def test_invalid_shards_fail(self):
        self.assertEqual(self.run_case("--test-shard-count=0").returncode, 2)
        self.assertEqual(self.run_case("--test-shard-count=2", "--test-shard-index=2").returncode, 2)

    def test_parallel_aggregate_propagates_failure(self):
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        log_dir = self.root / "parallel-failure"
        r = subprocess.run(["python3", "-B", str(harness), str(self.binary), "--logs", str(log_dir),
                            "--workers=3", "--policy=all"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("executed=3 passed=1 skipped=1 failed=1", r.stdout)
        self.assertTrue((log_dir / "inventory.txt").exists())

    def test_multiple_artifacts_all_run_and_failures_propagate(self):
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        log_dir = self.root / "multiple-artifacts"
        r = subprocess.run(["python3", "-B", str(harness), str(self.binary), str(self.binary),
                            "--logs", str(log_dir), "--workers=2"], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertEqual(sum(line.startswith("parallel artifact summary:") for line in r.stdout.splitlines()), 2, r.stdout)
        self.assertIn("parallel suite summary: artifacts=2 discovered=6 executed=6 passed=2 skipped=2 failed=2", r.stdout)
        captured = self.root / "multiple-artifact-output.log"
        captured.write_text(r.stdout)
        counts = gate_ledger.test_counts(captured)
        self.assertEqual((6, 2, 2, 2), tuple(counts[key] for key in ("total", "passed", "skipped", "failed")))
        self.assertTrue((log_dir / "artifact-0" / "run.json").exists())
        self.assertTrue((log_dir / "artifact-1" / "run.json").exists())

    def test_full_runtime_benchmark(self):
        # Concurrent wall-time fixture models independent test waits; no test is
        # skipped or removed. This proves scheduling, not production speedup.
        fixture = self.root / "benchmark.zig"
        fixture.write_text('const std = @import("std");\n' + "".join(
            f'test "wait {i}" {{ try std.Io.sleep(std.testing.io, .fromMilliseconds(60), .awake); }}\n'
            for i in range(24)))
        binary = self.root / "benchmark"
        compiled = subprocess.run([self.zig, "test", str(fixture), "--test-runner", str(self.root / "runner.zig"),
                                   "--test-no-exec", f"-femit-bin={binary}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(compiled.returncode, 0, compiled.stdout)
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        times = []
        for workers in (1, 4):
            started = time.monotonic()
            r = subprocess.run(["python3", "-B", str(harness), str(binary), "--logs", str(self.root / f"benchmark-{workers}"),
                                f"--workers={workers}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            times.append(time.monotonic() - started)
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("discovered=24 executed=24 passed=24 skipped=0 failed=0", r.stdout)
        print(f"full runtime fixture: 1 worker {times[0]:.3f}s; 4 workers {times[1]:.3f}s; speedup {times[0]/times[1]:.2f}x; same24cases/0skips")

    def fake_binary(self, name, body):
        binary = self.root / name
        binary.write_text("#!/usr/bin/env python3\nimport os, signal, subprocess, sys, time\n"
                          "if '--list-tests' in sys.argv:\n"
                          "    print('test selection: 1 discovered; 1 matched; 0 excluded')\n"
                          "    print('fixture.test.control')\n"
                          "    print('listed 1 tests; executed 0')\n"
                          "    sys.exit(0)\n" + body)
        binary.chmod(0o755)
        return binary

    def assert_child_stopped(self, pid):
        for _ in range(100):
            stat = Path(f"/proc/{pid}/stat")
            if not stat.exists() or stat.read_text().split()[2] == "Z":
                return
            time.sleep(0.01)
        self.fail(f"shard child {pid} still running")

    def test_timeout_kills_shard_and_stubborn_child(self):
        pid_file = self.root / "timeout-child.pid"
        binary = self.fake_binary("hang-control", f"""child = subprocess.Popen([sys.executable, '-c',
    'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
open({str(pid_file)!r}, 'w').write(str(child.pid))
print('[1/1] fixture.test.control ... ', flush=True)
time.sleep(60)
""")
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        log_dir = self.root / "timeout-logs"
        started = time.monotonic()
        r = subprocess.run(["python3", "-B", str(harness), str(binary), "--logs", str(log_dir),
                            "--workers=1", "--timeout=0.25", "--seed=123"], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertLess(time.monotonic() - started, 5)
        metadata = json.loads((log_dir / "run.json").read_text())
        self.assertEqual(metadata["seed"], 123)
        self.assertTrue(metadata["results"][0]["timed_out"])
        self.assertIn("timeout", metadata["results"][0]["error"])
        self.assert_child_stopped(int(pid_file.read_text()))

    def test_abnormal_exit_never_accepted(self):
        binary = self.fake_binary("abnormal-control", "os._exit(7)\n")
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        log_dir = self.root / "abnormal-logs"
        r = subprocess.run(["python3", "-B", str(harness), str(binary), "--logs", str(log_dir),
                            "--workers=1"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 1, r.stdout)
        result = json.loads((log_dir / "run.json").read_text())["results"][0]
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(result["error"], "missing terminal counts")

    def test_interrupt_cleans_active_shard_children(self):
        pid_file = self.root / "interrupt-child.pid"
        binary = self.fake_binary("interrupt-control", f"""child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
open({str(pid_file)!r}, 'w').write(str(child.pid))
time.sleep(60)
""")
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        log_dir = self.root / "interrupt-logs"
        proc = subprocess.Popen(["python3", "-B", str(harness), str(binary), "--logs", str(log_dir), "--workers=1"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pid_file.exists())
            proc.send_signal(signal.SIGTERM)
            output, _ = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 1, output)
            self.assert_child_stopped(int(pid_file.read_text()))
            metadata = json.loads((log_dir / "run.json").read_text())
            self.assertIn("interrupted", metadata["results"][0]["error"])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_default_log_paths_are_unique_and_retained(self):
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        for _ in range(2):
            r = subprocess.run(["python3", "-B", str(harness), str(self.binary), "--workers=1"], cwd=self.root,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(r.returncode, 1, r.stdout)  # Deliberate fixture failure.
            self.assertIn("retained full-suite logs: .zig-cache/full-suite-runs/", r.stdout)
        paths = list((self.root / ".zig-cache" / "full-suite-runs").iterdir())
        self.assertEqual(len(paths), 2)
        for path in paths:
            self.assertTrue((path / "suite.json").exists())
            self.assertTrue((path / "shard-0.log").exists())

    def test_explicit_existing_log_path_preserves_evidence(self):
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        path = self.root / "protected-logs"
        path.mkdir()
        marker = path / "original"
        marker.write_bytes(b"retained evidence")
        r = subprocess.run(["python3", "-B", str(harness), str(self.binary), "--logs", str(path)],
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("File exists", r.stdout)
        self.assertEqual(marker.read_bytes(), b"retained evidence")
        self.assertEqual(list(path.iterdir()), [marker])

    def test_warm_selection_reuses_identical_artifact(self):
        before = (self.binary.stat().st_mtime_ns, hashlib.sha256(self.binary.read_bytes()).hexdigest())
        started = time.monotonic()
        r = self.build("--test-filter=beta")
        elapsed = time.monotonic() - started
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("cached", r.stdout)
        self.assertIn("0 passed; 1 skipped; 0 failed", r.stdout)
        after = (self.binary.stat().st_mtime_ns, hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(before, after)
        print(f"warm runtime selection: {elapsed:.3f}s; compile cached; binary SHA-256 {after[1]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
