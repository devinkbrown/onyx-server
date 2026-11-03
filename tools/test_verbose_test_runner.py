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
import parallel_tests


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

    def test_exact_manifest_rejects_unknown_duplicate_and_empty_before_execution(self):
        listing = self.run_case("--list-tests").stdout.splitlines()[1:-1]
        first = listing[0]
        cases = [b"", b"\n", b"unknown.test.name\n", (first + "\n" + first + "\n").encode(),
                 (first + "\n\n").encode(), first.encode(), (first + "\r\n").encode(), b"bad\x00name\n"]
        for index, content in enumerate(cases):
            manifest = self.root / f"invalid-exact-{index}.names"
            manifest.write_bytes(content)
            r = self.run_case(f"--test-name-file={manifest}")
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertIn("invalid exact test selection", r.stdout)
            self.assertNotIn("[1/", r.stdout)

    def compile_fixture(self, name, source):
        path = self.root / f"{name}.zig"
        path.write_text(source)
        binary = self.root / name
        r = subprocess.run([self.zig, "test", str(path), "--test-runner", str(self.root / "runner.zig"),
                            "--test-no-exec", f"-femit-bin={binary}"], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 0, r.stdout)
        return binary

    def test_exact_manifest_does_not_select_prefix_collision(self):
        binary = self.compile_fixture("selector", 'test "prefix" {}\ntest "prefix longer" { return error.MustNotRun; }\n')
        listing = subprocess.run([str(binary), "--list-tests"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        name = next(line for line in listing.stdout.splitlines() if line.endswith(".test.prefix"))
        manifest = self.root / "prefix.names"
        manifest.write_text(name + "\n")
        selected = subprocess.run([str(binary), f"--test-name-file={manifest}"], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(selected.returncode, 0, selected.stdout)
        self.assertIn("2 discovered; 1 matched; 1 excluded", selected.stdout)
        self.assertIn("1 passed; 0 skipped; 0 failed", selected.stdout)
        self.assertNotIn("MustNotRun", selected.stdout)

    def test_exact_manifest_partitions_cover_full_inventory(self):
        names = self.run_case("--list-tests").stdout.splitlines()[1:-1]
        union = []
        for index, selection in enumerate((names[:1], names[1:])):
            manifest = self.root / f"cover-{index}.names"
            manifest.write_text("\n".join(selection) + "\n")
            r = self.run_case(f"--test-name-file={manifest}", "--list-tests")
            self.assertEqual(r.returncode, 0, r.stdout)
            union.extend(r.stdout.splitlines()[1:-1])
        self.assertEqual(union, names)

    def test_duration_profiles_complete_promotion_reuse_fallback_and_import(self):
        binary = self.compile_fixture("profile-fixture", 'test "one" {}\ntest "two" {}\ntest "three" {}\ntest "four" {}\n')
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        cache = self.root / "profile-cache"
        common = ["python3", "-B", str(harness), str(binary), str(binary), str(binary),
                  "--mode=debug", "--target=fixture", "--profile-cache", str(cache)]

        def execute(label):
            logs = self.root / label
            r = subprocess.run([*common, "--logs", str(logs)], cwd=self.root,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("artifacts=3 discovered=12 executed=12 passed=12 skipped=0 failed=0", r.stdout)
            return r, logs

        cold, cold_logs = execute("profile-cold")
        self.assertEqual(cold.stdout.count("scheduler=hash"), 3)
        profile_file, = cache.glob("*.json")
        original = json.loads(profile_file.read_text())
        warm, warm_logs = execute("profile-warm")
        self.assertEqual(warm.stdout.count("scheduler=duration"), 3, warm.stdout)
        for index in range(3):
            metadata = json.loads((warm_logs / f"artifact-{index}" / "run.json").read_text())
            self.assertEqual(metadata["scheduler"], "duration")
            self.assertTrue(metadata["complete"])
        variants = ["{broken", json.dumps(dict(original, mode="safe")), json.dumps(dict(original, complete=False))]
        invalid_root = json.loads(json.dumps(original))
        invalid_root["roots"][0]["identity"] = "cli"
        variants.append(json.dumps(invalid_root))
        for index, bad in enumerate(variants):
            profile_file.write_text(bad)
            fallback, _ = execute(f"profile-fallback-{index}")
            self.assertEqual(fallback.stdout.count("scheduler=hash"), 3, fallback.stdout)
        imported = self.root / "imported-profile.json"
        result = subprocess.run(["python3", "-B", str(harness), "--import-timings-suite", str(cold_logs / "suite.json"),
                                 "--mode=debug", "--target=fixture", "--profile-output", str(imported)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(imported.read_text())["roots"][0]["identity"], "module")
        explicit_logs = self.root / "profile-explicit"
        explicit = subprocess.run([*common, "--logs", str(explicit_logs), "--timings-profile", str(imported)],
                                  cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(explicit.returncode, 0, explicit.stdout)
        self.assertEqual(explicit.stdout.count("scheduler=duration"), 3, explicit.stdout)
        # Names added or renamed after the hint was produced still execute
        # through the current full inventory and exact cover proof.
        new_binary = self.compile_fixture("profile-fixture-new", 'test "one" {}\ntest "two" {}\ntest "three" {}\ntest "four" {}\ntest "new case" {}\n')
        added = subprocess.run(["python3", "-B", str(harness), str(new_binary), str(new_binary), str(new_binary),
                                "--mode=debug", "--target=fixture", "--profile-cache", str(self.root / "new-profile-cache"),
                                "--timings-profile", str(imported), "--logs", str(self.root / "profile-added-names")],
                               cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(added.returncode, 0, added.stdout)
        self.assertIn("artifacts=3 discovered=15 executed=15 passed=15 skipped=0 failed=0", added.stdout)

        # A changed raw log invalidates the mechanical source evidence.
        log = next((cold_logs / "artifact-0").glob("shard-*.log"))
        log.write_text(log.read_text() + "tampered\n")
        refused = self.root / "refused-profile.json"
        result = subprocess.run(["python3", "-B", str(harness), "--import-timings-suite", str(cold_logs / "suite.json"),
                                 "--mode=debug", "--target=fixture", "--profile-output", str(refused)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(refused.exists())

    def test_failing_full_suite_never_promotes_timing_profile(self):
        harness = Path(__file__).resolve().with_name("parallel_tests.py")
        cache = self.root / "failed-profile-cache"
        r = subprocess.run(["python3", "-B", str(harness), str(self.binary), str(self.binary), str(self.binary),
                            "--mode=debug", "--target=fixture", "--profile-cache", str(cache),
                            "--logs", str(self.root / "failing-timing-suite")], cwd=self.root,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertFalse(cache.exists())

    def test_duration_planning_is_deterministic_balanced_and_exhaustive(self):
        names = [f"case-{index}" for index in range(8)]
        weights = {name: (100 if index < 4 else 1) for index, name in enumerate(names)}
        first = parallel_tests.balanced_names(names, weights, 4)
        second = parallel_tests.balanced_names(list(reversed(names)), weights, 4)
        self.assertEqual(first, second)
        self.assertEqual(sorted(name for shard in first for name in shard), names)
        self.assertEqual([sum(weights[name] for name in shard) for shard in first], [101] * 4)

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
