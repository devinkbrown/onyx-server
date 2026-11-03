#!/usr/bin/env python3
"""Bounded real build-graph controls: unsupported runtime targets fail before compilation."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest


class RuntimeGraphControls(unittest.TestCase):
    zig = os.environ.get("ONYX_TEST_ZIG", "zig")
    root = Path(os.environ.get("ONYX_TEST_BUILD_ROOT", Path(__file__).resolve().parents[1]))

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="onyx-build-graph-")
        cls.fixture = Path(cls.temp.name)
        for name in ("build.zig", "build.zig.zon"):
            shutil.copyfile(cls.root / name, cls.fixture / name)
        (cls.fixture / "tools").mkdir()
        for name in ("verbose_test_runner.zig", "parallel_tests.py"):
            shutil.copyfile(cls.root / "tools" / name, cls.fixture / "tools" / name)
        (cls.fixture / "src" / "cli").mkdir(parents=True)
        source = ('const builtin = @import("builtin");\n'
                  'comptime { if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) @compileError("LEGACY_PLATFORM_GRAPH_REACHED"); }\n'
                  'pub fn main() void {}\ntest "alpha" {}\ntest "beta" {}\n')
        for name in ("root.zig", "main.zig", "cli/armor_main.zig"):
            (cls.fixture / "src" / name).write_text(source)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def fixture_build(self, *args):
        return subprocess.run([self.zig, "build", "-j2", "--summary", "all", *args], cwd=self.fixture,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)

    def test_default_full_and_reference_graphs_with_small_roots(self):
        default = self.fixture_build("test")
        self.assertEqual(default.returncode, 0, default.stdout)
        self.assertIn("parallel suite summary: artifacts=3 discovered=6 executed=6 passed=6 skipped=0 failed=0", default.stdout)
        self.assertIn("retained full-suite logs:", default.stdout)
        serial = self.fixture_build("test-serial")
        self.assertEqual(serial.returncode, 0, serial.stdout)
        self.assertNotIn("parallel suite summary:", serial.stdout)
        self.assertIn("6/6 tests passed", serial.stdout)
        filtered = self.fixture_build("test", "-Dtest-filter=alpha")
        self.assertEqual(filtered.returncode, 0, filtered.stdout)
        self.assertNotIn("parallel suite summary:", filtered.stdout)
        self.assertIn("3/3 tests passed", filtered.stdout)

    def test_default_windows_and_cross_graphs_retain_legacy_compiler_path(self):
        for target in ("x86_64-windows", "aarch64-linux"):
            with self.subTest(target=target):
                result = self.fixture_build("test", f"-Dtarget={target}")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                # The sentinel stops semantic analysis of these tiny roots,
                # proving the original compiler graph was reached without LLVM.
                self.assertIn("LEGACY_PLATFORM_GRAPH_REACHED", result.stdout)
                self.assertNotIn("native supported POSIX", result.stdout)
                self.assertNotIn("parallel suite summary:", result.stdout)
                self.assertNotIn("onyx-tests-cached", result.stdout)

    def build(self, *args):
        return subprocess.run([self.zig, "build", "--summary", "all", *args], cwd=self.root,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)

    def test_windows_runtime_targets_fail_before_test_compilers(self):
        for step, message in (("test-cached", "Windows compile shards"),
                              ("test-exe-cached", "Windows stack"),
                              ("test-full-parallel", "native supported POSIX")):
            with self.subTest(step=step):
                r = self.build(step, "-Dtarget=x86_64-windows")
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn(message, r.stdout)
                self.assertNotIn("compile test", r.stdout)
                self.assertNotIn("zig test", r.stdout)
                self.assertIn("0/2 steps succeeded", r.stdout)

    def test_cross_target_parallel_fails_before_test_compilers(self):
        r = self.build("test-full-parallel", "-Dtarget=aarch64-linux")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("native supported POSIX", r.stdout)
        self.assertNotIn("compile test", r.stdout)
        self.assertNotIn("zig test", r.stdout)
        self.assertIn("0/2 steps succeeded", r.stdout)

    def test_native_leaf_graph_can_compile_and_list(self):
        r = self.build("test-media-record-leaf", "--", "--list-tests")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("listed ", r.stdout)
        self.assertIn("tests; executed 0", r.stdout)
        self.assertIn("daemon.media_record.test.", r.stdout)
        self.assertIn("3/3 steps succeeded", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
