#!/usr/bin/env python3
"""Bounded real build-graph controls: unsupported runtime targets fail before compilation."""
import os
import hashlib
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
        # Stub only the aggregate's ancillary gates; execute its actual full
        # test dependencies against tiny roots, including the otherwise easy
        # to omit CLI root. Ancillary checks are verified in release gates.
        graph = cls.fixture / "build.zig"
        text = graph.read_text()
        for aggregate in ("all_checks_step", "all_checks_verbose_step"):
            for dependency in ("&check_exe.step", "wasm_step", "&run_fuzz_tests.step", "&run_bogo_shim_tests.step"):
                text = text.replace(f"    {aggregate}.dependOn({dependency});\n", "")
        graph.write_text(text)
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

    def test_documentation_commits_reuse_test_binaries_and_refresh_production_stamp(self):
        with tempfile.TemporaryDirectory(prefix="onyx-test-stamp-") as directory:
            root = Path(directory)
            shutil.copyfile(self.root / "build.zig", root / "build.zig")
            shutil.copyfile(self.root / "build.zig.zon", root / "build.zig.zon")
            (root / "tools").mkdir()
            for name in ("verbose_test_runner.zig", "parallel_tests.py"):
                shutil.copyfile(self.root / "tools" / name, root / "tools" / name)
            (root / "src" / "cli").mkdir(parents=True)
            (root / "src" / "root.zig").write_text('''const std = @import("std");
pub const git_commit = @import("build_info").git_commit;
pub const version = @import("build_info").version;
test "module stamp" { try std.testing.expectEqualStrings("test", git_commit); }
''')
            application = '''const std = @import("std");
const core = @import("onyx_server");
pub fn main() void { std.debug.print("{s}\\n", .{core.version}); }
test "application stamp" { try std.testing.expectEqualStrings("test", core.git_commit); }
'''
            (root / "src" / "main.zig").write_text(application)
            (root / "src" / "cli" / "armor_main.zig").write_text(application)
            (root / ".gitignore").write_text(".zig-cache/\nzig-out/\n")
            (root / "README.md").write_text("initial documentation\n")

            def command(*args):
                result = subprocess.run(args, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout)
                return result.stdout

            command("git", "init", "-q")
            command("git", "config", "user.name", "Onyx test fixture")
            command("git", "config", "user.email", "fixture@invalid.example")
            command("git", "add", ".")
            command("git", "commit", "-qm", "initial fixture")

            def build_and_check(old_binaries=None):
                output = command(self.zig, "build", "test", "-j2", "--summary", "all")
                self.assertIn("artifacts=3 discovered=3 executed=3 passed=3 skipped=0 failed=0", output)
                artifacts = {}
                for name in ("onyx-tests-cached", "onyx-exe-tests-cached", "onyx-cli-tests-cached"):
                    paths = list((root / ".zig-cache" / "o").glob(f"*/{name}"))
                    self.assertEqual(len(paths), 1, paths)
                    artifacts[name] = (paths[0].stat().st_mtime_ns, hashlib.sha256(paths[0].read_bytes()).hexdigest())
                if old_binaries is not None:
                    self.assertEqual(artifacts, old_binaries, output)
                command(self.zig, "build", "-j2")
                version = command(str(root / "zig-out" / "bin" / "onyx-server")).strip()
                head = command("git", "rev-parse", "--short=12", "HEAD").strip()
                self.assertIn("+" + head, version)
                return artifacts, version

            original, clean_version = build_and_check()
            self.assertFalse(clean_version.endswith("-dirty"), clean_version)
            (root / "README.md").write_text("documentation-only change\n")
            _, dirty_version = build_and_check(original)
            self.assertTrue(dirty_version.endswith("-dirty"), dirty_version)
            command("git", "add", "README.md")
            command("git", "commit", "-qm", "documentation only")
            _, new_version = build_and_check(original)
            self.assertNotEqual(clean_version, new_version)
            self.assertFalse(new_version.endswith("-dirty"), new_version)
            self.assertEqual(command("git", "status", "--porcelain"), "")

    def test_release_aggregates_execute_all_three_parallel_roots(self):
        for step in ("test-verbose", "all-checks", "all-checks-verbose"):
            with self.subTest(step=step):
                result = self.fixture_build(step)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout.count("parallel suite summary:"), 1)
                self.assertIn("artifacts=3 discovered=6 executed=6 passed=6 skipped=0 failed=0", result.stdout)

    def test_filtered_release_aggregate_preserves_serial_selection(self):
        for step in ("all-checks", "all-checks-verbose"):
            with self.subTest(step=step):
                result = self.fixture_build(step, "-Dtest-filter=beta")
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("parallel suite summary:", result.stdout)
                if step.endswith("-verbose"):
                    self.assertEqual(result.stdout.count("verbose test summary: 1 passed; 0 skipped; 0 failed;"), 3)
                    self.assertNotIn(".test.alpha", result.stdout)
                else:
                    self.assertIn("3/3 tests passed", result.stdout)

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
