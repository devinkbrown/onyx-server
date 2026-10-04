#!/usr/bin/env python3
"""Regression tests for conservative Onyx Server gate selection."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SELECTOR = Path(__file__).with_name("select-gates.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("onyx_select_gates", SELECTOR)
assert SPEC is not None and SPEC.loader is not None
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)


class GateSelectionTests(unittest.TestCase):
    def assert_selection(
        self, path: str, expected_gates: set[str], expected_critical: set[str]
    ) -> None:
        gates, critical = selector.select([path])
        self.assertEqual(expected_gates, set(gates))
        self.assertEqual(expected_critical, critical)
        self.assertLessEqual(critical, set(gates))

    def test_server_session_path_is_release_safe(self) -> None:
        self.assert_selection(
            "src/daemon/server.zig",
            {"test-server", "test-services"},
            {"test-server", "test-services"},
        )

    def test_helix_session_path_covers_mesh_and_session(self) -> None:
        self.assert_selection(
            "src/daemon/helix/session_snapshot.zig",
            {"test-helix", "test-mesh", "test-services", "test-session"},
            {"test-helix", "test-mesh", "test-services", "test-session"},
        )

    def test_event_path_covers_live_server_and_mesh(self) -> None:
        self.assert_selection(
            "src/daemon/event_spine_replay_guard.zig",
            {"test-event-spine", "test-mesh", "test-server"},
            {"test-event-spine", "test-mesh", "test-server"},
        )

    def test_auth_service_path_is_release_safe(self) -> None:
        self.assert_selection(
            "src/service/account.zig", {"test-services"}, {"test-services"}
        )

    def test_cli_path_stays_focused(self) -> None:
        self.assert_selection("src/cli/config.zig", {"test-cli", "test-config"}, set())

    def test_build_change_selects_full_release_safe_test(self) -> None:
        self.assert_selection("build.zig", {"test"}, {"test"})

    def test_store_includes_module_tests_and_auth_consumers(self) -> None:
        self.assert_selection(
            "src/daemon/store.zig",
            {"test-mod", "test-services"},
            {"test-mod", "test-services"},
        )

    def test_physical_lifecycle_includes_module_release_safe(self) -> None:
        self.assert_selection(
            "src/daemon/physical_lifecycle.zig", {"test-mod"}, {"test-mod"}
        )

    def test_output_leaves_include_all_tests_and_critical_callers(self) -> None:
        for path in ("src/daemon/sendq.zig", "src/daemon/ws_output.zig"):
            with self.subTest(path=path):
                self.assert_selection(
                    path,
                    {"test-mod", "test-server", "test-tls"},
                    {"test-mod", "test-server", "test-tls"},
                )

    def test_media_transport_paths_are_release_safe(self) -> None:
        for path in (
            "src/daemon/native_media_transport.zig",
            "src/daemon/sfu_srtp.zig",
            "src/substrate/rtp_nack.zig",
        ):
            with self.subTest(path=path):
                self.assert_selection(path, {"test-media"}, {"test-media"})

    def test_capability_keys_include_full_import_regressions(self) -> None:
        self.assert_selection(
            "src/substrate/media_capability.zig",
            {"test-media", "test-mod"},
            {"test-media", "test-mod"},
        )

    def test_native_codecs_include_media_callers_and_import_regressions(self) -> None:
        for path in (
            "src/substrate/cadence_frame.zig",
            "src/substrate/native_feedback.zig",
        ):
            with self.subTest(path=path):
                self.assert_selection(
                    path,
                    {"test-media", "test-mod"},
                    {"test-media", "test-mod"},
                )


if __name__ == "__main__":
    unittest.main()
