#!/usr/bin/env python3
"""Select conservative Onyx Server build gates from changed repository paths."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Iterable


def changed_paths() -> list[str]:
    tracked = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return sorted({line for output in (tracked.stdout, untracked.stdout) for line in output.splitlines() if line})


def contains(path: str, *needles: str) -> bool:
    return any(needle in path for needle in needles)


def select(paths: Iterable[str]) -> tuple[list[str], set[str]]:
    gates: set[str] = set()
    critical: set[str] = set()
    for path in paths:
        # Neither foundation's tests are selected by the services name filters.
        # Their complete module artifact covers storage and resource consumers.
        if path in {"src/daemon/store.zig", "src/daemon/physical_lifecycle.zig"}:
            gates.add("test-mod")
            critical.add("test-mod")
        if path == "src/daemon/store.zig":
            gates.add("test-services")
            critical.add("test-services")
        # Output leaf tests include names outside the TLS/server filters. The
        # full module artifact covers them; callers and TLS need both modes too.
        if path in {"src/daemon/sendq.zig", "src/daemon/ws_output.zig"}:
            gates.update(("test-mod", "test-server", "test-tls"))
            critical.update(("test-mod", "test-server", "test-tls"))
        if path == "src/daemon/server.zig" or contains(path, "world.zig", "sessions.zig", "deliver"):
            gates.update(("test-server", "test-services"))
            critical.update(("test-server", "test-services"))
        if contains(path, "sessions.zig", "world.zig", "session_", "migration_", "session-"):
            gates.add("test-session")
            critical.add("test-session")
        if path.startswith("src/daemon/helix/") or "session_" in path or "migration_" in path:
            gates.update(("test-helix", "test-services", "test-mesh"))
            critical.update(("test-helix", "test-services", "test-mesh"))
        if contains(path, "s2s", "undertow", "mesh", "relay_v2"):
            gates.update(("test-mesh", "test-helix"))
            critical.update(("test-mesh", "test-helix"))
        if contains(path, "event_spine", "event-spine", "event_history", "oper_event", "message_relay", "lotus.zig", "msgid.zig"):
            gates.update(("test-event-spine", "test-mesh", "test-server"))
            critical.update(("test-event-spine", "test-mesh", "test-server"))
        if contains(path, "ircx", "prop_store"):
            gates.add("test-ircx")
        if contains(path, "service", "account", "sasl", "webauthn", "totp", "tegami"):
            gates.add("test-services")
            critical.add("test-services")
        if contains(path, "config", "onyx-server.reference.toml"):
            gates.add("test-config")
        if contains(path, "media", "rtp", "rtcp", "srtp", "webtransport"):
            gates.add("test-media")
            critical.add("test-media")
        # Native frame/feedback codec names do not contain "media". Include
        # their complete imported tests as well as the media caller gate.
        if path in {
            "src/substrate/media_capability.zig",
            "src/substrate/cadence_frame.zig",
            "src/substrate/native_feedback.zig",
        }:
            gates.update(("test-media", "test-mod"))
            critical.update(("test-media", "test-mod"))
        if path.startswith("src/crypto/") or contains(path, "tls", "x509", "cloak"):
            gates.update(("test-tls", "test-exploit"))
            critical.update(("test-tls", "test-exploit"))
        if contains(path, "warden", "security"):
            gates.add("test-exploit")
            critical.add("test-exploit")
        if path.startswith("src/cli/"):
            gates.add("test-cli")
        if path in {"build.zig", "build.zig.zon"} or path.startswith("packaging/"):
            gates.add("test")
            critical.add("test")
    return sorted(gates), critical


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    paths = args.paths or changed_paths()
    gates, critical = select(paths)

    print("zig build check")
    for gate in gates:
        print(f"zig build {gate}")
    for gate in gates:
        if gate in critical:
            print(f"zig build {gate} -Doptimize=ReleaseSafe")
    print("git diff --check")
    if args.release:
        print("zig build all-checks")
        print("zig build release -Doptimize=ReleaseFast")
        print("zig build package -Doptimize=ReleaseFast")
        print("packaging/release.sh dist")
        print("packaging/verify-release.sh dist/SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
