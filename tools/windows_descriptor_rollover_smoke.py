#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise automatic Windows descriptor rollover through the pinned image.

Build the dedicated fixture with `zig build windows-rollover-smoke-server`, then
pass its executable. The production daemon has no marker hook.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, free_port, image_pids, sole_image_pid, wait_log_contains


def wait_single_pid(binary: Path, expected: int, timeout: float = 20) -> None:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if image_pids(binary) == {expected}:
            return
        time.sleep(0.2)
    raise AssertionError(f"expected only PID {expected}; live={image_pids(binary)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file() or original.name != "onyx-server-rollover-smoke.exe":
        parser.error("pass the dedicated onyx-server-rollover-smoke.exe fixture")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-rollover-") as temporary:
        root = Path(temporary)
        binary = root / original.name
        shutil.copy2(original, binary)
        config = root / "server.toml"
        marker = Path(str(config) + ".rollover-smoke")
        log_path = root / "daemon.log"
        port = free_port()
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\nsweep_interval = \"1s\"\n"
            f"[listen]\nirc = {port}\n",
            encoding="utf-8",
        )
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[Client] = []
        try:
            until = time.monotonic() + 30
            while True:
                try:
                    held = Client(port)
                    clients.append(held)
                    break
                except OSError:
                    if parent.poll() is not None or time.monotonic() >= until:
                        raise RuntimeError(f"daemon did not listen; exit={parent.poll()}")
                    time.sleep(0.2)
            held.register(b"heldrollover")
            held.ping(b"before-rollover")
            source_pid = sole_image_pid(binary)
            if source_pid != parent.pid:
                raise AssertionError(f"unexpected source PID {source_pid}, parent={parent.pid}")

            # The marker belongs only to this process. The successor inherits
            # the file path but its different PID cannot trigger another swap.
            marker.write_text(f"{source_pid} fail\n", encoding="ascii")
            wait_log_contains(log_path, "Windows rollover smoke pinned candidate negotiated (mode=fail)", timeout=40)
            wait_log_contains(log_path, "rollover UPGRADE failed (TestRolloverSmokeAbort)", timeout=20)
            refused_at = time.monotonic()
            wait_single_pid(binary, source_pid)
            held.ping(b"after-refused-rollover")
            fresh = Client(port)
            clients.append(fresh)
            fresh.register(b"freshrollover")
            fresh.ping(b"after-refused-fresh")
            print("PASS: pinned candidate negotiated and aborted; source and held sockets survived")

            marker.write_text(f"{source_pid} pass\n", encoding="ascii")
            time.sleep(3)
            wait_single_pid(binary, source_pid, timeout=3)
            if "Windows rollover smoke pinned candidate negotiated (mode=pass)" in log_path.read_text(encoding="utf-8", errors="replace"):
                raise AssertionError("automatic rollover ignored its retry interval")
            held.ping(b"retry-backoff")

            wait_log_contains(log_path, "Windows rollover smoke pinned candidate negotiated (mode=pass)", timeout=85)
            retry_elapsed = time.monotonic() - refused_at
            # Both log observations are polled, so allow one second of timing
            # slack while still rejecting a shortened retry interval.
            if retry_elapsed < 59:
                raise AssertionError(f"automatic rollover retried after only {retry_elapsed:.2f}s")
            successor_pid = sole_image_pid(binary, different_from=source_pid, timeout=45)
            held.ping(b"after-automatic-rollover")
            fresh.ping(b"fresh-held-after-rollover")
            after = Client(port)
            clients.append(after)
            after.register(b"afterrollover")
            after.ping(b"new-connection-after-rollover")
            if parent.wait(timeout=10) != 0:
                raise AssertionError("source process did not exit cleanly")
            time.sleep(2)
            wait_single_pid(binary, successor_pid, timeout=5)
            print(f"PASS: automatic pinned-image rollover {source_pid} -> {successor_pid} after {retry_elapsed:.1f}s; held and fresh IRC sockets survived")
            return 0
        except Exception:
            log.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace")[-8000:])
            for index, client in enumerate(clients):
                print(f"client {index} recent lines: {client.lines[-5:]!r}")
            raise
        finally:
            marker.unlink(missing_ok=True)
            for client in clients:
                client.close()
            try:
                for pid in image_pids(binary):
                    os.kill(pid, 15)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 10
                while image_pids(binary) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
