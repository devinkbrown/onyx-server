#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the standalone WebTransport interop server with a real browser.

The server's in-process Windows TCP echo bridge must return a byte-exact bidi
stream, and its WebTransport datagram echo must return a byte-exact datagram.
Usage: python -B tools/windows_quic_interop_smoke.py [server.exe]
"""

import argparse
import base64
from contextlib import contextmanager
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "quic_interop_wt_server.exe"
HARNESS = ROOT / "tools" / "quic_interop_browser.mjs"


def browser_path(requested: Path | None) -> Path:
    if requested:
        browser = requested.expanduser().resolve()
        if browser.is_file():
            return browser
        raise FileNotFoundError(f"Chrome/Edge not found: {browser}")
    candidates = [
        shutil.which("chrome"), shutil.which("msedge"),
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise FileNotFoundError("Chrome or Edge is required for WebTransport interop")


def stop(server: subprocess.Popen[str]) -> None:
    if server.poll() is not None:
        return
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)


@contextmanager
def disposable_run_dir():
    path = Path(tempfile.mkdtemp(prefix="onyx-wt-interop-windows-"))
    try:
        yield path
    finally:
        # Browser child processes can retain their profile briefly after the
        # harness exits. Retry only cleanup of this fixture's own directory.
        deadline = time.monotonic() + 10
        while path.exists():
            try:
                shutil.rmtree(path)
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)


def announced_values(server: subprocess.Popen[str]) -> tuple[int, str]:
    lines: queue.Queue[str] = queue.Queue()
    transcript: list[str] = []

    def read_output() -> None:
        assert server.stdout is not None
        for line in server.stdout:
            line = line.strip()
            transcript.append(line)
            lines.put(line)

    threading.Thread(target=read_output, daemon=True).start()
    values: dict[str, str] = {}
    deadline = time.monotonic() + 60
    required = {"PORT", "CERTHASH", "CERTHASHB64"}
    while not required.issubset(values) and time.monotonic() < deadline:
        try:
            line = lines.get(timeout=0.25)
        except queue.Empty:
            if server.poll() is not None:
                break
            continue
        key, separator, value = line.partition("=")
        if separator and key in required:
            values[key] = value
    if not required.issubset(values):
        raise AssertionError(f"interop server did not announce port and certificate hash: {transcript[-30:]}")
    port = int(values["PORT"])
    digest = values["CERTHASH"]
    if not (1 <= port <= 65535 and re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise AssertionError(f"invalid interop announcement: {values}")
    if base64.b64decode(values["CERTHASHB64"], validate=True) != bytes.fromhex(digest):
        raise AssertionError("interop certificate hashes disagree")
    return port, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--chromium", type=Path, help="Chrome or Edge executable")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    node = shutil.which("node")
    if not node:
        parser.error("Node.js is required for the browser harness")
    chromium = browser_path(args.chromium)

    with disposable_run_dir() as run_dir:
        server_env = os.environ.copy()
        server_env.pop("ONYX_WT_BRIDGE_PORT", None)
        server = subprocess.Popen(
            [str(binary)], cwd=run_dir, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW, env=server_env,
        )
        try:
            port, digest = announced_values(server)
            print("PASS: standalone WebTransport server announced matching certificate hashes", flush=True)
            env = os.environ.copy()
            env["TMPDIR"] = str(run_dir)
            browser = subprocess.Popen(
                [node, str(HARNESS), "--port", str(port), "--certhash", digest,
                 "--chromium", str(chromium), "--timeout-ms", "45000"],
                cwd=run_dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                stdout, stderr = browser.communicate(timeout=70)
            except subprocess.TimeoutExpired as exc:
                # Node spawns Chrome. A timeout must stop the whole test tree
                # before the temporary browser profile is removed.
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(browser.pid), "/T", "/F"],
                        capture_output=True, check=False, timeout=10,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                finally:
                    if browser.poll() is None:
                        browser.kill()
                    browser.wait(timeout=5)
                raise TimeoutError("browser WebTransport interop timed out") from exc
            output = stdout + stderr
            if browser.returncode != 0 or "PASS: all legs byte-exact" not in output:
                raise AssertionError(f"browser interop failed (exit {browser.returncode}):\n{output[-12000:]}")
            if server.poll() is not None:
                raise AssertionError(f"interop server exited after browser exchange ({server.returncode})")
            print("PASS: Chrome/Edge bidi stream and datagram echoed byte-exact", flush=True)
        finally:
            stop(server)
    return 0


if __name__ == "__main__":
    sys.exit(main())
