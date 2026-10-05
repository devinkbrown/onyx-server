#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Run a real OroWasm reply plugin inside the native Windows daemon."""

import argparse
from pathlib import Path
import os
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"

# Same minimal, harmless reply module as src/wasm/host/bridge.zig's test fixture.
REPLY_WASM = bytes.fromhex(
    "0061736d01000000"
    "01090260027f7f00600000"
    "020d0103656e76057265706c790000"
    "03020101"
    "0503010001"
    "070a010668616e646c650001"
    "0a0a0108004100410210000b"
    "0b08010041000b026f6b"
)


def free_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def run_cli(binary, run_dir, *args):
    return subprocess.run([str(binary), *map(str, args)], cwd=run_dir,
                          text=True, capture_output=True, timeout=20, check=False)


def wait_irc(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"daemon exited before IRC listen: {process.returncode}")
        try:
            conn = socket.create_connection((HOST, port), timeout=0.5)
            conn.settimeout(5)
            return conn
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("IRC listener did not start")


def until_line(conn, needle):
    deadline = time.monotonic() + 8
    pending = b""
    while time.monotonic() < deadline:
        pending += conn.recv(4096)
        for line in pending.split(b"\n")[:-1]:
            if needle in line:
                return line.strip()
        pending = pending.rsplit(b"\n", 1)[-1]
    raise TimeoutError(f"no IRC line containing {needle!r}")


def probe(binary):
    with tempfile.TemporaryDirectory(prefix="onyx-windows-wasm-") as scratch:
        run_dir = Path(scratch)
        plugins = run_dir / "plugins"
        plugins.mkdir()
        (plugins / "PINGME.wasm").write_bytes(REPLY_WASM)
        config = run_dir / "wasm.toml"
        port = free_port()
        config.write_text("\n".join((
            "[node]", "id = 1", "",
            "[listen]", f'host = "{HOST}"', f"irc = {port}", "",
            "[wasm]", 'plugin_dir = "plugins"', "",
        )), encoding="utf-8")

        checked = run_cli(binary, run_dir, "--check-config", config)
        if checked.returncode:
            raise AssertionError(f"WASM preflight failed: {checked.stdout + checked.stderr}")
        plugins.rename(run_dir / "plugins-away")
        missing = run_cli(binary, run_dir, "--check-config", config)
        if missing.returncode == 0:
            raise AssertionError("missing WASM directory passed Windows preflight")
        (run_dir / "plugins-away").rename(plugins)
        print("PASS: plugin directory preflight accepts present and rejects missing")

        log_path = run_dir / "daemon.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                with wait_irc(process, port) as conn:
                    conn.sendall(b"NICK wasmprobe\r\nUSER wasmprobe 0 * :WASM Probe\r\n")
                    until_line(conn, b" 001 wasmprobe ")
                    conn.sendall(b"PINGME\r\n")
                    until_line(conn, b" NOTICE wasmprobe :ok")
                print("PASS: loaded plugin dispatched IRC command and emitted its reply")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=8)
        if "loaded 1 OroWasm plugin" not in log_path.read_text(encoding="utf-8", errors="replace"):
            raise AssertionError(f"WASM load missing from daemon log: {log_path.read_text(encoding='utf-8', errors='replace')}")

        (plugins / "PINGME.wasm").write_bytes(b"invalid wasm")
        with (run_dir / "invalid.log").open("wb") as log:
            rejected = subprocess.run([str(binary), str(config)], cwd=run_dir,
                                      stdout=log, stderr=subprocess.STDOUT,
                                      timeout=12, check=False)
        if rejected.returncode == 0:
            raise AssertionError("malformed configured WASM plugin booted successfully")
        print("PASS: malformed plugin aborts Windows boot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    probe(binary)


if __name__ == "__main__":
    main()
