#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Run the shipped Windows quickstart with the daemon's private-dir CLI."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import os
import shutil
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"


def run(binary, cwd, *args, success=True):
    result = subprocess.run(
        [str(binary), *map(str, args)], cwd=cwd, capture_output=True,
        text=True, timeout=20,
    )
    output = result.stdout + result.stderr
    if success and result.returncode != 0:
        raise AssertionError(f"{args!r} failed ({result.returncode}): {output}")
    if not success and result.returncode == 0:
        raise AssertionError(f"{args!r} unexpectedly succeeded: {output}")
    return output


def free_ports(count):
    with ExitStack() as stack:
        ports = []
        for _ in range(count):
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.bind((HOST, 0))
            ports.append(sock.getsockname()[1])
        return ports


def wait_for_listener(proc, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"quickstart daemon exited early ({proc.returncode})")
        try:
            return socket.create_connection((HOST, port), timeout=0.5)
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"quickstart listener {port} did not start")


def read_until(sock, marker):
    sock.settimeout(8)
    received = b""
    while marker not in received:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(f"connection closed before {marker!r}: {received!r}")
        received += chunk
        if len(received) > 65536:
            raise AssertionError("quickstart response too long")
    return received


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path,
                        default=ROOT / "zig-out/bin/onyx-server.exe")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve(strict=True)
    template = ROOT / "packaging/onyx-server.windows.quickstart.toml"

    with tempfile.TemporaryDirectory(prefix="onyx-quickstart-") as temp:
        run_dir = Path(temp)
        config = run_dir / "onyx-server.toml"
        shutil.copyfile(template, config)
        irc_port, ws_port = free_ports(2)
        contents = config.read_text(encoding="utf-8")
        contents = contents.replace("irc = 6667", f"irc = {irc_port}")
        contents = contents.replace("ws = 8080", f"ws = {ws_port}")
        config.write_text(contents, encoding="utf-8")

        # The template must require private setup, and no CLI command may
        # silently replace a broad directory's ACL.
        missing = run(binary, run_dir, "--check-config", config, success=False)
        assert "FileNotFound" in missing, missing
        broad = run_dir / "broad"
        broad.mkdir()
        rejected = run(binary, run_dir, "--init-private-dir", broad, success=False)
        assert "InsecurePermissions" in rejected, rejected
        rejected = run(binary, run_dir, "--init-private-dir", broad, success=False)
        assert "InsecurePermissions" in rejected, rejected

        private = run_dir / "accounts-private"
        run(binary, run_dir, "--init-private-dir", "accounts-private")
        run(binary, run_dir, "--init-private-dir", private)
        checked = run(binary, run_dir, "--check-config", config)
        assert "OK" in checked, checked

        log = run_dir / "daemon.log"
        with log.open("wb") as output:
            proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                    stdout=output, stderr=subprocess.STDOUT)
            try:
                with wait_for_listener(proc, irc_port) as irc:
                    irc.sendall(b"NICK quickstart\r\nUSER quickstart 0 * :Quickstart\r\n")
                    read_until(irc, b" 001 quickstart ")
                    irc.sendall(b"PING :quickstart-check\r\n")
                    read_until(irc, b"PONG ")
                with wait_for_listener(proc, ws_port) as ws:
                    ws.sendall(
                        f"GET / HTTP/1.1\r\nHost: {HOST}:{ws_port}\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                        .encode("ascii")
                    )
                    response = read_until(ws, b"\r\n\r\n")
                    assert b"101 Switching Protocols" in response, response
                assert (private / "accounts.db").exists(), "account WAL missing"
                assert not (run_dir / "accounts.db").exists(), "account WAL escaped private directory"
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        print("PASS: private-dir CLI, fail-closed ACL, preflight, IRC, WebSocket, account WAL")


if __name__ == "__main__":
    main()
