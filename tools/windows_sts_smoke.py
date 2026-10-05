#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify native Windows STS advertisement leads to a live TLS listener."""

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time


HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parent.parent


def ports():
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket()) for _ in range(2)]
        for listener in listeners:
            listener.bind((HOST, 0))
        return [listener.getsockname()[1] for listener in listeners]


def connect(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before listener opened ({process.returncode})")
        try:
            connection = socket.create_connection((HOST, port), timeout=0.5)
            connection.settimeout(5)
            return connection
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"listener {port} did not open")


def line(connection, pending):
    while b"\n" not in pending:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before expected IRC response")
        pending += chunk
    answer, pending = pending.split(b"\n", 1)
    return answer.rstrip(b"\r"), pending


def probe(binary):
    irc_port, tls_port = ports()
    with tempfile.TemporaryDirectory(prefix="onyx-windows-sts-") as scratch:
        run_dir = Path(scratch)
        config = run_dir / "sts.toml"
        log = run_dir / "daemon.log"
        config.write_text(
            "\n".join((
                "[node]", "id = 1", "",
                "[listen]", f'host = "{HOST}"', f"irc = {irc_port}", "",
                "[tls]", "enabled = true", f"port = {tls_port}", 'dns_name = "localhost"', "",
                "[sts]", "enabled = true", "duration = 3600", f"port = {tls_port}", "",
            )), encoding="utf-8",
        )
        checked = subprocess.run(
            [str(binary), "--check-config", str(config)], cwd=run_dir,
            capture_output=True, text=True, timeout=15, check=False,
        )
        if checked.returncode != 0:
            raise RuntimeError(f"STS config preflight: {(checked.stdout + checked.stderr).strip()}")

        with log.open("wb") as output:
            process = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                       stdout=output, stderr=subprocess.STDOUT)
        try:
            expected = f"sts=duration=3600,port={tls_port}".encode()
            with connect(process, irc_port) as plain:
                plain.sendall(b"CAP LS 302\r\n")
                pending = b""
                cap_lines = []
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    reply, pending = line(plain, pending)
                    if b" CAP * LS " in reply:
                        cap_lines.append(reply)
                        if b" CAP * LS :" in reply:
                            break
                else:
                    raise TimeoutError("CAP LS did not complete")
                if not any(expected in reply for reply in cap_lines):
                    raise AssertionError(f"STS capability absent or wrong: {cap_lines!r}")

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # disposable self-signed fixture
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            with connect(process, tls_port) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as secure:
                    secure.sendall(b"NICK stsprobe\r\nUSER stsprobe 0 * :stsprobe\r\n")
                    pending = b""
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        reply, pending = line(secure, pending)
                        if b" 001 stsprobe " in reply:
                            break
                    else:
                        raise TimeoutError("TLS registration did not complete")
                    secure.sendall(b"PING :sts-live\r\n")
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        reply, pending = line(secure, pending)
                        if b"PONG" in reply and b"sts-live" in reply:
                            break
                    else:
                        raise TimeoutError("TLS PONG absent")
            if process.poll() is not None:
                raise RuntimeError(f"daemon exited after STS and TLS checks ({process.returncode})")
            print("PASS: plaintext CAP LS advertises STS with the live native TLS port")
        except Exception:
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path,
                        default=ROOT / "zig-out" / "bin" / "onyx-server.exe")
    arguments = parser.parse_args()
    if os.name != "nt":
        parser.error("native Windows is required")
    path = arguments.binary.resolve()
    if not path.is_file():
        parser.error(f"binary not found: {path}")
    probe(path)
