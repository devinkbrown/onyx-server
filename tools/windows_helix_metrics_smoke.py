#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep /metrics and held IRC sockets live through two native Windows Helix swaps.

Usage: python -B tools/windows_helix_metrics_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory


def scrape_metrics(port: int, *, timeout: float = 40.0) -> bytes:
    """One real HTTP scrape; connection refusal, truncated text and 5xx fail."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 2 * 1024 * 1024:
                raise AssertionError("metrics response exceeded the bounded fixture capacity")
    headers, divider, body = bytes(response).partition(b"\r\n\r\n")
    if not divider or not headers.startswith(b"HTTP/1.1 200 OK\r\n"):
        raise AssertionError(f"invalid metrics HTTP response: {bytes(response[:200])!r}")
    lengths = [line.split(b":", 1)[1].strip() for line in headers.split(b"\r\n")
               if line.lower().startswith(b"content-length:")]
    if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) != len(body):
        raise AssertionError("metrics Content-Length did not match the complete body")
    if b"onyx_" not in body:
        raise AssertionError("metrics exposition contained no Onyx samples")
    return body


class MetricsPoller:
    """Probe the transferred listener through each cut, one scrape at a time."""

    def __init__(self, port: int):
        self.port = port
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.successes = 0
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self.run, name="metrics-helix-poller", daemon=True)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                scrape_metrics(self.port)
            except Exception as exc:
                with self.lock:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
            else:
                with self.lock:
                    self.successes += 1
            self.stop.wait(0.05)

    def start(self) -> None:
        self.thread.start()

    def inspect(self) -> tuple[int, list[str]]:
        with self.lock:
            return self.successes, self.errors.copy()

    def finish(self) -> None:
        self.stop.set()
        self.thread.join(timeout=45)
        if self.thread.is_alive():
            raise TimeoutError("metrics poller did not finish its bounded scrape")
        _, failures = self.inspect()
        if failures:
            raise AssertionError(f"metrics polling saw listener failures: {failures!r}")


def wait_irc(port: int, process: subprocess.Popen[bytes], timeout: float = 30) -> helix.Client:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listen: {process.returncode}")
        try:
            return helix.Client(port)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("IRC listener did not start")


def wait_metrics(port: int, process: subprocess.Popen[bytes], timeout: float = 30) -> bytes:
    until = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before metrics listen: {process.returncode}")
        try:
            return scrape_metrics(port, timeout=2)
        except (OSError, AssertionError) as exc:
            last = exc
            time.sleep(0.2)
    raise TimeoutError(f"metrics listener did not start: {last}")


def session_token(client: helix.Client) -> bytes:
    line = client.command(b"SESSION TOKEN", b" :SESSION TOKEN ")
    return line.split(b" :SESSION TOKEN ", 1)[1].split()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-metrics-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        create_private_directory(root / "private")
        irc_port = helix.free_port()
        metrics_port = helix.free_port()
        while metrics_port == irc_port:
            metrics_port = helix.free_port()
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\n"
            f"[metrics]\nbind = \"127.0.0.1\"\nlisten = {metrics_port}\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        preflight = subprocess.run(
            [str(binary), "--check-config", str(config)], cwd=root,
            capture_output=True, text=True, timeout=20, check=False,
        )
        if preflight.returncode != 0:
            raise RuntimeError(f"metrics Helix config preflight failed: {(preflight.stdout + preflight.stderr).strip()}")

        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[helix.Client] = []
        poller: MetricsPoller | None = None
        try:
            owner = wait_irc(irc_port, parent)
            clients.append(owner)
            owner.register(b"owner")
            owner.command(f"REGISTER helixadmin * {password}".encode(), b"REGISTER SUCCESS", timeout=45)

            held = helix.Client(irc_port)
            clients.append(held)
            held.register(b"heldmetrics")

            oper = helix.Client(irc_port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0helixadmin\0" + password.encode("ascii"))
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK metricsadmin")
            oper.send(b"USER smoke 0 * :Windows metrics Helix operator")
            oper.wait(b" 381 ", start=start)
            token = session_token(oper)

            wait_metrics(metrics_port, parent)
            poller = MetricsPoller(metrics_port)
            poller.start()
            serving_pid = parent.pid
            for sequence in (1, 2):
                before, failures = poller.inspect()
                if failures:
                    raise AssertionError(f"metrics polling failed before swap {sequence}: {failures!r}")
                oper.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(binary, different_from=serving_pid, timeout=45)
                # Deliberately no retry: this checks the first scrape after the
                # old process exits, while the transferred listener is reused.
                immediate = scrape_metrics(metrics_port)
                if b"onyx_" not in immediate:
                    raise AssertionError("first successor metrics scrape was empty")
                marker = f"metrics-helix-{sequence}".encode("ascii")
                for client in clients:
                    client.ping(marker)
                if session_token(oper) != token:
                    raise AssertionError("held local reusable session token changed")
                fresh = helix.Client(irc_port)
                clients.append(fresh)
                fresh.register(f"metricsfresh{sequence}".encode("ascii"))
                fresh.ping(marker)
                until = time.monotonic() + 5
                while True:
                    count, failures = poller.inspect()
                    if failures:
                        raise AssertionError(f"metrics polling failed through swap {sequence}: {failures!r}")
                    if count > before:
                        break
                    if time.monotonic() >= until:
                        raise TimeoutError("continuous metrics poller did not scrape successor")
                    time.sleep(0.05)
                print(
                    f"PASS: metrics Helix swap {sequence}, {serving_pid} -> {successor_pid}; "
                    "held IRC, fresh IRC and uninterrupted /metrics scrapes",
                    flush=True,
                )
                serving_pid = successor_pid
            if parent.wait(timeout=5) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception as exc:
            log.flush()
            print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
            print(log_path.read_text(encoding="utf-8", errors="replace")[-12000:], file=sys.stderr)
            raise
        finally:
            try:
                if poller is not None:
                    poller.finish()
            finally:
                for client in clients:
                    client.close()
                try:
                    for pid in helix.image_pids(binary):
                        os.kill(pid, 15)
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=10)
                    until = time.monotonic() + 10
                    while helix.image_pids(binary) and time.monotonic() < until:
                        time.sleep(0.1)
                    log.close()


if __name__ == "__main__":
    raise SystemExit(main())
