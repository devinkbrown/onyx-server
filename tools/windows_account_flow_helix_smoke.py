#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prove a pending email reset code survives two native Windows Helix swaps.

Usage: python -B tools/windows_account_flow_helix_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from windows_backup_smoke import run_cli
from windows_helix_smoke import Client, free_port, image_pids, sole_image_pid
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture


class SmtpSink:
    """Disposable loopback STARTTLS relay; captures only complete DATA bodies."""

    def __init__(self, root: Path):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.5)
        self.port = self.listener.getsockname()[1]
        self.messages: queue.Queue[bytes] = queue.Queue()
        self.errors: queue.Queue[str] = queue.Queue()
        self.running = threading.Event()
        self.running.set()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(root / "leaf.pem", root / "keys-private/server.key")
        self.thread = threading.Thread(target=self._serve, name="smtp-sink", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.running.clear()
        self.listener.close()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise TimeoutError("SMTP sink did not stop")

    @staticmethod
    def _line(reader) -> bytes:
        line = reader.readline(4096)
        if not line.endswith(b"\r\n"):
            raise ConnectionError("incomplete SMTP command")
        return line

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(12)
        conn.sendall(b"220 localhost test relay\r\n")
        reader = conn.makefile("rb")
        try:
            if not self._line(reader).startswith(b"EHLO "):
                raise AssertionError("SMTP client did not greet relay")
            conn.sendall(b"250 STARTTLS\r\n")
            if self._line(reader) != b"STARTTLS\r\n":
                raise AssertionError("SMTP client did not require STARTTLS")
            conn.sendall(b"220 ready for TLS\r\n")
        finally:
            reader.close()
        with self.context.wrap_socket(conn, server_side=True) as secure:
            secure.settimeout(12)
            reader = secure.makefile("rb")
            try:
                if not self._line(reader).startswith(b"EHLO "):
                    raise AssertionError("SMTP client did not greet after TLS")
                secure.sendall(b"250 encrypted relay\r\n")
                if not self._line(reader).startswith(b"MAIL FROM:<"):
                    raise AssertionError("missing SMTP sender")
                secure.sendall(b"250 sender ok\r\n")
                if not self._line(reader).startswith(b"RCPT TO:<"):
                    raise AssertionError("missing SMTP recipient")
                secure.sendall(b"250 recipient ok\r\n")
                if self._line(reader) != b"DATA\r\n":
                    raise AssertionError("missing SMTP DATA")
                secure.sendall(b"354 send message\r\n")
                body = bytearray()
                while True:
                    line = self._line(reader)
                    if line == b".\r\n":
                        break
                    body.extend(line)
                    if len(body) > 64 * 1024:
                        raise AssertionError("SMTP test message exceeded bound")
                self.messages.put(bytes(body))
                secure.sendall(b"250 queued\r\n")
                if self._line(reader) != b"QUIT\r\n":
                    raise AssertionError("SMTP client omitted QUIT")
                secure.sendall(b"221 bye\r\n")
            finally:
                reader.close()

    def _serve(self) -> None:
        while self.running.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn)
            except Exception as exc:
                self.errors.put(type(exc).__name__ + ": " + str(exc))
            finally:
                conn.close()

    def code(self, marker: bytes, timeout: float = 35) -> bytes:
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if not self.errors.empty():
                raise AssertionError("SMTP sink failed: " + self.errors.get_nowait())
            try:
                body = self.messages.get(timeout=min(0.5, until - time.monotonic()))
            except queue.Empty:
                continue
            match = re.search(marker + rb"([0-9a-f]{32})", body)
            if match is not None:
                return match.group(1)
        raise TimeoutError("SMTP relay did not receive the expected account code")


def write_config(path: Path, port: int, sink_port: int, account_db: Path) -> None:
    path.write_text(
        "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
        "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
        "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
        f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
        f"[sasl]\nenabled = true\naccount_db = \"{account_db.as_posix()}\"\n"
        "[accounts]\npbkdf2_rounds = 10000\n"
        "[mail]\nenabled = true\nrelay_host = \"localhost\"\n"
        f"relay_port = {sink_port}\n"
        "from = \"noreply@example.test\"\ntrust_store_path = \"roots.pem\"\n"
        "insecure_skip_verify = true\n"
        "[[oper_groups]]\nname = \"netadmin\"\n"
        "privileges = [\"server_restart\", \"server_admin\"]\n"
        "[[opers]]\naccount = \"flowadmin\"\nclass = \"netadmin\"\n",
        encoding="utf-8",
    )


def connect_when_ready(proc: subprocess.Popen, port: int) -> Client:
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before listener opened ({proc.returncode})")
        try:
            return Client(port)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("account-flow Helix listener did not open")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-account-flow-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        create_fixture(root)
        sink = SmtpSink(root)
        sink.start()
        config = root / "server.toml"
        port = free_port()
        write_config(config, port, sink.port, root / "private/accounts.wal")
        checked = run_cli(binary, root, "--check-config", config)
        if checked.returncode != 0:
            raise AssertionError("account-flow config is invalid: " + checked.stdout + checked.stderr)
        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[Client] = []
        try:
            owner = connect_when_ready(parent, port)
            clients.append(owner)
            owner.register(b"flowowner")
            password = secrets.token_urlsafe(22).encode()
            owner.command(b"REGISTER flowadmin * " + password, b"REGISTER SUCCESS", timeout=45)

            oper = Client(port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            oper.command(b"AUTHENTICATE " + base64.b64encode(b"\0flowadmin\0" + password), b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK flowadmin")
            oper.send(b"USER smoke 0 * :Account-flow Helix operator")
            oper.wait(b" 381 ", start=start)

            flow = Client(port)
            clients.append(flow)
            flow.register(b"flowguest")
            flow.command(b"REGISTER flowacct flow@example.test flow-password", b"REGISTER SUCCESS flowacct", timeout=45)
            verification = sink.code(b"verification code for onyx.local is: ")
            flow.command(b"VERIFY flowacct " + verification, b"VERIFY: your account email is now verified")
            flow.command(b"RESETPASS flowacct", b"if that account has a verified email")
            reset = sink.code(b"Reset code: ")
            flow.command(b"RESETPASS flowacct deadbeef changed-password", b"BAD_CODE")

            serving_pid = parent.pid
            for sequence in (1, 2):
                oper.send(b"UPGRADE")
                next_pid = sole_image_pid(binary, different_from=serving_pid)
                owner.ping(f"account-flow-swap-{sequence}".encode())
                oper.ping(f"account-flow-swap-{sequence}".encode())
                flow.ping(f"account-flow-swap-{sequence}".encode())
                flow.command(b"RESETPASS flowacct deadbeef changed-password", b"BAD_CODE")
                print(f"PASS: pending reset code survived Helix swap {sequence}, {serving_pid} -> {next_pid}", flush=True)
                serving_pid = next_pid
            flow.command(b"RESETPASS flowacct " + reset + b" changed-password", b"RESETPASS SUCCESS flowacct")
            flow.command(b"RESETPASS flowacct deadbeef changed-password", b"NO_REQUEST")
            print("PASS: exact reset code remained valid and was consumed after two swaps", flush=True)
            if parent.wait(timeout=2) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception:
            log.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace")[-10000:])
            for index, client in enumerate(clients):
                print(f"client {index} recent lines: {client.lines[-8:]!r}")
            raise
        finally:
            for client in clients:
                client.close()
            try:
                for pid in image_pids(binary):
                    os.kill(pid, 15)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 20
                while image_pids(binary) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()
                sink.close()


if __name__ == "__main__":
    raise SystemExit(main())
