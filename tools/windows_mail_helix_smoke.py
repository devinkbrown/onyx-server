#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise Windows mail failure custody across rollback and two Helix swaps.

Usage: python -B tools/windows_mail_helix_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from windows_backup_smoke import run_cli
from windows_helix_smoke import Client, free_port, image_pids, sole_image_pid, wait_log_contains
from windows_private_account_dir import create_private_directory


def write_config(path: Path, port: int, relay_port: int, account_db: Path) -> None:
    path.write_text(
        "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
        "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
        "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
        f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
        f"[sasl]\nenabled = true\naccount_db = \"{account_db.as_posix()}\"\n"
        "[accounts]\npbkdf2_rounds = 10000\n"
        "[mail]\nenabled = true\nrelay_host = \"127.0.0.1\"\n"
        f"relay_port = {relay_port}\n"
        "from = \"noreply@example.test\"\ntrust_store_path = \"roots.pem\"\n"
        "[[oper_groups]]\nname = \"netadmin\"\n"
        "privileges = [\"server_restart\", \"server_admin\"]\n"
        "[[opers]]\naccount = \"mailadmin\"\nclass = \"netadmin\"\n",
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
    raise TimeoutError("mail Helix listener did not open")


def wait_failure(wal: Path, sequence: int, recipient: bytes, timeout: float = 35) -> None:
    until = time.monotonic() + timeout
    key = f"mailfail:{sequence}".encode()
    while time.monotonic() < until:
        try:
            data = wal.read_bytes()
            if (key in data and recipient in data
                    and (b"ConnectFailed" in data or b"ConnectTimeout" in data)):
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"failure WAL did not record {key!r} for {recipient!r}")


def submit_failure(port: int, sequence: int, wal: Path) -> None:
    client = Client(port)
    account = f"mailacct{sequence}".encode()
    recipient = f"recipient{sequence}@example.test".encode()
    try:
        client.register(f"mailguest{sequence}".encode())
        start = len(client.lines)
        client.command(
            b"REGISTER " + account + b" " + recipient + b" mail-password",
            b"REGISTER SUCCESS " + account,
            timeout=45,
        )
        notice = client.wait(b"verification code was emailed", start=start, timeout=4)
        if b"verification code was emailed" not in notice:
            raise AssertionError(f"mail worker did not accept verification enqueue: {notice!r}")
        wait_failure(wal, sequence, recipient)
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    roots = ssl.enum_certificates("ROOT")
    der = next((cert for cert, encoding, _ in roots if encoding == "x509_asn"), None)
    if der is None:
        raise RuntimeError("Windows ROOT certificate store has no X.509 trust anchor")
    original_bundle = ssl.DER_cert_to_PEM_cert(der)

    with tempfile.TemporaryDirectory(prefix="onyx-windows-mail-helix-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        private = root / "private"
        create_private_directory(private)
        wal = private / "mail-failures.wal"
        bundle = root / "roots.pem"
        bundle.write_text(original_bundle, encoding="ascii")
        config = root / "server.toml"
        port = free_port()
        log_path = root / "daemon.log"

        # Bound without listen: Winsock rejects the SMTP connection while no
        # other process can take the chosen relay port during the swaps.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_relay:
            closed_relay.bind(("127.0.0.1", 0))
            write_config(config, port, closed_relay.getsockname()[1], private / "accounts.wal")
            checked = run_cli(binary, root, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError("mail config is invalid: " + checked.stdout + checked.stderr)
            log = log_path.open("wb")
            parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            clients: list[Client] = []
            try:
                owner = connect_when_ready(parent, port)
                clients.append(owner)
                owner.register(b"mailowner")
                password = secrets.token_urlsafe(22).encode()
                owner.command(b"REGISTER mailadmin * " + password, b"REGISTER SUCCESS", timeout=45)

                oper = Client(port)
                clients.append(oper)
                oper.command(b"CAP LS 302", b" LS ")
                oper.command(b"CAP REQ :sasl", b" ACK ")
                oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
                proof = base64.b64encode(b"\0mailadmin\0" + password)
                oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
                start = len(oper.lines)
                oper.send(b"CAP END")
                oper.send(b"NICK mailadmin")
                oper.send(b"USER smoke 0 * :Mail Helix operator")
                oper.wait(b" 381 ", start=start)

                submit_failure(port, 1, wal)
                serving_pid = parent.pid
                bundle.write_text(original_bundle + original_bundle, encoding="ascii")
                checked = run_cli(binary, root, "--check-config", config)
                if checked.returncode != 0:
                    raise AssertionError("changed mail trust bundle is invalid: " + checked.stdout + checked.stderr)
                oper.send(b"UPGRADE")
                wait_log_contains(log_path, "deferred UPGRADE failed")
                rollback_log = log_path.read_text(encoding="utf-8", errors="replace")
                if "Windows mail restore failed (ConfigMismatch)" not in rollback_log:
                    raise AssertionError("changed mail trust bundle did not reach HXMA restore: " + rollback_log[-4000:])
                if image_pids(binary) != {serving_pid}:
                    raise AssertionError("changed mail trust bundle left a successor or lost predecessor")
                owner.ping(b"after-mail-proof-rejection")
                oper.ping(b"after-mail-proof-rejection")
                print("PASS: changed valid mail trust bundle aborted before COMMIT", flush=True)

                bundle.write_text(original_bundle, encoding="ascii")
                for sequence in (1, 2):
                    oper.send(b"UPGRADE")
                    next_pid = sole_image_pid(binary, different_from=serving_pid)
                    owner.ping(f"mail-swap-{sequence}".encode())
                    oper.ping(f"mail-swap-{sequence}".encode())
                    submit_failure(port, sequence + 1, wal)
                    print(f"PASS: mail failure WAL sequence {sequence + 1} after Helix swap {sequence}, {serving_pid} -> {next_pid}", flush=True)
                    serving_pid = next_pid
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


if __name__ == "__main__":
    raise SystemExit(main())
