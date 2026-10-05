#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise Windows Web Push Helix rollback and two swaps with held clients.

The queued delivery and overflow counters have no deterministic IRC inspection
surface; their exact owner checkpoint is covered by native codec tests. This
smoke checks live VAPID identity, a stored subscription, and a changed valid
trust bundle that must abort the candidate before COMMIT.

Usage: python -B tools/windows_webpush_helix_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, free_port, image_pids, sole_image_pid, wait_log_contains
from windows_private_account_dir import create_private_directory
from windows_webpush_smoke import run_cli


def write_config(path: Path, port: int, account_db: Path) -> None:
    path.write_text(
        "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
        "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
        "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
        f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
        f"[sasl]\nenabled = true\naccount_db = \"{account_db.as_posix()}\"\n"
        "[acme]\nca_bundle_path = \"roots.pem\"\n"
        "[webpush]\nenabled = true\n"
        "vapid_key_path = \"vapid-private/vapid.key\"\n"
        "subject = \"mailto:ops@example.test\"\n"
        "[[oper_groups]]\nname = \"netadmin\"\n"
        "privileges = [\"server_restart\", \"server_admin\"]\n"
        "[[opers]]\naccount = \"pushadmin\"\nclass = \"netadmin\"\n",
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
    raise TimeoutError("Web Push Helix listener did not open")


def vapid_public(client: Client) -> bytes:
    line = client.wait(b"VAPID=", start=0, timeout=8)
    match = re.search(rb"\bVAPID=([A-Za-z0-9_-]+)", line)
    if match is None:
        raise AssertionError(f"registration did not advertise VAPID: {client.lines[-10:]!r}")
    return match.group(1)


def assert_subscription(client: Client, endpoint: bytes) -> None:
    start = len(client.lines)
    client.send(b"WEBPUSH LIST")
    client.wait(b"subscription(s)", start=start)
    replies = client.lines[start:]
    if not any(endpoint in line for line in replies):
        raise AssertionError(f"Web Push subscription disappeared: {replies!r}")


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

    with tempfile.TemporaryDirectory(prefix="onyx-windows-webpush-helix-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        private = root / "private"
        vapid_private = root / "vapid-private"
        create_private_directory(private)
        create_private_directory(vapid_private)
        bundle = root / "roots.pem"
        bundle.write_text(original_bundle, encoding="ascii")
        config = root / "server.toml"
        port = free_port()
        write_config(config, port, private / "accounts.wal")
        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[Client] = []
        try:
            owner = connect_when_ready(parent, port)
            clients.append(owner)
            owner.register(b"pushowner")
            public = vapid_public(owner)
            password = secrets.token_urlsafe(22).encode()
            owner.command(b"REGISTER pushadmin * " + password, b"REGISTER SUCCESS", timeout=45)

            # This is the P-256 generator in uncompressed SEC1 form. The
            # subscription stays inert; no outbound push service is contacted.
            key = bytes.fromhex(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
            endpoint = b"https://push.invalid/onyx-helix-smoke"
            auth = secrets.token_bytes(16)
            owner.command(
                b"WEBPUSH SUBSCRIBE " + endpoint + b" "
                + base64.urlsafe_b64encode(key).rstrip(b"=") + b" "
                + base64.urlsafe_b64encode(auth).rstrip(b"="),
                b"WEBPUSH: subscription stored",
            )
            assert_subscription(owner, endpoint)

            oper = Client(port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0pushadmin\0" + password)
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK pushadmin")
            oper.send(b"USER smoke 0 * :Web Push Helix operator")
            oper.wait(b" 381 ", start=start)

            serving_pid = parent.pid
            # A duplicate, individually valid certificate changes the parsed
            # trust-anchor sequence while keeping candidate preflight valid.
            bundle.write_text(original_bundle + original_bundle, encoding="ascii")
            checked = run_cli(binary, root, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError("changed trust bundle is invalid: " + checked.stdout + checked.stderr)
            oper.send(b"UPGRADE")
            wait_log_contains(log_path, "deferred UPGRADE failed")
            rollback_log = log_path.read_text(encoding="utf-8", errors="replace")
            if "Windows Web Push restore failed (ConfigMismatch)" not in rollback_log:
                raise AssertionError("changed trust bundle did not reach exact HXWP restore: " + rollback_log[-4000:])
            if image_pids(binary) != {serving_pid}:
                raise AssertionError("changed trust bundle left a successor or lost predecessor")
            owner.ping(b"after-webpush-proof-rejection")
            oper.ping(b"after-webpush-proof-rejection")
            assert_subscription(owner, endpoint)
            print("PASS: changed valid Web Push trust bundle aborted before COMMIT", flush=True)

            bundle.write_text(original_bundle, encoding="ascii")
            for sequence in (1, 2):
                oper.send(b"UPGRADE")
                next_pid = sole_image_pid(binary, different_from=serving_pid)
                owner.ping(f"push-swap-{sequence}".encode())
                oper.ping(f"push-swap-{sequence}".encode())
                assert_subscription(owner, endpoint)
                fresh = Client(port)
                clients.append(fresh)
                fresh.register(f"pushfresh{sequence}".encode())
                if vapid_public(fresh) != public:
                    raise AssertionError("VAPID public identity changed across Helix")
                print(f"PASS: Web Push Helix swap {sequence}, {serving_pid} -> {next_pid}", flush=True)
                serving_pid = next_pid
            if parent.wait(timeout=2) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            if not (vapid_private / "vapid.key").is_file():
                raise AssertionError("VAPID private key disappeared")
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
