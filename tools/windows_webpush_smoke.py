#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows Web Push VAPID custody, memo enqueue, and worker boot.

The local SSRF guard intentionally rejects loopback delivery endpoints, so
this smoke checks private key preflight, live worker startup, memo-triggered
delivery refusal, and key/subscription identity across restart. Native module
tests cover the pinned-address HTTPS path.

Usage: python -B tools/windows_webpush_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import base64
from contextlib import closing
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time

from windows_private_account_dir import create_private_directory
from windows_helix_smoke import Client, authenticate_account, wait_log_contains


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
P256_GENERATOR = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
PUSH_ENDPOINT = b"https://127.0.0.1/onyx-webpush-smoke"


def reserve_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def config_text(port, vapid_path):
    return "\n".join([
        "[node]", "id = 1", "",
        "[listen]", f'host = "{HOST}"', f"irc = {port}", "",
        "[sasl]", "enabled = true", 'account_db = "accounts-private/accounts.wal"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
        "[acme]", 'ca_bundle_path = "roots.pem"', "",
        "[webpush]", "enabled = true", f'vapid_key_path = "{vapid_path}"',
        'subject = "mailto:ops@example.test"', "",
    ])


def run_cli(binary, run_dir, *args):
    return subprocess.run([str(binary), *map(str, args)], cwd=run_dir,
                          capture_output=True, text=True, timeout=20, check=False)


def wait_irc(proc, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"daemon exited before IRC listen (exit {proc.returncode})")
        try:
            return socket.create_connection((HOST, port), timeout=0.5)
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("IRC listener did not start")


def vapid_isupport(sock):
    sock.settimeout(5)
    sock.sendall(b"NICK pushsmoke\r\nUSER pushsmoke 0 * :Push Smoke\r\n")
    incoming = b""
    deadline = time.monotonic() + 8
    seen_registration = False
    public = None
    while time.monotonic() < deadline and (not seen_registration or public is None):
        incoming += sock.recv(4096)
        while b"\n" in incoming:
            line, incoming = incoming.split(b"\n", 1)
            if b" 001 " in line:
                seen_registration = True
            match = re.search(rb"\bVAPID=([A-Za-z0-9_-]+)", line)
            if match:
                public = match.group(1)
    if not seen_registration or public is None:
        raise AssertionError("IRC registration did not advertise VAPID")
    sock.sendall(b"QUIT :smoke complete\r\n")
    return public


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def exercise_memo_push(port, log_path, attempt, recipient_password, sender_password, auth):
    if attempt == 1:
        recipient = Client(port)
        try:
            recipient.register(b"pushrecipient")
            recipient.command(b"REGISTER pushrecipient * " + recipient_password,
                              b"REGISTER SUCCESS", timeout=45)
            recipient.command(
                b"WEBPUSH SUBSCRIBE " + PUSH_ENDPOINT + b" "
                + base64.urlsafe_b64encode(P256_GENERATOR).rstrip(b"=") + b" "
                + base64.urlsafe_b64encode(auth).rstrip(b"="),
                b"WEBPUSH: subscription stored",
            )
        finally:
            recipient.close()
    else:
        recipient = authenticate_account(port, b"pushrecipient", recipient_password,
                                         b"pushrecipient")
        try:
            start = len(recipient.lines)
            recipient.command(b"WEBPUSH LIST", b"subscription(s)")
            if not any(PUSH_ENDPOINT in line for line in recipient.lines[start:]):
                raise AssertionError("Web Push subscription did not survive cold restart")
        finally:
            recipient.close()

    if attempt == 1:
        sender = Client(port)
    else:
        sender = authenticate_account(port, b"pushsender", sender_password,
                                      b"pushsender")
    try:
        if attempt == 1:
            sender.register(b"pushsender")
            sender.command(b"REGISTER pushsender * " + sender_password,
                           b"REGISTER SUCCESS", timeout=45)
        marker = f"offline-push-{attempt}".encode("ascii")
        sender.command(b"MEMO SEND pushrecipient :" + marker,
                       b"MEMO: message stored for delivery")
        wait_log_contains(log_path,
                          "webpush: delivery to " + PUSH_ENDPOINT.decode("ascii")
                          + " failed: DisallowedPushEndpoint", timeout=15)
    finally:
        sender.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    roots = ssl.enum_certificates("ROOT")
    der = next((cert for cert, encoding, _ in roots if encoding == "x509_asn"), None)
    if der is None:
        raise RuntimeError("Windows ROOT certificate store has no X.509 trust anchor")

    with tempfile.TemporaryDirectory(prefix="onyx-webpush-windows-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "accounts-private")
        create_private_directory(run_dir / "vapid-private")
        (run_dir / "broad").mkdir()
        (run_dir / "roots.pem").write_text(ssl.DER_cert_to_PEM_cert(der), encoding="ascii")
        port = reserve_port()
        config = run_dir / "webpush.toml"
        broad = run_dir / "broad.toml"
        config.write_text(config_text(port, "vapid-private/vapid.key"), encoding="utf-8")
        broad.write_text(config_text(port, "broad/vapid.key"), encoding="utf-8")

        accepted = run_cli(binary, run_dir, "--check-config", config)
        if accepted.returncode != 0:
            raise AssertionError(f"private VAPID preflight failed: {(accepted.stdout + accepted.stderr).strip()}")
        refused = run_cli(binary, run_dir, "--check-config", broad)
        if refused.returncode == 0:
            raise AssertionError("broad VAPID key directory passed preflight")
        if (run_dir / "vapid-private" / "vapid.key").exists():
            raise AssertionError("read-only preflight created a VAPID key")
        print("PASS: private VAPID directory accepted; broad directory rejected without key creation")

        public = None
        key_bytes = None
        recipient_password = secrets.token_urlsafe(22).encode("ascii")
        sender_password = secrets.token_urlsafe(22).encode("ascii")
        auth = secrets.token_bytes(16)
        for attempt in (1, 2):
            log = run_dir / f"daemon-{attempt}.log"
            proc = None
            try:
                with log.open("w", encoding="utf-8") as output:
                    proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                            stdout=output, stderr=subprocess.STDOUT)
                    with closing(wait_irc(proc, port)) as sock:
                        advertised = vapid_isupport(sock)
                    deadline = time.monotonic() + 5
                    while "web push live" not in log.read_text(encoding="utf-8", errors="replace") and time.monotonic() < deadline:
                        time.sleep(0.05)
                    if "web push live" not in log.read_text(encoding="utf-8", errors="replace"):
                        raise AssertionError(f"worker did not report live startup: {log.read_text(encoding='utf-8', errors='replace')}")
                    if proc.poll() is not None:
                        raise AssertionError("daemon exited after Web Push worker startup")
                    exercise_memo_push(port, log, attempt, recipient_password,
                                       sender_password, auth)
            finally:
                stop(proc)
            persisted = (run_dir / "vapid-private" / "vapid.key").read_bytes()
            if len(persisted) != 64 or not re.fullmatch(rb"[0-9a-f]{64}", persisted):
                raise AssertionError("VAPID key did not persist as a 64-byte private scalar")
            if public is None:
                public, key_bytes = advertised, persisted
            elif advertised != public or persisted != key_bytes:
                raise AssertionError("VAPID key or advertised public identity changed after restart")
        print("PASS: Windows Web Push memo enqueue and loopback guard; VAPID and subscription persist across restart")


if __name__ == "__main__":
    main()
