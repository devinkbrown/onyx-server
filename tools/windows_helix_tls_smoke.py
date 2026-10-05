#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep TLS IRC and WSS alive through two Windows Helix swaps.

The default fixture enables both ACME and OCSP schedulers without contacting
public endpoints. --generated checks daemon-minted default and TLS 1.2 leaves.

Usage: python -B tools/windows_helix_tls_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import windows_full_daemon_smoke as full
import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture, reserve_ports


class TlsClient(helix.Client):
    def __init__(self, port: int, context: ssl.SSLContext):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            self.socket = context.wrap_socket(raw, server_hostname="localhost")
        except Exception:
            raw.close()
            raise
        self.socket.settimeout(0.2)
        self.buffer = b""
        self.lines: list[bytes] = []

    def certificate_digest(self) -> bytes:
        return hashlib.sha256(self.socket.getpeercert(binary_form=True)).digest()


def connect_tls(port: int, context: ssl.SSLContext, process: subprocess.Popen | None,
                timeout: float = 30) -> TlsClient:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"daemon exited before TLS listener opened: {process.returncode}")
        try:
            return TlsClient(port, context)
        except (OSError, ssl.SSLError):
            time.sleep(0.2)
    raise TimeoutError(f"TLS IRC listener did not open on port {port}")


def connect_wss(port: int, context: ssl.SSLContext, process: subprocess.Popen | None,
                timeout: float = 30) -> full.WebSocketClient:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"daemon exited before WSS listener opened: {process.returncode}")
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                secure = context.wrap_socket(raw, server_hostname="localhost")
            except Exception:
                raw.close()
                raise
            client = full.WebSocketClient(secure)
            try:
                client.upgrade(port)
            except Exception:
                secure.close()
                raise
            return client
        except (OSError, ssl.SSLError):
            time.sleep(0.2)
    raise TimeoutError(f"WSS listener did not open on port {port}")


def token(client: TlsClient) -> bytes:
    return client.command(b"SESSION TOKEN", b" :SESSION TOKEN ").split(
        b" :SESSION TOKEN ", 1
    )[1].split()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--generated", action="store_true",
                        help="carry daemon-generated default and TLS 1.2 certificates")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    # Reuse the full-daemon smoke's bounded RFC 6455 client for both held and
    # fresh WSS connections. Its normal 90-second all-feature budget is too
    # short for two process swaps and Argon2-backed account registration.
    full.START = time.monotonic()
    full.DEADLINE_SECONDS = 300.0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disposable self-signed P-256 fixture.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    tls12_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls12_context.check_hostname = False
    tls12_context.verify_mode = ssl.CERT_NONE
    tls12_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls12_context.maximum_version = ssl.TLSVersion.TLSv1_2

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-tls-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        create_fixture(root)
        irc_port, tls_port, ws_port, challenge_port = reserve_ports(4)
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        tls_settings = (
            "dns_name = \"localhost\"\nenable_tls12 = true\n"
            if args.generated else
            "dns_name = \"localhost\"\ncert_path = \"leaf.pem\"\n"
            "key_path = \"keys-private/server.key\"\n"
        )
        acme_settings = (
            "[acme]\nenabled = false\n"
            if args.generated else
            "[acme]\nenabled = true\ndomain = \"localhost\"\n"
            f"check_interval = \"1s\"\nrenew_before_days = 1\nchallenge_port = {challenge_port}\n"
        )
        ocsp_settings = f"[ocsp]\nenabled = {'false' if args.generated else 'true'}\ncheck_interval = \"1s\"\n"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\nws = {ws_port}\n"
            f"[tls]\nenabled = true\nport = {tls_port}\n"
            + tls_settings
            + acme_settings
            + "ca_bundle_path = \"roots.pem\"\n"
            + ocsp_settings
            +
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        log = (root / "daemon.log").open("wb")
        parent = subprocess.Popen(
            [str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT
        )
        clients: list[object] = []
        try:
            owner = connect_tls(tls_port, context, parent)
            clients.append(owner)
            owner.register(b"tlsowner")
            owner.command(
                f"REGISTER helixadmin * {password}".encode(), b"REGISTER SUCCESS", timeout=45
            )

            held_tls = connect_tls(tls_port, context, parent)
            clients.append(held_tls)
            held_tls.register(b"heldtls")
            certificate = held_tls.certificate_digest()
            tls12_certificate = None
            if args.generated:
                held_tls12 = connect_tls(tls_port, tls12_context, parent)
                clients.append(held_tls12)
                held_tls12.register(b"heldtls12")
                tls12_certificate = held_tls12.certificate_digest()
                if tls12_certificate == certificate:
                    raise AssertionError("generated TLS 1.2 leg reused the TLS 1.3 leaf")

            held_wss = connect_wss(ws_port, context, parent)
            clients.append(held_wss)
            held_wss.register("heldwss")
            if hashlib.sha256(held_wss.sock.getpeercert(binary_form=True)).digest() != certificate:
                raise AssertionError("TLS IRC and WSS served different certificates")

            oper = connect_tls(tls_port, context, parent)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            encoded = base64.b64encode(b"\0helixadmin\0" + password.encode())
            oper.command(b"AUTHENTICATE " + encoded, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK admin")
            oper.send(b"USER smoke 0 * :Windows TLS Helix operator")
            oper.wait(b" 381 ", start=start)
            original_token = token(oper)
            if args.generated:
                helix.wait_log_contains(root / "daemon.log", "hardened TLS 1.2 also accepted")
            else:
                helix.wait_log_contains(root / "daemon.log", "acme renewal scheduler enabled")
                helix.wait_log_contains(root / "daemon.log", "acme renewal not due for localhost")
                helix.wait_log_contains(root / "daemon.log", "ocsp staple scheduler enabled")

            serving_pid = parent.pid
            for sequence in (1, 2):
                acme_checks_before = (
                    (root / "daemon.log").read_text(encoding="utf-8", errors="replace").count(
                        "acme renewal not due for localhost") if not args.generated else 0
                )
                oper.send(b"UPGRADE")
                next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                marker = f"tls-wss-helix-{sequence}"
                for held in clients:
                    if isinstance(held, TlsClient):
                        held.ping(marker.encode())
                    else:
                        held.ping(marker)
                held_wss.control_ping()
                if token(oper) != original_token:
                    raise AssertionError("local reusable session token changed across Helix")

                held_tls.send(f"PRIVMSG heldwss :{marker}".encode())
                held_wss.until(f"PRIVMSG heldwss :{marker}")

                fresh_tls = connect_tls(tls_port, context, None)
                clients.append(fresh_tls)
                fresh_tls.register(f"freshtls{sequence}".encode())
                fresh_tls.ping(marker.encode())
                if fresh_tls.certificate_digest() != certificate:
                    raise AssertionError("fresh TLS connection saw a changed certificate")

                if args.generated:
                    fresh_tls12 = connect_tls(tls_port, tls12_context, None)
                    clients.append(fresh_tls12)
                    fresh_tls12.register(f"freshtls12{sequence}".encode())
                    fresh_tls12.ping(marker.encode())
                    if fresh_tls12.certificate_digest() != tls12_certificate:
                        raise AssertionError("fresh TLS 1.2 connection saw a changed generated certificate")
                else:
                    until = time.monotonic() + 10
                    while time.monotonic() < until:
                        contents = (root / "daemon.log").read_text(encoding="utf-8", errors="replace")
                        if contents.count("acme renewal not due for localhost") > acme_checks_before:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("ACME worker did not resume after Helix COMMIT")

                fresh_wss = connect_wss(ws_port, context, None)
                clients.append(fresh_wss)
                fresh_wss.register(f"freshwss{sequence}")
                fresh_wss.ping(marker)
                if hashlib.sha256(fresh_wss.sock.getpeercert(binary_form=True)).digest() != certificate:
                    raise AssertionError("fresh WSS connection saw a changed certificate")
                print(
                    f"PASS: Windows TLS/WSS Helix swap {sequence}, {serving_pid} -> {next_pid}; "
                    "held sockets, session token, and fresh TLS/WSS accepted"
                    + (" with generated TLS 1.2" if args.generated else " with ACME/OCSP"),
                    flush=True,
                )
                serving_pid = next_pid
            if parent.wait(timeout=2) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception:
            log.flush()
            print((root / "daemon.log").read_text(encoding="utf-8", errors="replace")[-12000:])
            raise
        finally:
            for client in clients:
                if isinstance(client, TlsClient):
                    client.close()
                else:
                    client.sock.close()
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
