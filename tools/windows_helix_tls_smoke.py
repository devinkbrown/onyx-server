#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep TLS IRC and WSS alive through Windows REHASH and Helix.

The default fixture enables both ACME and OCSP schedulers without contacting
public endpoints. It performs an unchanged, on-disk TLS REHASH before two
swaps. --generated first checks two pristine swaps, then confirms that REHASH
minted a new TLS 1.2 side leaf and UPGRADE refuses. Optional negative modes
exercise valid cert rotation and failed cert reload after the positive swaps.

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
    def __init__(self, port: int, context: ssl.SSLContext,
                 resume_session: ssl.SSLSession | None = None):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            self.socket = context.wrap_socket(
                raw, server_hostname="localhost", session=resume_session,
            )
        except Exception:
            raw.close()
            raise
        self.socket.settimeout(0.2)
        self.buffer = b""
        self.lines: list[bytes] = []

    def certificate_digest(self) -> bytes:
        return hashlib.sha256(self.socket.getpeercert(binary_form=True)).digest()


def connect_tls(port: int, context: ssl.SSLContext, process: subprocess.Popen | None,
                timeout: float = 30, resume_session: ssl.SSLSession | None = None) -> TlsClient:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"daemon exited before TLS listener opened: {process.returncode}")
        try:
            return TlsClient(port, context, resume_session)
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
                        help="carry generated certificates, then refuse UPGRADE after REHASH")
    parser.add_argument("--negative", choices=("rotation", "failed-reload"),
                        help="after two swaps, REHASH rotated or unreadable TLS files and require UPGRADE refusal")
    parser.add_argument("--resumption", action="store_true",
                        help="prove 1-RTT TLS ticket reuse across unchanged REHASH and two swaps")
    parser.add_argument("--early-data", action="store_true",
                        help="prove two swaps with TLS 1.3 early data enabled and 1-RTT ticket reuse")
    parser.add_argument("--resumption-tls12", action="store_true",
                        help="prove single-use TLS 1.2 tickets and replay history across REHASH and two swaps")
    args = parser.parse_args()
    if args.generated and args.negative:
        parser.error("--generated and --negative require separate fixture runs")
    if (args.resumption or args.early_data) and (args.generated or args.negative):
        parser.error("--resumption and --early-data require the positive on-disk certificate fixture")
    if args.resumption and args.early_data:
        parser.error("--resumption and --early-data require separate fixture runs")
    if args.resumption_tls12 and (args.generated or args.negative or args.resumption or args.early_data):
        parser.error("--resumption-tls12 requires the positive on-disk certificate fixture")
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
        if args.resumption_tls12:
            tls_settings += "enable_tls12 = true\n"
        if args.resumption or args.resumption_tls12 or args.early_data:
            tls_settings += (
                "enable_resumption = true\n"
                f"early_data_max_size = {4096 if args.early_data else 0}\n"
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
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\", \"server_rehash\"]\n"
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
            if args.generated or args.resumption_tls12:
                held_tls12 = connect_tls(tls_port, tls12_context, parent)
                clients.append(held_tls12)
                held_tls12.register(b"heldtls12")
                tls12_certificate = held_tls12.certificate_digest()
                if args.generated and tls12_certificate == certificate:
                    raise AssertionError("generated TLS 1.2 leg reused the TLS 1.3 leaf")
                if args.resumption_tls12 and tls12_certificate != certificate:
                    raise AssertionError("on-disk P-256 TLS 1.2 leg changed the serving leaf")

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
            if args.generated or args.resumption_tls12:
                helix.wait_log_contains(root / "daemon.log", "hardened TLS 1.2 also accepted")
            if not args.generated:
                helix.wait_log_contains(root / "daemon.log", "acme renewal scheduler enabled")
                helix.wait_log_contains(root / "daemon.log", "acme renewal not due for localhost")
                helix.wait_log_contains(root / "daemon.log", "ocsp staple scheduler enabled")

            serving_pid = parent.pid

            def assert_held(marker: str) -> None:
                for held in clients:
                    if isinstance(held, TlsClient):
                        held.ping(marker.encode())
                    else:
                        held.ping(marker)
                held_wss.control_ping()
                if token(oper) != original_token:
                    raise AssertionError("local reusable session token changed across REHASH or Helix")
                held_tls.send(f"PRIVMSG heldwss :{marker}".encode())
                held_wss.until(f"PRIVMSG heldwss :{marker}")

            def fresh_fingerprint(label: str) -> bytes:
                fresh_tls = connect_tls(tls_port, context, None)
                clients.append(fresh_tls)
                fresh_tls.register(f"{label}tls".encode())
                fresh_tls.ping(label.encode())
                fingerprint = fresh_tls.certificate_digest()
                fresh_wss = connect_wss(ws_port, context, None)
                clients.append(fresh_wss)
                fresh_wss.register(f"{label}wss")
                fresh_wss.ping(label)
                if hashlib.sha256(fresh_wss.sock.getpeercert(binary_form=True)).digest() != fingerprint:
                    raise AssertionError("fresh TLS IRC and WSS served different certificates")
                return fingerprint

            def require_refusal(label: str) -> None:
                oper.send(b"UPGRADE")
                # The source-proof branch logs this exact refusal before
                # hooks.begin can launch a candidate. A generic failed upgrade
                # could instead hide an unrelated candidate abort.
                helix.wait_log_contains(
                    root / "daemon.log",
                    "UPGRADE refused: Windows config or external material has no exact source proof",
                )
                if helix.image_pids(binary) != {serving_pid}:
                    raise AssertionError(f"{label}: refused UPGRADE lost predecessor or left a successor")
                assert_held(f"{label}-refused")
                print(f"PASS: {label}: REHASH refused UPGRADE; held TLS/WSS and token stayed live", flush=True)

            def ticket_from(client: TlsClient, label: str,
                            different_from: ssl.SSLSession | None = None) -> ssl.SSLSession:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    candidate = client.socket.session
                    if (candidate is not None and candidate.has_ticket and
                            (different_from is None or candidate.id != different_from.id)):
                        return candidate
                    client.ping(f"ticket-{label}".encode())
                raise AssertionError(f"{label}: fresh TLS session ticket was not issued")

            def assert_resumed(saved: ssl.SSLSession, label: str) -> ssl.SSLSession:
                resumed = connect_tls(tls_port, context, None, resume_session=saved)
                try:
                    if not resumed.socket.session_reused:
                        raise AssertionError(f"{label}: TLS 1.3 session was not resumed")
                    resumed.register(label.encode())
                    resumed.ping(f"{label}-pong".encode())
                    return ticket_from(resumed, label, different_from=saved)
                finally:
                    resumed.close()

            def assert_tls12_ticket_use(saved: ssl.SSLSession, expected: bool, label: str) -> None:
                probe = connect_tls(tls_port, tls12_context, None, resume_session=saved)
                try:
                    if probe.socket.session_reused != expected:
                        raise AssertionError(
                            f"{label}: TLS 1.2 ticket reuse was {probe.socket.session_reused}, expected {expected}"
                        )
                    probe.register(label.encode())
                    probe.ping(f"{label}-pong".encode())
                finally:
                    probe.close()

            startup_ticket: ssl.SSLSession | None = None
            post_rehash_ticket: ssl.SSLSession | None = None
            held_tls12_ticket: ssl.SSLSession | None = None
            consumed_tls12_ticket: ssl.SSLSession | None = None
            post_rehash_tls12_ticket: ssl.SSLSession | None = None
            if args.resumption or args.early_data:
                startup_ticket = ticket_from(owner, "startup")
                assert_resumed(startup_ticket, "resbefore")
                print(
                    "PASS: startup TLS 1.3 session ticket resumed"
                    + (" with early data enabled" if args.early_data else " with early data disabled"),
                    flush=True,
                )
            if args.resumption_tls12:
                held_tls12_ticket = ticket_from(held_tls12, "held12")
                fresh_tls12 = connect_tls(tls_port, tls12_context, None)
                try:
                    fresh_tls12.register(b"seed12")
                    consumed_tls12_ticket = ticket_from(fresh_tls12, "seed12")
                finally:
                    fresh_tls12.close()
                assert_tls12_ticket_use(consumed_tls12_ticket, True, "used12")
                assert_tls12_ticket_use(consumed_tls12_ticket, False, "replay12")
                print("PASS: TLS 1.2 ticket resumed once and its replay fell back to a full handshake", flush=True)

            if not args.generated:
                oper.command(b"REHASH", b"Configuration reloaded")
                if helix.image_pids(binary) != {serving_pid}:
                    raise AssertionError("unchanged TLS REHASH changed the serving process")
                assert_held("unchanged-tls-rehash")
                if fresh_fingerprint("rehash") != certificate:
                    raise AssertionError("unchanged TLS REHASH changed the serving certificate")
                if args.resumption or args.early_data:
                    assert startup_ticket is not None
                    post_rehash_ticket = assert_resumed(startup_ticket, "resrehash")
                    print("PASS: pre-REHASH TLS 1.3 ticket resumed after key rotation", flush=True)
                if args.resumption_tls12:
                    fresh_tls12 = connect_tls(tls_port, tls12_context, None)
                    try:
                        fresh_tls12.register(b"postrh12")
                        post_rehash_tls12_ticket = ticket_from(fresh_tls12, "postrh12")
                    finally:
                        fresh_tls12.close()
                print("PASS: unchanged on-disk TLS REHASH kept held TLS/WSS, token and certificate", flush=True)

            held_baseline = len(clients)
            for sequence in (1, 2):
                acme_checks_before = (
                    (root / "daemon.log").read_text(encoding="utf-8", errors="replace").count(
                        "acme renewal not due for localhost") if not args.generated else 0
                )
                oper.send(b"UPGRADE")
                next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                marker = f"tls-wss-helix-{sequence}"
                assert_held(marker)

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
                if args.resumption or args.early_data:
                    assert startup_ticket is not None and post_rehash_ticket is not None
                    assert_resumed(startup_ticket, f"resold{sequence}")
                    assert_resumed(post_rehash_ticket, f"resnew{sequence}")
                    print(f"PASS: swap {sequence} retained pre- and post-REHASH TLS ticket keys", flush=True)
                if args.resumption_tls12:
                    assert held_tls12_ticket is not None
                    assert consumed_tls12_ticket is not None
                    assert post_rehash_tls12_ticket is not None
                    assert_tls12_ticket_use(consumed_tls12_ticket, False, f"used12s{sequence}")
                    assert_tls12_ticket_use(held_tls12_ticket, sequence == 1, f"old12s{sequence}")
                    if sequence == 2:
                        assert_tls12_ticket_use(post_rehash_tls12_ticket, True, "new12s2")
                        assert_tls12_ticket_use(post_rehash_tls12_ticket, False, "dup12s2")
                    print(f"PASS: swap {sequence} retained TLS 1.2 ticket replay history", flush=True)
                serving_pid = next_pid

            # The first swap's fresh probes remain open through the second
            # swap. Release them now so refusal cases measure REHASH rather
            # than the fixture's accumulated short-lived probe connections.
            for probe in clients[held_baseline:]:
                if isinstance(probe, TlsClient):
                    probe.close()
                else:
                    probe.sock.close()
            del clients[held_baseline:]

            if args.generated:
                # REHASH always mints a new default Ed25519 leaf and a separate
                # P-256 TLS 1.2 leg. The bounded same-material proof must reject
                # the next upgrade even though the TOML source is unchanged.
                oper.command(b"REHASH", b"Configuration reloaded")
                assert_held("generated-rehash")
                fresh_tls12 = connect_tls(tls_port, tls12_context, None)
                clients.append(fresh_tls12)
                fresh_tls12.register(b"rehashfresh12")
                fresh_tls12.ping(b"generated-rehash")
                if fresh_tls12.certificate_digest() == tls12_certificate:
                    raise AssertionError("generated REHASH did not replace the TLS 1.2 side leaf")
                if fresh_fingerprint("genrh") == certificate:
                    raise AssertionError("generated REHASH did not replace the default TLS leaf")
                require_refusal("generated TLS 1.2 material changed")
            elif args.negative == "rotation":
                staged = root / "rotated"
                staged.mkdir()
                create_private_directory(staged / "keys-private")
                create_fixture(staged)
                (staged / "leaf.pem").replace(root / "leaf.pem")
                (staged / "keys-private" / "server.key").replace(root / "keys-private" / "server.key")
                oper.command(b"REHASH", b"Configuration reloaded")
                assert_held("rotated-rehash")
                if fresh_fingerprint("rotated") == certificate:
                    raise AssertionError("valid TLS cert rotation did not change the serving leaf")
                require_refusal("valid TLS cert rotation")
            elif args.negative == "failed-reload":
                key_path = root / "keys-private" / "server.key"
                hidden_key = root / "keys-private" / "server.key.held"
                key_path.replace(hidden_key)
                try:
                    start = len(oper.lines)
                    oper.send(b"REHASH")
                    oper.wait(b"TLS cert reload failed", start=start)
                    oper.wait(b"Configuration reloaded", start=start)
                finally:
                    hidden_key.replace(key_path)
                assert_held("failed-reload")
                if fresh_fingerprint("failedreload") != certificate:
                    raise AssertionError("failed TLS reload changed the serving leaf")
                require_refusal("failed TLS cert reload")
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
