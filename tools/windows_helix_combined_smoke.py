#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hold browser WebTransport and native/WebRTC media across two Windows Helix swaps.

Usage: python -B tools/windows_helix_combined_smoke.py zig-out/bin/onyx-server.exe
       python -B tools/windows_helix_combined_smoke.py zig-out/bin/onyx-server.exe --chromium C:/path/to/msedge.exe
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error

import windows_helix_media_smoke as media_helix
import windows_helix_smoke as helix
import windows_helix_tls_smoke as helix_tls
import windows_helix_webtransport_smoke as wt_helix
import windows_media_smoke as media
import windows_webtransport_smoke as wt
from windows_private_account_dir import create_private_directory


def finish_browser(proc: subprocess.Popen | None, port: int, log_path: Path) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        wt_helix.held_control(port, "/finish")
        if proc.wait(timeout=10) == 0:
            return
    except (OSError, urllib.error.URLError, subprocess.TimeoutExpired):
        pass
    if proc.poll() is None:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True, text=True, timeout=10, check=False)
        if proc.poll() is None:
            proc.kill()
    proc.wait(timeout=10)
    if proc.returncode != 0:
        print(f"held browser cleanup exit {proc.returncode}:\n"
              f"{wt_helix.held_log_tail(log_path)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--chromium", type=Path, help="Chrome or Edge executable")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")
    pwsh = shutil.which("pwsh")
    node = shutil.which("node")
    if not pwsh or not node:
        parser.error("PowerShell 7 and Node.js are required for this browser fixture")
    browser = wt.browser_path(args.chromium)

    with wt.disposable_run_dir() as root:
        binary = root / "onyx-server.exe"
        shutil.copy2(source, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        cert_hash = wt.make_certificate(root, pwsh)
        with closing(wt.udp_socket()) as reserved_wt:
            wt_port = reserved_wt.getsockname()[1]
            media_port, native_port = media.reserve_udp_ports(2)
        irc_port, tls_port, control_port = wt.tcp_ports(3)
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\n"
            f"webtransport = {wt_port}\nmedia = {media_port}\n"
            f"native_media = {native_port}\nmedia_host = \"127.0.0.1\"\n"
            f"[tls]\nenabled = true\nport = {tls_port}\ndns_name = \"localhost\"\n"
            "cert_path = \"leaf.pem\"\nkey_path = \"keys-private/server.key\"\n"
            "[media]\nenabled = true\nnative_media_require_mac = true\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disposable short-lived fixture.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        log_path = root / "daemon.log"
        held_log_path = root / "held-browser.log"
        with log_path.open("wb") as log:
            parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log,
                                      stderr=subprocess.STDOUT)
            clients: list[helix.Client] = []
            media_clients: list[media_helix.MediaClient] = []
            ice_peers: list[media_helix.HeldIce] = []
            native_peer: media_helix.HeldNative | None = None
            observer_socket: socket.socket | None = None
            held_proc: subprocess.Popen | None = None
            held_log = None
            try:
                wt.wait_ready(parent, irc_port, log_path)
                owner = helix_tls.connect_tls(tls_port, context, parent)
                clients.append(owner)
                owner.register(b"tlsowner")
                owner.command(f"REGISTER helixadmin * {password}".encode(),
                              b"REGISTER SUCCESS", timeout=45)

                oper = helix_tls.connect_tls(tls_port, context, parent)
                clients.append(oper)
                oper.command(b"CAP LS 302", b" LS ")
                oper.command(b"CAP REQ :sasl", b" ACK ")
                oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
                proof = base64.b64encode(b"\0helixadmin\0" + password.encode())
                oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
                start = len(oper.lines)
                oper.send(b"CAP END")
                oper.send(b"NICK admin")
                oper.send(b"USER smoke 0 * :Windows combined Helix operator")
                oper.wait(b" 381 ", start=start)
                token = helix_tls.token(oper)

                observer_socket = socket.create_connection(("127.0.0.1", irc_port), timeout=5)
                observer = wt.IrcObserver(observer_socket)
                observer_socket.sendall(b"NICK wtobserver\r\nUSER smoke 0 * :WT Observer\r\n")
                observer.until(lambda line: b" 001 wtobserver " in line, 8)
                observer_socket.sendall(b"JOIN #web\r\n")
                observer.until(lambda line: b" 366 wtobserver #web " in line, 8)

                env = os.environ.copy()
                env["TMPDIR"] = str(root)
                held_log = held_log_path.open("wb")
                held_proc = subprocess.Popen(
                    [node, str(wt.HARNESS), "--port", str(wt_port), "--certhash", cert_hash,
                     "--chromium", str(browser), "--http-port", str(control_port),
                     "--timeout-ms", "240000", "--held"],
                    cwd=root, env=env, stdout=held_log, stderr=subprocess.STDOUT,
                )
                ready = wt_helix.wait_held_status(held_proc, control_port, 0, held_log_path)
                session_id = ready.get("sessionId")
                if not isinstance(session_id, str) or not session_id:
                    raise AssertionError("held browser omitted session identity")
                wt_helix.require_held_identity(ready, session_id)
                observer.until(lambda line: line.startswith(b":webuser!") and
                               b"PRIVMSG #web :wt-held-baseline" in line, 10)
                baseline_count = sum(line.startswith(b":webuser!") and
                                     b"PRIVMSG #web :wt-held-baseline" in line
                                     for line in observer.lines)
                if baseline_count != 1:
                    raise AssertionError(f"expected one browser baseline delivery, got {baseline_count}")

                a = media_helix.tls_media_client(tls_port, context, "mediaa")
                media_clients.append(a)
                b = media_helix.tls_media_client(tls_port, context, "mediab")
                media_clients.append(b)
                a_offer = media.offer(a, "OFFER")
                b_offer = media.offer(b, "ANSWER")
                ice_peers.extend((media_helix.HeldIce(media_port, a_offer),
                                  media_helix.HeldIce(media_port, b_offer)))
                native_peer = media_helix.HeldNative(native_port, a_offer, b_offer)
                for ice in ice_peers:
                    ice.check()
                native_peer.check()
                media_helix.require_call_roster(a, "mediab")
                media_helix.require_call_roster(b, "mediaa")
                print("PASS: held browser stream and native/WebRTC call established together", flush=True)

                serving_pid = parent.pid
                nonces: list[bytes] = []
                for sequence in (1, 2):
                    oper.send(b"UPGRADE")
                    next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                    marker = f"combined-{sequence}".encode()
                    owner.ping(marker)
                    oper.ping(marker)
                    observer_socket.sendall(b"PING :" + marker + b"\r\n")
                    observer.until(lambda line: b" PONG " in line and marker in line, 10)
                    if helix_tls.token(oper) != token:
                        raise AssertionError("held local session token changed across Helix")
                    fresh = helix_tls.connect_tls(tls_port, context, None)
                    try:
                        if fresh.certificate_digest().hex() != cert_hash:
                            raise AssertionError("serving WebTransport certificate changed across Helix")
                    finally:
                        fresh.close()

                    nonce = f"combined-{sequence}-{secrets.token_hex(4)}".encode()
                    accepted = wt_helix.held_control(control_port, "/probe", {
                        "phase": sequence, "nonce": nonce.decode("ascii"),
                    })
                    if accepted != {"phase": sequence, "nonce": nonce.decode("ascii")}:
                        raise AssertionError(f"held browser probe was not accepted: {accepted!r}")
                    status = wt_helix.wait_held_status(held_proc, control_port, sequence,
                                                       held_log_path, timeout=25)
                    wt_helix.require_held_identity(status, session_id)
                    if status.get("nonce") != nonce.decode("ascii"):
                        raise AssertionError("held browser acknowledged a different post-upgrade probe")
                    nonces.append(nonce)
                    observer.until(lambda line: line.startswith(b":webuser!") and
                                   b"PRIVMSG #web :" + nonce in line, 10)
                    delivery_cut = f"combined-delivery-cut-{sequence}".encode()
                    observer_socket.sendall(b"PING :" + delivery_cut + b"\r\n")
                    observer.until(lambda line: b" PONG " in line and delivery_cut in line, 10)
                    for expected in nonces:
                        deliveries = sum(line.startswith(b":webuser!") and
                                         b"PRIVMSG #web :" + expected in line
                                         for line in observer.lines)
                        if deliveries != 1:
                            raise AssertionError(f"expected one browser delivery for {expected!r}, got {deliveries}")

                    a.ping(f"media-combined-{sequence}")
                    b.ping(f"media-combined-{sequence}")
                    media_helix.require_call_roster(a, "mediab")
                    media_helix.require_call_roster(b, "mediaa")
                    for ice in ice_peers:
                        ice.check()
                    native_peer.check()
                    print(f"PASS: combined Windows Helix swap {sequence}, "
                          f"{serving_pid} -> {next_pid}; same browser session, exact delivery, "
                          f"call, ICE peers and native sequence {native_peer.sequence}", flush=True)
                    serving_pid = next_pid

                wt_helix.held_control(control_port, "/finish")
                if held_proc.wait(timeout=10) != 0:
                    raise AssertionError(f"held browser exited {held_proc.returncode}:\n"
                                         f"{wt_helix.held_log_tail(held_log_path)}")
                if parent.wait(timeout=2) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                return 0
            except Exception:
                log.flush()
                contents = log_path.read_text(encoding="utf-8", errors="replace")[-16000:]
                print(contents.encode("ascii", "backslashreplace").decode("ascii"))
                print(wt_helix.held_log_tail(held_log_path).encode("ascii", "backslashreplace").decode("ascii"))
                raise
            finally:
                finish_browser(held_proc, control_port, held_log_path)
                if held_log is not None:
                    held_log.close()
                if native_peer is not None:
                    native_peer.close()
                for ice in ice_peers:
                    ice.close()
                for client in media_clients:
                    client.close()
                if observer_socket is not None:
                    observer_socket.close()
                for client in clients:
                    client.close()
                try:
                    for pid in helix.image_pids(binary):
                        os.kill(pid, 15)
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=10)
                    deadline = time.monotonic() + 10
                    while helix.image_pids(binary):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("combined Helix successor did not exit during cleanup")
                        time.sleep(0.1)
                    time.sleep(0.2)  # Let Windows retire browser profile and WAL HANDLEs.


if __name__ == "__main__":
    raise SystemExit(main())
