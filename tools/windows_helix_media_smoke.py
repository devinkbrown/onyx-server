#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prove two idle Windows media UDP handoffs, then exercise both media pumps.

Usage: python -B tools/windows_helix_media_smoke.py zig-out/bin/onyx-server.exe
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

import windows_helix_smoke as helix
import windows_helix_tls_smoke as helix_tls
import windows_media_smoke as media
from windows_private_account_dir import create_private_directory


def tls_media_client(port: int, context: ssl.SSLContext, nick: str) -> media.Irc:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock = context.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        raw.close()
        raise
    client = media.Irc(sock)
    client.send(f"NICK {nick}")
    client.send(f"USER {nick} 0 * :Windows media Helix probe")
    client.until(" 001 ")
    client.send("JOIN #media")
    client.until(" 366 ")
    client.send("MEDIA JOIN #media voice")
    return client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-media-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(source, binary)
        create_private_directory(root / "private")
        irc_port, tls_port = media.reserve_ports(2)
        media_port, native_port = media.reserve_udp_ports(2)
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\n"
            f"media = {media_port}\nnative_media = {native_port}\n"
            "media_host = \"127.0.0.1\"\n"
            f"[tls]\nenabled = true\nport = {tls_port}\ndns_name = \"localhost\"\n"
            "[media]\nenabled = true\nnative_media_require_mac = true\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disposable generated certificate.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        log_path = root / "daemon.log"
        with log_path.open("wb") as log:
            parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log,
                                      stderr=subprocess.STDOUT)
            held: list[helix.Client] = []
            try:
                owner = helix_tls.connect_tls(tls_port, context, parent)
                held.append(owner)
                owner.register(b"mediaowner")
                owner.command(f"REGISTER helixadmin * {password}".encode(),
                              b"REGISTER SUCCESS", timeout=45)

                oper = helix_tls.connect_tls(tls_port, context, parent)
                held.append(oper)
                oper.command(b"CAP LS 302", b" LS ")
                oper.command(b"CAP REQ :sasl", b" ACK ")
                oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
                proof = base64.b64encode(b"\0helixadmin\0" + password.encode())
                oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
                start = len(oper.lines)
                oper.send(b"CAP END")
                oper.send(b"NICK admin")
                oper.send(b"USER smoke 0 * :Windows media Helix operator")
                oper.wait(b" 381 ", start=start)
                token = helix_tls.token(oper)

                serving_pid = parent.pid
                for sequence in (1, 2):
                    oper.send(b"UPGRADE")
                    next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                    marker = f"media-idle-{sequence}".encode()
                    owner.ping(marker)
                    oper.ping(marker)
                    if helix_tls.token(oper) != token:
                        raise AssertionError("held local session token changed across media Helix")
                    print(f"PASS: Windows pristine media Helix swap {sequence}, "
                          f"{serving_pid} -> {next_pid}; held TLS and both UDP owners", flush=True)
                    serving_pid = next_pid

                a = tls_media_client(tls_port, context, "mediaa")
                try:
                    b = tls_media_client(tls_port, context, "mediab")
                except Exception:
                    a.sock.close()
                    raise
                try:
                    a_offer = media.offer(a, "OFFER")
                    b_offer = media.offer(b, "ANSWER")
                    media.check_stun(a_offer[0], a_offer[1], media_port)
                    media.check_native(a_offer, b_offer, native_port)
                finally:
                    a.sock.close()
                    b.sock.close()
                print("PASS: inherited WebRTC ICE and native authenticated media UDP", flush=True)

                # Once signaling has touched the graph, a further upgrade must
                # refuse before COMMIT until live media state has a checkpoint.
                start = len(oper.lines)
                oper.send(b"UPGRADE")
                oper.wait(b"UPGRADE refused", start=start, timeout=12)
                oper.ping(b"media-guard")
                if helix.image_pids(binary) != {serving_pid}:
                    raise AssertionError("active-media refusal replaced the serving process")
                print("PASS: active media handoff refused without disconnecting held clients", flush=True)
                if parent.wait(timeout=2) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                return 0
            except Exception:
                log.flush()
                contents = log_path.read_text(encoding="utf-8", errors="replace")[-16000:]
                print(contents.encode("ascii", "backslashreplace").decode("ascii"))
                raise
            finally:
                for client in held:
                    client.close()
                try:
                    for pid in helix.image_pids(binary):
                        os.kill(pid, 15)
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=10)
                    until = time.monotonic() + 10
                    while helix.image_pids(binary):
                        if time.monotonic() >= until:
                            raise RuntimeError("media Helix successor did not exit during cleanup")
                        time.sleep(0.1)
                    time.sleep(0.2)  # Let Windows retire the final WAL HANDLE.
                    log.close()


if __name__ == "__main__":
    raise SystemExit(main())
