#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prove two Windows media Helix swaps and their UDP continuity.

With --active, two held IRC clients keep one negotiated call, ICE peer, and
authenticated native media sockets across both swaps. The default first
checks two pristine swaps, then one active call swap.

Usage: python -B tools/windows_helix_media_smoke.py zig-out/bin/onyx-server.exe
       python -B tools/windows_helix_media_smoke.py zig-out/bin/onyx-server.exe --active
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time

import windows_helix_smoke as helix
import windows_helix_tls_smoke as helix_tls
import windows_media_smoke as media
from windows_private_account_dir import create_private_directory


class MediaClient:
    def __init__(self, sock: ssl.SSLSocket):
        self.sock = sock
        self.pending = b""

    def close(self) -> None:
        self.sock.close()

    def send(self, line: str) -> None:
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def line(self, timeout: float = 10) -> str:
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" not in self.pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("held media IRC line timed out")
                self.sock.settimeout(remaining)
                part = self.sock.recv(4096)
                if not part:
                    raise ConnectionError("held media IRC socket closed")
                self.pending += part
            line, self.pending = self.pending.split(b"\n", 1)
            decoded = line.rstrip(b"\r").decode("utf-8", "replace")
            if decoded.startswith("PING "):
                self.send("PONG " + decoded[5:])
                continue
            return decoded

    def until(self, marker: str, timeout: float = 10) -> str:
        deadline = time.monotonic() + timeout
        seen: list[str] = []
        while time.monotonic() < deadline:
            line = self.line(deadline - time.monotonic())
            seen.append(line)
            if marker in line:
                return line
        raise TimeoutError(f"held media IRC expected {marker!r}; got {seen[-12:]!r}")

    def ping(self, marker: str) -> None:
        self.send("PING :" + marker)
        reply = self.until(" PONG ")
        if marker not in reply:
            raise AssertionError(f"held media client received wrong PONG: {reply!r}")


def tls_media_client(port: int, context: ssl.SSLContext, nick: str) -> MediaClient:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock = context.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        raw.close()
        raise
    client = MediaClient(sock)
    client.send(f"NICK {nick}")
    client.send(f"USER {nick} 0 * :Windows media Helix probe")
    client.until(" 001 ")
    client.send("JOIN #media")
    client.until(" 366 ")
    client.send("MEDIA JOIN #media voice")
    return client


def require_call_roster(client: MediaClient, other: str) -> None:
    client.send("MEDIA ROSTER #media")
    lines: list[str] = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        line = client.line(deadline - time.monotonic())
        lines.append(line)
        if "MEDIA ROSTER-END #media" in line:
            if not any(f"MEDIA ROSTER #media {other} voice" in item for item in lines):
                raise AssertionError(f"held call lost {other}: {lines!r}")
            return
    raise TimeoutError(f"held call roster did not end: {lines!r}")


class HeldIce:
    def __init__(self, port: int, offer: tuple):
        self.port = port
        self.ufrag, self.pwd = offer[:2]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)

    def close(self) -> None:
        self.sock.close()

    def check(self) -> None:
        request, transaction = media.stun_binding_request(self.ufrag, self.pwd)
        self.sock.sendto(request, ("127.0.0.1", self.port))
        deadline = time.monotonic() + 5
        other_packets: list[str] = []
        while time.monotonic() < deadline:
            self.sock.settimeout(deadline - time.monotonic())
            try:
                reply, sender = self.sock.recvfrom(4096)
            except socket.timeout:
                break
            if sender == ("127.0.0.1", self.port) and len(reply) >= 20 and \
                    reply[:2] == b"\x01\x01" and reply[8:20] == transaction:
                return
            if len(other_packets) < 4:
                other_packets.append(f"{sender!r}/{reply[:20].hex()}")
        raise AssertionError(
            "held WebRTC ICE peer lost its authenticated UDP response; "
            f"other packets={other_packets!r}"
        )


class HeldNative:
    def __init__(self, port: int, offer_a: tuple, offer_b: tuple):
        self.port = port
        self.a_stream, self.a_master = offer_a[2:]
        self.b_stream, self.b_master = offer_b[2:]
        self.source = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.source.bind(("127.0.0.1", 0))
        self.receiver.bind(("127.0.0.1", 0))
        self.receiver.settimeout(5)
        self.sequence = 0

    def close(self) -> None:
        self.source.close()
        self.receiver.close()

    def check(self) -> None:
        self.sequence += 1
        b_key = media.native_key(self.b_master, self.b_stream, "c2s")
        a_key = media.native_key(self.a_master, self.a_stream, "c2s")
        self.receiver.sendto(media.native_frame(self.b_stream, b_key, self.sequence),
                             ("127.0.0.1", self.port))
        time.sleep(0.1)
        self.source.sendto(media.native_frame(self.a_stream, a_key, self.sequence),
                           ("127.0.0.1", self.port))
        wire, sender = self.receiver.recvfrom(4096)
        if sender != ("127.0.0.1", self.port) or len(wire) < 39:
            raise AssertionError("held native media socket received no forwarded frame")
        frame, tag = wire[:-16], wire[-16:]
        expected = hmac.new(media.native_key(self.b_master, self.b_stream, "s2c"),
                            frame, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected) or frame[23:] != b"\xde\xad\xbe\xef" or \
                struct.unpack_from("<I", frame, 9)[0] != self.sequence:
            raise AssertionError("held native media changed MAC, payload or replay sequence")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--active", action="store_true",
                        help="hold the same negotiated call and UDP peers through both upgrades")
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
            media_clients: list[MediaClient] = []
            ice_peers: list[HeldIce] = []
            native_peer: HeldNative | None = None
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

                if args.active:
                    a = tls_media_client(tls_port, context, "mediaa")
                    media_clients.append(a)
                    b = tls_media_client(tls_port, context, "mediab")
                    media_clients.append(b)
                    a_offer = media.offer(a, "OFFER")
                    b_offer = media.offer(b, "ANSWER")
                    ice_peers.extend((HeldIce(media_port, a_offer), HeldIce(media_port, b_offer)))
                    native_peer = HeldNative(native_port, a_offer, b_offer)
                    for ice in ice_peers:
                        ice.check()
                    native_peer.check()
                    require_call_roster(a, "mediab")
                    require_call_roster(b, "mediaa")
                    print("PASS: established held native/WebRTC call and both UDP peers", flush=True)

                serving_pid = parent.pid
                for sequence in (1, 2):
                    oper.send(b"UPGRADE")
                    next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                    marker = f"media-idle-{sequence}".encode()
                    owner.ping(marker)
                    oper.ping(marker)
                    if helix_tls.token(oper) != token:
                        raise AssertionError("held local session token changed across media Helix")
                    if args.active:
                        for client in media_clients:
                            client.ping(f"media-active-{sequence}")
                        require_call_roster(media_clients[0], "mediab")
                        require_call_roster(media_clients[1], "mediaa")
                        for ice in ice_peers:
                            ice.check()
                        assert native_peer is not None
                        native_peer.check()
                        print(f"PASS: Windows active media Helix swap {sequence}, "
                              f"{serving_pid} -> {next_pid}; same IRC call, ICE peers, "
                              f"native sockets and MAC-keyed data sequence {native_peer.sequence}", flush=True)
                    else:
                        print(f"PASS: Windows pristine media Helix swap {sequence}, "
                              f"{serving_pid} -> {next_pid}; held TLS and both UDP owners", flush=True)
                    serving_pid = next_pid

                if args.active:
                    if parent.wait(timeout=2) != 0:
                        raise AssertionError("original predecessor did not exit cleanly")
                    return 0

                a = tls_media_client(tls_port, context, "mediaa")
                media_clients.append(a)
                b = tls_media_client(tls_port, context, "mediab")
                media_clients.append(b)
                a_offer = media.offer(a, "OFFER")
                b_offer = media.offer(b, "ANSWER")
                ice_peers.extend((HeldIce(media_port, a_offer), HeldIce(media_port, b_offer)))
                native_peer = HeldNative(native_port, a_offer, b_offer)
                for ice in ice_peers:
                    ice.check()
                native_peer.check()
                require_call_roster(a, "mediab")
                require_call_roster(b, "mediaa")
                print("PASS: inherited WebRTC ICE and native authenticated media UDP", flush=True)

                oper.send(b"UPGRADE")
                next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                owner.ping(b"media-active-default")
                oper.ping(b"media-active-default")
                if helix_tls.token(oper) != token:
                    raise AssertionError("held local session token changed across active media Helix")
                a.ping("media-active-default")
                b.ping("media-active-default")
                require_call_roster(a, "mediab")
                require_call_roster(b, "mediaa")
                for ice in ice_peers:
                    ice.check()
                native_peer.check()
                print(f"PASS: Windows active media Helix swap, {serving_pid} -> {next_pid}; "
                      "same IRC call, ICE peers and MAC-keyed native data", flush=True)
                if parent.wait(timeout=2) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                return 0
            except Exception:
                log.flush()
                contents = log_path.read_text(encoding="utf-8", errors="replace")[-16000:]
                print(contents.encode("ascii", "backslashreplace").decode("ascii"))
                raise
            finally:
                if native_peer is not None:
                    native_peer.close()
                for ice in ice_peers:
                    ice.close()
                for client in media_clients:
                    client.close()
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
