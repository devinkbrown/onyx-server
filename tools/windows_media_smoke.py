#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows WebRTC ICE and authenticated native media pumps.

Usage: python -B tools/windows_media_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import zlib

from windows_backup_smoke import Irc, reserve_ports, run_cli, stop, wait_listener


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"


def reserve_udp_ports(count):
    ports = []
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((HOST, 0))
            sockets.append(sock)
            ports.append(sock.getsockname()[1])
        return ports
    finally:
        for sock in sockets:
            sock.close()


def write_config(path, irc_port, tls_port, media_port, native_port):
    path.write_text("\n".join([
        "[node]", "id = 1", "",
        "[listen]", f'host = "{HOST}"', f"irc = {irc_port}",
        f"media = {media_port}", f"native_media = {native_port}",
        f'media_host = "{HOST}"', "",
        "[tls]", "enabled = true", f"port = {tls_port}",
        'dns_name = "localhost"', "",
        "[media]", "enabled = true", "native_media_require_mac = true", "",
    ]), encoding="utf-8")


def get_field(line, name):
    match = re.search(r"(?:^| )" + re.escape(name) + r"=([^ ]+)", line)
    if match is None:
        raise AssertionError(f"missing {name} in MEDIA reply")
    return match.group(1)


def offer(client, verb):
    client.send(f"MEDIA {verb} #media cadencevox")
    transport = client.until("MEDIA TRANSPORT #media")
    native = client.until("MEDIA NATIVE #media")
    mac = client.until("MEDIA NATIVE-MACKEY #media")
    ufrag = get_field(transport, "ufrag")
    pwd = get_field(transport, "pwd")
    candidate = get_field(transport, "candidate")
    native_candidate = get_field(native, "candidate")
    stream = int(get_field(native, "stream"))
    if candidate.split(":")[0] != HOST or native_candidate.split(":")[0] != HOST:
        raise AssertionError("advertised media candidate was not loopback")
    if stream <= 0 or stream != int(get_field(mac, "stream")):
        raise AssertionError("native stream authority changed within one offer")
    master = base64.b64decode(get_field(mac, "key"), validate=True)
    if len(master) != 32:
        raise AssertionError("native endpoint master key had unexpected length")
    return ufrag, pwd, stream, master


def stun_binding_request(ufrag, pwd):
    transaction = os.urandom(12)
    username = (ufrag + ":peer").encode("ascii")
    attr = struct.pack(">HH", 0x0006, len(username)) + username
    attr += b"\x00" * (-len(username) % 4)
    mac_header = struct.pack(">HHI", 0x0001, len(attr) + 24, 0x2112A442) + transaction
    digest = hmac.new(pwd.encode("ascii"), mac_header + attr, hashlib.sha1).digest()
    attr += struct.pack(">HH", 0x0008, 20) + digest
    fp_header = struct.pack(">HHI", 0x0001, len(attr) + 8, 0x2112A442) + transaction
    fingerprint = zlib.crc32(fp_header + attr) ^ 0x5354554E
    attr += struct.pack(">HHI", 0x8028, 4, fingerprint)
    return struct.pack(">HHI", 0x0001, len(attr), 0x2112A442) + transaction + attr, transaction


def native_key(master, stream, direction):
    label = f"onyx native endpoint capability v1 {direction} frame".encode("ascii")
    return hmac.new(master, label + b"\x00" + struct.pack(">I", stream), hashlib.sha256).digest()


def native_frame(stream, key, sequence):
    payload = b"\xde\xad\xbe\xef"
    frame = struct.pack("<IBIIQBB", len(payload), 64, stream, sequence, 0, 1, 1) + payload
    return frame + hmac.new(key, frame, hashlib.sha256).digest()[:16]


def check_stun(ufrag, pwd, media_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind((HOST, 0))
        peer.settimeout(3)
        request, transaction = stun_binding_request(ufrag, pwd)
        peer.sendto(request, (HOST, media_port))
        reply, sender = peer.recvfrom(4096)
        if sender != (HOST, media_port) or len(reply) < 20 or reply[:2] != b"\x01\x01" or reply[8:20] != transaction:
            raise AssertionError("media pump did not answer the authenticated ICE binding check")


def check_native(a, b, native_port):
    _, _, a_stream, a_master = a
    _, _, b_stream, b_master = b
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as source, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        source.bind((HOST, 0))
        receiver.bind((HOST, 0))
        receiver.settimeout(3)
        receiver.sendto(native_frame(b_stream, native_key(b_master, b_stream, "c2s"), 1), (HOST, native_port))
        time.sleep(0.1)
        source.sendto(native_frame(a_stream, native_key(a_master, a_stream, "c2s"), 1), (HOST, native_port))
        wire, sender = receiver.recvfrom(4096)
        if sender != (HOST, native_port) or len(wire) < 39:
            raise AssertionError("native media pump did not forward from its bound socket")
        frame, tag = wire[:-16], wire[-16:]
        expected = hmac.new(native_key(b_master, b_stream, "s2c"), frame, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected) or frame[23:] != b"\xde\xad\xbe\xef":
            raise AssertionError("native media fanout had invalid directional MAC or payload")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    proc = None
    stage = "prepare"
    with tempfile.TemporaryDirectory(prefix="onyx-media-windows-") as scratch:
        run_dir = Path(scratch)
        config = run_dir / "media.toml"
        log = run_dir / "daemon.log"
        irc_port, tls_port = reserve_ports(2)
        media_port, native_port = reserve_udp_ports(2)
        write_config(config, irc_port, tls_port, media_port, native_port)
        try:
            stage = "media preflight"
            checked = run_cli(binary, run_dir, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError((checked.stdout + checked.stderr).strip())
            print("PASS: Windows media and native media preflight")

            stage = "media daemon startup"
            with log.open("w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                        stdout=log_file, stderr=subprocess.STDOUT)
            with wait_listener(proc, tls_port) as a_socket, wait_listener(proc, tls_port) as b_socket:
                a = Irc(a_socket)
                b = Irc(b_socket)
                for client, nick in ((a, "mediaa"), (b, "mediab")):
                    client.send(f"NICK {nick}")
                    client.send(f"USER {nick} 0 * :{nick}")
                    client.until(" 001 ")
                    client.send("JOIN #media")
                    client.until(" 366 ")
                    client.send("MEDIA JOIN #media voice")
                a_offer = offer(a, "OFFER")
                b_offer = offer(b, "ANSWER")
                check_stun(a_offer[0], a_offer[1], media_port)
                print("PASS: Windows media pump answered an authenticated STUN/ICE check")
                check_native(a_offer, b_offer, native_port)
                print("PASS: Windows native media pump forwarded a directional MAC frame")
                a.send("QUIT :media smoke")
                b.send("QUIT :media smoke")
            return 0
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            if log.exists():
                print("--- Windows media daemon log ---")
                print(log.read_text(encoding="utf-8", errors="replace"))
            return 1
        finally:
            stop(proc)


if __name__ == "__main__":
    sys.exit(main())
