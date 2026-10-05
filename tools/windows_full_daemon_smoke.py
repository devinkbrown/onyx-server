#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the native full Server on Windows in a disposable run directory.

The default check covers plaintext NICK/USER, VERSION, PING/PONG, and QUIT/EOF. Optional
TLS, WebSocket, metrics, webhook, PROXY protocol, and account probes are opt-in. This script deliberately
does not assert PortableServer CAP/ISUPPORT.

Usage: python tools/windows_full_daemon_smoke.py [binary] [--tls] [--wss] [--ws-plain] [--metrics] [--webhook] [--proxy] [--accounts]
"""

import argparse
import base64
from contextlib import ExitStack
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from windows_private_account_dir import create_private_directory


HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
DEADLINE_SECONDS = 90.0
START = time.monotonic()


def remaining():
    return max(0.0, DEADLINE_SECONDS - (time.monotonic() - START))


def budget(seconds):
    left = remaining()
    if left <= 0:
        raise TimeoutError("full daemon smoke reached its 90-second deadline")
    return min(seconds, left)


def reserved_ports(count):
    """Choose distinct loopback ports without keeping listeners in the daemon."""
    with ExitStack() as stack:
        ports = []
        for _ in range(count):
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.bind((HOST, 0))
            ports.append(sock.getsockname()[1])
        return ports


def wait_for_listener(proc, port, label):
    end = time.monotonic() + budget(15.0)
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before {label} accepted a connection (exit {proc.returncode})")
        try:
            return socket.create_connection((HOST, port), timeout=budget(0.5))
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(min(0.05, budget(0.05)))
    raise TimeoutError(f"{label} did not listen on {HOST}:{port}")


class IrcClient:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""

    def send(self, line):
        self.sock.settimeout(budget(4.0))
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def line(self, seconds=5.0):
        end = time.monotonic() + budget(seconds)
        while b"\n" not in self.pending:
            left = min(end - time.monotonic(), remaining())
            if left <= 0:
                raise TimeoutError("IRC response timed out")
            self.sock.settimeout(left)
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError(f"IRC connection closed with pending {self.pending!r}")
            self.pending += data
        raw, self.pending = self.pending.split(b"\n", 1)
        return raw.rstrip(b"\r").decode("utf-8", "replace")

    def until(self, marker, seconds=8.0, forbidden=None):
        end = time.monotonic() + budget(seconds)
        seen = []
        while time.monotonic() < end:
            line = self.line(end - time.monotonic())
            seen.append(line)
            if forbidden is not None and forbidden in line:
                raise AssertionError(f"unexpected {forbidden!r} in {line!r}")
            if marker in line:
                return line
        raise TimeoutError(f"expected {marker!r}; received {seen!r}")

    def register(self, nick):
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
        self.until(" 001 ")
        self.send("VERSION")
        self.until(" 351 ")  # Full Server command; PortableServer cannot satisfy it.

    def ping(self, token, forbidden=None):
        self.send(f"PING :{token}")
        pong = self.until(f":{token}", forbidden=forbidden)
        if " PONG " not in pong:
            raise AssertionError(f"wrong PONG: {pong!r}")

    def names(self, channel):
        self.send(f"NAMES {channel}")
        end = time.monotonic() + budget(8.0)
        roster = set()
        lines = []
        while time.monotonic() < end:
            line = self.line(end - time.monotonic())
            lines.append(line)
            if " 353 " in line and channel in line:
                # PREFIX=(YQqov)*!.@+; tolerate conventional extra status symbols.
                roster.update(nick.lstrip("~&*!.@%+").lower() for nick in line.rsplit(" :", 1)[-1].split())
            if " 366 " in line and channel in line:
                return roster, lines
        raise TimeoutError(f"NAMES {channel} did not complete; lines={lines!r}")

    def quit(self):
        self.send("QUIT :smoke complete")
        end = time.monotonic() + budget(8.0)
        while time.monotonic() < end:
            left = min(end - time.monotonic(), remaining())
            if left <= 0:
                break
            self.sock.settimeout(left)
            if not self.sock.recv(4096):
                return
        raise TimeoutError("daemon did not close the IRC socket after QUIT")


class WebSocketClient:
    """Small RFC 6455 client with bounded reads and mandatory client masking."""

    KEY = "dGhlIHNhbXBsZSBub25jZQ=="
    ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    MAX_FRAME = 1024 * 1024

    def __init__(self, sock):
        self.sock = sock
        self.pending = b""
        self.lines = []

    def read_exact(self, count, deadline):
        while len(self.pending) < count:
            left = min(deadline - time.monotonic(), remaining())
            if left <= 0:
                raise TimeoutError("WebSocket read timed out")
            self.sock.settimeout(left)
            chunk = self.sock.recv(4096)
            if not chunk:
                if not self.pending:
                    return None
                raise EOFError("WebSocket stream ended inside a frame")
            self.pending += chunk
        result, self.pending = self.pending[:count], self.pending[count:]
        return result

    def upgrade(self, port):
        request = (
            f"GET /irc HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {self.KEY}\r\nSec-WebSocket-Protocol: text.ircv3.net\r\n\r\n"
        ).encode("ascii")
        self.sock.settimeout(budget(5.0))
        self.sock.sendall(request)
        deadline = time.monotonic() + budget(8.0)
        while b"\r\n\r\n" not in self.pending:
            if len(self.pending) > 8192:
                raise AssertionError("WebSocket response head exceeded 8 KiB")
            left = min(deadline - time.monotonic(), remaining())
            if left <= 0:
                raise TimeoutError("WebSocket upgrade timed out")
            self.sock.settimeout(left)
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket closed before HTTP upgrade")
            self.pending += chunk
        head, self.pending = self.pending.split(b"\r\n\r\n", 1)
        lines = head.decode("ascii").split("\r\n")
        if lines[0] != "HTTP/1.1 101 Switching Protocols":
            raise AssertionError(f"WebSocket upgrade returned {lines[0]!r}")
        headers = {}
        for line in lines[1:]:
            key, separator, value = line.partition(":")
            if not separator:
                raise AssertionError(f"malformed WebSocket upgrade header: {line!r}")
            headers[key.lower()] = value.strip()
        if headers.get("sec-websocket-accept") != self.ACCEPT:
            raise AssertionError("WebSocket upgrade returned the wrong accept digest")
        if headers.get("sec-websocket-protocol") != "text.ircv3.net":
            raise AssertionError("WebSocket upgrade did not select text.ircv3.net")

    def send_frame(self, opcode, payload):
        if len(payload) >= 126:
            raise AssertionError("smoke client only sends short WebSocket frames")
        mask = os.urandom(4)
        frame = bytes((0x80 | opcode, 0x80 | len(payload))) + mask
        frame += bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.settimeout(budget(5.0))
        self.sock.sendall(frame)

    def send(self, line):
        self.send_frame(0x1, line.encode("utf-8"))

    def read_frame(self, seconds=8.0):
        deadline = time.monotonic() + budget(seconds)
        head = self.read_exact(2, deadline)
        if head is None:
            return None
        first, second = head
        if first & 0x70 or second & 0x80:
            raise AssertionError("server sent reserved bits or a masked WebSocket frame")
        opcode = first & 0x0F
        if opcode in (0x1, 0x8, 0x9, 0xA) and not first & 0x80:
            raise AssertionError("server fragmented a text or control frame")
        length = second & 0x7F
        if length == 126:
            raw = self.read_exact(2, deadline)
            if raw is None:
                raise EOFError("WebSocket extended length missing")
            length = int.from_bytes(raw, "big")
        elif length == 127:
            raw = self.read_exact(8, deadline)
            if raw is None:
                raise EOFError("WebSocket extended length missing")
            length = int.from_bytes(raw, "big")
        if length > self.MAX_FRAME:
            raise AssertionError(f"WebSocket frame exceeded {self.MAX_FRAME} bytes")
        payload = self.read_exact(length, deadline)
        if payload is None:
            raise EOFError("WebSocket frame payload missing")
        return opcode, payload

    def until(self, marker, seconds=8.0):
        deadline = time.monotonic() + budget(seconds)
        seen = []
        while time.monotonic() < deadline:
            while self.lines:
                line = self.lines.pop(0)
                seen.append(line)
                if marker in line:
                    return line
            frame = self.read_frame(deadline - time.monotonic())
            if frame is None:
                raise ConnectionError(f"WebSocket closed before {marker!r}; saw {seen!r}")
            opcode, payload = frame
            if opcode == 0x1:
                self.lines.extend(payload.decode("utf-8").splitlines())
            elif opcode == 0x9:
                self.send_frame(0xA, payload)
            elif opcode == 0x8:
                raise ConnectionError(f"WebSocket closed before {marker!r}; saw {seen!r}")
            elif opcode != 0xA:
                raise AssertionError(f"unexpected WebSocket opcode {opcode}")
        raise TimeoutError(f"WebSocket response missing {marker!r}; saw {seen!r}")

    def register(self, nick):
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
        self.until(" 001 ")
        self.send("VERSION")
        self.until(" 351 ")

    def ping(self, token):
        self.send(f"PING :{token}")
        pong = self.until(f":{token}")
        if " PONG " not in pong:
            raise AssertionError(f"wrong framed IRC PONG: {pong!r}")

    def control_ping(self):
        self.send_frame(0x9, b"ws-live")
        deadline = time.monotonic() + budget(8.0)
        while time.monotonic() < deadline:
            frame = self.read_frame(deadline - time.monotonic())
            if frame is None:
                raise ConnectionError("WebSocket closed before control pong")
            opcode, payload = frame
            if opcode == 0xA:
                if payload != b"ws-live":
                    raise AssertionError(f"wrong WebSocket control pong: {payload!r}")
                return
            if opcode == 0x1:
                self.lines.extend(payload.decode("utf-8").splitlines())
            elif opcode == 0x9:
                self.send_frame(0xA, payload)
            else:
                raise AssertionError(f"unexpected WebSocket opcode {opcode} before pong")
        raise TimeoutError("WebSocket control pong timed out")

    def quit(self):
        self.send("QUIT :smoke complete")
        deadline = time.monotonic() + budget(8.0)
        while time.monotonic() < deadline:
            frame = self.read_frame(deadline - time.monotonic())
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 0x8:
                self.send_frame(0x8, payload)
            elif opcode == 0x9:
                self.send_frame(0xA, payload)
        raise TimeoutError("WebSocket socket stayed open after IRC QUIT")


def probe_http(proc, port, path, expected_status, label, method="GET", body=b""):
    with wait_for_listener(proc, port, label) as sock:
        sock.settimeout(budget(5.0))
        request = (
            f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        sock.sendall(request)
        response = bytearray()
        while len(response) < 1024 * 1024:
            sock.settimeout(budget(5.0))
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        else:
            raise AssertionError(f"{label} response exceeded 1 MiB")
    status = bytes(response).split(b"\r\n", 1)[0]
    if not status.startswith(f"HTTP/1.1 {expected_status} ".encode("ascii")):
        raise AssertionError(f"{label} returned {status!r}, expected HTTP {expected_status}")


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def expect_proxy_refusal(proc, port, label, payload):
    """A trusted source must not reach IRC registration without a valid header."""
    with wait_for_listener(proc, port, label) as sock:
        sock.settimeout(budget(5.0))
        try:
            sock.sendall(payload)
        except (ConnectionAbortedError, ConnectionResetError):
            return
        deadline = time.monotonic() + budget(8.0)
        received = bytearray()
        while time.monotonic() < deadline:
            sock.settimeout(min(deadline - time.monotonic(), remaining()))
            try:
                chunk = sock.recv(4096)
            except (ConnectionAbortedError, ConnectionResetError):
                return
            if not chunk:
                return
            received.extend(chunk)
            if b" 001 " in received:
                raise AssertionError(f"{label} registered without a valid PROXY header")
    raise TimeoutError(f"{label} was not disconnected after its invalid PROXY header")


def probe_proxy(binary):
    """Exercise live trusted PROXY v1/v2 identity and fail-closed parsing."""
    stage = "prepare PROXY protocol probe"
    proc = None
    with tempfile.TemporaryDirectory(prefix="onyx-proxy-windows-") as scratch:
        run_dir = Path(scratch)
        port = reserved_ports(1)[0]
        config = run_dir / "proxy.toml"
        log = run_dir / "daemon.log"
        config.write_text(
            f'[node]\nid = 1\n\n[listen]\nhost = "{HOST}"\nirc = {port}\n'
            'proxy_protocol = true\ntrusted_proxies = ["127.0.0.1"]\n',
            encoding="utf-8",
        )
        try:
            stage = "PROXY config preflight"
            checked = subprocess.run(
                [str(binary), "--check-config", str(config)],
                cwd=run_dir, capture_output=True, text=True, timeout=budget(15.0), check=False,
            )
            if checked.returncode != 0:
                raise RuntimeError(f"PROXY preflight failed: {(checked.stdout + checked.stderr).strip()}")
            with log.open("w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)

            stage = "trusted PROXY v1/v2 address application"
            with wait_for_listener(proc, port, "PROXY v1 IRC") as v1_sock, \
                    wait_for_listener(proc, port, "PROXY v2 IRC") as v2_sock:
                v1_sock.settimeout(budget(5.0))
                v1_sock.sendall(b"PROXY TCP4 198.51.")
                time.sleep(min(0.05, budget(0.05)))
                v1_sock.sendall(f"100.7 127.0.0.1 40123 {port}\r\n".encode("ascii"))
                v1 = IrcClient(v1_sock)
                v1.register("v1proxy")

                v2_header = (
                    b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"
                    + socket.inet_aton("203.0.113.22") + socket.inet_aton(HOST)
                    + (40124).to_bytes(2, "big") + port.to_bytes(2, "big")
                )
                v2_sock.settimeout(budget(5.0))
                v2_sock.sendall(v2_header + b"NICK v2proxy\r\nUSER v2proxy 0 * :v2proxy\r\n")
                v2 = IrcClient(v2_sock)
                v2.until(" 001 ")
                v2.send("VERSION")
                v2.until(" 351 ")

                # The daemon generates a fresh cloak key by default, so public
                # message prefixes hide IPs. WHOIS self 338 exposes the real
                # post-PROXY address without weakening that privacy policy.
                v1.send("WHOIS v1proxy")
                actual = v1.until(" 338 ")
                if " 338 v1proxy v1proxy 198.51.100.7 :" not in actual:
                    raise AssertionError(f"PROXY v1 source address was not applied: {actual!r}")
                v2.send("WHOIS v2proxy")
                actual = v2.until(" 338 ")
                if " 338 v2proxy v2proxy 203.0.113.22 :" not in actual:
                    raise AssertionError(f"PROXY v2 source address was not applied: {actual!r}")

                v1.send("PRIVMSG v2proxy :from-proxy-v1")
                delivered = v2.until("PRIVMSG v2proxy :from-proxy-v1")
                if not delivered.startswith(":v1proxy!") or "@198.51.100.7 PRIVMSG " in delivered:
                    raise AssertionError(f"PROXY v1 delivery prefix was missing or exposed the real IP: {delivered!r}")
                v2.send("PRIVMSG v1proxy :from-proxy-v2")
                delivered = v1.until("PRIVMSG v1proxy :from-proxy-v2")
                if not delivered.startswith(":v2proxy!") or "@203.0.113.22 PRIVMSG " in delivered:
                    raise AssertionError(f"PROXY v2 delivery prefix was missing or exposed the real IP: {delivered!r}")
                v1.ping("proxy-v1-live")
                v2.ping("proxy-v2-live")
                v2.quit()
                v1.quit()
            print("PASS: trusted fragmented PROXY v1 and coalesced PROXY v2 preserved source identity and IRC delivery")

            stage = "invalid and missing PROXY header refusal"
            expect_proxy_refusal(
                proc, port, "malformed PROXY v1",
                f"PROXY TCP4 999.999.999.999 127.0.0.1 40125 {port}\r\nNICK badproxy\r\nUSER badproxy 0 * :badproxy\r\n".encode("ascii"),
            )
            expect_proxy_refusal(proc, port, "missing PROXY preamble", b"NICK bypass\r\nUSER bypass 0 * :bypass\r\n")
            print("PASS: malformed and missing trusted PROXY headers were disconnected before registration")
            if proc.poll() is not None:
                raise RuntimeError(f"PROXY daemon exited unexpectedly (exit {proc.returncode})")
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            stop(proc)
            if log.exists():
                print("--- PROXY daemon log ---")
                print(log.read_text(encoding="utf-8", errors="replace"))
            return 1
        finally:
            stop(proc)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--tls", action="store_true", help="probe the full Server's self-signed TLS listener")
    parser.add_argument("--wss", action="store_true", help="probe WebSocket over the TLS certificate")
    parser.add_argument("--ws-plain", action="store_true", help="probe testing-only plaintext WebSocket")
    parser.add_argument("--metrics", action="store_true", help="probe GET /metrics")
    parser.add_argument("--webhook", action="store_true", help="probe the webhook HTTP listener's 404 path")
    parser.add_argument("--proxy", action="store_true", help="probe trusted PROXY v1/v2 and invalid header refusal")
    parser.add_argument("--accounts", action="store_true", help="create a durable account and authenticate with SASL PLAIN over TLS after restart")
    args = parser.parse_args()
    if args.ws_plain and (args.tls or args.wss):
        parser.error("--ws-plain requires TLS to be disabled; run it as a separate probe")
    if args.accounts and not (args.tls or args.wss):
        parser.error("--accounts requires --tls or --wss for credential transport")
    binary = args.binary.resolve()
    if os.name != "nt":
        parser.error("this smoke is for native Windows; use runtime_smoke.py elsewhere")
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    stage = "prepare"
    proc = None
    with tempfile.TemporaryDirectory(prefix="onyx-full-windows-") as scratch:
        run_dir = Path(scratch)
        config = run_dir / "full.toml"
        log = run_dir / "daemon.log"
        webhook_store = run_dir / "webhooks.tsv"
        account_directory = run_dir / "accounts-private"
        account_store = account_directory / "accounts.wal"
        if args.accounts:
            create_private_directory(account_directory)
        tls_enabled = args.tls or args.wss
        ws_enabled = args.wss or args.ws_plain
        count = 1 + tls_enabled + ws_enabled + args.metrics + args.webhook
        ports = iter(reserved_ports(count))
        irc_port = next(ports)
        tls_port = next(ports) if tls_enabled else None
        ws_port = next(ports) if ws_enabled else None
        metrics_port = next(ports) if args.metrics else None
        webhook_port = next(ports) if args.webhook else None
        lines = [
            "[node]", "id = 1", "",
            "[listen]", f'host = "{HOST}"', f"irc = {irc_port}",
        ]
        if ws_port is not None:
            lines.append(f"ws = {ws_port}")
            if args.ws_plain:
                lines.append("ws_plain = true")
        lines.append("")
        if tls_port is not None:
            lines += ["[tls]", "enabled = true", f"port = {tls_port}", 'dns_name = "localhost"', ""]
        if metrics_port is not None:
            lines += ["[metrics]", f"listen = {metrics_port}", f'bind = "{HOST}"', ""]
        if webhook_port is not None:
            lines += [
                "[webhook]", "enabled = true", f"listen = {webhook_port}",
                f'bind = "{HOST}"', 'store_path = "webhooks.tsv"', "",
            ]
        if args.accounts:
            lines += [
                "[sasl]", "enabled = true", 'account_db = "accounts-private/accounts.wal"', "",
                "[accounts]", "pbkdf2_rounds = 10000", "",
            ]
        config.write_text("\n".join(lines), encoding="utf-8")

        try:
            stage = "read-only config preflight"
            checked = subprocess.run(
                [str(binary), "--check-config", str(config)],
                cwd=run_dir, capture_output=True, text=True, timeout=budget(15.0), check=False,
            )
            if checked.returncode != 0:
                raise RuntimeError(f"preflight rejected requested features: {(checked.stdout + checked.stderr).strip()}")
            print("PASS: full daemon config preflight")

            stage = "start full daemon"
            with log.open("w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)

            stage = "plaintext registration, VERSION, PING, and three-client delivery"
            webhook_target = None
            with wait_for_listener(proc, irc_port, "plaintext IRC") as first_sock:
                first = IrcClient(first_sock)
                first.register("fullsmoke")
                with wait_for_listener(proc, irc_port, "second IRC client") as peer_sock, \
                        wait_for_listener(proc, irc_port, "third IRC client") as outsider_sock:
                    peer = IrcClient(peer_sock)
                    outsider = IrcClient(outsider_sock)
                    peer.register("fullpeer")
                    outsider.register("fulloutside")
                    first.ping("three-clients-live")
                    print("PASS: three full-daemon clients registered and first stayed responsive")

                    stage = "direct and channel delivery"
                    first.send("PRIVMSG fullpeer :full-direct")
                    peer.until("PRIVMSG fullpeer :full-direct")
                    outsider.ping("direct-outsider", forbidden="full-direct")
                    channel = "#full-smoke"
                    first.send(f"JOIN {channel}")
                    first.until(" JOIN ")
                    first.until(" 366 ")
                    peer.send(f"JOIN {channel}")
                    peer.until(" JOIN ")
                    peer.until(" 366 ")
                    joined = first.until(" JOIN ")
                    if not joined.startswith(":fullpeer!") or channel not in joined:
                        raise AssertionError(f"wrong JOIN fanout: {joined!r}")
                    roster, lines = first.names(channel)
                    if roster != {"fullsmoke", "fullpeer"}:
                        raise AssertionError(f"NAMES missed a joined client: roster={roster!r}; lines={lines!r}")
                    first.send(f"PRIVMSG {channel} :full-channel")
                    peer.until(f"PRIVMSG {channel} :full-channel")
                    outsider.ping("channel-outsider", forbidden="full-channel")
                    print("PASS: direct/channel delivery and NAMES reached the intended peers")

                    if webhook_port is not None:
                        stage = "webhook creation and channel delivery"
                        first.send(f"WEBHOOK CREATE {channel} smoke")
                        created = first.until("WEBHOOK: created")
                        target = re.search(r"/api/webhooks/[0-9a-f]{32}/[0-9a-f]{64}(?![0-9a-f])", created)
                        if target is None:
                            raise AssertionError("WEBHOOK CREATE did not return a one-time binding URL")
                        webhook_target = target.group(0)
                        probe_http(
                            proc, webhook_port, webhook_target, 204, "created webhook",
                            method="POST", body=b'{"content":"full-webhook-first"}',
                        )
                        peer.until(f"PRIVMSG {channel} :full-webhook-first")
                        if not webhook_store.is_file() or webhook_store.stat().st_size == 0:
                            raise AssertionError("WEBHOOK CREATE did not persist the binding store")
                        print("PASS: WEBHOOK CREATE persisted and POST delivered to a joined peer")

                    stage = "PART, rejoin, and QUIT fanout"
                    peer.send(f"PART {channel} :done")
                    peer.until(" PART ")
                    parted = first.until(" PART ")
                    if not parted.startswith(":fullpeer!") or channel not in parted:
                        raise AssertionError(f"wrong PART fanout: {parted!r}")
                    roster, lines = first.names(channel)
                    if roster != {"fullsmoke"}:
                        raise AssertionError(f"NAMES retained a departed client: roster={roster!r}; lines={lines!r}")
                    peer.send(f"JOIN {channel}")
                    peer.until(" JOIN ")
                    peer.until(" 366 ")
                    first.until(" JOIN ")
                    peer.quit()
                    quit_notice = first.until(" QUIT ")
                    if not quit_notice.startswith(":fullpeer!"):
                        raise AssertionError(f"wrong QUIT fanout: {quit_notice!r}")
                    outsider.quit()
                    print("PASS: PART, rejoin, and QUIT fanout left the channel consistent")

                first.ping("after-peer-disconnects")
                first.quit()
            print("PASS: first client stayed responsive after peers left, then reached QUIT EOF")

            if tls_port is not None:
                stage = "TLS registration, VERSION, PING, and QUIT"
                with wait_for_listener(proc, tls_port, "TLS IRC") as raw:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    with context.wrap_socket(raw, server_hostname="localhost") as secure:
                        tls_client = IrcClient(secure)
                        tls_client.register("fulltls")
                        tls_client.ping("tls-live")
                        tls_client.quit()
                print("PASS: full daemon TLS registration, VERSION, PING/PONG, and QUIT/EOF")

            if args.accounts:
                stage = "TLS account creation and durable WAL"
                with wait_for_listener(proc, tls_port, "TLS account registration") as raw:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    with context.wrap_socket(raw, server_hostname="localhost") as secure:
                        owner = IrcClient(secure)
                        owner.register("acctowner")
                        owner.send("REGISTER acctfull * correcthorse")
                        owner.until("REGISTER SUCCESS acctfull")
                        owner.quit()
                if not account_store.is_file() or account_store.stat().st_size == 0:
                    raise AssertionError("REGISTER did not persist the account WAL")
                print("PASS: TLS REGISTER created an account and persisted its WAL")

            if ws_port is not None:
                label = "WSS" if args.wss else "plaintext WebSocket"
                stage = f"{label} upgrade, framed IRC, direct delivery, PING, and QUIT"
                with ExitStack() as ws_stack:
                    raw = ws_stack.enter_context(wait_for_listener(proc, ws_port, label))
                    if args.wss:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                        transport = ws_stack.enter_context(context.wrap_socket(raw, server_hostname="localhost"))
                    else:
                        transport = raw
                    ws_client = WebSocketClient(transport)
                    ws_client.upgrade(ws_port)
                    ws_client.register("fullws")
                    ws_client.ping("framed-irc-live")
                    ws_client.control_ping()
                    with wait_for_listener(proc, irc_port, "WebSocket peer") as peer_sock:
                        peer = IrcClient(peer_sock)
                        peer.register("wspeer")
                        ws_client.send("PRIVMSG wspeer :from-websocket")
                        peer.until("PRIVMSG wspeer :from-websocket")
                        peer.send("PRIVMSG fullws :to-websocket")
                        ws_client.until("PRIVMSG fullws :to-websocket")
                        peer.quit()
                    ws_client.quit()
                print(f"PASS: {label} upgrade, framed IRC, direct delivery, PING/PONG, and QUIT/EOF")

            if metrics_port is not None:
                stage = "metrics HTTP"
                probe_http(proc, metrics_port, "/metrics", 200, "metrics")
                print("PASS: full daemon metrics HTTP 200")

            if webhook_port is not None:
                stage = "webhook HTTP"
                unknown_id = "0" * 32
                unknown_token = "0" * 64
                probe_http(
                    proc, webhook_port, f"/api/webhooks/{unknown_id}/{unknown_token}",
                    404, "webhook", method="POST", body=b'{"content":"probe"}',
                )
                print("PASS: full daemon webhook POST returned HTTP 404 for unknown binding")

                stage = "persisted webhook cold restart"
                stop(proc)
                proc = None
                with log.open("a", encoding="utf-8") as log_file:
                    proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
                with wait_for_listener(proc, irc_port, "restarted plaintext IRC") as owner_sock, \
                        wait_for_listener(proc, irc_port, "restarted peer IRC") as peer_sock:
                    owner = IrcClient(owner_sock)
                    receiver = IrcClient(peer_sock)
                    owner.register("fullreturn")
                    receiver.register("fullrecv")
                    owner.send("JOIN #full-smoke")
                    owner.until(" JOIN ")
                    owner.until(" 366 ")
                    receiver.send("JOIN #full-smoke")
                    receiver.until(" JOIN ")
                    receiver.until(" 366 ")
                    owner.until(" JOIN ")
                    probe_http(
                        proc, webhook_port, webhook_target, 204, "restored webhook",
                        method="POST", body=b'{"content":"full-webhook-restored"}',
                    )
                    receiver.until("PRIVMSG #full-smoke :full-webhook-restored")
                    receiver.quit()
                    owner.quit()
                if not webhook_store.is_file() or webhook_store.stat().st_size == 0:
                    raise AssertionError("webhook binding store vanished after restart")
                print("PASS: cold restart restored webhook binding and POST delivery")

            if args.accounts:
                stage = "cold restart and TLS SASL PLAIN recovery"
                stop(proc)
                proc = None
                with log.open("a", encoding="utf-8") as log_file:
                    proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
                with wait_for_listener(proc, tls_port, "restarted TLS SASL") as raw:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    with context.wrap_socket(raw, server_hostname="localhost") as secure:
                        auth = IrcClient(secure)
                        auth.send("CAP LS 302")
                        auth.send("NICK acctauth")
                        auth.send("USER acctauth 0 * :acctauth")
                        offered_lines = []
                        while True:
                            offered = auth.until(" CAP ")
                            if " LS " not in offered:
                                raise AssertionError(f"unexpected CAP response: {offered!r}")
                            offered_lines.append(offered)
                            if " LS * :" not in offered:
                                break
                        if "sasl=" not in " ".join(offered_lines):
                            raise AssertionError(f"SASL capability was not advertised: {offered_lines!r}")
                        auth.send("CAP REQ :sasl")
                        auth.until(" ACK ")
                        auth.send("AUTHENTICATE PLAIN")
                        auth.until("AUTHENTICATE +")
                        payload = base64.b64encode(b"acctfull\x00acctfull\x00correcthorse").decode("ascii")
                        auth.send(f"AUTHENTICATE {payload}")
                        auth.until(" 903 ")
                        auth.send("CAP END")
                        auth.until(" 001 acctauth ")
                        auth.send("WHOIS acctauth")
                        whois = auth.until(" 330 ")
                        if " acctfull " not in whois:
                            raise AssertionError(f"SASL account identity did not survive restart: {whois!r}")
                        auth.quit()
                with wait_for_listener(proc, tls_port, "TLS invalid SASL") as raw:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    with context.wrap_socket(raw, server_hostname="localhost") as secure:
                        bad = IrcClient(secure)
                        bad.send("CAP LS 302")
                        bad.send("NICK acctbad")
                        bad.send("USER acctbad 0 * :acctbad")
                        while " LS * :" in bad.until(" CAP "):
                            pass
                        bad.send("CAP REQ :sasl")
                        bad.until(" ACK ")
                        bad.send("AUTHENTICATE PLAIN")
                        bad.until("AUTHENTICATE +")
                        payload = base64.b64encode(b"acctfull\x00acctfull\x00wrong-password").decode("ascii")
                        bad.send(f"AUTHENTICATE {payload}")
                        bad.until(" 904 ")
                        bad.send("CAP END")
                        bad.until(" 001 acctbad ")
                        bad.quit()
                print("PASS: cold restart restored the account, TLS SASL PLAIN accepted its password and rejected an invalid one")

            if proc.poll() is not None:
                raise RuntimeError(f"daemon exited unexpectedly (exit {proc.returncode})")
            print("PASS: full daemon remains running after client probes")
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            stop(proc)
            if log.exists():
                print("--- daemon log ---")
                print(log.read_text(encoding="utf-8", errors="replace"))
            return 1
        finally:
            stop(proc)

    if args.proxy and probe_proxy(binary) != 0:
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
