#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Native Windows A-B-C secured-mesh reusable-session acceptance fixture.

Runs only in disposable loopback directories with a pinned copy of the supplied
daemon. Builds on windows_mesh_smoke's established-link and edge-chat checks,
then tests four physical attachments to one session across all three nodes,
every attachment's channel/direct participation, a fifth far-edge attachment,
and exact per-recipient msgid/time. By default it also cold-restarts the hub B
and verifies that surviving edge sockets remain live and a new B attachment
can resume after mesh reconnection.

Windows uses the `UPGRADE` command for guarded native Helix handoff, rather
than the POSIX USR2 signal. This fixture deliberately cold-restarts the hub:
that check does not prove preservation of its physical sockets across Helix.
The separate windows_helix_smoke.py fixture tests sequential process upgrades.

Test-vector node seeds are public; all listeners bind 127.0.0.1. Client account
passwords are generated per run and are never printed.

Usage: python tools/windows_session_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import windows_mesh_smoke as mesh
from windows_private_account_dir import create_private_directory


CAPS = b"message-tags server-time echo-message onyx/session-sync sasl"
ROOM = b"#windows-native-sessions"
ACCOUNT = b"windowsession"
OBSERVER_ACCOUNT = b"windowobserver"


class Client:
    def __init__(self, port: int, label: str):
        raw = socket.create_connection((mesh.HOST, port), timeout=6)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # disposable self-signed loopback fixture
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            self.sock = context.wrap_socket(raw, server_hostname="localhost")
        except Exception:
            raw.close()
            raise
        self.sock.settimeout(0.1)
        self.label = label
        self.nick = b""
        self.buffer = b""
        self.seen: list[bytes] = []

    def close(self) -> None:
        self.sock.close()

    def send(self, line: bytes) -> None:
        self.sock.sendall(line + b"\r\n")

    def pump(self) -> None:
        try:
            chunk = self.sock.recv(65536)
        except (socket.timeout, ssl.SSLWantReadError):
            return
        if not chunk:
            raise ConnectionError(f"{self.label}: original physical socket closed")
        self.buffer += chunk
        while b"\r\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\r\n", 1)
            if line.startswith(b"PING "):
                self.send(b"PONG " + line[5:])
            self.seen.append(line)

    def wait(self, predicate, start: int, operation: str, timeout: float = 20) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.seen[start:]:
                if predicate(line):
                    return line
            self.pump()
        raise TimeoutError(f"{self.label}: {operation} response absent")

    def command(self, line: bytes, needle: bytes, operation: str, timeout: float = 20) -> bytes:
        start = len(self.seen)
        self.send(line)
        return self.wait(lambda reply: needle in reply, start, operation, timeout)

    def register(self, nick: str, account: bytes | None = None, password: bytes | None = None) -> None:
        self.command(b"CAP LS 302", b" LS ", "CAP LS")
        if account is not None:
            response = self.command(b"CAP REQ :" + CAPS, b" CAP ", "CAP REQ")
            if b" ACK " not in response or not all(cap in response for cap in CAPS.split()):
                raise RuntimeError(f"{self.label}: required IRCv3 capabilities refused")
            self.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +", "SASL challenge")
            assert password is not None
            encoded = base64.b64encode(b"\0" + account + b"\0" + password)
            start = len(self.seen)
            self.send(b"AUTHENTICATE " + encoded)
            outcome = self.wait(
                lambda line: any(b" " + code + b" " in line for code in (b"903", b"904", b"905", b"906", b"907")),
                start,
                "SASL outcome",
            )
            if b" 903 " not in outcome:
                raise RuntimeError(f"{self.label}: SASL login refused")
        start = len(self.seen)
        self.send(b"CAP END")
        self.send(b"NICK " + nick.encode("ascii"))
        self.send(b"USER fixture 0 * :Windows native session fixture")
        welcome = self.wait(lambda line: b" 001 " in line, start, "IRC registration")
        fields = welcome.split()
        self.nick = fields[fields.index(b"001") + 1]

    def join(self) -> None:
        self.command(b"JOIN " + ROOM, b" 366 ", "channel join")

    def tokens(self) -> tuple[bytes, bytes]:
        start = len(self.seen)
        self.send(b"SESSION TOKEN")
        local = self.wait(lambda line: b" :SESSION TOKEN " in line, start, "local session token")
        portable = self.wait(lambda line: b" :SESSION MTOKEN " in line, start, "portable session token")
        return (
            local.split(b" :SESSION TOKEN ", 1)[1].split()[0],
            portable.split(b" :SESSION MTOKEN ", 1)[1].split()[0],
        )

    def resume(self, credential: bytes) -> None:
        deadline = time.monotonic() + 45
        redirected = False
        while time.monotonic() < deadline:
            start = len(self.seen)
            self.send(b"SESSION RESUME " + credential)
            response = self.wait(
                lambda line: any(needle in line for needle in
                                 (b"SESSION RESUME:", b"SESSION REDIRECT:", b"FAIL SESSION ", b"WARN SESSION ")),
                start,
                "reusable session attachment",
                timeout=min(20, max(0.1, deadline - time.monotonic())),
            )
            if b"SESSION RESUME:" in response and any(word in response for word in (b"attached", b"restored")):
                return
            if b"SESSION REDIRECT:" in response:
                if not redirected:
                    print(f"WAIT {self.label}: signed session replica converging", flush=True)
                    redirected = True
            elif b"WARN SESSION " not in response:
                raise RuntimeError(f"{self.label}: reusable session attachment refused")
            time.sleep(0.25)
        raise TimeoutError(f"{self.label}: reusable session attachment did not converge")

    def ping(self, marker: bytes) -> None:
        start = len(self.seen)
        self.send(b"PING :" + marker)
        self.wait(lambda line: b"PONG " in line and marker in line, start, "physical socket PONG")

    def wait_nick(self, nick: bytes) -> None:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            start = len(self.seen)
            self.send(b"WHOIS " + nick)
            terminal = self.wait(lambda line: b" 318 " in line and nick.lower() in line.lower(), start, "WHOIS route")
            replies = self.seen[start:]
            if any(b" 311 " in line and nick.lower() in line.lower()
                   for line in replies[:replies.index(terminal)]):
                return
            time.sleep(0.25)
        raise TimeoutError(f"{self.label}: recipient nickname route did not converge")


class Oracle:
    def __init__(self) -> None:
        self.events: list[tuple[bytes, tuple[Client, ...], tuple[Client, ...], tuple[bytes, bytes]]] = []
        self.nonce = secrets.token_hex(4).encode("ascii")
        self.sequence = 0

    def event(self, source: Client, clients: list[Client], eligible: list[Client], target: bytes, phase: str) -> None:
        if source not in eligible or not eligible or any(client not in clients for client in eligible):
            raise ValueError("event recipient set is vacuous or lacks its author")
        marker = b"wsm-" + self.nonce + b"-" + phase.encode("ascii") + b"-" + str(self.sequence).encode("ascii")
        self.sequence += 1
        needle = b"PRIVMSG " + target + b" :" + marker
        starts = {client: len(client.seen) for client in clients}
        source.send(needle)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for client in clients:
                client.pump()
            if all(any(needle in line for line in client.seen[starts[client]:]) for client in eligible):
                break
        else:
            missing = [client.label for client in eligible if not any(needle in line for line in client.seen[starts[client]:])]
            raise TimeoutError(f"{phase}: accepted message absent at {','.join(missing)}")
        settle = time.monotonic() + 0.35
        while time.monotonic() < settle:
            for client in clients:
                client.pump()
        identities: set[tuple[bytes, bytes]] = set()
        for client in clients:
            matching = [line for line in client.seen[starts[client]:] if needle in line]
            expected = 1 if client in eligible else 0
            if len(matching) != expected:
                raise RuntimeError(f"{phase}: {client.label} received {len(matching)} matching events, expected {expected}")
            if not matching:
                continue
            line = matching[0]
            if not line.startswith(b"@"):
                raise RuntimeError(f"{phase}: message identity tags absent")
            tags = dict(item.split(b"=", 1) for item in line[1:].split(b" ", 1)[0].split(b";") if b"=" in item)
            if not tags.get(b"msgid") or not tags.get(b"time"):
                raise RuntimeError(f"{phase}: msgid/server-time absent")
            identities.add((tags[b"msgid"], tags[b"time"]))
        if len(identities) != 1:
            raise RuntimeError(f"{phase}: accepted identity differs between recipients")
        self.events.append((needle, tuple(eligible), tuple(c for c in clients if c not in eligible), identities.pop()))

    def cumulative(self, live: list[Client]) -> None:
        for index, client in enumerate(live):
            client.ping(b"cumulative-" + str(index).encode("ascii"))
        settle = time.monotonic() + 0.5
        while time.monotonic() < settle:
            for client in live:
                client.pump()
        deliveries = 0
        for needle, eligible, excluded, identity in self.events:
            for client in eligible:
                lines = [line for line in client.seen if needle in line]
                if len(lines) != 1:
                    raise RuntimeError(f"{client.label}: cumulative event count {len(lines)}, expected one")
                tags = dict(item.split(b"=", 1) for item in lines[0][1:].split(b" ", 1)[0].split(b";") if b"=" in item)
                if (tags.get(b"msgid"), tags.get(b"time")) != identity:
                    raise RuntimeError(f"{client.label}: cumulative event identity changed")
                deliveries += 1
            for client in excluded:
                if any(needle in line for line in client.seen):
                    raise RuntimeError(f"{client.label}: received an excluded message")
        print(f"PASS: cumulative {len(self.events)} accepted events and {deliveries} exact recipient deliveries", flush=True)


def participation(oracle: Oracle, attached: list[Client], observer: Client, phase: str) -> None:
    everyone = attached + [observer]
    for index, source in enumerate(attached):
        oracle.event(source, everyone, everyone, ROOM, f"{phase}-channel-{index}")
        oracle.event(source, everyone, attached, attached[0].nick, f"{phase}-direct-{index}")
    oracle.event(observer, everyone, everyone, attached[0].nick, f"{phase}-observer-direct")
    for index, client in enumerate(everyone):
        client.ping(f"{phase}-physical-{index}".encode("ascii"))
    print(f"PASS: {phase}: {len(attached)} same-token attachments independently sent channel/direct traffic", flush=True)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def run(args: argparse.Namespace) -> None:
    ports = mesh.reserve_ports(12)
    irc_ports, s2s_ports, metric_ports, tls_ports = (
        ports[:3], ports[3:6], ports[6:9], ports[9:12]
    )
    with tempfile.TemporaryDirectory(prefix="onyx-windows-session-") as scratch:
        root = Path(scratch)
        pinned = root / "onyx-server.exe"
        source_digest = digest(args.binary)
        shutil.copy2(args.binary, pinned)
        if digest(pinned) != source_digest or digest(args.binary) != source_digest:
            raise RuntimeError("daemon changed during snapshot pinning")
        print(f"ARTIFACT native Windows daemon sha256={source_digest}", flush=True)
        directories = [root / label for label in "ABC"]
        configs = [directory / "node.toml" for directory in directories]
        for index, (directory, config) in enumerate(zip(directories, configs)):
            directory.mkdir()
            create_private_directory(directory / "accounts-private")
            config.write_text(
                mesh.node_config(
                    index, irc_ports[index], s2s_ports[index], metric_ports[index], s2s_ports[1],
                    tls=tls_ports[index], account_services=True, relay_v2=True,
                ),
                encoding="utf-8",
            )
        mesh.preflight(pinned, configs, directories)
        processes: list[subprocess.Popen[bytes]] = []
        clients: list[Client] = []
        by_label: dict[str, subprocess.Popen[bytes]] = {}
        with ExitStack() as logs:
            outputs = {label: logs.enter_context((directory / "daemon.log").open("ab"))
                       for label, directory in zip("ABC", directories)}
            try:
                for index in (1, 0, 2):
                    label = "ABC"[index]
                    process = subprocess.Popen([str(pinned), str(configs[index])], cwd=directories[index],
                                               stdout=outputs[label], stderr=subprocess.STDOUT)
                    processes.append(process)
                    by_label[label] = process
                    if label == "B":
                        mesh.wait_for_hub(process, metric_ports[index])
                ordered = [by_label[label] for label in "ABC"]
                mesh.wait_for_links(ordered, metric_ports)
                mesh.edge_chat(irc_ports)
                password = secrets.token_urlsafe(24).encode("ascii")

                def client(node: int, label: str, account: bytes | None = ACCOUNT) -> Client:
                    result = Client(tls_ports[node], label)
                    clients.append(result)
                    result.register(label, account, password if account else None)
                    return result

                for index in range(3):
                    registrar = client(index, f"Registrar{index}", None)
                    registrar.command(b"REGISTER " + ACCOUNT + b" * " + password,
                                      b"REGISTER SUCCESS ", "account registration", timeout=35)
                    registrar.close()
                    clients.remove(registrar)
                print("PASS: account registered in all three separate durable stores", flush=True)

                origin = client(0, "Origin")
                origin.join()
                local, portable = origin.tokens()
                if not re.fullmatch(rb"[0-9a-f]{32}", local) or len(portable) <= len(local):
                    raise RuntimeError("reusable local or portable session credential absent")
                sibling = client(0, "NearSibling")
                sibling.resume(local)
                middle = client(1, "MiddleAttachment")
                middle.resume(portable)
                far = client(2, "FarAttachment")
                far.resume(portable)
                attached = [origin, sibling, middle, far]

                observer_registrar = client(2, "ObserverRegistrar", None)
                observer_registrar.command(b"REGISTER " + OBSERVER_ACCOUNT + b" * " + password,
                                           b"REGISTER SUCCESS ", "observer account registration", timeout=35)
                observer_registrar.close()
                clients.remove(observer_registrar)
                observer = client(2, "Observer", OBSERVER_ACCOUNT)
                observer.join()
                observer.tokens()  # publish a signed independent recipient identity
                observer.wait_nick(origin.nick)
                for attachment in attached:
                    if attachment.tokens()[0] != local:
                        raise RuntimeError("shared local session token differs across physical attachments")
                print("PASS: four physical attachments share one token across A, B, and C", flush=True)

                oracle = Oracle()
                participation(oracle, attached, observer, "four-attachments")
                fifth = client(2, "LaterFarAttachment")
                fifth.resume(portable)
                if fifth.tokens()[0] != local:
                    raise RuntimeError("fifth edge attachment did not keep the reusable token")
                attached.append(fifth)
                participation(oracle, attached, observer, "fifth-far-resume")
                oracle.cumulative(attached + [observer])

                if not args.skip_hub_restart:
                    # Cold restart intentionally loses B's physical socket. Test
                    # only the edges that remain attached to their live origin.
                    middle.close()
                    clients.remove(middle)
                    attached.remove(middle)
                    by_label["B"].terminate()
                    try:
                        by_label["B"].wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        by_label["B"].kill()
                        by_label["B"].wait(timeout=5)
                    for index, attachment in enumerate(attached + [observer]):
                        attachment.ping(f"hub-down-physical-{index}".encode("ascii"))
                    replacement = subprocess.Popen([str(pinned), str(configs[1])], cwd=directories[1],
                                                   stdout=outputs["B"], stderr=subprocess.STDOUT)
                    processes.append(replacement)
                    by_label["B"] = replacement
                    mesh.wait_for_links([by_label[label] for label in "ABC"], metric_ports)
                    rejoined = client(1, "RejoinedMiddle")
                    rejoined.resume(portable)
                    if rejoined.tokens()[0] != local:
                        raise RuntimeError("portable token did not resume on restarted hub")
                    attached.append(rejoined)
                    participation(oracle, attached, observer, "hub-cold-reconnect")
                    oracle.cumulative(attached + [observer])
                    print("PASS: B cold reconnect restored the secured line; surviving A/C sockets and token stayed live", flush=True)
                print("ALL WINDOWS SESSION SMOKE CHECKS PASSED", flush=True)
            finally:
                for attachment in reversed(clients):
                    try:
                        attachment.close()
                    except OSError:
                        pass
                mesh.stop(processes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=mesh.DEFAULT_BINARY)
    parser.add_argument("--skip-hub-restart", action="store_true",
                        help="isolate four/five-attachment and exact-delivery evidence")
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    if not args.binary.is_file():
        parser.error(f"binary not found: {args.binary}")
    if sys.platform != "win32":
        parser.error("this fixture requires native Windows")
    try:
        run(args)
        return 0
    except Exception as exc:
        # Credentials, tokens and full transcripts are intentionally omitted.
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
