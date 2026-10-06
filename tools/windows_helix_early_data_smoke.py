#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise native Armor TLS 1.3 0-RTT through two Windows Helix swaps.

A pure-Zig client supplies the first flight and captures session tickets. The
optional --exact-replay mode resends one byte-identical first flight across
the first swap through a TCP proxy.

Usage: python -B tools/windows_helix_early_data_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture, reserve_ports


def wait_for(path: Path, needle: bytes, process: subprocess.Popen[bytes],
             *, timeout: float = 12) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = path.read_bytes() if path.exists() else b""
        if needle in data:
            return data
        if process.poll() is not None:
            raise AssertionError(
                f"native TLS client exited {process.returncode} before {needle!r}: {data[-6000:]!r}"
            )
        time.sleep(0.05)
    data = path.read_bytes() if path.exists() else b""
    raise TimeoutError(f"native TLS client did not report {needle!r}: {data[-6000:]!r}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def native_connection(client: Path, root: Path, port: int, label: str,
                      *, session_in: tuple[Path, float] | None = None,
                      early_data: bytes = b"", fallback: bytes = b"",
                      active: list[subprocess.Popen[bytes]]) -> tuple[subprocess.Popen[bytes], Path]:
    output = root / f"native-tls-{label}.log"
    command = [str(client), str(port),
               session_in[0].read_bytes().hex() if session_in else "-",
               str(max(0, int((time.monotonic() - session_in[1]) * 1000))) if session_in else "0",
               early_data.hex() if early_data else "-",
               fallback.hex() if fallback else "-"]
    with output.open("wb") as log:
        process = subprocess.Popen(
            command, cwd=root, stdin=subprocess.DEVNULL, stdout=log,
            stderr=subprocess.STDOUT,
        )
    active.append(process)
    return process, output


def seed_ticket(client: Path, root: Path, port: int,
                active: list[subprocess.Popen[bytes]]) -> tuple[Path, float]:
    ticket = root / "private" / "early-session.bin"
    process, log = native_connection(
        client, root, port, "ticket-seed",
        fallback=b"NICK seedearly\r\nUSER smoke 0 * :0RTT ticket seed\r\n",
        active=active,
    )
    try:
        wait_for(log, b" 001 seedearly ", process)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            output = log.read_bytes()
            marker = output.find(b"TICKET=")
            if marker >= 0:
                start = marker + len(b"TICKET=")
                end = output.find(b"\n", start)
                if end >= 0:
                    encoded = output[start:end].removesuffix(b"\r")
                    if not encoded or len(encoded) % 2:
                        raise AssertionError("native client emitted a malformed session ticket")
                    try:
                        ticket.write_bytes(bytes.fromhex(encoded.decode("ascii")))
                    except (ValueError, UnicodeDecodeError) as error:
                        raise AssertionError("native client emitted a malformed session ticket") from error
                    return ticket, time.monotonic()
            if process.poll() is not None:
                raise AssertionError(f"native client exited before complete session ticket: {output[-6000:]!r}")
            time.sleep(0.05)
        raise TimeoutError(f"complete post-handshake session ticket absent: {log.read_bytes()[-6000:]!r}")
    finally:
        stop_process(process)
        active.remove(process)


def accepted_early_registration(client: Path, root: Path, port: int,
                                ticket: tuple[Path, float], label: str,
                                active: list[subprocess.Popen[bytes]]) -> None:
    nick = f"early{label}".encode("ascii")
    nonce = secrets.token_hex(8).encode("ascii")
    early = (
        b"NICK " + nick + b"\r\nUSER smoke 0 * :0RTT Helix delivery\r\n"
        + b"PING :" + nonce + b"\r\n"
    )
    process, log = native_connection(
        client, root, port, label, session_in=ticket, early_data=early,
        active=active,
    )
    try:
        output = wait_for(log, b"EARLY=accepted", process)
        if b"RESUMED=yes" not in output:
            raise AssertionError(f"{label}: native TLS client did not resume")
        output = wait_for(log, b" 001 " + nick + b" ", process)
        output = wait_for(log, b" PONG onyx.local :" + nonce, process)
        # No 1-RTT IRC bytes are sent. The unique PONG proves the early-data
        # payload reached the application, not just that a session resumed.
        if output.count(b" 001 " + nick + b" ") != 1:
            raise AssertionError(f"{label}: early registration delivered more than once")
        if output.count(b" PONG onyx.local :" + nonce) != 1:
            raise AssertionError(f"{label}: early nonce delivered more than once")
        print(
            f"PASS: {label}: resumed native TLS 1.3, accepted 0-RTT, "
            f"IRC registered early nonce {nonce.decode('ascii')}", flush=True,
        )
    finally:
        stop_process(process)
        active.remove(process)


def capture_first_flight(client: socket.socket) -> bytes:
    """Read one complete TLS ClientHello plus its encrypted 0-RTT records."""
    first_flight = bytearray()
    deadline = time.monotonic() + 5
    client.settimeout(0.08)
    complete_at: float | None = None
    while time.monotonic() < deadline:
        try:
            chunk = client.recv(8192)
        except socket.timeout:
            if complete_at is not None and time.monotonic() - complete_at >= 0.08:
                return bytes(first_flight)
            continue
        if not chunk:
            raise AssertionError("native TLS client closed before sending 0-RTT first flight")
        first_flight.extend(chunk)
        if len(first_flight) > 32768:
            raise AssertionError("0-RTT first flight exceeded fixture bound")
        offset = 0
        types: list[int] = []
        while offset + 5 <= len(first_flight):
            length = int.from_bytes(first_flight[offset + 3:offset + 5], "big")
            if length > 18432:
                raise AssertionError("invalid TLS record length in captured first flight")
            if offset + 5 + length > len(first_flight):
                break
            types.append(first_flight[offset])
            offset += 5 + length
        complete_at = time.monotonic() if offset == len(first_flight) and 22 in types and 23 in types else None
    raise TimeoutError("native TLS client did not send a complete TLS 0-RTT first flight")


def relay_tls(client: socket.socket, server: socket.socket, stop: threading.Event,
              failures: list[str]) -> None:
    try:
        while not stop.is_set():
            readable, _, _ = select.select([client, server], [], [], 0.1)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (server if source is client else client).sendall(data)
    except OSError as error:
        if not stop.is_set():
            failures.append(str(error))


def exact_replay_across_swap(client_binary: Path, root: Path, tls_port: int,
                             ticket: tuple[Path, float], oper: helix.Client,
                             owner: helix.Client, binary: Path, serving_pid: int,
                             active: list[subprocess.Popen[bytes]]) -> int:
    """Replay one byte-identical CH/0-RTT flight after transferring the guard."""
    early_nick = b"exactreplay"
    fallback_nick = b"replayfallback"
    early_nonce = secrets.token_hex(8).encode("ascii")
    fallback_nonce = secrets.token_hex(8).encode("ascii")
    early = (
        b"NICK " + early_nick + b"\r\nUSER smoke 0 * :exact replay probe\r\n"
        + b"PING :" + early_nonce + b"\r\n"
    )
    fallback = (
        b"NICK " + fallback_nick + b"\r\n"
        b"USER smoke 0 * :replay fallback\r\n"
        b"PING :" + fallback_nonce + b"\r\n"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        proxy_port = listener.getsockname()[1]
        process, output = native_connection(
            client_binary, root, proxy_port, "exact-replay",
            session_in=ticket, early_data=early, fallback=fallback, active=active,
        )
        stop = threading.Event()
        failures: list[str] = []
        relay: threading.Thread | None = None
        try:
            client, _ = listener.accept()
            with client:
                first_flight = capture_first_flight(client)
                flight_at = time.monotonic()
                # The predecessor answers this exact ClientHello. A TLS handshake
                # alone does not prove that it accepted the early data. Its
                # response is discarded so the native client can finish with
                # the successor using the byte-identical first flight.
                with socket.create_connection(("127.0.0.1", tls_port), timeout=3) as predecessor:
                    predecessor.settimeout(3)
                    predecessor.sendall(first_flight)
                    first_response = predecessor.recv(4096)
                    if not first_response or first_response[0] != 22:
                        raise AssertionError(
                            f"predecessor did not send a handshake response: {first_response[:32]!r}"
                        )

                oper.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(
                    binary, different_from=serving_pid, timeout=45,
                )
                owner.ping(b"exact-replay-swap")
                oper.ping(b"exact-replay-swap")
                elapsed = time.monotonic() - flight_at
                if elapsed > 8:
                    raise AssertionError(
                        f"captured first flight aged {elapsed:.1f}s before successor replay"
                    )
                with socket.create_connection(("127.0.0.1", tls_port), timeout=3) as successor:
                    successor.settimeout(None)
                    client.settimeout(None)
                    successor.sendall(first_flight)
                    relay = threading.Thread(
                        target=relay_tls, args=(client, successor, stop, failures), daemon=True,
                    )
                    relay.start()
                    rejected = wait_for(output, b"EARLY=rejected", process)
                    if b"RESUMED=yes" not in rejected:
                        raise AssertionError("replayed first flight did not resume")
                    if b" 001 " + early_nick + b" " in rejected:
                        raise AssertionError("rejected early IRC registration reached application")
                    if b" PONG onyx.local :" + early_nonce in rejected:
                        raise AssertionError("rejected early nonce reached application")
                    final = wait_for(output, b" 001 " + fallback_nick + b" ", process)
                    final = wait_for(output, b" PONG onyx.local :" + fallback_nonce, process)
                    if b" 001 " + early_nick + b" " in final:
                        raise AssertionError("rejected early IRC registration reached application")
                    if b" PONG onyx.local :" + early_nonce in final:
                        raise AssertionError("rejected early nonce reached application")
                    if failures:
                        raise AssertionError(f"TLS proxy relay failed: {failures}")
                print(
                    "PASS: duplicate CH/early TLS records "
                    f"SHA-256 {hashlib.sha256(first_flight).hexdigest()[:16]} "
                    f"rejected after Helix in {elapsed:.2f}s; resumed 1-RTT fallback registered "
                    "(predecessor acceptance of this exact flight was not observed)",
                    flush=True,
                )
                return successor_pid
        finally:
            stop.set()
            if relay is not None:
                relay.join(timeout=2)
            stop_process(process)
            active.remove(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--client", type=Path,
                        help="native Zig TLS client executable (default: zig-out/bin/windows-helix-early-client.exe)")
    parser.add_argument("--exact-replay", action="store_true",
                        help="also replay one byte-identical 0-RTT first flight across the first swap")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary_source = args.binary.resolve()
    if not binary_source.is_file():
        parser.error(f"binary not found: {binary_source}")
    default_client = Path(__file__).resolve().parent.parent / "zig-out" / "bin" / "windows-helix-early-client.exe"
    native_client = (args.client or default_client).resolve()
    if not native_client.is_file():
        parser.error(f"native Zig client not found: {native_client}; build with `zig build windows-helix-early-client`")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-early-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(binary_source, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        create_fixture(root)
        irc_port, tls_port = reserve_ports(2)
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\n"
            f"[tls]\nenabled = true\nport = {tls_port}\n"
            "dns_name = \"localhost\"\ncert_path = \"leaf.pem\"\n"
            "key_path = \"keys-private/server.key\"\n"
            "enable_resumption = true\nearly_data_max_size = 4096\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\n"
            "privileges = [\"server_restart\", \"server_rehash\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        preflight = subprocess.run(
            [str(binary), "--check-config", str(config)], cwd=root,
            capture_output=True, text=True, timeout=20, check=False,
        )
        if preflight.returncode:
            raise AssertionError(
                f"fixture config failed: {(preflight.stdout + preflight.stderr).strip()}"
            )

        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen(
            [str(binary), str(config)], cwd=root, stdout=log,
            stderr=subprocess.STDOUT,
        )
        active: list[subprocess.Popen[bytes]] = []
        clients: list[helix.Client] = []
        try:
            deadline = time.monotonic() + 30
            while True:
                if parent.poll() is not None:
                    raise AssertionError(f"daemon exited before IRC listen: {parent.returncode}")
                try:
                    owner = helix.Client(irc_port)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("IRC listener did not open")
                    time.sleep(0.1)
            clients.append(owner)
            owner.register(b"earlyowner")
            owner.command(
                f"REGISTER helixadmin * {password}".encode("ascii"),
                b"REGISTER SUCCESS", timeout=45,
            )
            oper = helix.Client(irc_port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0helixadmin\0" + password.encode("ascii"))
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK earlyadmin")
            oper.send(b"USER smoke 0 * :Windows 0RTT Helix operator")
            oper.wait(b" 381 ", start=start)

            ticket = seed_ticket(native_client, root, tls_port, active)
            serving_pid = parent.pid
            accepted_early_registration(
                native_client, root, tls_port, ticket, "before", active,
            )
            if args.exact_replay:
                serving_pid = exact_replay_across_swap(
                    native_client, root, tls_port, ticket, oper, owner, binary,
                    serving_pid, active,
                )
                accepted_early_registration(
                    native_client, root, tls_port, ticket, "swap1", active,
                )
                remaining_swaps = (2,)
            else:
                remaining_swaps = (1, 2)
            for sequence in remaining_swaps:
                stage = f"swap{sequence}"
                oper.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(
                    binary, different_from=serving_pid, timeout=45,
                )
                owner.ping(stage.encode("ascii"))
                oper.ping(stage.encode("ascii"))
                serving_pid = successor_pid
                accepted_early_registration(
                    native_client, root, tls_port, ticket, stage, active,
                )
            if parent.wait(timeout=5) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            if not args.exact_replay:
                print(
                    "LIMIT: a fresh TLS client generates a new binder per connection; "
                    "byte-identical 0-RTT replay rejection was not exercised.", flush=True,
                )
            return 0
        except Exception:
            log.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace")[-12000:])
            for path in sorted(root.glob("native-tls-*.log")):
                print(f"{path.name}: {path.read_text(encoding='utf-8', errors='replace')[-6000:]}")
            raise
        finally:
            for process in active:
                stop_process(process)
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
                while helix.image_pids(binary) and time.monotonic() < deadline:
                    time.sleep(0.1)
                log.close()
                if helix.image_pids(binary):
                    raise AssertionError("Helix successor retained the disposable fixture")


if __name__ == "__main__":
    raise SystemExit(main())
