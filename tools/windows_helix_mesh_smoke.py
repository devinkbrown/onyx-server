#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep a secured mesh link and reusable session live through Windows Helix.

Node A dials B over Mooring, then upgrades while both nodes' IRC clients stay
connected. B alone exposes metrics, so A's guarded Helix config has no
untransferred metrics listener. All files and ports belong to this temporary
loopback fixture; the RFC 8032 identities are public test vectors.

Usage: python -B tools/windows_helix_mesh_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import windows_helix_smoke as helix
import windows_mesh_smoke as mesh
import windows_session_smoke as session
from windows_private_account_dir import create_private_directory


ACCOUNT = b"meshhelix"
OBSERVER = b"meshobserver"


class PlainClient(session.Client):
    """Use the session fixture's strict IRC oracle over a loopback TCP socket."""

    def __init__(self, port: int, label: str):
        self.sock = socket.create_connection((mesh.HOST, port), timeout=6)
        self.sock.settimeout(0.1)
        self.label = label
        self.nick = b""
        self.buffer = b""
        self.seen: list[bytes] = []


def wait_for_link(a: subprocess.Popen[bytes], b: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + mesh.LINK_TIMEOUT
    last: object = None
    while time.monotonic() < deadline:
        if a.poll() is not None or b.poll() is not None:
            raise RuntimeError(f"mesh node exited during AKE (A={a.poll()}, B={b.poll()})")
        try:
            last = mesh.gauges(port)
            if link_healthy(last):
                return
        except OSError as exc:
            last = str(exc)
        time.sleep(0.2)
    raise TimeoutError(f"secured A-B link did not establish; B metrics={last!r}")


def link_healthy(row: dict[str, float]) -> bool:
    return (
        row.get("onyx_s2s_links_active") == 1
        and row.get("onyx_s2s_tcp_active") == 1
        and row.get("onyx_mesh_peers_up") == 1
        and row.get("onyx_mesh_partitioned") == 0
    )


def require_link(port: int) -> None:
    row = mesh.gauges(port)
    if not link_healthy(row):
        raise AssertionError(f"B lost its secured A link: {row!r}")


def register_account(port: int, account: bytes, password: bytes, label: str) -> None:
    registrar = PlainClient(port, label)
    try:
        registrar.register(label)
        registrar.command(
            b"REGISTER " + account + b" * " + password,
            b"REGISTER SUCCESS ",
            "account registration",
            timeout=45,
        )
    finally:
        registrar.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=mesh.DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")

    irc_a, irc_b, s2s_a, s2s_b, metrics_b = mesh.reserve_ports(5)
    password = secrets.token_urlsafe(24).encode("ascii")
    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-mesh-") as temporary:
        root = Path(temporary)
        directories = [root / label for label in "AB"]
        for directory in directories:
            directory.mkdir()
            create_private_directory(directory / "accounts-private")
            shutil.copy2(source, directory / "onyx-server.exe")
        binary_a = directories[0] / "onyx-server.exe"
        binaries = [directory / "onyx-server.exe" for directory in directories]
        configs = [directory / "node.toml" for directory in directories]
        configs[0].write_text(
            mesh.node_config(0, irc_a, s2s_a, 0, s2s_b, account_services=True, relay_v2=True)
            + '[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_restart"]\n'
            + '[[opers]]\naccount = "meshhelix"\nclass = "netadmin"\n',
            encoding="utf-8",
        )
        configs[1].write_text(
            mesh.node_config(1, irc_b, s2s_b, metrics_b, s2s_b, account_services=True, relay_v2=True),
            encoding="utf-8",
        )
        for label, binary, config, directory in zip("AB", binaries, configs, directories):
            result = subprocess.run(
                [str(binary), "--check-config", str(config)], cwd=directory,
                capture_output=True, text=True, timeout=60, check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"node {label} preflight failed: {(result.stdout + result.stderr).strip()}")
        print("PASS: A and B config preflight", flush=True)

        processes: list[subprocess.Popen[bytes]] = []
        clients: list[PlainClient] = []
        with ExitStack() as logs:
            outputs = [logs.enter_context((directory / "daemon.log").open("wb")) for directory in directories]
            try:
                b = subprocess.Popen([str(binaries[1]), str(configs[1])], cwd=directories[1],
                                     stdout=outputs[1], stderr=subprocess.STDOUT)
                processes.append(b)
                mesh.wait_for_hub(b, metrics_b)
                a = subprocess.Popen([str(binary_a), str(configs[0])], cwd=directories[0],
                                     stdout=outputs[0], stderr=subprocess.STDOUT)
                processes.append(a)
                wait_for_link(a, b, metrics_b)
                print("PASS: A-B Mooring link established; B reports TCP/link/peer 1 and partition 0", flush=True)

                register_account(irc_a, ACCOUNT, password, "RegistrarA")
                register_account(irc_b, ACCOUNT, password, "RegistrarB")
                register_account(irc_b, OBSERVER, password, "ObserverRegistrar")

                origin = PlainClient(irc_a, "Origin")
                clients.append(origin)
                origin.register("Origin", ACCOUNT, password)
                origin.wait(lambda line: b" 381 " in line, 0, "operator elevation")
                origin.join()
                local_token, portable_token = origin.tokens()
                if not re.fullmatch(rb"[0-9a-f]{32}", local_token) or len(portable_token) <= len(local_token):
                    raise AssertionError("A did not issue reusable local and portable session tokens")

                middle = PlainClient(irc_b, "Middle")
                clients.append(middle)
                middle.register("Middle", ACCOUNT, password)
                middle.resume(portable_token)
                if middle.tokens()[0] != local_token:
                    raise AssertionError("B attachment did not join A's reusable session")

                observer = PlainClient(irc_b, "Observer")
                clients.append(observer)
                observer.register("Observer", OBSERVER, password)
                observer.join()
                observer.tokens()
                observer.wait_nick(origin.nick)
                oracle = session.Oracle()
                session.participation(oracle, [origin, middle], observer, "before-helix")
                require_link(metrics_b)
                print("PASS: held A/B attachments exchanged accepted channel and direct messages", flush=True)

                # The short raid-correlation window is deliberately not
                # checkpointed by Windows Helix. Let ordinary JOIN watches age
                # out before asking for an exact handoff.
                time.sleep(2.3)
                predecessor_pid = a.pid
                origin.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(binary_a, different_from=predecessor_pid)
                if a.wait(timeout=10) != 0:
                    raise AssertionError("Windows Helix predecessor exited unsuccessfully")
                if b.poll() is not None:
                    raise AssertionError("mesh peer B exited during A's upgrade")
                require_link(metrics_b)
                origin.ping(b"after-helix-origin")
                middle.ping(b"after-helix-middle")
                observer.ping(b"after-helix-observer")
                if origin.tokens()[0] != local_token or middle.tokens()[0] != local_token:
                    raise AssertionError("reusable session token changed across Helix")
                session.participation(oracle, [origin, middle], observer, "after-helix")
                oracle.cumulative([origin, middle, observer])
                require_link(metrics_b)

                outputs[1].flush()
                peer_log = (directories[1] / "daemon.log").read_text(encoding="utf-8", errors="replace")
                establishes = peer_log.count("mesh S2S established (secured)")
                if establishes != 1:
                    raise AssertionError(f"B saw {establishes} secured establishments; expected one held S2S socket")
                print(f"PASS: A Helix {predecessor_pid} -> {successor_pid}; held S2S link, sockets, token and exact messages survived", flush=True)
            except Exception as exc:
                print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
                for label, directory in zip("AB", directories):
                    log = directory / "daemon.log"
                    if log.exists():
                        tail = log.read_text(encoding="utf-8", errors="replace")[-8000:]
                        print(f"--- node {label} log ---\n{tail.replace(password.decode(), '[redacted]')}", file=sys.stderr)
                return 1
            finally:
                for client in reversed(clients):
                    try:
                        client.close()
                    except OSError:
                        pass
                for pid in helix.image_pids(binary_a):
                    os.kill(pid, 15)
                mesh.stop(processes)
    print("ALL WINDOWS HELIX MESH CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
