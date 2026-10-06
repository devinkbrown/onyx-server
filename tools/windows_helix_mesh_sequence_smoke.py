#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise sequential native Windows Helix on an A-B-C session mesh.

Four sockets attach to one reusable session on A, B, and C. A then B upgrade
while every attachment, an independent C observer, and both operator sockets
remain open. The strict session oracle checks exact channel/direct deliveries
and identical msgid/time across the two-hop A-B-C line after each swap. A fifth
far-edge attachment resumes after both swaps. All nodes must expose the full,
nonzero Mooring link/TCP/peer topology at every sampled phase.

This fixture uses disposable loopback directories and public RFC 8032 mesh
test identities. It samples topology before and after each swap and never
modifies a deployment.

Usage: python -B tools/windows_helix_mesh_sequence_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error

import windows_helix_mesh_smoke as helix_mesh
import windows_helix_smoke as helix
import windows_mesh_smoke as mesh
import windows_session_smoke as session
from windows_private_account_dir import create_private_directory


ACCOUNT = b"meshsequence"
OBSERVER = b"meshobserver"
ADMIN = b"meshoperator"
EXPECTED_LINKS = (1, 2, 1)
PlainClient = helix_mesh.PlainClient


def topology_healthy(rows: list[dict[str, float]]) -> bool:
    if len(rows) != 3:
        return False
    return all(
        row.get("onyx_s2s_links_active") == count
        and row.get("onyx_s2s_tcp_active") == count
        and row.get("onyx_mesh_peers_up") == count
        and row.get("onyx_mesh_partitioned") == 0
        for row, count in zip(rows, EXPECTED_LINKS)
    )


def wait_topology(metric_ports: list[int], phase: str) -> None:
    deadline = time.monotonic() + mesh.LINK_TIMEOUT
    last: object = None
    while time.monotonic() < deadline:
        try:
            rows = [mesh.gauges(port) for port in metric_ports]
            last = rows
            if topology_healthy(rows):
                print(f"PASS: {phase}: A/B/C secured links, TCP and peers = 1/2/1; partitions = 0", flush=True)
                return
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last = str(exc)
        time.sleep(0.2)
    raise TimeoutError(f"{phase}: non-vacuous A-B-C mesh topology absent; last={last!r}")


def require_images(binaries: list[Path], expected_pids: list[int], phase: str) -> None:
    for label, binary, expected in zip("ABC", binaries, expected_pids):
        actual = helix.image_pids(binary)
        if actual != {expected}:
            raise AssertionError(f"{phase}: node {label} image PIDs {actual!r}, expected {{{expected}}}")


def established_counts(directories: list[Path]) -> tuple[int, int, int]:
    counts = [
        (directory / "daemon.log").read_text(encoding="utf-8", errors="replace")
        .count("mesh S2S established (secured)")
        for directory in directories
    ]
    return counts[0], counts[1], counts[2]


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

    ports = mesh.reserve_ports(9)
    irc_ports, s2s_ports, metric_ports = ports[:3], ports[3:6], ports[6:9]
    password = secrets.token_urlsafe(24).encode("ascii")
    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-mesh-sequence-") as temporary:
        root = Path(temporary)
        directories = [root / label for label in "ABC"]
        configs = [directory / "node.toml" for directory in directories]
        binaries = [directory / "onyx-server.exe" for directory in directories]
        source_digest = session.digest(source)
        for index, (directory, config, binary) in enumerate(zip(directories, configs, binaries)):
            directory.mkdir()
            create_private_directory(directory / "accounts-private")
            shutil.copy2(source, binary)
            if session.digest(binary) != source_digest:
                raise RuntimeError(f"node {'ABC'[index]} executable snapshot changed during copy")
            oper = (
                '[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_restart"]\n'
                '[[opers]]\naccount = "meshoperator"\nclass = "netadmin"\n'
                if index in (0, 1) else ""
            )
            config.write_text(
                mesh.node_config(
                    index, irc_ports[index], s2s_ports[index], metric_ports[index],
                    s2s_ports[1], account_services=True, relay_v2=True,
                ) + oper,
                encoding="utf-8",
            )
        if session.digest(source) != source_digest:
            raise RuntimeError("source executable changed during snapshot pinning")
        print(f"ARTIFACT native Windows daemon sha256={source_digest}", flush=True)
        for label, binary, config, directory in zip("ABC", binaries, configs, directories):
            result = subprocess.run(
                [str(binary), "--check-config", str(config)], cwd=directory,
                capture_output=True, text=True, timeout=20, check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"node {label} preflight failed: {(result.stdout + result.stderr).strip()}"
                )
        print("PASS: A, B, and C config preflight", flush=True)

        processes: list[subprocess.Popen[bytes]] = []
        by_label: dict[str, subprocess.Popen[bytes]] = {}
        clients: list[PlainClient] = []
        with ExitStack() as logs:
            outputs = [logs.enter_context((directory / "daemon.log").open("ab")) for directory in directories]
            try:
                for index in (1, 0, 2):
                    label = "ABC"[index]
                    process = subprocess.Popen(
                        [str(binaries[index]), str(configs[index])], cwd=directories[index],
                        stdout=outputs[index], stderr=subprocess.STDOUT,
                    )
                    processes.append(process)
                    by_label[label] = process
                    if index == 1:
                        mesh.wait_for_hub(process, metric_ports[index])
                mesh.wait_for_links([by_label[label] for label in "ABC"], metric_ports)
                wait_topology(metric_ports, "before Helix")
                current_pids = [by_label[label].pid for label in "ABC"]
                require_images(binaries, current_pids, "before Helix")

                for index in range(3):
                    register_account(irc_ports[index], ACCOUNT, password, f"Registrar{index}")
                register_account(irc_ports[2], OBSERVER, password, "ObserverRegistrar")
                for index in (0, 1):
                    register_account(irc_ports[index], ADMIN, password, f"OperRegistrar{index}")
                print("PASS: session, observer and operator accounts registered in separate durable stores", flush=True)

                def client(node: int, label: str, account: bytes = ACCOUNT) -> PlainClient:
                    result = PlainClient(irc_ports[node], label)
                    clients.append(result)
                    result.register(label, account, password)
                    return result

                operators = [client(index, f"Oper{index}", ADMIN) for index in (0, 1)]
                for oper in operators:
                    oper.wait(lambda line: b" 381 " in line, 0, "operator elevation")

                origin = client(0, "Origin")
                origin.join()
                local, portable = origin.tokens()
                if not re.fullmatch(rb"[0-9a-f]{32}", local) or len(portable) <= len(local):
                    raise AssertionError("reusable local or portable session credential absent")
                sibling = client(0, "NearSibling")
                sibling.resume(local)
                middle = client(1, "MiddleAttachment")
                middle.resume(portable)
                far = client(2, "FarAttachment")
                far.resume(portable)
                attached = [origin, sibling, middle, far]

                observer = client(2, "Observer", OBSERVER)
                observer.join()
                observer.tokens()
                observer.wait_nick(origin.nick)
                for attachment in attached:
                    if attachment.tokens()[0] != local:
                        raise AssertionError("shared local session token differs across physical attachments")
                oracle = session.Oracle()
                session.participation(oracle, attached, observer, "before-a")
                oracle.cumulative(attached + [observer])
                wait_topology(metric_ports, "before A swap")

                # The short raid-correlation window is not checkpointed. Let
                # ordinary JOIN watches age out before each exact handoff.
                time.sleep(2.3)
                baseline_establishes = established_counts(directories)
                if any(count < need for count, need in zip(baseline_establishes, EXPECTED_LINKS)):
                    raise AssertionError(f"secured establishment logs were vacuous: {baseline_establishes!r}")

                for node, phase in ((0, "after-a"), (1, "after-b")):
                    label = "ABC"[node]
                    predecessor = by_label[label]
                    old_pid = current_pids[node]
                    operators[node].send(b"UPGRADE")
                    new_pid = helix.sole_image_pid(binaries[node], different_from=old_pid)
                    if predecessor.wait(timeout=10) != 0:
                        raise AssertionError(f"node {label} predecessor exited unsuccessfully")
                    current_pids[node] = new_pid
                    for other in ("BC" if node == 0 else "C"):
                        if by_label[other].poll() is not None:
                            raise AssertionError(f"node {other} exited during {label} Helix")
                    require_images(binaries, current_pids, phase)
                    wait_topology(metric_ports, phase)
                    for index, held in enumerate(clients):
                        held.ping(f"{phase}-held-{index}".encode("ascii"))
                    for attachment in attached:
                        if attachment.tokens()[0] != local:
                            raise AssertionError(f"{phase}: reusable session token changed")
                    session.participation(oracle, attached, observer, phase)
                    oracle.cumulative(attached + [observer])
                    wait_topology(metric_ports, f"{phase} participation")
                    establishes = established_counts(directories)
                    if establishes != baseline_establishes:
                        raise AssertionError(
                            f"{phase}: secured S2S socket re-established; "
                            f"baseline={baseline_establishes!r}, current={establishes!r}"
                        )
                    print(
                        f"PASS: {label} Helix {old_pid} -> {new_pid}; held sockets, "
                        "mesh links, session token and exact deliveries survived",
                        flush=True,
                    )
                    if node == 0:
                        time.sleep(2.3)

                fifth = client(2, "LaterFarAttachment")
                fifth.resume(portable)
                if fifth.tokens()[0] != local:
                    raise AssertionError("fifth far-edge attachment did not keep reusable token")
                attached.append(fifth)
                session.participation(oracle, attached, observer, "fifth-after-b")
                oracle.cumulative(attached + [observer])
                wait_topology(metric_ports, "after fifth attachment")
                require_images(binaries, current_pids, "final")
                if established_counts(directories) != baseline_establishes:
                    raise AssertionError("secured S2S socket re-established after fifth attachment")
                print("ALL WINDOWS HELIX MESH SEQUENCE CHECKS PASSED", flush=True)
            except Exception as exc:
                print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
                for label, directory in zip("ABC", directories):
                    log = directory / "daemon.log"
                    if log.exists():
                        tail = log.read_text(encoding="utf-8", errors="replace")[-8000:]
                        print(
                            f"--- node {label} log ---\n{tail.replace(password.decode(), '[redacted]')}",
                            file=sys.stderr,
                        )
                return 1
            finally:
                for held in reversed(clients):
                    try:
                        held.close()
                    except OSError:
                        pass
                try:
                    for binary in binaries:
                        for pid in helix.image_pids(binary):
                            try:
                                os.kill(pid, 15)
                            except ProcessLookupError:
                                pass
                finally:
                    mesh.stop(processes)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if all(not helix.image_pids(binary) for binary in binaries):
                        break
                    time.sleep(0.1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
