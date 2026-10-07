#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Native Windows secured-mesh *transport* gate on a disposable A-B-C line.

Runs three independent Onyx Server processes bound to loopback. A and C dial B;
there is no A-C socket. The script requires Mooring-established link metrics on
all nodes and then exchanges channel messages between clients on the two edge
nodes, in both directions. It is an initial transport/integration gate, not the
full mesh-wide session, Helix, exact-once, or allocation-failure acceptance.

The RFC 8032 Ed25519 test-vector seeds below are public and deliberately usable
only for this temporary local test. Never copy these identities into a deployment.

Usage: python tools/windows_mesh_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from windows_private_account_dir import create_private_directory
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
LINK_TIMEOUT = 45.0
CHAT_TIMEOUT = 45.0

# RFC 8032 section 7.1, tests 1-3: explicit fixed identity for an isolated test.
IDENTITIES = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
)


def reserve_ports(count: int) -> list[int]:
    # Hold all reservations until the set is complete, so each is distinct.
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket(socket.AF_INET)) for _ in range(count)]
        for sock in sockets:
            sock.bind((HOST, 0))
        return [sock.getsockname()[1] for sock in sockets]


def node_config(
    index: int,
    irc: int,
    s2s: int,
    metrics: int,
    b_s2s: int,
    *,
    tls: int | None = None,
    account_services: bool = False,
    relay_v2: bool = False,
) -> str:
    seed, public = IDENTITIES[index]
    roots = [IDENTITIES[1][1]] if index != 1 else [IDENTITIES[0][1], IDENTITIES[2][1]]
    roots_text = ", ".join(f'"{key}"' for key in roots)
    roster_text = ", ".join(f'"{key}"' for _, key in IDENTITIES)
    connect = f'connect = ["{HOST}:{b_s2s}"]\n' if index != 1 else ""
    relay = (
        'relay_v2_authoring = "active"\nrelay_v2_activation_epoch = 1\n'
        f'relay_v2_roster = [{roster_text}]\n'
        if relay_v2 else ""
    )
    tls_config = f'[tls]\nenabled = true\nport = {tls}\ndns_name = "localhost"\n' if tls else ""
    account_config = (
        '[sasl]\nenabled = true\naccount_db = "accounts-private/accounts.wal"\n'
        '[accounts]\npbkdf2_rounds = 10000\n'
        '[sessions]\nresume_composite_issuance = false\n'
        if account_services else ""
    )
    return (
        f"[node]\nid = {index + 1}\nsecret_key = \"{seed}\"\npublic_key = \"{public}\"\n"
        f"[network]\nname = \"Windows mesh smoke\"\nserver_name = \"node-{index + 1}.smoke.local\"\n"
        f"[listen]\nhost = \"{HOST}\"\nirc = {irc}\ns2s = {s2s}\n"
        f"[mesh]\nrealm = \"windows-mesh-smoke\"\nmesh_pass = \"test-only-mesh-pass\"\n"
        f"require_secured = true\nrequire_signed_frames = true\ntrust_roots = [{roots_text}]\n{connect}{relay}"
        f"[cloak]\nsecret = \"test-only-shared-cloak-secret\"\n"
        f"{tls_config}{account_config}"
        # Link gauges use the periodic stats snapshot. Keep the acceptance
        # oracle fresh during the cold-reconnect window.
        f"[stats]\ninterval = \"1s\"\n"
        f"[metrics]\nbind = \"{HOST}\"\nlisten = {metrics}\n"
    )


def preflight(binary: Path, configs: list[Path], directories: list[Path]) -> None:
    for label, config, directory in zip("ABC", configs, directories):
        result = subprocess.run(
            [str(binary), "--check-config", str(config)],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stdout + result.stderr).strip()
            raise RuntimeError(
                f"node {label} config preflight blocked (exit {result.returncode}): {detail}"
            )
    print("PASS: A, B, and C config preflight")


def gauges(port: int) -> dict[str, float]:
    url = f"http://{HOST}:{port}/metrics"
    with urllib.request.urlopen(url, timeout=1.5) as response:
        if response.status != 200:
            raise RuntimeError(f"metrics HTTP {response.status} from {url}")
        body = response.read(2 * 1024 * 1024).decode("utf-8", "replace")
    parsed: dict[str, float] = {}
    for line in body.splitlines():
        match = re.fullmatch(r"(onyx_(?:s2s_links_active|s2s_tcp_active|mesh_peers_up|mesh_partitioned)) ([0-9.]+)", line)
        if match:
            parsed[match.group(1)] = float(match.group(2))
    return parsed


def wait_for_hub(process: subprocess.Popen[bytes], metrics_port: int) -> None:
    deadline = time.monotonic() + 12.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"hub node B exited before edge start (exit {process.returncode})")
        try:
            if "onyx_s2s_links_active" in gauges(metrics_port):
                return
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.1)
    raise TimeoutError("hub node B metrics did not become ready within 12s")


def wait_for_links(processes: list[subprocess.Popen[bytes]], metric_ports: list[int]) -> None:
    deadline = time.monotonic() + LINK_TIMEOUT
    expected = (1, 2, 1)
    last: list[object] = []
    while time.monotonic() < deadline:
        for label, process in zip("ABC", processes):
            if process.poll() is not None:
                raise RuntimeError(f"node {label} exited while waiting for links (exit {process.returncode})")
        try:
            last = [gauges(port) for port in metric_ports]
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last = [str(exc)]
        else:
            ready = True
            for row, need in zip(last, expected):
                assert isinstance(row, dict)
                ready &= row.get("onyx_s2s_links_active", -1) == need
                ready &= row.get("onyx_mesh_peers_up", -1) == need
                ready &= row.get("onyx_mesh_partitioned", -1) == 0
            if ready:
                print("PASS: secured links established A-B-C (A=1, B=2, C=1; partitioned=0)")
                return
        time.sleep(0.2)
    raise TimeoutError(f"Mooring links did not establish within {LINK_TIMEOUT:g}s; last metrics={last!r}")


def edge_chat(irc_ports: list[int]) -> None:
    # Reuse the established IRC protocol smoke. Its clients attach only to A
    # and C, so every accepted message has to traverse both secured hops via B.
    environment = os.environ.copy()
    environment.update(
        MESH_SMOKE_A_TLS="0",
        MESH_SMOKE_B_TLS="0",
        MESH_SMOKE_ALLOW_GUEST="1",
        MESH_SMOKE_REQUIRE_SASL="0",
        MESH_SMOKE_SASL_USER="",
        MESH_SMOKE_SASL_PASS="",
        ANNOUNCE_SASL_USER="",
        ANNOUNCE_SASL_PASS="",
        MESH_SMOKE_CHANNEL="#windows-mesh-smoke",
        MESH_SMOKE_TIMEOUT=str(int(CHAT_TIMEOUT)),
        PYTHONIOENCODING="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "mesh_chat_smoke.py"),
            f"{HOST}:{irc_ports[0]}",
            f"{HOST}:{irc_ports[2]}",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=CHAT_TIMEOUT + 8,
        check=False,
    )
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"A-C IRC exchange failed (exit {result.returncode})")
    print("PASS: A and C clients exchanged channel messages through B in both directions")


def stop(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in reversed(processes):
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    if os.name != "nt":
        parser.error("this smoke is for native Windows; use the existing Linux mesh gates there")

    ports = reserve_ports(9)
    irc_ports, s2s_ports, metric_ports = ports[:3], ports[3:6], ports[6:9]
    with tempfile.TemporaryDirectory(prefix="onyx-windows-mesh-") as temp:
        root = Path(temp)
        directories = [root / label for label in "ABC"]
        configs = [directory / "node.toml" for directory in directories]
        for index, (directory, config) in enumerate(zip(directories, configs)):
            directory.mkdir()
            create_private_directory(directory / "accounts-private")
            config.write_text(
                node_config(index, irc_ports[index], s2s_ports[index], metric_ports[index], s2s_ports[1], account_services=True, relay_v2=True),
                encoding="utf-8",
            )
        processes: list[subprocess.Popen[bytes]] = []
        try:
            preflight(binary, configs, directories)
            with ExitStack() as logs:
                # Bring up the passive hub before either outbound edge dial. A
                # connection refusal otherwise waits for the production redial
                # cadence and needlessly makes this test timing dependent.
                by_label: dict[str, subprocess.Popen[bytes]] = {}
                for index in (1, 0, 2):
                    label, config, directory = "ABC"[index], configs[index], directories[index]
                    output = logs.enter_context((directory / "daemon.log").open("wb"))
                    process = subprocess.Popen([str(binary), str(config)], cwd=directory, stdout=output, stderr=subprocess.STDOUT)
                    processes.append(process)
                    by_label[label] = process
                    print(f"started node {label} (pid {process.pid})")
                    if label == "B":
                        wait_for_hub(process, metric_ports[1])
                ordered = [by_label[label] for label in "ABC"]
                wait_for_links(ordered, metric_ports)
                edge_chat(irc_ports)
                for label, process in zip("ABC", ordered):
                    if process.poll() is not None:
                        raise RuntimeError(f"node {label} exited after chat (exit {process.returncode})")
        except Exception as exc:
            print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
            stop(processes)
            for label, directory in zip("ABC", directories):
                log = directory / "daemon.log"
                if log.exists():
                    print(f"--- node {label} log ---\n{log.read_text(encoding='utf-8', errors='replace')}", file=sys.stderr)
            return 1
        finally:
            stop(processes)
    print("ALL WINDOWS MESH TRANSPORT CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
