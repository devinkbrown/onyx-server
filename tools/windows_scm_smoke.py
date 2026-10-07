#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the Windows service worker lifecycle without SCM elevation.

Usage: python -B tools/windows_scm_smoke.py zig-out/bin/onyx-server.exe

The console host runs the same worker, kill-on-close job, stop event and
generation lease as the real SCM host. Ctrl+Break targets its private console
process group and reaches the same cooperative stop hook as Ctrl+C.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, free_port, image_pids
from windows_private_account_dir import create_private_directory


def wait_worker(binary: Path, host: subprocess.Popen[bytes], previous: int | None = None,
                timeout: float = 45) -> int:
    until = time.monotonic() + timeout
    last: set[int] = set()
    while time.monotonic() < until:
        if host.poll() is not None:
            raise AssertionError(f"service host exited early ({host.returncode})")
        last = image_pids(binary)
        if host.pid not in last:
            raise AssertionError(f"stable service host PID {host.pid} vanished: {last}")
        workers = last - {host.pid}
        if len(workers) == 1:
            worker = next(iter(workers))
            if worker != previous:
                return worker
        time.sleep(0.25)
    raise TimeoutError(f"worker did not replace {previous}; live image PIDs={last}")


def wait_gone(binary: Path, timeout: float = 15) -> None:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if not image_pids(binary):
            return
        time.sleep(0.25)
    raise AssertionError(f"host or worker survived stop: {image_pids(binary)}")


def wait_client(port: int, host: subprocess.Popen[bytes], timeout: float = 45) -> Client:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            return Client(port)
        except OSError:
            if host.poll() is not None:
                raise AssertionError(f"service host exited before listen ({host.returncode})")
            time.sleep(0.2)
    raise TimeoutError(f"worker never listened on port {port}")


def operator(port: int, password: str) -> Client:
    client = Client(port)
    try:
        client.command(b"CAP LS 302", b" LS ")
        client.command(b"CAP REQ :sasl", b" ACK ")
        client.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
        proof = base64.b64encode(b"\0scmadmin\0" + password.encode())
        client.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
        start = len(client.lines)
        client.send(b"CAP END")
        client.send(b"NICK scmoper")
        client.send(b"USER smoke 0 * :SCM operator")
        client.wait(b" 381 ", start=start)
        return client
    except Exception:
        client.close()
        raise


def port_rebound(port: int) -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        probe.bind(("::", port))
        probe.listen(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--skip-upgrades", action="store_true",
                        help="exercise startup and cooperative stop only")
    parser.add_argument("--kill-host", action="store_true",
                        help="kill the host after upgrades and prove job containment")
    parser.add_argument("--invalid-config", action="store_true",
                        help="prove worker startup failure stops the host")
    parser.add_argument("--direct-scm", action="store_true",
                        help="prove SCM mode refuses a foreground launch")
    args = parser.parse_args()
    refusal_mode = args.invalid_config or args.direct_scm
    if (refusal_mode and (args.kill_host or args.skip_upgrades)) or (args.invalid_config and args.direct_scm):
        parser.error("startup refusal modes cannot be combined with other modes")
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-scm-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        private = root / "private"
        create_private_directory(private)
        config = root / "server.toml"
        log_path = root / "service-host.log"
        port = free_port()
        password = secrets.token_urlsafe(22)
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 3\nsweep_interval = \"1s\"\n"
            f"[listen]\nirc = {port}\n"
            f"[sasl]\naccount_db = \"{(private / 'accounts.wal').as_posix()}\"\n"
            "[[oper_groups]]\nname = \"netadmin\"\n"
            "privileges = [\"server_restart\", \"server_admin\"]\n"
            "[[opers]]\naccount = \"scmadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        if args.invalid_config:
            config.unlink()
        with log_path.open("wb") as log:
            host = subprocess.Popen(
                [str(binary), "--windows-service" if args.direct_scm else
                 "--windows-service-console-test", str(config)],
                cwd=root, stdout=log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            clients: list[Client] = []
            stopped = False
            try:
                if args.invalid_config or args.direct_scm:
                    code = host.wait(timeout=30)
                    if code == 0:
                        raise AssertionError("service host accepted invalid startup mode")
                    wait_gone(binary)
                    port_rebound(port)
                    reason = "foreground SCM dispatch" if args.direct_scm else "missing config"
                    print(f"PASS: {reason} failed startup; host and worker exited without binding", flush=True)
                    return 0
                worker = wait_worker(binary, host)
                held = wait_client(port, host)
                clients.append(held)
                held.register(b"scmheld")
                held.ping(b"before-upgrade")
                print(f"PASS: stable host {host.pid} launched worker {worker} with three shards", flush=True)

                if not args.skip_upgrades:
                    held.command(f"REGISTER scmadmin * {password}".encode(), b"REGISTER SUCCESS", timeout=45)
                    oper = operator(port, password)
                    clients.append(oper)
                    for generation in (1, 2):
                        oper.send(b"UPGRADE")
                        next_worker = wait_worker(binary, host, worker)
                        held.ping(f"after-upgrade-{generation}".encode())
                        oper.ping(f"oper-after-upgrade-{generation}".encode())
                        if host.poll() is not None or host.pid not in image_pids(binary):
                            raise AssertionError("SCM host did not survive Helix")
                        print(f"PASS: Helix {generation} replaced {worker} -> {next_worker}; held IRC socket and host survived", flush=True)
                        worker = next_worker

                if args.kill_host:
                    host.kill()
                    host.wait(timeout=15)
                    wait_gone(binary)
                    port_rebound(port)
                    stopped = True
                    print("PASS: host loss killed the final Helix worker and released the IRC listener", flush=True)
                    return 0

                host.send_signal(signal.CTRL_BREAK_EVENT)
                code = host.wait(timeout=35)
                if code != 0:
                    raise AssertionError(f"service host exited {code} after cooperative stop")
                stopped = True
                for client in clients:
                    client.close()
                clients.clear()
                wait_gone(binary)
                port_rebound(port)
                print("PASS: targeted console stop exited host and worker; dual-stack IRC port rebound", flush=True)
                return 0
            except Exception:
                log.flush()
                print(log_path.read_text(encoding="utf-8", errors="replace")[-8000:])
                for index, client in enumerate(clients):
                    print(f"client {index} recent lines: {client.lines[-5:]!r}")
                raise
            finally:
                for client in clients:
                    client.close()
                if not stopped and host.poll() is None:
                    try:
                        host.send_signal(signal.CTRL_BREAK_EVENT)
                        host.wait(timeout=15)
                    except (OSError, subprocess.TimeoutExpired):
                        host.kill()
                        host.wait(timeout=15)


if __name__ == "__main__":
    raise SystemExit(main())
