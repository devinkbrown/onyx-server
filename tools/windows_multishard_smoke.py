#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows three-shard plaintext, TLS, and WSS admission.

The operational ``onyx_reactor_accepts_total{shard="N"}`` metric must advance
on all three shards after the smoke clients connect. Every channel member then
sends an IRC message to every other member, including plaintext, TLS, and WSS
connections. Temporary TLS files are removed after the daemon exits.

Usage: python -B tools/windows_multishard_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from contextlib import ExitStack
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time

import windows_full_daemon_smoke as full
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
CHANNEL = "#winshards"
SHARDS = frozenset(range(3))
ACCEPT_LINE = re.compile(r'^onyx_reactor_accepts_total\{shard="([0-2])"\}\s+(\d+)(?:\.0)?$', re.MULTILINE)


def config_text(irc_port, tls_port, ws_port, metrics_port):
    return "\n".join([
        "[node]", "id = 1", "",
        "[listen]", f'host = "{HOST}"', f"irc = {irc_port}",
        f"ws = {ws_port}", "",
        "[tls]", "enabled = true", f"port = {tls_port}",
        'dns_name = "localhost"', 'cert_path = "leaf.pem"',
        'key_path = "keys-private/server.key"', "",
        "[limits]", "num_shards = 3", "max_clients = 64", "",
        "[metrics]", f"listen = {metrics_port}", f'bind = "{HOST}"', "",
    ])


def metrics(metrics_port):
    conn = http.client.HTTPConnection(HOST, metrics_port, timeout=3)
    try:
        conn.request("GET", "/metrics")
        response = conn.getresponse()
        body = response.read(1024 * 1024 + 1)
    finally:
        conn.close()
    if response.status != 200 or len(body) > 1024 * 1024:
        raise AssertionError(f"metrics returned HTTP {response.status} or exceeded 1 MiB")
    rows = {int(shard): int(count) for shard, count in ACCEPT_LINE.findall(body.decode("utf-8", "replace"))}
    if rows.keys() != SHARDS:
        raise AssertionError(f"three shard accept-counter rows are required, got {rows!r}")
    return rows


def wait_ready(proc, log, metrics_port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"three-shard daemon exited during boot ({proc.returncode}): {log.read_text(errors='replace')}")
        try:
            return metrics(metrics_port)
        except (OSError, AssertionError):
            time.sleep(0.05)
    raise TimeoutError(f"three-shard metrics did not become ready: {log.read_text(errors='replace')}")


def all_shards_advanced(metrics_port, baseline, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        current = metrics(metrics_port)
        if all(current[shard] > baseline[shard] for shard in SHARDS):
            return current
        time.sleep(0.05)
    return metrics(metrics_port)


def connect_when_ready(proc, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"three-shard daemon exited before client admission ({proc.returncode})")
        try:
            return socket.create_connection((HOST, port), timeout=0.5)
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"listener on {HOST}:{port} did not accept a client")


def connect_client(proc, stack, context, role, port, nick):
    raw = connect_when_ready(proc, port)
    if role == "plain":
        sock = stack.enter_context(raw)
        client = full.IrcClient(sock)
    else:
        try:
            secured = context.wrap_socket(raw, server_hostname="localhost")
        except Exception:
            raw.close()
            raise
        sock = stack.enter_context(secured)
        if role == "wss":
            client = full.WebSocketClient(sock)
            client.upgrade(port)
        else:
            client = full.IrcClient(sock)
    client.register(nick)
    client.send(f"JOIN {CHANNEL}")
    client.until(f" 366 {nick} {CHANNEL} ")
    return client


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    full.START = time.monotonic()
    full.DEADLINE_SECONDS = 120

    with tempfile.TemporaryDirectory(prefix="onyx-multishard-windows-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "keys-private")
        create_fixture(run_dir)
        irc_port, tls_port, ws_port, metrics_port = full.reserved_ports(4)
        config = run_dir / "multishard.toml"
        config.write_text(config_text(irc_port, tls_port, ws_port, metrics_port), encoding="utf-8")
        checked = subprocess.run([str(binary), "--check-config", str(config)], cwd=run_dir,
                                 capture_output=True, text=True, timeout=20, check=False)
        if checked.returncode != 0:
            raise AssertionError(f"three-shard config rejected: {(checked.stdout + checked.stderr).strip()}")

        log = run_dir / "daemon.log"
        proc = None
        try:
            with log.open("w", encoding="utf-8") as output:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                        stdout=output, stderr=subprocess.STDOUT)
                baseline = wait_ready(proc, log, metrics_port)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                members = []
                with ExitStack() as stack:
                    roles = ["plain"] * 3 + ["tls"] * 3 + ["wss"] * 3
                    for index, role in enumerate(roles):
                        nick = f"msh{role[0]}{index:02d}"
                        port = {"plain": irc_port, "tls": tls_port, "wss": ws_port}[role]
                        client = connect_client(proc, stack, context, role, port, nick)
                        members.append((client, nick, role))
                    current = all_shards_advanced(metrics_port, baseline)
                    # A few extra clients may be needed if the Windows acceptor
                    # receives an uneven burst, while the fixed cap keeps this
                    # smoke bounded and requires evidence for all three shards.
                    for index in range(9, 18):
                        if all(current[shard] > baseline[shard] for shard in SHARDS):
                            break
                        nick = f"mshp{index:02d}"
                        client = connect_client(proc, stack, context, "plain", irc_port, nick)
                        members.append((client, nick, "plain"))
                        current = all_shards_advanced(metrics_port, baseline)
                    if not all(current[shard] > baseline[shard] for shard in SHARDS):
                        raise AssertionError(f"not all shards admitted clients: baseline={baseline!r}, current={current!r}")
                    if {member[2] for member in members} != {"plain", "tls", "wss"}:
                        raise AssertionError("plaintext, TLS, and WSS clients were not all admitted")
                    print(f"PASS: {len(members)} live plaintext/TLS/WSS clients advanced accept counters on shards 0, 1, and 2")

                    for index, (sender, nick, _) in enumerate(members):
                        marker = f"winshard-{index}"
                        sender.send(f"PRIVMSG {CHANNEL} :{marker}")
                        for recipient, other_nick, _ in members:
                            if recipient is sender:
                                continue
                            line = recipient.until(f"PRIVMSG {CHANNEL} :{marker}", seconds=10)
                            if not line.startswith(f":{nick}!"):
                                raise AssertionError(f"{other_nick} received wrong sender: {line!r}")
                        sender.ping(f"after-{marker}")
                    print("PASS: every channel member delivered IRC PRIVMSG to all other members across the three-shard topology")

                    for client, _, _ in members:
                        client.quit()
                    if proc.poll() is not None:
                        raise AssertionError(f"daemon exited before clean client shutdown: {log.read_text(errors='replace')[-8000:]}")
                    print("PASS: all plaintext, TLS, and WSS clients completed QUIT/close")
        except Exception as exc:
            raise AssertionError(f"{exc}\ndaemon log:\n{log.read_text(errors='replace')[-12000:]}") from exc
        finally:
            stop(proc)
        if proc is None or proc.poll() is None:
            raise AssertionError("daemon process did not stop")
        print("PASS: three-shard daemon process exited and released its disposable TLS files")


if __name__ == "__main__":
    main()
