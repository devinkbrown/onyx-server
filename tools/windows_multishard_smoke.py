#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe Windows three-shard plaintext, TLS, and WSS through Helix.

The operational ``onyx_reactor_accepts_total{shard="N"}`` metric must advance
on all three shards after the smoke clients connect. Every channel member then
sends an IRC message to every other member, including plaintext, TLS, and WSS
connections. A Helix swap must preserve those clients and admit fresh clients
on all three shards. Temporary TLS files are removed after both daemons exit.

Usage: python -B tools/windows_multishard_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import base64
from contextlib import ExitStack
import http.client
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import windows_full_daemon_smoke as full
import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
CHANNEL = "#winshards"
SHARDS = frozenset(range(3))
ACCEPT_LINE = re.compile(r'^onyx_reactor_accepts_total\{shard="([0-2])"\}\s+(\d+)(?:\.0)?$', re.MULTILINE)


def config_text(irc_port, tls_port, ws_port, metrics_port, node_key, cloak_secret):
    return "\n".join([
        "[node]", "id = 1", f'secret_key = "{node_key}"', "",
        "[cloak]", f'secret = "{cloak_secret}"', "",
        "[listen]", f'host = "{HOST}"', f"irc = {irc_port}",
        f"ws = {ws_port}", "",
        "[tls]", "enabled = true", f"port = {tls_port}",
        'dns_name = "localhost"', 'cert_path = "leaf.pem"',
        'key_path = "keys-private/server.key"', "",
        "[limits]", "num_shards = 3", "max_clients = 64", "",
        "[metrics]", f"listen = {metrics_port}", f'bind = "{HOST}"', "",
        "[sasl]", "enabled = true", 'account_db = "private/accounts.wal"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
        "[[oper_groups]]", 'name = "netadmin"',
        'privileges = ["server_restart"]', "",
        "[[opers]]", 'account = "shardadmin"', 'class = "netadmin"', "",
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
        if proc is not None and proc.poll() is not None:
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


def fanout(members, label):
    for index, (sender, nick, _) in enumerate(members):
        marker = f"{label}-{index}"
        sender.send(f"PRIVMSG {CHANNEL} :{marker}")
        for recipient, other_nick, _ in members:
            if recipient is sender:
                continue
            line = recipient.until(f"PRIVMSG {CHANNEL} :{marker}", seconds=10)
            if not line.startswith(f":{nick}!"):
                raise AssertionError(f"{other_nick} received wrong sender: {line!r}")
        sender.ping(f"after-{marker}")


def stop_image(binary, parent):
    try:
        for pid in helix.image_pids(binary):
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
    finally:
        stop(parent)
    deadline = time.monotonic() + 15
    while helix.image_pids(binary) and time.monotonic() < deadline:
        time.sleep(0.1)
    if helix.image_pids(binary):
        raise AssertionError("disposable three-shard daemon image remained live")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")
    full.START = time.monotonic()
    full.DEADLINE_SECONDS = 240

    with tempfile.TemporaryDirectory(prefix="onyx-multishard-windows-") as scratch:
        run_dir = Path(scratch)
        binary = run_dir / "onyx-server.exe"
        shutil.copy2(source, binary)
        create_private_directory(run_dir / "private")
        create_private_directory(run_dir / "keys-private")
        create_fixture(run_dir)
        irc_port, tls_port, ws_port, metrics_port = full.reserved_ports(4)
        password = secrets.token_urlsafe(22)
        config = run_dir / "multishard.toml"
        config.write_text(config_text(irc_port, tls_port, ws_port, metrics_port,
                                      secrets.token_hex(32), secrets.token_urlsafe(32)), encoding="utf-8")
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

                    fanout(members, "winshard-before")
                    print("PASS: every channel member delivered IRC PRIVMSG to all other members across the three-shard topology")

                    owner = members[0][0]
                    owner.send(f"REGISTER shardadmin * {password}")
                    owner.until("REGISTER SUCCESS", seconds=45)
                    oper = helix.Client(irc_port)
                    stack.callback(oper.close)
                    oper.command(b"CAP LS 302", b" LS ")
                    oper.command(b"CAP REQ :sasl", b" ACK ")
                    oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
                    proof = base64.b64encode(b"\0shardadmin\0" + password.encode("ascii"))
                    oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
                    start = len(oper.lines)
                    oper.send(b"CAP END")
                    oper.send(b"NICK shardoper")
                    oper.send(b"USER smoke 0 * :Windows three-shard Helix operator")
                    oper.wait(b" 381 ", start=start)
                    held_members = members.copy()
                    predecessor_pid = proc.pid
                    oper.send(b"UPGRADE")
                    if proc.wait(timeout=45) != 0:
                        raise AssertionError("three-shard Helix predecessor did not exit cleanly")
                    successor_pid = helix.sole_image_pid(binary, different_from=predecessor_pid)
                    helix.wait_log_contains(log, "Windows Helix adoption committed; starting reactors")
                    oper.ping(b"three-shard-after-swap")
                    fanout(held_members, "winshard-after")
                    print(f"PASS: Helix {predecessor_pid} -> {successor_pid}; every held plaintext/TLS/WSS member still sends to every other member")

                    post_swap_baseline = metrics(metrics_port)
                    fresh_members = []
                    for role, port in (("plain", irc_port), ("tls", tls_port), ("wss", ws_port)):
                        nick = f"fresh{role}"
                        client = connect_client(None, stack, context, role, port, nick)
                        fresh_members.append((client, nick, role))
                        members.append((client, nick, role))
                    current = all_shards_advanced(metrics_port, post_swap_baseline)
                    for index in range(15):
                        if all(current[shard] > post_swap_baseline[shard] for shard in SHARDS):
                            break
                        nick = f"freshp{index:02d}"
                        client = connect_client(None, stack, context, "plain", irc_port, nick)
                        members.append((client, nick, "plain"))
                        current = all_shards_advanced(metrics_port, post_swap_baseline)
                    if not all(current[shard] > post_swap_baseline[shard] for shard in SHARDS):
                        raise AssertionError(f"successor did not admit on all shards: baseline={post_swap_baseline!r}, current={current!r}")
                    fanout(held_members + fresh_members, "winshard-fresh")
                    if helix.image_pids(binary) != {successor_pid}:
                        raise AssertionError("three-shard Helix successor was not the sole live daemon")
                    print(f"PASS: fresh plaintext/TLS/WSS clients and per-shard accepts advanced after Helix: {post_swap_baseline!r} -> {current!r}")

                    for client, _, _ in members:
                        client.quit()
                    oper.close()
                    if helix.image_pids(binary) != {successor_pid}:
                        raise AssertionError(f"successor exited before clean client shutdown: {log.read_text(errors='replace')[-8000:]}")
                    print("PASS: all plaintext, TLS, and WSS clients completed QUIT/close")
        except Exception as exc:
            tail = log.read_text(errors="replace")[-12000:].replace(password, "[redacted]")
            raise AssertionError(f"{exc}\ndaemon log:\n{tail}") from exc
        finally:
            stop_image(binary, proc)
        if proc is None or proc.poll() is None:
            raise AssertionError("three-shard predecessor process did not stop")
        print("PASS: three-shard Helix successor exited and released its disposable TLS files")


if __name__ == "__main__":
    main()
