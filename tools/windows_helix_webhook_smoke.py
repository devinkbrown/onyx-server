#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep one webhook binding and held IRC delivery live through two Windows Helix swaps.

Usage: python -B tools/windows_helix_webhook_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory


CHANNEL = b"#helix-webhook"
TARGET = re.compile(rb"/api/webhooks/([0-9a-f]{32})/[0-9a-f]{64}(?![0-9a-f])")


def wait_irc(port: int, process: subprocess.Popen[bytes], timeout: float = 30) -> helix.Client:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listen: {process.returncode}")
        try:
            return helix.Client(port)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("IRC listener did not start")


def post(port: int, target: bytes, marker: bytes) -> None:
    body = b'{"content":"' + marker + b'"}'
    request = (
        b"POST " + target + b" HTTP/1.1\r\nHost: localhost\r\n"
        b"Content-Type: application/json\r\nConnection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(request)
        response = bytearray()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 1024 * 1024:
                raise AssertionError("webhook HTTP response exceeded 1 MiB")
    if not bytes(response).startswith(b"HTTP/1.1 204 No Content\r\n"):
        raise AssertionError(f"webhook POST returned {bytes(response[:120])!r}, expected HTTP 204")


def drain(client: helix.Client, seconds: float = 0.3) -> None:
    """Read trailing IRC lines so a second copy cannot hide behind a PONG."""
    until = time.monotonic() + seconds
    old_timeout = client.socket.gettimeout()
    try:
        while (remaining := until - time.monotonic()) > 0:
            client.socket.settimeout(min(0.05, remaining))
            try:
                chunk = client.socket.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("held IRC socket closed while checking webhook delivery")
            client.buffer += chunk
            while b"\r\n" in client.buffer:
                line, client.buffer = client.buffer.split(b"\r\n", 1)
                if line.startswith(b"PING "):
                    client.send(b"PONG " + line[5:])
                client.lines.append(line)
    finally:
        client.socket.settimeout(old_timeout)


def expect_one(client: helix.Client, marker: bytes, start: int) -> None:
    client.wait(marker, start=start)
    client.ping(b"delivery-barrier-" + marker)
    drain(client)
    matches = [line for line in client.lines[start:] if marker in line and b" PRIVMSG " in line]
    expected_tail = b" PRIVMSG " + CHANNEL + b" :" + marker
    if len(matches) != 1 or not matches[0].endswith(expected_tail):
        raise AssertionError(f"expected one exact webhook event {marker!r}, received {matches!r}")


def check_binding(owner: helix.Client, binding_id: bytes) -> None:
    line = owner.command(b"WEBHOOK LIST " + CHANNEL, b"WEBHOOK: id=" + binding_id)
    if b" name=smoke " not in line:
        raise AssertionError(f"webhook binding changed: {line!r}")


def deliver_once(port: int, target: bytes, marker: bytes, owner: helix.Client, peer: helix.Client) -> None:
    owner_start = len(owner.lines)
    peer_start = len(peer.lines)
    post(port, target, marker)
    expect_one(owner, marker, owner_start)
    expect_one(peer, marker, peer_start)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-webhook-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        create_private_directory(root / "private")
        irc_port = helix.free_port()
        webhook_port = helix.free_port()
        while webhook_port == irc_port:
            webhook_port = helix.free_port()
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\n"
            f"[webhook]\nenabled = true\nbind = \"127.0.0.1\"\nlisten = {webhook_port}\n"
            'store_path = "webhooks.tsv"\n'
            '[sasl]\nenabled = true\naccount_db = "private/accounts.wal"\n'
            '[accounts]\npbkdf2_rounds = 10000\n'
            '[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_restart"]\n'
            '[[opers]]\naccount = "helixadmin"\nclass = "netadmin"\n',
            encoding="utf-8",
        )
        preflight = subprocess.run(
            [str(binary), "--check-config", str(config)], cwd=root,
            capture_output=True, text=True, timeout=20, check=False,
        )
        if preflight.returncode != 0:
            raise RuntimeError(f"webhook Helix config preflight failed: {(preflight.stdout + preflight.stderr).strip()}")

        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[helix.Client] = []
        try:
            owner = wait_irc(irc_port, parent)
            clients.append(owner)
            owner.register(b"hookowner")
            owner.command(f"REGISTER helixadmin * {password}".encode("ascii"), b"REGISTER SUCCESS", timeout=45)
            owner.command(b"JOIN " + CHANNEL, b" 366 ")

            peer = helix.Client(irc_port)
            clients.append(peer)
            peer.register(b"hookpeer")
            peer.command(b"JOIN " + CHANNEL, b" 366 ")

            oper = helix.Client(irc_port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0helixadmin\0" + password.encode("ascii"))
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK hookadmin")
            oper.send(b"USER smoke 0 * :Windows webhook Helix operator")
            oper.wait(b" 381 ", start=start)

            created = owner.command(b"WEBHOOK CREATE " + CHANNEL + b" smoke", b"WEBHOOK: created")
            match = TARGET.search(created)
            if match is None:
                raise AssertionError("WEBHOOK CREATE did not return a binding URL")
            target, binding_id = match.group(0), match.group(1)
            store = root / "webhooks.tsv"
            if not store.is_file() or store.stat().st_size == 0:
                raise AssertionError("WEBHOOK CREATE did not persist its binding")
            check_binding(owner, binding_id)
            deliver_once(webhook_port, target, b"webhook-before-swap", owner, peer)
            serving_pid = parent.pid
            print("PASS: created webhook bound to held channel clients and delivered exactly once", flush=True)

            original_config = config.read_text(encoding="utf-8")
            changed_config = original_config.replace("num_shards = 2", "num_shards = 3", 1)
            if changed_config == original_config:
                raise AssertionError("rollback fixture did not change config")
            config.write_text(changed_config, encoding="utf-8")
            try:
                oper.send(b"UPGRADE")
                helix.wait_log_contains(log_path, "deferred UPGRADE failed")
            finally:
                config.write_text(original_config, encoding="utf-8")
            if helix.image_pids(binary) != {serving_pid}:
                raise AssertionError("failed Helix left a successor or lost the webhook predecessor")
            for held in clients:
                held.ping(b"webhook-after-abort")
            check_binding(owner, binding_id)
            deliver_once(webhook_port, target, b"webhook-after-abort", owner, peer)
            print("PASS: rejected candidate retained the same binding, listener, and held IRC delivery", flush=True)

            for sequence in (1, 2):
                oper.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(binary, different_from=serving_pid, timeout=45)
                for held in clients:
                    held.ping(f"webhook-after-swap-{sequence}".encode("ascii"))
                check_binding(owner, binding_id)
                deliver_once(webhook_port, target, f"webhook-after-swap-{sequence}".encode("ascii"), owner, peer)
                print(
                    f"PASS: webhook Helix swap {sequence}, {serving_pid} -> {successor_pid}; "
                    "same URL and listener, held IRC, exact delivery",
                    flush=True,
                )
                serving_pid = successor_pid
            if parent.wait(timeout=5) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception:
            log.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace")[-12000:])
            raise
        finally:
            for client in clients:
                client.close()
            try:
                for pid in helix.image_pids(binary):
                    os.kill(pid, 15)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 10
                while helix.image_pids(binary) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
