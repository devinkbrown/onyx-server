#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep mutable OroWasm memory and held IRC clients through two Windows Helix swaps.

Usage: python -B tools/windows_helix_wasm_smoke.py zig-out/bin/onyx-server.exe
       python -B tools/windows_helix_wasm_smoke.py --rehash zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

import windows_helix_smoke as helix
from windows_private_account_dir import create_private_directory
from windows_wasm_smoke import REPLY_WASM


def section(section_id: int, payload: bytes) -> bytes:
    """The fixture's sections are all shorter than one unsigned LEB byte."""
    assert len(payload) < 128
    return bytes((section_id, len(payload))) + payload


# This module imports env.reply(ptr, len), exports handle(), and owns one page
# of linear memory. Each call increments the i32 at offset 4, writes its ASCII
# digit at offset 0, then replies with that one byte. Nine calls fit the smoke.
# A fresh load would reply "1" again; a disk reload below would reply "ok".
COUNTER_BODY = bytes.fromhex(
    "01017f"  # one i32 local
    "4104410428020041016a2200360200"  # memory[4] += 1; keep it in local 0
    "4100200041306a360200"  # memory[0] = local 0 + '0'
    "4100410110000b"  # env.reply(0, 1)
)
COUNTER_WASM = (
    b"\x00asm\x01\x00\x00\x00"
    + section(1, bytes.fromhex("0260027f7f00600000"))
    + section(2, bytes.fromhex("0103656e76057265706c790000"))
    + section(3, bytes.fromhex("0101"))
    + section(5, bytes.fromhex("010001"))
    + section(7, bytes.fromhex("010668616e646c650001"))
    + section(10, b"\x01" + bytes((len(COUNTER_BODY),)) + COUNTER_BODY)
)


def wait_irc(port: int, process: subprocess.Popen[bytes]) -> helix.Client:
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listen: {process.returncode}")
        try:
            return helix.Client(port)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("IRC listener did not start")


def count(client: helix.Client, nick: bytes, expected: int) -> None:
    line = client.command(b"COUNTME", b" NOTICE " + nick + b" :", timeout=15)
    wanted = b" NOTICE " + nick + b" :" + str(expected).encode("ascii")
    if not line.endswith(wanted):
        raise AssertionError(f"OroWasm counter expected {expected}, received {line!r}")


def session_token(client: helix.Client) -> bytes:
    line = client.command(b"SESSION TOKEN", b" :SESSION TOKEN ")
    token = line.split(b" :SESSION TOKEN ", 1)[1].split()[0]
    if len(token) != 32 or any(byte not in b"0123456789abcdef" for byte in token):
        raise AssertionError(f"invalid local session token: {token!r}")
    return token


def reply(client: helix.Client, nick: bytes) -> None:
    line = client.command(b"COUNTME", b" NOTICE " + nick + b" :", timeout=15)
    if not line.endswith(b" NOTICE " + nick + b" :ok"):
        raise AssertionError(f"OroWasm reply module expected ok, received {line!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rehash", action="store_true", help="reload changed plugin bytes before the two Helix swaps")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-wasm-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        plugins = root / "plugins"
        plugins.mkdir()
        module = plugins / "COUNTME.wasm"
        module.write_bytes(REPLY_WASM if args.rehash else COUNTER_WASM)
        port = helix.free_port()
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
            '[wasm]\nplugin_dir = "plugins"\ndefault_fuel = 16384\n'
            '[sasl]\nenabled = true\naccount_db = "private/accounts.wal"\n'
            '[accounts]\npbkdf2_rounds = 10000\n'
            '[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_restart", "server_rehash"]\n'
            '[[opers]]\naccount = "helixadmin"\nclass = "netadmin"\n',
            encoding="utf-8",
        )
        create_private_directory(root / "private")
        preflight = subprocess.run(
            [str(binary), "--check-config", str(config)], cwd=root,
            capture_output=True, text=True, timeout=20, check=False,
        )
        if preflight.returncode != 0:
            raise RuntimeError(f"OroWasm Helix preflight failed: {(preflight.stdout + preflight.stderr).strip()}")

        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[helix.Client] = []
        try:
            user = wait_irc(port, parent)
            clients.append(user)
            user.register(b"wasmuser")
            user.command(f"REGISTER helixadmin * {password}".encode("ascii"), b"REGISTER SUCCESS", timeout=45)

            oper = helix.Client(port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0helixadmin\0" + password.encode("ascii"))
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK wasmadmin")
            oper.send(b"USER smoke 0 * :Windows OroWasm Helix operator")
            oper.wait(b" 381 ", start=start)

            serving_pid = parent.pid
            token_before = session_token(oper)
            original_config = config.read_text(encoding="utf-8")
            if args.rehash:
                reply(user, b"wasmuser")
                module.write_bytes(COUNTER_WASM)
                oper.command(b"REHASH", b"Configuration reloaded", timeout=30)
                if config.read_text(encoding="utf-8") != original_config:
                    raise AssertionError("unchanged-source REHASH altered config text")
                if session_token(oper) != token_before:
                    raise AssertionError("unchanged-source REHASH changed the local session token")
                count(user, b"wasmuser", 1)
                count(oper, b"wasmadmin", 2)
                if helix.image_pids(binary) != {serving_pid}:
                    raise AssertionError("REHASH replaced the serving process")
                # The candidate must inherit the post-REHASH module and memory,
                # even though the disk now contains the old reply module again.
                module.write_bytes(REPLY_WASM)
                print("PASS: unchanged-source REHASH activated changed OroWasm bytes and shared counter state", flush=True)
                next_count = 3
            else:
                count(user, b"wasmuser", 1)
                count(oper, b"wasmadmin", 2)
                module.write_bytes(REPLY_WASM)
                print("PASS: OroWasm counter is shared by two held IRC clients", flush=True)

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
                    raise AssertionError("failed Helix left a successor or lost the OroWasm predecessor")
                for held in clients:
                    held.ping(b"wasm-after-abort")
                count(user, b"wasmuser", 3)
                print("PASS: rejected candidate kept held clients and mutable OroWasm memory", flush=True)
                next_count = 4

            for sequence in (1, 2):
                oper.send(b"UPGRADE")
                successor_pid = helix.sole_image_pid(binary, different_from=serving_pid, timeout=45)
                for held in clients:
                    held.ping(f"wasm-after-swap-{sequence}".encode("ascii"))
                first_count = next_count
                count(user, b"wasmuser", first_count)
                count(oper, b"wasmadmin", first_count + 1)
                fresh = helix.Client(port)
                clients.append(fresh)
                fresh_nick = f"wasmfresh{sequence}".encode("ascii")
                fresh.register(fresh_nick)
                count(fresh, fresh_nick, first_count + 2)
                next_count += 3
                if session_token(oper) != token_before:
                    raise AssertionError(f"Helix swap {sequence} changed the local session token")
                print(
                    f"PASS: OroWasm Helix swap {sequence}, {serving_pid} -> {successor_pid}; "
                    "held and fresh IRC, source bytes, mutable memory",
                    flush=True,
                )
                serving_pid = successor_pid
            if args.rehash:
                changed_config = original_config.replace("default_fuel = 16384", "default_fuel = 16385", 1)
                if changed_config == original_config:
                    raise AssertionError("WASM policy negative did not change config")
                config.write_text(changed_config, encoding="utf-8")
                oper.command(b"REHASH", b"Configuration reloaded", timeout=30)
                oper.command(b"OROWASM STATUS", b"default_fuel=16385", timeout=15)
                oper.send(b"UPGRADE")
                helix.wait_log_contains(log_path, "deferred UPGRADE failed: NativeUpgradeUnavailable")
                if helix.image_pids(binary) != {serving_pid}:
                    raise AssertionError("changed WASM policy REHASH replaced the serving process")
                for held in clients:
                    held.ping(b"wasm-after-policy-refusal")
                if session_token(oper) != token_before:
                    raise AssertionError("changed WASM policy REHASH changed the local session token")
                print("PASS: changed WASM policy REHASH refused Helix and kept held clients live", flush=True)
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
