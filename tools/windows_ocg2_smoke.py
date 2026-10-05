#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows OCG2 durable authority boot and strict cold restore.

Usage: python -B tools/windows_ocg2_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from contextlib import closing
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from windows_private_account_dir import create_private_directory


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
# Generated from fixed Ed25519 seeds 0x94 and 0x95 using Onyx's BLAKE3-160
# node ID and MZ-S2S-SHORTID-v1 derivation. These are disposable test keys.
AUTHORITY = ("94" * 32, "0e34c045c22372f70828069cdc3df899c02d55ccc932a5470c2d152023a644aa", "a8abf3d7a2f861c5")
OTHER_AUTHORITY = ("4c71b3dc27513f994bd3391fdfcc6300b2e7daf180979468b34e432cf14e5e35", "1b12997a63f788f8")


def reserve_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def config_text(port, authority_public, authority_short, mode):
    return "\n".join([
        "[node]", "id = 1", f'secret_key = "{AUTHORITY[0]}"', "",
        "[listen]", f'host = "{HOST}"', f"irc = {port}", "",
        "[sasl]", "enabled = true", 'account_db = "accounts-private/accounts.wal"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
        "[oper.ocg2]", "enabled = true",
        f"projection_enabled = {'true' if mode in ('project', 'mint') else 'false'}",
        f"minting_enabled = {'true' if mode == 'mint' else 'false'}",
        f'authority_node_id = "{authority_short}"',
        f'authority_public_key = "{authority_public}"', "",
    ])


def run_cli(binary, run_dir, *args):
    return subprocess.run([str(binary), *map(str, args)], cwd=run_dir,
                          capture_output=True, text=True, timeout=20, check=False)


def wait_registered(proc, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"daemon exited before IRC listener (exit {proc.returncode})")
        try:
            sock = socket.create_connection((HOST, port), timeout=0.5)
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise TimeoutError("OCG2 IRC listener did not start")
    with closing(sock):
        sock.settimeout(5)
        sock.sendall(b"NICK ocg2smoke\r\nUSER ocg2smoke 0 * :OCG2 Smoke\r\n")
        incoming = b""
        while b" 001 " not in incoming:
            part = sock.recv(4096)
            if not part:
                raise ConnectionError("OCG2 daemon closed during registration")
            incoming += part
            if len(incoming) > 65536:
                raise AssertionError("IRC registration burst exceeded 64 KiB")
        sock.sendall(b"PING :ocg2-smoke\r\n")
        while b" PONG " not in incoming or b":ocg2-smoke" not in incoming:
            part = sock.recv(4096)
            if not part:
                raise ConnectionError("OCG2 daemon closed before PONG")
            incoming += part
            if len(incoming) > 131072:
                raise AssertionError("IRC response exceeded 128 KiB")
        sock.sendall(b"QUIT :smoke complete\r\n")


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

    with tempfile.TemporaryDirectory(prefix="onyx-ocg2-windows-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "accounts-private")
        port = reserve_port()
        config = run_dir / "ocg2-mint.toml"
        wrong = run_dir / "ocg2-other-authority.toml"
        config.write_text(config_text(port, AUTHORITY[1], AUTHORITY[2], "mint"), encoding="utf-8")
        wrong.write_text(config_text(port, OTHER_AUTHORITY[0], OTHER_AUTHORITY[1], "observe"), encoding="utf-8")

        checked = run_cli(binary, run_dir, "--check-config", config)
        if checked.returncode != 0:
            raise AssertionError(f"private OCG2 config rejected: {(checked.stdout + checked.stderr).strip()}")
        if (run_dir / "accounts-private" / "accounts.wal").exists():
            raise AssertionError("read-only OCG2 preflight created account state")
        print("PASS: private OCG2 mint config accepted without cold mutation")

        for attempt, source in ((1, "initialized"), (2, "restored")):
            log = run_dir / f"daemon-{attempt}.log"
            proc = None
            try:
                with log.open("w", encoding="utf-8") as output:
                    proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                            stdout=output, stderr=subprocess.STDOUT)
                    wait_registered(proc, port)
                    text = log.read_text(encoding="utf-8", errors="replace")
                    if f"OCG2 mint runtime primed ({source}; authority;" not in text:
                        raise AssertionError(f"OCG2 did not report {source} mint projection: {text}")
                    if proc.poll() is not None:
                        raise AssertionError("OCG2 daemon exited after registration")
            finally:
                stop(proc)
        wal = run_dir / "accounts-private" / "accounts.wal"
        if not wal.is_file() or wal.stat().st_size == 0:
            raise AssertionError("OCG2 durable authority did not persist in the private account WAL")
        print("PASS: OCG2 authority initialized, then cold-restored with mint projection live")

        for mode in ("project", "observe"):
            staged = run_dir / f"ocg2-{mode}.toml"
            staged.write_text(config_text(port, AUTHORITY[1], AUTHORITY[2], mode), encoding="utf-8")
            checked_mode = run_cli(binary, run_dir, "--check-config", staged)
            if checked_mode.returncode != 0:
                raise AssertionError(f"{mode} config rejected: {(checked_mode.stdout + checked_mode.stderr).strip()}")
            log = run_dir / f"daemon-{mode}.log"
            proc = None
            try:
                with log.open("w", encoding="utf-8") as output:
                    proc = subprocess.Popen([str(binary), str(staged)], cwd=run_dir,
                                            stdout=output, stderr=subprocess.STDOUT)
                    wait_registered(proc, port)
                    text = log.read_text(encoding="utf-8", errors="replace")
                    if f"OCG2 {mode} runtime primed (restored; authority;" not in text:
                        raise AssertionError(f"{mode} runtime did not restore: {text}")
            finally:
                stop(proc)
        print("PASS: project and observe modes cold-restored the same private authority")

        wrong_check = run_cli(binary, run_dir, "--check-config", wrong)
        if wrong_check.returncode != 0:
            raise AssertionError(f"other valid authority config rejected before durable check: {(wrong_check.stdout + wrong_check.stderr).strip()}")
        rejected = run_cli(binary, run_dir, wrong)
        if rejected.returncode == 0 or "OCG2 strict durable activation failed" not in (rejected.stdout + rejected.stderr):
            raise AssertionError(f"changed authority did not fail closed: {(rejected.stdout + rejected.stderr).strip()}")
        print("PASS: changed authority tuple refused the existing durable image before serving")


if __name__ == "__main__":
    main()
