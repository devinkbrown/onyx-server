#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows mail boot, private failure custody, and account preflight.

Usage: python -B tools/windows_mail_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from pathlib import Path
import os
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from windows_backup_smoke import Irc, reserve_ports, run_cli, stop, wait_listener
from windows_private_account_dir import create_private_directory


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"


def write_config(path, irc_port, tls_port, relay_port, account_db):
    path.write_text("\n".join([
        "[node]", "id = 1", "",
        "[listen]", 'host = "127.0.0.1"', f"irc = {irc_port}", "",
        "[tls]", "enabled = true", f"port = {tls_port}", 'dns_name = "localhost"', "",
        "[sasl]", "enabled = true", f'account_db = "{account_db}"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
        "[mail]", "enabled = true", 'relay_host = "127.0.0.1"',
        f"relay_port = {relay_port}", 'from = "noreply@example.test"', "",
    ]), encoding="utf-8")


def wait_private_failure(proc, wal):
    # A refused Winsock connect can consume the sender's full 15-second
    # timeout before the worker records its failure.
    end = time.monotonic() + 25
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited while mail worker ran ({proc.returncode})")
        try:
            data = wal.read_bytes()
            if (b"mailfail:1" in data and b"recipient@example.test" in data
                    and (b"ConnectFailed" in data or b"ConnectTimeout" in data)):
                return
        except OSError:
            pass
        time.sleep(0.1)
    entries = [(item.name, item.stat().st_size) for item in wal.parent.iterdir()]
    raise TimeoutError(f"mail worker did not record a private SMTP connection failure; private entries={entries!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    stage = "prepare"
    proc = None
    with tempfile.TemporaryDirectory(prefix="onyx-mail-windows-") as scratch:
        run_dir = Path(scratch)
        private = run_dir / "accounts-private"
        broad = run_dir / "accounts-broad"
        create_private_directory(private)
        broad.mkdir()
        config = run_dir / "mail.toml"
        broad_config = run_dir / "broad.toml"
        log = run_dir / "daemon.log"
        irc_port, tls_port = reserve_ports(2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_relay:
            closed_relay.bind(("127.0.0.1", 0))
            relay_port = closed_relay.getsockname()[1]
            write_config(config, irc_port, tls_port, relay_port, "accounts-private/accounts.wal")
            write_config(broad_config, irc_port, tls_port, relay_port, "accounts-broad/accounts.wal")
            try:
                stage = "mail private account preflight"
                checked = run_cli(binary, run_dir, "--check-config", config)
                if checked.returncode != 0:
                    raise AssertionError(f"private mail config rejected: {(checked.stdout + checked.stderr).strip()}")
                rejected = run_cli(binary, run_dir, "--check-config", broad_config)
                if rejected.returncode == 0:
                    raise AssertionError("broad account parent passed Windows mail preflight")
                print("PASS: private mail account parent accepted and broad parent rejected")

                stage = "mail worker startup and failure journal"
                with log.open("w", encoding="utf-8") as log_file:
                    proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
                with wait_listener(proc, tls_port) as sock:
                    client = Irc(sock)
                    client.send("NICK mailsmoke")
                    client.send("USER mailsmoke 0 * :mailsmoke")
                    client.until(" 001 ")
                    client.send("REGISTER mailacct recipient@example.test mail-password")
                    client.until("REGISTER SUCCESS mailacct")
                    notice = client.until("recipient@example.test", timeout=4)
                    if "verification code was emailed" not in notice:
                        raise AssertionError(f"mail sender did not accept verification enqueue: {notice}")
                    client.send("QUIT :mail smoke")
                wait_private_failure(proc, private / "mail-failures.wal")
                print("PASS: enabled Windows mail worker recorded a real SMTP connection failure in the private WAL")
                return 0
            except Exception as exc:
                print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
                traceback.print_exc(file=sys.stdout)
                if log.exists():
                    print("--- Windows mail daemon log ---")
                    print(log.read_text(encoding="utf-8", errors="replace"))
                return 1
            finally:
                stop(proc)


if __name__ == "__main__":
    sys.exit(main())
