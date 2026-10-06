#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe live Windows mail delivery, private failure custody, and account preflight.

Build the local relay with ``zig build windows-mail-relay`` first. It uses the
project's pure Zig TLS stack and writes a disposable DER trust anchor.
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
DEFAULT_RELAY = ROOT / "zig-out" / "bin" / "windows-mail-relay.exe"


def write_config(path, irc_port, tls_port, relay_port, account_db, *, trust_store=None):
    lines = [
        "[node]", "id = 1", "",
        "[network]", 'server_name = "onyx.test"', "",
        "[listen]", 'host = "127.0.0.1"', f"irc = {irc_port}", "",
        "[tls]", "enabled = true", f"port = {tls_port}", 'dns_name = "localhost"', "",
        "[sasl]", "enabled = true", f'account_db = "{account_db}"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
        "[mail]", "enabled = true", 'relay_host = "127.0.0.1"',
        f"relay_port = {relay_port}", 'from = "noreply@example.test"',
    ]
    if trust_store:
        lines.append(f'trust_store_path = "{trust_store}"')
    path.write_text("\n".join([*lines, ""]), encoding="utf-8")


def wait_cert(relay, cert):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if cert.is_file() and cert.stat().st_size > 0:
            return
        if relay.poll() is not None:
            raise RuntimeError(f"Zig SMTP relay exited during startup ({relay.returncode})")
        time.sleep(0.05)
    raise TimeoutError("Zig SMTP relay did not write its trust anchor")


def register_mail(binary, config, run_dir, log, tls_port, account):
    with log.open("w", encoding="utf-8") as log_file:
        proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                stdout=log_file, stderr=subprocess.STDOUT)
    try:
        with wait_listener(proc, tls_port) as sock:
            client = Irc(sock)
            client.send("NICK mailsmoke")
            client.send("USER mailsmoke 0 * :mailsmoke")
            client.until(" 001 ")
            client.send(f"REGISTER {account} recipient@example.test mail-password")
            client.until(f"REGISTER SUCCESS {account}")
            notice = client.until("recipient@example.test", timeout=4)
            if "verification code was emailed" not in notice:
                raise AssertionError(f"mail sender did not accept verification enqueue: {notice}")
            client.send("QUIT :mail smoke")
        return proc
    except BaseException:
        stop(proc)
        raise


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
    parser.add_argument("--relay", type=Path, default=DEFAULT_RELAY)
    args = parser.parse_args()
    binary = args.binary.resolve()
    relay_binary = args.relay.resolve()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    if not relay_binary.is_file():
        parser.error(f"Zig relay not found: {relay_binary}; build with `zig build windows-mail-relay`")

    stage = "prepare"
    proc = None
    relay = None
    with tempfile.TemporaryDirectory(prefix="onyx-mail-windows-") as scratch:
        run_dir = Path(scratch)
        private = run_dir / "accounts-private"
        success_private = run_dir / "accounts-success-private"
        broad = run_dir / "accounts-broad"
        create_private_directory(private)
        create_private_directory(success_private)
        broad.mkdir()
        config = run_dir / "mail.toml"
        broad_config = run_dir / "broad.toml"
        log = run_dir / "daemon.log"
        relay_log = run_dir / "relay.log"
        irc_port, tls_port, success_port = reserve_ports(3)
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

                stage = "trusted STARTTLS delivery through live daemon"
                cert = run_dir / "mail-cert.der"
                with relay_log.open("w", encoding="utf-8") as relay_file:
                    relay = subprocess.Popen([str(relay_binary), str(success_port), str(cert)],
                                             cwd=run_dir, stdout=relay_file,
                                             stderr=subprocess.STDOUT)
                wait_cert(relay, cert)
                write_config(config, irc_port, tls_port, success_port,
                             "accounts-success-private/accounts.wal", trust_store="mail-cert.der")
                checked = run_cli(binary, run_dir, "--check-config", config)
                if checked.returncode != 0:
                    raise AssertionError(f"trusted mail config rejected: {(checked.stdout + checked.stderr).strip()}")
                proc = register_mail(binary, config, run_dir, log, tls_port, "deliveredacct")
                try:
                    if relay.wait(timeout=25) != 0:
                        raise AssertionError("pure Zig STARTTLS relay rejected mail")
                    relay = None
                    failure_wal = success_private / "mail-failures.wal"
                    if failure_wal.exists() and b"mailfail:" in failure_wal.read_bytes():
                        raise AssertionError("successful mail delivery wrote a failure row")
                    print("PASS: live Windows account mail reached a trusted pure Zig STARTTLS relay")
                finally:
                    stop(proc)
                    proc = None

                stage = "mail worker startup and failure journal"
                write_config(config, irc_port, tls_port, relay_port, "accounts-private/accounts.wal")
                proc = register_mail(binary, config, run_dir, log, tls_port, "mailacct")
                wait_private_failure(proc, private / "mail-failures.wal")
                print("PASS: enabled Windows mail worker recorded a real SMTP connection failure in the private WAL")
                return 0
            except Exception as exc:
                print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
                traceback.print_exc(file=sys.stdout)
                if log.exists():
                    print("--- Windows mail daemon log ---")
                    print(log.read_text(encoding="utf-8", errors="replace"))
                if relay_log.exists():
                    print("--- Windows mail Zig relay log ---")
                    print(relay_log.read_text(encoding="utf-8", errors="replace"))
                return 1
            finally:
                stop(proc)
                stop(relay)


if __name__ == "__main__":
    sys.exit(main())
