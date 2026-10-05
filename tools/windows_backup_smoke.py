#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe private Windows backup publication and restore through the native daemon.

Usage: python -B tools/windows_backup_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

from windows_private_account_dir import create_private_directory


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HOST = "127.0.0.1"
DEADLINE = time.monotonic() + 120.0


def remaining(maximum):
    left = DEADLINE - time.monotonic()
    if left <= 0 or maximum <= 0:
        raise TimeoutError("Windows backup smoke exceeded its 120-second deadline")
    return min(maximum, left)


def reserve_ports(count):
    with ExitStack() as stack:
        ports = []
        for _ in range(count):
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.bind((HOST, 0))
            ports.append(sock.getsockname()[1])
        return ports


def write_config(path, irc_port, tls_port, account_db, backup_dir=None, chanstats_dir=None):
    lines = [
        "[node]", "id = 1", "",
        "[listen]", f'host = "{HOST}"', f"irc = {irc_port}", "",
        "[tls]", "enabled = true", f"port = {tls_port}", 'dns_name = "localhost"', "",
        "[sasl]", "enabled = true", f'account_db = "{account_db}"', "",
        "[accounts]", "pbkdf2_rounds = 10000", "",
    ]
    if backup_dir is not None:
        lines += ["[limits]", 'sweep_interval = "100ms"', ""]
        lines += ["[backup]", f'dir = "{backup_dir}"', 'interval = "200ms"', ""]
    if chanstats_dir is not None:
        lines += ["[stats]", f'channel_dir = "{chanstats_dir}"', 'interval = "200ms"', ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def run_cli(binary, run_dir, *args):
    return subprocess.run(
        [str(binary), *map(str, args)], cwd=run_dir,
        capture_output=True, text=True, timeout=remaining(20), check=False,
    )


def wait_listener(proc, port):
    end = time.monotonic() + remaining(15)
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before TLS listener opened ({proc.returncode})")
        try:
            sock = socket.create_connection((HOST, port), timeout=remaining(0.5))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            try:
                return context.wrap_socket(sock, server_hostname="localhost")
            except Exception:
                sock.close()
                raise
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(remaining(0.05))
    raise TimeoutError(f"TLS listener did not open on {HOST}:{port}")


class Irc:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""

    def send(self, line):
        self.sock.settimeout(remaining(5))
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def line(self, timeout=8):
        end = time.monotonic() + remaining(timeout)
        while b"\n" not in self.pending:
            self.sock.settimeout(remaining(end - time.monotonic()))
            part = self.sock.recv(4096)
            if not part:
                raise ConnectionError(f"IRC socket closed with pending {self.pending!r}")
            self.pending += part
        line, self.pending = self.pending.split(b"\n", 1)
        return line.rstrip(b"\r").decode("utf-8", "replace")

    def until(self, marker, timeout=8):
        end = time.monotonic() + remaining(timeout)
        seen = []
        while time.monotonic() < end:
            line = self.line(end - time.monotonic())
            seen.append(line)
            if marker in line:
                return line
        raise TimeoutError(f"expected {marker!r}; got {seen!r}")


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def wait_manifest(proc, backup_dir, previous=None, required_snapshot_bytes=None):
    latest = backup_dir / "latest.json"
    end = time.monotonic() + remaining(25)
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before backup publication ({proc.returncode})")
        try:
            raw = latest.read_bytes()
            if raw and raw != previous:
                manifest = json.loads(raw)
                account_files = [item["name"] for item in manifest["files"] if item["kind"] == "accounts"]
                if len(account_files) == 1:
                    snapshot = backup_dir / account_files[0]
                    if snapshot.is_file() and snapshot.stat().st_size > 0:
                        if required_snapshot_bytes is None or required_snapshot_bytes in snapshot.read_bytes():
                            return raw
        except (OSError, json.JSONDecodeError, KeyError):
            pass
        time.sleep(remaining(0.1))
    raise TimeoutError("backup manifest and account snapshot were not published")


def one_artifact(manifest, kind):
    found = [item["name"] for item in manifest["files"] if item["kind"] == kind]
    if len(found) != 1 or Path(found[0]).name != found[0]:
        raise AssertionError(f"manifest needs one safe {kind} artifact: {found!r}")
    return found[0]


def wait_same_second_distinct_artifacts(proc, backup_dir):
    seen = {}
    checked = set()
    end = time.monotonic() + remaining(10)
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before same-second backups ({proc.returncode})")
        for path in backup_dir.glob("accounts-*.db.snap"):
            match = re.fullmatch(r"accounts-(\d+)-[0-9a-f]{32}\.db\.snap", path.name)
            if match is None or path.name in checked:
                continue
            try:
                content = path.read_bytes()
            except OSError:
                continue
            if not content:
                raise AssertionError("account artifact is empty")
            checked.add(path.name)
            same_second = seen.setdefault(match.group(1), {})
            same_second[path.name] = content
            if len(same_second) > 1:
                for old_name, old_content in same_second.items():
                    if (backup_dir / old_name).read_bytes() != old_content:
                        raise AssertionError(f"published artifact was overwritten: {old_name}")
                return tuple(same_second)
        time.sleep(remaining(0.1))
    raise TimeoutError("two same-second distinct intact account artifacts were not observed")


def register_account(proc, tls_port):
    with wait_listener(proc, tls_port) as sock:
        client = Irc(sock)
        client.send("NICK backupowner")
        client.send("USER backupowner 0 * :backupowner")
        client.until(" 001 ")
        client.send("REGISTER backupacct * backup-password")
        client.until("REGISTER SUCCESS backupacct")
        client.send("QUIT :backup smoke")


def authenticate_restored(proc, tls_port):
    with wait_listener(proc, tls_port) as sock:
        client = Irc(sock)
        client.send("CAP LS 302")
        client.send("NICK backuprestored")
        client.send("USER backuprestored 0 * :backuprestored")
        offered = []
        while True:
            line = client.until(" CAP ")
            offered.append(line)
            if " LS * :" not in line:
                break
        if "sasl=" not in " ".join(offered):
            raise AssertionError(f"restored daemon did not advertise SASL: {offered!r}")
        client.send("CAP REQ :sasl")
        client.until(" ACK ")
        client.send("AUTHENTICATE PLAIN")
        client.until("AUTHENTICATE +")
        payload = base64.b64encode(b"backupacct\x00backupacct\x00backup-password").decode("ascii")
        client.send(f"AUTHENTICATE {payload}")
        client.until(" 903 ")
        client.send("CAP END")
        client.until(" 001 backuprestored ")
        client.send("WHOIS backuprestored")
        if " backupacct " not in client.until(" 330 "):
            raise AssertionError("restored account identity was not visible through WHOIS")
        client.send("QUIT :backup smoke")


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
    with tempfile.TemporaryDirectory(prefix="onyx-backup-windows-") as scratch:
        run_dir = Path(scratch)
        backup_dir = run_dir / "backup-private"
        account_dir = run_dir / "accounts-private"
        restore_dir = run_dir / "restore-private"
        chanstats_dir = run_dir / "stats"
        broad_dir = run_dir / "broad"
        for path in (backup_dir, account_dir, restore_dir):
            create_private_directory(path)
        broad_dir.mkdir()
        chanstats_dir.mkdir()
        account_db = "accounts-private/accounts.wal"
        config = run_dir / "backup.toml"
        broad_config = run_dir / "broad-backup.toml"
        restored_config = run_dir / "restored.toml"
        log = run_dir / "daemon.log"
        irc_port, tls_port, restored_irc_port, restored_tls_port = reserve_ports(4)
        write_config(config, irc_port, tls_port, account_db, "backup-private", "stats")
        write_config(broad_config, irc_port, tls_port, account_db, "broad")
        write_config(restored_config, restored_irc_port, restored_tls_port, "restore-private/restored.wal")

        try:
            stage = "private backup preflight"
            checked = run_cli(binary, run_dir, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError(f"private backup config rejected: {(checked.stdout + checked.stderr).strip()}")
            broad = run_cli(binary, run_dir, "--check-config", broad_config)
            if broad.returncode == 0:
                raise AssertionError("broad backup directory passed config preflight")
            print("PASS: private backup directory accepted and broad directory rejected")

            stage = "initial backup publication"
            with log.open("w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
            initial = wait_manifest(proc, backup_dir)
            initial_manifest = json.loads(initial)
            initial_account_name = one_artifact(initial_manifest, "accounts")
            initial_account_bytes = (backup_dir / initial_account_name).read_bytes()
            chanstats_name = one_artifact(initial_manifest, "chanstats")
            if "chanstats" not in initial_manifest["included"] or "chanstats" in initial_manifest["excluded"]:
                raise AssertionError("chanstats was not listed as an included family")
            if not (backup_dir / chanstats_name).read_bytes():
                raise AssertionError("included chanstats artifact is empty")
            print("PASS: account and chanstats snapshots published with latest.json")

            stage = "same-second artifact preservation"
            names = wait_same_second_distinct_artifacts(proc, backup_dir)
            print(f"PASS: same-second account artifacts retained distinct intact names ({', '.join(names)})")

            stage = "register account and publish updated snapshot"
            register_account(proc, tls_port)
            latest = wait_manifest(proc, backup_dir, previous=initial, required_snapshot_bytes=b"backupacct")
            manifest = json.loads(latest)
            if manifest.get("included") is None or manifest.get("excluded") is None:
                raise AssertionError("backup manifest omitted family lists")
            if (backup_dir / initial_account_name).read_bytes() != initial_account_bytes:
                raise AssertionError("older published account artifact was overwritten after mutation")
            print("PASS: account mutation followed by a new backup set")
            stop(proc)
            proc = None

            stage = "restore privacy and CLI drill"
            rejected = run_cli(binary, run_dir, "--restore-drill", backup_dir, "--into", broad_dir)
            if rejected.returncode == 0 or (broad_dir / "restored.wal.snap").exists():
                raise AssertionError("restore drill accepted a broad scratch directory")
            restored = run_cli(binary, run_dir, "--restore-drill", backup_dir, "--into", restore_dir)
            if restored.returncode != 0:
                raise AssertionError(f"private restore drill failed: {(restored.stdout + restored.stderr).strip()}")
            if not (restore_dir / "restored.wal.snap").is_file() or not (restore_dir / "restored.wal").is_file():
                raise AssertionError("restore drill omitted protected snapshot or WAL")
            print("PASS: broad restore refused and private restore drill reopened the snapshot")

            stage = "boot restored store and authenticate"
            checked = run_cli(binary, run_dir, "--check-config", restored_config)
            if checked.returncode != 0:
                raise AssertionError(f"restored config rejected: {(checked.stdout + checked.stderr).strip()}")
            with log.open("a", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(restored_config)], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
            authenticate_restored(proc, restored_tls_port)
            if proc.poll() is not None:
                raise RuntimeError(f"restored daemon exited ({proc.returncode})")
            print("PASS: restored snapshot booted and TLS SASL authenticated the saved account")
            return 0
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            if backup_dir.is_dir():
                print("--- backup directory entries ---")
                print([item.name for item in backup_dir.iterdir()])
            if log.exists():
                print("--- Windows backup daemon log ---")
                print(log.read_text(encoding="utf-8", errors="replace"))
            return 1
        finally:
            stop(proc)


if __name__ == "__main__":
    sys.exit(main())
