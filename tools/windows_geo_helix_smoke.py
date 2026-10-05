#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise exact Windows Helix GeoIP/ASN material across rollback and two swaps.

Usage: python -B tools/windows_geo_helix_smoke.py zig-out/bin/onyx-server.exe
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

from windows_backup_smoke import run_cli
from windows_geo_smoke import HEADLINE, mmdb_fixture
from windows_helix_smoke import Client, free_port, image_pids, sole_image_pid, wait_log_contains
from windows_private_account_dir import create_private_directory


class ProxyClient(Client):
    def __init__(self, port: int, address: str):
        super().__init__(port)
        self.socket.sendall(
            f"PROXY TCP4 {address} 127.0.0.1 40123 {port}\r\n".encode("ascii")
        )


def connect_when_ready(proc: subprocess.Popen, port: int, address: str) -> ProxyClient:
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before listener opened ({proc.returncode})")
        try:
            return ProxyClient(port, address)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("GeoIP Helix listener did not open")


def assert_geoip(client: ProxyClient, nick: bytes) -> None:
    start = len(client.lines)
    client.send(b"WHOIS " + nick)
    client.wait(b" 318 ", start=start)
    replies = client.lines[start:]
    if not any(b" 338 " in line and b"198.51.100.7" in line for line in replies):
        raise AssertionError(f"PROXY client address disappeared: {replies!r}")
    if not any(b" 320 " in line and b"JP" in line and b"AS2516" in line for line in replies):
        raise AssertionError(f"pinned GeoIP country/ASN disappeared: {replies!r}")


def assert_cached_news(client: ProxyClient) -> None:
    for _ in range(15):
        start = len(client.lines)
        client.send(b"PRIVMSG #geo :!news bbc")
        notice = client.wait(b"NOTICE #geo :", start=start, timeout=4)
        if b"News - BBC World:" in notice:
            client.wait(HEADLINE.encode("utf-8"), start=start, timeout=4)
            client.wait(b"Windows cache second headline", start=start, timeout=4)
            return
        if b"Fetching BBC World headlines" not in notice:
            raise AssertionError(f"unexpected Geo news reply: {notice!r}")
        time.sleep(0.2)
    raise TimeoutError("Geo worker did not serve the retained headline")


def write_config(path: Path, port: int, account_db: Path) -> None:
    path.write_text(
        "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
        "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
        "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
        "[listen]\nhost = \"127.0.0.1\"\n"
        f"irc = {port}\nproxy_protocol = true\ntrusted_proxies = [\"127.0.0.1\"]\n"
        "[geo]\nenabled = true\ncmd_cooldown_ms = 0\nnews_cache_dir = \"news-cache\"\n"
        "[geoip]\ndatabase = \"city-東京.mmdb\"\nasn_database = \"city-東京.mmdb\"\n"
        f"[sasl]\naccount_db = \"{account_db.as_posix()}\"\n"
        "[[oper_groups]]\nname = \"netadmin\"\n"
        "privileges = [\"server_restart\", \"server_admin\"]\n"
        "[[opers]]\naccount = \"geoadmin\"\nclass = \"netadmin\"\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-geo-helix-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        private = root / "private"
        create_private_directory(private)
        cache = root / "news-cache"
        cache.mkdir()
        cache_file = cache / "src_bbc.txt"
        cache_file.write_text(
            "# disposable updater output\n" + HEADLINE + "\nWindows cache second headline\n",
            encoding="utf-8",
        )
        database = root / "city-東京.mmdb"
        original_mmdb = mmdb_fixture()
        database.write_bytes(original_mmdb)
        config = root / "server.toml"
        port = free_port()
        write_config(config, port, private / "accounts.wal")
        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[ProxyClient] = []
        try:
            owner = connect_when_ready(parent, port, "198.51.100.7")
            clients.append(owner)
            owner.register(b"geoowner")
            owner.command(b"JOIN #geo", b" 366 ")
            owner.command(b"MODE #geo +W", b"MODE #geo +W")
            assert_cached_news(owner)
            # The next image must answer from HXGE live cache, without a
            # configured updater file from which to reconstruct the headline.
            cache_file.unlink()
            password = secrets.token_urlsafe(22).encode()
            owner.command(b"REGISTER geoadmin * " + password, b"REGISTER SUCCESS", timeout=45)
            assert_geoip(owner, b"geoowner")

            oper = ProxyClient(port, "198.51.100.8")
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            proof = base64.b64encode(b"\0geoadmin\0" + password)
            oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK geoadmin")
            oper.send(b"USER smoke 0 * :GeoIP Helix operator")
            oper.wait(b" 381 ", start=start)

            serving_pid = parent.pid
            changed_mmdb = original_mmdb.replace(b"JP", b"US", 1)
            if changed_mmdb == original_mmdb:
                raise AssertionError("MMDB rollback fixture did not change")
            database.write_bytes(changed_mmdb)
            checked = run_cli(binary, root, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError("changed MMDB is invalid: " + (checked.stdout + checked.stderr))
            oper.send(b"UPGRADE")
            wait_log_contains(log_path, "deferred UPGRADE failed")
            if image_pids(binary) != {serving_pid}:
                raise AssertionError("mismatched MMDB left a successor or lost predecessor")
            owner.ping(b"after-geo-proof-rejection")
            oper.ping(b"after-geo-proof-rejection")
            assert_geoip(owner, b"geoowner")
            assert_cached_news(owner)
            print("PASS: changed valid MMDB aborted before COMMIT; predecessor kept pinned JP/AS2516 and live news cache", flush=True)

            database.write_bytes(original_mmdb)
            for sequence in (1, 2):
                oper.send(b"UPGRADE")
                next_pid = sole_image_pid(binary, different_from=serving_pid)
                owner.ping(f"geo-swap-{sequence}".encode())
                oper.ping(f"geo-swap-{sequence}".encode())
                assert_geoip(owner, b"geoowner")
                assert_cached_news(owner)
                fresh = ProxyClient(port, "198.51.100.9")
                clients.append(fresh)
                fresh.register(f"geofresh{sequence}".encode())
                fresh.ping(f"geo-fresh-{sequence}".encode())
                print(f"PASS: GeoIP/ASN and live news cache Helix swap {sequence}, {serving_pid} -> {next_pid}", flush=True)
                serving_pid = next_pid
            if parent.wait(timeout=2) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception:
            log.flush()
            print(log_path.read_text(encoding="utf-8", errors="replace")[-10000:])
            for index, client in enumerate(clients):
                print(f"client {index} recent lines: {client.lines[-8:]!r}")
            raise
        finally:
            for client in clients:
                client.close()
            try:
                for pid in image_pids(binary):
                    os.kill(pid, 15)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 20
                while image_pids(binary) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
