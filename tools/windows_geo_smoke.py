#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows news cache, checked geo worker, and GeoIP lookup.

Usage: python -B tools/windows_geo_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from windows_backup_smoke import Irc, reserve_ports, run_cli, stop


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HEADLINE = "Windows cache headline from a regular file"


def mmdb_string(value):
    raw = value.encode("utf-8")
    if len(raw) >= 29:
        raise ValueError("test MMDB string is too long")
    return bytes([0x40 | len(raw)]) + raw


def mmdb_unsigned(value, kind):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return bytes([(kind << 5) | len(raw)]) + raw


def mmdb_fixture():
    # One 24-bit tree node routes both halves of IPv4 to data record 17:
    # node_count (1) + 16-byte separator + zero data offset.
    data = bytearray(b"\x00\x00\x11" * 2 + b"\x00" * 16)
    data += bytes([0xE2])  # two-entry map
    data += mmdb_string("country") + bytes([0xE1])
    data += mmdb_string("iso_code") + mmdb_string("JP")
    data += mmdb_string("autonomous_system_number") + mmdb_unsigned(2516, 6)
    data += b"\xab\xcd\xefMaxMind.com" + bytes([0xE3])
    data += mmdb_string("node_count") + mmdb_unsigned(1, 6)
    data += mmdb_string("record_size") + mmdb_unsigned(24, 5)
    data += mmdb_string("ip_version") + mmdb_unsigned(4, 5)
    return bytes(data)


def write_config(path, irc_port):
    path.write_text("\n".join([
        "[node]", "id = 1", "",
        "[listen]", 'host = "127.0.0.1"', f"irc = {irc_port}",
        "proxy_protocol = true", 'trusted_proxies = ["127.0.0.1"]', "",
        "[geo]", "enabled = true", "cmd_cooldown_ms = 0",
        'news_cache_dir = "news-cache"', "",
        "[geoip]", 'database = "city-東京.mmdb"',
        'asn_database = "city-東京.mmdb"', "",
    ]), encoding="utf-8")


def check_news(client):
    for attempt in range(15):
        client.send("PRIVMSG #geo :!news bbc")
        notice = client.until("NOTICE #geo :", timeout=4)
        if "News - BBC World:" in notice:
            line = client.until(HEADLINE, timeout=4)
            if "  1. " + HEADLINE not in line:
                raise AssertionError(f"unexpected cached headline: {line!r}")
            client.until("Windows cache second headline", timeout=4)
            return
        if "Fetching BBC World headlines" not in notice:
            raise AssertionError(f"unexpected geo bot response: {notice!r}")
        time.sleep(0.2)
    raise TimeoutError("checked geo worker did not serve the file cache")


def collect_until(client, marker, timeout=8):
    end = time.monotonic() + timeout
    lines = []
    while time.monotonic() < end:
        line = client.line(end - time.monotonic())
        lines.append(line)
        if marker in line:
            return lines
    raise TimeoutError(f"expected {marker!r}; got {lines!r}")


def wait_proxy_listener(proc, port):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listener opened ({proc.returncode})")
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            sock.sendall(f"PROXY TCP4 198.51.100.7 127.0.0.1 40123 {port}\r\n".encode("ascii"))
            return sock
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("Windows geo IRC listener did not open")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    proc = None
    stage = "prepare fixtures"
    with tempfile.TemporaryDirectory(prefix="onyx-geo-windows-") as scratch:
        run_dir = Path(scratch)
        cache = run_dir / "news-cache"
        cache.mkdir()
        (cache / "src_bbc.txt").write_text(
            "# disposable updater output\n" + HEADLINE + "\nWindows cache second headline\n",
            encoding="utf-8",
        )
        mmdb = run_dir / "city-東京.mmdb"
        mmdb.write_bytes(mmdb_fixture())
        config = run_dir / "geo.toml"
        log = run_dir / "daemon.log"
        irc_port = reserve_ports(1)[0]
        write_config(config, irc_port)
        try:
            stage = "geo and GeoIP preflight"
            checked = run_cli(binary, run_dir, "--check-config", config)
            if checked.returncode != 0:
                raise AssertionError((checked.stdout + checked.stderr).strip())
            print("PASS: Windows geo and Unicode MMDB preflight")
            mmdb.write_bytes(b"truncated MMDB")
            rejected = run_cli(binary, run_dir, "--check-config", config)
            if rejected.returncode == 0:
                raise AssertionError("malformed GeoIP database passed preflight")
            mmdb.write_bytes(mmdb_fixture())
            print("PASS: malformed Windows GeoIP database rejected")

            stage = "daemon GeoIP and news cache"
            with log.open("w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                        stdout=log_file, stderr=subprocess.STDOUT)
            with wait_proxy_listener(proc, irc_port) as sock:
                client = Irc(sock)
                client.send("NICK geosmoke")
                client.send("USER geosmoke 0 * :geosmoke")
                client.until(" 001 ")
                client.send("WHOIS geosmoke")
                whois = collect_until(client, " 318 ")
                if not any(" 338 " in line and "198.51.100.7" in line for line in whois):
                    raise AssertionError(f"PROXY source IP was not applied: {whois!r}")
                if not any(" 320 " in line and "JP" in line and "AS2516" in line for line in whois):
                    raise AssertionError(f"Unicode MMDB lookup missing country/ASN: {whois!r}")
                print("PASS: Windows GeoIP country and ASN visible in self WHOIS")

                client.send("JOIN #geo")
                client.until(" 366 ")
                client.send("MODE #geo +W")
                client.until("MODE #geo +W")
                check_news(client)
                client.send("QUIT :geo smoke")
            print("PASS: checked Windows geo worker served a cached !news headline")
            return 0
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            if log.exists():
                print("--- Windows geo daemon log ---")
                print(log.read_text(encoding="utf-8", errors="replace"))
            return 1
        finally:
            stop(proc)


if __name__ == "__main__":
    sys.exit(main())
