#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep a scoped, assigned IPv6 listener and IRC clients through Windows Helix.

Usage: python -B tools/windows_helix_scoped_ipv6_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, image_pids, sole_image_pid, wait_log_contains
from windows_private_account_dir import create_private_directory


AF_INET6 = 23
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232
IF_OPER_STATUS_UP = 1
IP_DAD_STATE_PREFERRED = 4
TCP_TABLE_OWNER_PID_LISTENER = 3


class SocketAddress(ctypes.Structure):
    _fields_ = [("address", ctypes.c_void_p), ("length", ctypes.c_int32)]


class SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("flowinfo", ctypes.c_uint32),
        ("address", ctypes.c_ubyte * 16),
        ("scope_id", ctypes.c_uint32),
    ]


class Unicast(ctypes.Structure):
    pass


Unicast._fields_ = [
    ("alignment", ctypes.c_uint64),
    ("next", ctypes.POINTER(Unicast)),
    ("address", SocketAddress),
    ("prefix_origin", ctypes.c_uint32),
    ("suffix_origin", ctypes.c_uint32),
    ("dad_state", ctypes.c_uint32),
]


class Adapter(ctypes.Structure):
    pass


Adapter._fields_ = [
    ("alignment", ctypes.c_uint64),
    ("next", ctypes.POINTER(Adapter)),
    ("adapter_name", ctypes.c_char_p),
    ("first_unicast", ctypes.POINTER(Unicast)),
    ("first_anycast", ctypes.c_void_p),
    ("first_multicast", ctypes.c_void_p),
    ("first_dns", ctypes.c_void_p),
    ("dns_suffix", ctypes.c_void_p),
    ("description", ctypes.c_void_p),
    ("friendly_name", ctypes.c_wchar_p),
    ("physical_address", ctypes.c_ubyte * 8),
    ("physical_address_length", ctypes.c_uint32),
    ("flags", ctypes.c_uint32),
    ("mtu", ctypes.c_uint32),
    ("if_type", ctypes.c_uint32),
    ("oper_status", ctypes.c_uint32),
    ("ipv6_if_index", ctypes.c_uint32),
]


class Tcp6Row(ctypes.Structure):
    _fields_ = [
        ("local_address", ctypes.c_ubyte * 16),
        ("local_scope", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_address", ctypes.c_ubyte * 16),
        ("remote_scope", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("owning_pid", ctypes.c_uint32),
    ]


def ip_helper():
    helper = ctypes.WinDLL("iphlpapi", use_last_error=True)
    helper.GetAdaptersAddresses.argtypes = (
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(Adapter), ctypes.POINTER(ctypes.c_uint32),
    )
    helper.GetAdaptersAddresses.restype = ctypes.c_uint32
    helper.GetExtendedTcpTable.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
        ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32,
    )
    helper.GetExtendedTcpTable.restype = ctypes.c_uint32
    return helper


def assigned_link_local_adapters(helper) -> list[tuple[str, str, int, int]]:
    """Return address, Windows alias, interface index and type for preferred IPv6."""
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    if (ctypes.sizeof(SockaddrIn6) != 28 or
            Adapter.friendly_name.offset != 8 + 8 * pointer_size or
            Adapter.ipv6_if_index.offset != 8 + 9 * pointer_size + 28):
        raise AssertionError("Windows IP Helper adapter ABI prefix changed")

    size = ctypes.c_uint32(15 * 1024)
    for _ in range(4):
        words = (ctypes.c_uint64 * ((size.value + 7) // 8))()
        result = helper.GetAdaptersAddresses(
            AF_INET6, 0, None, ctypes.cast(words, ctypes.POINTER(Adapter)),
            ctypes.byref(size),
        )
        if result == ERROR_BUFFER_OVERFLOW:
            continue
        if result == ERROR_NO_DATA:
            return []
        if result != 0:
            raise OSError(f"GetAdaptersAddresses failed: {result}")
        found: list[tuple[str, str, int, int]] = []
        adapter = ctypes.cast(words, ctypes.POINTER(Adapter))
        while adapter:
            current = adapter.contents
            if ((current.alignment & 0xffffffff) >=
                    Adapter.ipv6_if_index.offset + ctypes.sizeof(ctypes.c_uint32) and
                    current.oper_status == IF_OPER_STATUS_UP and
                    current.ipv6_if_index != 0):
                alias = current.friendly_name
                if alias and len(alias) <= 256 and "%" not in alias:
                    unicast = current.first_unicast
                    while unicast:
                        address = unicast.contents
                        if ((address.alignment & 0xffffffff) >=
                                Unicast.dad_state.offset + ctypes.sizeof(ctypes.c_uint32) and
                                address.dad_state == IP_DAD_STATE_PREFERRED and
                                address.address.address and
                                address.address.length >= ctypes.sizeof(SockaddrIn6)):
                            raw = ctypes.cast(address.address.address,
                                              ctypes.POINTER(SockaddrIn6)).contents
                            if raw.family == AF_INET6:
                                parsed = ipaddress.IPv6Address(bytes(raw.address))
                                if parsed.is_link_local:
                                    found.append((str(parsed), alias,
                                                  current.ipv6_if_index,
                                                  current.if_type))
                        unicast = address.next
            adapter = current.next
        # Prefer a physical Wi-Fi or Ethernet adapter over virtual interfaces.
        found.sort(key=lambda row: (row[3] != 71, row[3] != 6, row[1]))
        return found
    raise OSError("GetAdaptersAddresses buffer kept growing")


def ipv6_listeners(helper) -> list[tuple[bytes, int, int, int]]:
    """Return local address, port, scope and diagnostic owning PID."""
    size = ctypes.c_uint32(16 * 1024)
    for _ in range(4):
        words = (ctypes.c_uint64 * ((size.value + 7) // 8))()
        result = helper.GetExtendedTcpTable(
            ctypes.cast(words, ctypes.c_void_p), ctypes.byref(size), 0,
            AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0,
        )
        if result == ERROR_INSUFFICIENT_BUFFER:
            continue
        if result != 0:
            raise OSError(f"GetExtendedTcpTable failed: {result}")
        count = ctypes.cast(words, ctypes.POINTER(ctypes.c_uint32)).contents.value
        if 4 + count * ctypes.sizeof(Tcp6Row) > size.value:
            raise AssertionError("truncated IPv6 TCP listener table")
        rows = ctypes.cast(ctypes.addressof(words) + 4,
                           ctypes.POINTER(Tcp6Row * count)).contents
        return [
            (bytes(row.local_address), socket.ntohs(row.local_port & 0xffff),
             row.local_scope, row.owning_pid)
            for row in rows
        ]
    raise OSError("GetExtendedTcpTable buffer kept growing")


def listener_at(helper, address: bytes, port: int, scope: int) -> tuple[bytes, int, int, int] | None:
    rows = [row for row in ipv6_listeners(helper)
            if row[:3] == (address, port, scope)]
    if len(rows) > 1:
        raise AssertionError(f"duplicate scoped listener rows: {rows!r}")
    return rows[0] if rows else None


class ScopedClient(Client):
    def __init__(self, address: str, port: int, index: int):
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            self.socket.settimeout(5)
            self.socket.connect((address, port, 0, index))
            self.socket.settimeout(0.2)
        except Exception:
            self.socket.close()
            raise
        self.buffer = b""
        self.lines: list[bytes] = []


def wait_scoped_client(parent: subprocess.Popen, address: str, port: int,
                       index: int, timeout: float = 30) -> ScopedClient:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            return ScopedClient(address, port, index)
        except OSError:
            if parent.poll() is not None:
                raise RuntimeError(f"daemon exited before scoped listener opened: {parent.returncode}")
            time.sleep(0.2)
    raise TimeoutError("scoped IPv6 listener did not accept a connection")


def assert_message(sender: ScopedClient, receiver: ScopedClient,
                   marker: bytes) -> None:
    start = len(receiver.lines)
    sender.send(b"PRIVMSG #scoped-helix :" + marker)
    receiver.wait(marker, start=start)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")

    helper = ip_helper()
    candidates = assigned_link_local_adapters(helper)
    if not candidates:
        print("SKIP: no Up adapter with a preferred assigned link-local IPv6 address", flush=True)
        return 0
    address, alias, index, _ = candidates[0]
    address_bytes = ipaddress.IPv6Address(address).packed
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
        probe.bind((address, 0, 0, index))
        port = probe.getsockname()[1]

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-scoped-ipv6-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(source, binary)
        create_private_directory(root / "private")
        password = secrets.token_urlsafe(22).encode("ascii")
        config = root / "server.toml"
        scoped_host = f"{address}%{alias}"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 1\n"
            f"[listen]\nhost = {json.dumps(scoped_host, ensure_ascii=False)}\nirc = {port}\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"scopeadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        checked = subprocess.run([str(binary), "--check-config", str(config)],
                                 cwd=root, capture_output=True, text=True,
                                 timeout=25, check=False)
        if checked.returncode != 0:
            raise AssertionError("scoped IPv6 config rejected: " + checked.stdout + checked.stderr)

        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root,
                                  stdout=log, stderr=subprocess.STDOUT)
        clients: list[ScopedClient] = []
        try:
            owner = wait_scoped_client(parent, address, port, index)
            clients.append(owner)
            owner.register(b"scopeowner")
            owner.command(b"REGISTER scopeadmin * " + password, b"REGISTER SUCCESS", timeout=45)

            oper = ScopedClient(address, port, index)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            oper.command(b"AUTHENTICATE " + base64.b64encode(b"\0scopeadmin\0" + password),
                         b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK scopeoper")
            oper.send(b"USER smoke 0 * :Scoped IPv6 Helix operator")
            oper.wait(b" 381 ", start=start)
            owner.command(b"JOIN #scoped-helix", b" 366 ")
            oper.command(b"JOIN #scoped-helix", b" 366 ")
            owner.ping(b"before-scoped-helix")
            assert_message(owner, oper, b"before-scoped-helix-message")

            before = listener_at(helper, address_bytes, port, index)
            if before is None:
                raise AssertionError(f"missing scoped listener before Helix: {scoped_host}:{port}")
            oper.send(b"UPGRADE")
            if parent.wait(timeout=35) != 0:
                raise AssertionError("Helix predecessor did not exit cleanly")
            next_pid = sole_image_pid(binary, different_from=parent.pid)
            wait_log_contains(log_path, "Windows Helix adoption committed; starting reactors")
            owner.ping(b"after-scoped-helix")
            oper.ping(b"after-scoped-helix-oper")

            fresh = ScopedClient(address, port, index)
            clients.append(fresh)
            fresh.register(b"scopefresh")
            fresh.command(b"JOIN #scoped-helix", b" 366 ")
            fresh.ping(b"fresh-scoped-helix")
            assert_message(owner, fresh, b"held-to-fresh-scoped")
            assert_message(fresh, owner, b"fresh-to-held-scoped")

            after = listener_at(helper, address_bytes, port, index)
            if after is None or after[:3] != before[:3]:
                raise AssertionError(f"scoped listener changed across Helix: {before!r} -> {after!r}")
            if image_pids(binary) != {next_pid}:
                raise AssertionError("Helix successor was not the sole live daemon")
            print(f"PASS: {scoped_host}:{port} retained address, port, scope {index}, "
                  f"held sockets and fresh client through Windows Helix "
                  f"({parent.pid} -> {next_pid})", flush=True)
            return 0
        except Exception:
            log.flush()
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-10000:]
            print("--- daemon log ---\n" + tail.replace(password.decode("ascii"), "[redacted]"), flush=True)
            for number, client in enumerate(clients):
                print(f"client {number} recent lines: {client.lines[-8:]!r}", flush=True)
            raise
        finally:
            for client in reversed(clients):
                client.close()
            try:
                for pid in image_pids(binary):
                    try:
                        os.kill(pid, 15)
                    except ProcessLookupError:
                        pass
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
