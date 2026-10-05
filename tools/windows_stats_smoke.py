#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows stats, status, and channel snapshot publication.

Usage: python tools/windows_stats_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import traceback


ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"


def free_port():
    with socket.socket() as listener:
        listener.bind((HOST, 0))
        return listener.getsockname()[1]


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def connect(proc, port, deadline):
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listener opened ({proc.returncode})")
        try:
            sock = socket.create_connection((HOST, port), timeout=0.5)
            sock.settimeout(5)
            return sock
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("IRC listener did not open")


class Client:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""

    def send(self, command):
        self.sock.sendall((command + "\r\n").encode("utf-8"))

    def until(self, marker):
        end = time.monotonic() + 8
        while time.monotonic() < end:
            while b"\n" not in self.pending:
                self.sock.settimeout(max(0.1, end - time.monotonic()))
                part = self.sock.recv(4096)
                if not part:
                    raise ConnectionError(f"IRC closed before {marker!r}")
                self.pending += part
            line, self.pending = self.pending.split(b"\n", 1)
            if marker in line.decode("utf-8", "replace"):
                return
        raise TimeoutError(f"IRC did not return {marker!r}")

    def register(self, nick):
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
        self.until(" 001 ")


def await_stats(directory, expected_messages, expected_clients, deadline, since_ns=0):
    while time.monotonic() < deadline:
        paths = [
            directory / "index.json",
            directory / "windows.json",
            directory / "status.json",
            directory.parent / "web" / "stats.json",
            directory.parent / "web" / "index.html",
            directory / ".chanstats.snapshot",
        ]
        if all(path.is_file() and path.stat().st_size > 0 and path.stat().st_mtime_ns >= since_ns for path in paths):
            index = json.loads(paths[0].read_text(encoding="utf-8"))
            channel = json.loads(paths[1].read_text(encoding="utf-8"))
            status = json.loads(paths[2].read_text(encoding="utf-8"))
            web = json.loads(paths[3].read_text(encoding="utf-8"))
            if (
                any(row.get("channel") == "#windows" and row.get("messages", 0) >= expected_messages
                    for row in index.get("channels", []))
                and channel.get("totals", {}).get("messages", 0) >= expected_messages
                and status.get("activity", {}).get("messages", 0) >= expected_messages
                and status.get("users_online", 0) >= expected_clients
                and web.get("clients", 0) >= expected_clients
                and "<!DOCTYPE html>" in paths[4].read_text(encoding="utf-8")
                and paths[5].read_bytes().startswith(b"OCS2")
            ):
                return
        time.sleep(0.1)
    raise TimeoutError(f"stats/status/snapshot did not reach messages={expected_messages}, clients={expected_clients}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=ROOT / "zig-out" / "bin" / "onyx-server.exe")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this probe requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    stage = "prepare"
    proc = None
    succeeded = False
    with tempfile.TemporaryDirectory(prefix="onyx-stats-windows-") as scratch:
        run_dir = Path(scratch)
        channel_dir = run_dir / "channels"
        web_dir = run_dir / "web"
        channel_dir.mkdir()
        web_dir.mkdir()
        port = free_port()
        config = run_dir / "stats.toml"
        log = run_dir / "daemon.log"
        config.write_text(
            "\n".join([
                "[node]", "id = 1", "",
                "[listen]", f'host = "{HOST}"', f"irc = {port}", "",
                "[stats]", f"dir = {json.dumps(web_dir.as_posix())}",
                f"channel_dir = {json.dumps(channel_dir.as_posix())}",
                'interval = "1s"', "",
            ]),
            encoding="utf-8",
        )
        try:
            stage = "Windows config preflight"
            check = subprocess.run(
                [str(binary), "--check-config", str(config)],
                cwd=run_dir, capture_output=True, text=True, timeout=15, check=False,
            )
            if check.returncode != 0:
                raise RuntimeError((check.stdout + check.stderr).strip())

            stage = "first stats publication"
            with log.open("w", encoding="utf-8") as output:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=output, stderr=subprocess.STDOUT)
            with connect(proc, port, time.monotonic() + 15) as a_sock, connect(proc, port, time.monotonic() + 15) as b_sock:
                a, b = Client(a_sock), Client(b_sock)
                a.register("statowner")
                b.register("statpeer")
                a.send("JOIN #windows")
                a.until(" JOIN ")
                a.until(" 366 ")
                b.send("JOIN #windows")
                b.until(" JOIN ")
                b.until(" 366 ")
                a.until(" JOIN ")
                a.send("PRIVMSG #windows :first publication")
                b.until("PRIVMSG #windows :first publication")
                await_stats(channel_dir, 1, 2, time.monotonic() + 15)
                a.send("PRIVMSG #windows :second publication")
                b.until("PRIVMSG #windows :second publication")
                await_stats(channel_dir, 2, 2, time.monotonic() + 15)
                if proc.poll() is not None:
                    raise RuntimeError(f"daemon exited after stats publication ({proc.returncode})")
            print("PASS: native Windows stats.json, index.html, channel JSON, status.json, and snapshot updated atomically")

            stage = "cold restart snapshot recovery"
            stop(proc)
            proc = None
            restarted_ns = time.time_ns()
            with log.open("a", encoding="utf-8") as output:
                proc = subprocess.Popen([str(binary), str(config)], cwd=run_dir, stdout=output, stderr=subprocess.STDOUT)
            with connect(proc, port, time.monotonic() + 15) as sock:
                client = Client(sock)
                client.register("statreturn")
                await_stats(channel_dir, 2, 1, time.monotonic() + 15, restarted_ns)
                client.send("PING :stats-restart")
                client.until("PONG")
            print("PASS: cold restart restored channel totals and the public status feed remained live")
            succeeded = True
            return 0
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            return 1
        finally:
            stop(proc)
            if not succeeded:
                if log.exists():
                    print("--- stats daemon log ---")
                    print(log.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    raise SystemExit(main())
