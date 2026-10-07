#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise Windows REHASH source proof and guarded Helix continuity.

The positive cases perform unchanged and live-limit REHASH, then two UPGRADE
swaps with held IRC sockets, a stable local session token, and WAL reads/writes.
Each negative case has its own cold boot so a prior invalidation cannot hide
another one. Use --negative-only to isolate the refusal cases.

The environment case switches a TOML env: reference between two variables
seeded before daemon launch. An external fixture cannot change the environment
block of an already-running Windows process, so this case also changes TOML.
The @file case changes only the resolved file bytes, leaving TOML unchanged.

Usage: python -B tools/windows_helix_rehash_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Iterator

from windows_helix_smoke import Client, authenticate_account, free_port, image_pids, sole_image_pid, wait_log_contains
from windows_private_account_dir import create_private_directory


ACCOUNT = b"rehashadmin"
ENV_A = "ONYX_REHASH_SMOKE_NETWORK_A"
ENV_B = "ONYX_REHASH_SMOKE_NETWORK_B"


class Fixture:
    def __init__(self, root: Path, binary: Path, config: Path, motd: Path,
                 log_path: Path, parent: subprocess.Popen[bytes], log,
                 port: int, password: bytes, original_config: str):
        self.root = root
        self.binary = binary
        self.config = config
        self.motd = motd
        self.log_path = log_path
        self.parent = parent
        self.log = log
        self.port = port
        self.password = password
        self.original_config = original_config
        self.clients: list[Client] = []
        self.owner: Client | None = None
        self.survivor: Client | None = None
        self.oper: Client | None = None
        self.token: bytes | None = None

    def connect(self) -> Client:
        client = Client(self.port)
        self.clients.append(client)
        return client

    def setup_clients(self) -> None:
        until = time.monotonic() + 30
        while True:
            try:
                owner = self.connect()
                break
            except OSError:
                if self.parent.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError(f"daemon did not listen; exit={self.parent.poll()}")
                time.sleep(0.2)
        self.owner = owner
        owner.register(b"rehashowner")
        owner.command(b"REGISTER " + ACCOUNT + b" * " + self.password,
                      b"REGISTER SUCCESS", timeout=45)

        self.survivor = self.connect()
        self.survivor.register(b"rehashsurvivor")
        owner.command(b"JOIN #rehash-proof", b" 366 ")
        self.survivor.command(b"JOIN #rehash-proof", b" 366 ")

        oper = authenticate_account(self.port, ACCOUNT, self.password, b"rehashop")
        self.clients.append(oper)
        self.oper = oper
        oper.wait(b" 381 ", start=0)
        oper.command(b"IRCX", b" 800 ")
        self.token = self.session_token()
        self.assert_held(b"before-rehash")

    def session_token(self) -> bytes:
        assert self.oper is not None
        line = self.oper.command(b"SESSION TOKEN", b" :SESSION TOKEN ")
        return line.split(b" :SESSION TOKEN ", 1)[1].split()[0]

    def assert_held(self, marker: bytes) -> None:
        assert self.owner is not None and self.survivor is not None and self.oper is not None
        for client in (self.owner, self.survivor, self.oper):
            client.ping(marker)
        start = len(self.survivor.lines)
        self.owner.send(b"PRIVMSG #rehash-proof :" + marker)
        self.survivor.wait(marker, start=start)
        start = len(self.owner.lines)
        self.survivor.send(b"PRIVMSG #rehash-proof :reverse-" + marker)
        self.owner.wait(b"reverse-" + marker, start=start)
        if self.session_token() != self.token:
            raise AssertionError("local reusable-session token changed")

    def rehash(self) -> None:
        assert self.oper is not None
        self.oper.command(b"REHASH", b"Configuration reloaded", timeout=30)

    def assert_wal(self, phase: str) -> None:
        account = f"rw{phase}".encode("ascii")
        password = secrets.token_urlsafe(22).encode("ascii")
        writer = Client(self.port)
        try:
            writer.register(f"writer{phase}".encode("ascii"))
            writer.command(b"REGISTER " + account + b" * " + password,
                           b"REGISTER SUCCESS", timeout=45)
        finally:
            writer.close()
        reader = authenticate_account(self.port, account, password,
                                      f"reader{phase}".encode("ascii"))
        try:
            reader.ping(f"wal-{phase}".encode("ascii"))
        finally:
            reader.close()

    def refuse_upgrade(self, label: str, *, notice: bytes | None = None) -> None:
        assert self.oper is not None
        serving_pid = self.parent.pid
        if notice is None:
            self.oper.send(b"UPGRADE")
            wait_log_contains(self.log_path, "deferred UPGRADE failed: NativeUpgradeUnavailable")
        else:
            self.oper.command(b"UPGRADE", notice)
        if image_pids(self.binary) != {serving_pid}:
            raise AssertionError(f"{label}: refused UPGRADE changed the serving process")
        marker = f"refused-{label}".encode("ascii")
        self.assert_held(marker)
        self.assert_wal(label)
        print(f"PASS: {label} REHASH refused UPGRADE; predecessor sockets, token, and WAL stayed live", flush=True)

    def print_failure(self) -> None:
        self.log.flush()
        if self.log_path.exists():
            tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-10000:]
            print("--- daemon log ---\n" + tail.replace(self.password.decode("ascii"), "[redacted]"), flush=True)
        for index, client in enumerate(self.clients):
            print(f"client {index} recent lines: {client.lines[-8:]!r}", flush=True)

    def close(self) -> None:
        for client in reversed(self.clients):
            client.close()
        try:
            for pid in image_pids(self.binary):
                os.kill(pid, 15)
        finally:
            if self.parent.poll() is None:
                self.parent.kill()
            self.parent.wait(timeout=10)
            until = time.monotonic() + 20
            while image_pids(self.binary) and time.monotonic() < until:
                time.sleep(0.1)
            self.log.close()


@contextmanager
def fixture(source: Path, label: str) -> Iterator[Fixture]:
    with tempfile.TemporaryDirectory(prefix=f"onyx-windows-rehash-{label}-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(source, binary)
        create_private_directory(root / "private")
        motd = root / "motd.txt"
        motd.write_text("Original Windows Helix MOTD\n", encoding="utf-8")
        port = free_port()
        password = secrets.token_urlsafe(22).encode("ascii")
        config = root / "server.toml"
        original_config = (
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            f"[network]\nname = \"env:{ENV_A}\"\n"
            "[motd]\ntext = \"@file:motd.txt\"\n"
            "[limits]\nnum_shards = 1\nmax_clones_per_ip = 8\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\n"
            "privileges = [\"server_restart\", \"server_rehash\"]\n"
            "[[opers]]\naccount = \"rehashadmin\"\nclass = \"netadmin\"\n"
        )
        config.write_text(original_config, encoding="utf-8")
        env = os.environ.copy()
        env[ENV_A] = "OnyxRehashA"
        env[ENV_B] = "OnyxRehashB"
        checked = subprocess.run([str(binary), "--check-config", str(config)], cwd=root,
                                 env=env, capture_output=True, text=True, timeout=25, check=False)
        if checked.returncode != 0:
            raise AssertionError("REHASH fixture config rejected: " + checked.stdout + checked.stderr)
        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, env=env,
                                  stdout=log, stderr=subprocess.STDOUT)
        run = Fixture(root, binary, config, motd, log_path, parent, log,
                      port, password, original_config)
        try:
            run.setup_clients()
            yield run
        except Exception:
            run.print_failure()
            raise
        finally:
            run.close()


def positive(source: Path) -> None:
    with fixture(source, "identical") as run:
        run.rehash()
        run.assert_held(b"after-identical-rehash")
        serving_pid = run.parent.pid
        assert run.oper is not None
        for sequence in (1, 2):
            run.oper.send(b"UPGRADE")
            next_pid = sole_image_pid(run.binary, different_from=serving_pid)
            run.assert_held(f"after-swap-{sequence}".encode("ascii"))
            run.assert_wal(f"swap{sequence}")
            if sequence == 1 and run.parent.wait(timeout=10) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            print(f"PASS: unchanged REHASH Helix swap {sequence}, {serving_pid} -> {next_pid}; held sockets, token, and WAL survived", flush=True)
            serving_pid = next_pid

    with fixture(source, "live-limit") as run:
        changed = run.original_config.replace("max_clones_per_ip = 8", "max_clones_per_ip = 9", 1)
        if changed == run.original_config:
            raise AssertionError("live-limit fixture did not change the limit")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        assert run.oper is not None
        policy = run.oper.command(b"CLONES", b"CLONES policy: max_per_ip=9")
        if b"max_per_ip=9" not in policy:
            raise AssertionError("REHASH did not install the new clone limit")
        run.assert_held(b"after-live-limit-rehash")
        serving_pid = run.parent.pid
        for sequence in (1, 2):
            run.oper.send(b"UPGRADE")
            next_pid = sole_image_pid(run.binary, different_from=serving_pid)
            run.assert_held(f"after-live-limit-swap-{sequence}".encode("ascii"))
            run.assert_wal(f"live{sequence}")
            policy = run.oper.command(b"CLONES", b"CLONES policy: max_per_ip=9")
            if b"max_per_ip=9" not in policy:
                raise AssertionError("successor lost the live clone limit")
            if sequence == 1 and run.parent.wait(timeout=10) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            print(f"PASS: live-limit REHASH Helix swap {sequence}, {serving_pid} -> {next_pid}; held sockets, token, limit, and WAL survived", flush=True)
            serving_pid = next_pid


def negatives(source: Path) -> None:
    with fixture(source, "mixed-static") as run:
        changed = run.original_config.replace("max_clones_per_ip = 8", "max_clones_per_ip = 9", 1)
        changed = changed.replace("num_shards = 1", "num_shards = 2", 1)
        if changed == run.original_config:
            raise AssertionError("mixed static negative did not change the config")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("live-limit-plus-static-shards")

    with fixture(source, "listener") as run:
        changed = run.original_config.replace(f"irc = {run.port}", f"irc = {free_port()}", 1)
        if changed == run.original_config:
            raise AssertionError("listener negative did not change the port")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("changed-listener", notice=b"cold restart required")

    with fixture(source, "lower-cap") as run:
        changed = run.original_config.replace("max_clones_per_ip = 8", "max_clones_per_ip = 4", 1)
        if changed == run.original_config:
            raise AssertionError("lower-cap negative did not change the limit")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("lowered-live-cap")

    with fixture(source, "network-cap") as run:
        changed = run.original_config.replace(
            "max_clones_per_ip = 8", "max_clones_per_ip = 8\nmax_clones_per_ip_net = 3", 1,
        )
        if changed == run.original_config:
            raise AssertionError("network-cap negative did not change the limit")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("enabled-network-cap")

    with fixture(source, "env") as run:
        changed = run.original_config.replace(f"env:{ENV_A}", f"env:{ENV_B}", 1)
        if changed == run.original_config:
            raise AssertionError("env-reference negative did not change the source")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("changed-env-reference")

    with fixture(source, "file") as run:
        run.motd.write_text("Changed Windows Helix MOTD\n", encoding="utf-8")
        if run.config.read_text(encoding="utf-8") != run.original_config:
            raise AssertionError("@file negative unexpectedly changed TOML")
        run.rehash()
        run.refuse_upgrade("changed-file-value")

    with fixture(source, "restored") as run:
        changed = run.original_config.replace("num_shards = 1", "num_shards = 2", 1)
        if changed == run.original_config:
            raise AssertionError("restored-source negative did not change shards")
        run.config.write_text(changed, encoding="utf-8")
        run.rehash()
        run.config.write_text(run.original_config, encoding="utf-8")
        run.rehash()
        run.refuse_upgrade("changed-then-restored")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--negative-only", action="store_true",
                       help="run only restart-only and unresolved-source refusal cases")
    scope.add_argument("--positive-only", action="store_true",
                       help="run unchanged and changed live-limit two-swap cases")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")
    if not args.positive_only:
        negatives(source)
    if not args.negative_only:
        positive(source)
    if args.negative_only:
        print("ALL WINDOWS REHASH HELIX REFUSAL CHECKS PASSED", flush=True)
    elif args.positive_only:
        print("WINDOWS REHASH HELIX TWO-SWAP CHECKS PASSED", flush=True)
    else:
        print("ALL WINDOWS REHASH HELIX CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
