#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise Windows Helix UPGRADE with an absolute staged executable path.

Three separate executable paths hold a compatible image. The running A image
must launch B, then B must launch C, while held IRC clients, the local session
token, and account WAL reads/writes survive. With --stage-b-binary, B is a
different compatible build and the smoke stops after one cross-build swap.
Relative and malformed candidate paths must refuse without disturbing A.
Supply --incompatible-binary to verify an older image cannot take custody.

Usage: python -B tools/windows_helix_candidate_path_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, authenticate_account, free_port, image_pids, sole_image_pid
from windows_private_account_dir import create_private_directory


ACCOUNT = b"pathadmin"


def copy_stage(source: Path, root: Path, name: str) -> Path:
    destination = root / f"onyx-server-{name}.exe"
    shutil.copy2(source, destination)
    return destination


def connect_when_ready(parent: subprocess.Popen[bytes], port: int) -> Client:
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if parent.poll() is not None:
            raise RuntimeError(f"daemon exited before listener opened ({parent.returncode})")
        try:
            return Client(port)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("candidate-path Helix listener did not open")


def token(client: Client) -> bytes:
    line = client.command(b"SESSION TOKEN", b" :SESSION TOKEN ")
    return line.split(b" :SESSION TOKEN ", 1)[1].split()[0]


def assert_held(owner: Client, survivor: Client, oper: Client,
                expected_token: bytes, phase: str) -> None:
    marker = phase.encode("ascii")
    for client in (owner, survivor, oper):
        client.ping(marker)
    start = len(survivor.lines)
    owner.send(b"PRIVMSG #path-handoff :" + marker)
    survivor.wait(marker, start=start)
    start = len(owner.lines)
    survivor.send(b"PRIVMSG #path-handoff :reverse-" + marker)
    owner.wait(b"reverse-" + marker, start=start)
    if token(oper) != expected_token:
        raise AssertionError(f"{phase}: local reusable-session token changed")


def assert_wal(port: int, original_password: bytes, phase: str) -> None:
    original = authenticate_account(port, ACCOUNT, original_password,
                                    f"old{phase}".encode("ascii"))
    try:
        original.ping(f"old-wal-{phase}".encode("ascii"))
    finally:
        original.close()
    account = f"path{phase}".encode("ascii")
    password = secrets.token_urlsafe(22).encode("ascii")
    writer = Client(port)
    try:
        writer.register(f"writer{phase}".encode("ascii"))
        writer.command(b"REGISTER " + account + b" * " + password,
                       b"REGISTER SUCCESS", timeout=45)
    finally:
        writer.close()
    reader = authenticate_account(port, account, password,
                                  f"reader{phase}".encode("ascii"))
    try:
        reader.ping(f"wal-{phase}".encode("ascii"))
    finally:
        reader.close()


def upgrade_command(path: str) -> bytes:
    # IRC trailing-parameter syntax preserves spaces in an absolute path.
    return b"UPGRADE :" + path.encode("utf-8")


def refusal_observed(oper: Client, start: int, log_path: Path, log_offset: int,
                     timeout: float = 20) -> bool:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        for line in oper.lines[start:]:
            lowered = line.lower()
            if b"upgrade" in lowered and (b"refus" in lowered or b"invalid" in lowered):
                return True
        if log_path.exists():
            tail = log_path.read_bytes()[log_offset:].lower()
            if b"deferred upgrade failed" in tail or (b"upgrade" in tail and b"refus" in tail):
                return True
        # PING pumps the held socket and checks that it still participates.
        oper.ping(f"refusal-wait-{int((until - time.monotonic()) * 10)}".encode("ascii"))
        time.sleep(0.1)
    return False


def reject_path(oper: Client, owner: Client, survivor: Client, expected_token: bytes,
                current: Path, all_paths: list[Path], candidate: str,
                log_path: Path, port: int, original_password: bytes, label: str) -> None:
    old_pids = image_pids(current)
    if len(old_pids) != 1:
        raise AssertionError(f"{label}: expected one serving process at {current}")
    serving_pid = next(iter(old_pids))
    start = len(oper.lines)
    log_offset = log_path.stat().st_size if log_path.exists() else 0
    oper.send(upgrade_command(candidate))
    if not refusal_observed(oper, start, log_path, log_offset):
        raise AssertionError(f"{label}: no UPGRADE refusal was observed")
    for path in all_paths:
        expected = {serving_pid} if path == current else set()
        if image_pids(path) != expected:
            raise AssertionError(f"{label}: refusal left an unexpected image at {path}")
    assert_held(owner, survivor, oper, expected_token, f"after-{label}-refusal")
    assert_wal(port, original_password, label)
    print(f"PASS: {label} candidate path refused; predecessor sockets, token, and WAL stayed live", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="compatible daemon image for A, B, and C")
    parser.add_argument("--stage-b-binary", type=Path,
                        help="different compatible Onyx build for a single A-to-B swap")
    parser.add_argument("--incompatible-binary", type=Path,
                        help="optional older/incompatible onyx-server.exe for refusal check")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    source = args.binary.resolve()
    if not source.is_file():
        parser.error(f"binary not found: {source}")
    stage_b_source = args.stage_b_binary.resolve() if args.stage_b_binary else source
    if not stage_b_source.is_file():
        parser.error(f"stage B binary not found: {stage_b_source}")
    if args.stage_b_binary and hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(stage_b_source.read_bytes()).digest():
        parser.error("stage B binary must differ from the running image")
    incompatible = args.incompatible_binary.resolve() if args.incompatible_binary else None
    if incompatible is not None and not incompatible.is_file():
        parser.error(f"incompatible binary not found: {incompatible}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-candidate-path-") as temporary:
        root = Path(temporary)
        stages = [copy_stage(source, root, "stage-a"),
                  copy_stage(stage_b_source, root, "stage-b")]
        if not args.stage_b_binary:
            stages.append(copy_stage(source, root, "stage-c"))
        incompatible_stage = copy_stage(incompatible, root, "stage-incompatible") if incompatible else None
        outside_dir = root / "outside"
        outside_dir.mkdir()
        outside_stage = copy_stage(source, outside_dir, "stage-outside")
        all_paths = stages + [outside_stage] + ([incompatible_stage] if incompatible_stage else [])
        create_private_directory(root / "private")
        port = free_port()
        password = secrets.token_urlsafe(22).encode("ascii")
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {port}\n"
            "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"pathadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        checked = subprocess.run([str(stages[0]), "--check-config", str(config)], cwd=root,
                                 capture_output=True, text=True, timeout=25, check=False)
        if checked.returncode != 0:
            raise AssertionError("candidate-path config rejected: " + checked.stdout + checked.stderr)
        log_path = root / "daemon.log"
        log = log_path.open("wb")
        parent = subprocess.Popen([str(stages[0]), str(config)], cwd=root,
                                  stdout=log, stderr=subprocess.STDOUT)
        clients: list[Client] = []
        try:
            owner = connect_when_ready(parent, port)
            clients.append(owner)
            owner.register(b"pathowner")
            owner.command(b"REGISTER " + ACCOUNT + b" * " + password,
                          b"REGISTER SUCCESS", timeout=45)

            survivor = Client(port)
            clients.append(survivor)
            survivor.register(b"pathsurvivor")
            owner.command(b"JOIN #path-handoff", b" 366 ")
            survivor.command(b"JOIN #path-handoff", b" 366 ")

            oper = authenticate_account(port, ACCOUNT, password, b"pathoper")
            clients.append(oper)
            oper.wait(b" 381 ", start=0)
            oper.command(b"IRCX", b" 800 ")
            held_token = token(oper)
            assert_held(owner, survivor, oper, held_token, "before-upgrade")

            relative = "onyx-server-stage-b.exe"
            reject_path(oper, owner, survivor, held_token, stages[0], all_paths,
                        relative, log_path, port, password, "relative")
            reject_path(oper, owner, survivor, held_token, stages[0], all_paths,
                        "\\onyx-server-stage-b.exe", log_path, port, password, "current-drive-rooted")
            malformed = str(root / 'onyx-server-bad"candidate.exe')
            reject_path(oper, owner, survivor, held_token, stages[0], all_paths,
                        malformed, log_path, port, password, "malformed")
            reject_path(oper, owner, survivor, held_token, stages[0], all_paths,
                        str(outside_stage), log_path, port, password, "outside-running-directory")
            if incompatible_stage is not None:
                reject_path(oper, owner, survivor, held_token, stages[0], all_paths,
                            str(incompatible_stage), log_path, port, password, "incompatible")
            else:
                print("SKIP: no incompatible candidate binary supplied", flush=True)

            serving_path = stages[0]
            serving_pid = parent.pid
            for sequence, next_path in enumerate(stages[1:], 1):
                oper.send(upgrade_command(str(next_path)))
                next_pid = sole_image_pid(next_path, different_from=serving_pid)
                assert_held(owner, survivor, oper, held_token, f"swap-{sequence}")
                assert_wal(port, password, f"swap{sequence}")
                if image_pids(serving_path):
                    raise AssertionError(f"swap {sequence}: predecessor image remained at {serving_path}")
                for unused in all_paths:
                    if unused not in (serving_path, next_path) and image_pids(unused):
                        raise AssertionError(f"swap {sequence}: unexpected candidate image at {unused}")
                if image_pids(next_path) != {next_pid}:
                    raise AssertionError(f"swap {sequence}: selected child path/PID did not match {next_path}")
                if sequence == 1 and parent.wait(timeout=10) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                print(f"PASS: selected {next_path} ({serving_pid} -> {next_pid}); held sockets, token, and WAL survived", flush=True)
                serving_path, serving_pid = next_path, next_pid
            print("ALL WINDOWS CANDIDATE-PATH HELIX CHECKS PASSED", flush=True)
            return 0
        except Exception:
            log.flush()
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-10000:]
            print("--- daemon log ---\n" + tail.replace(password.decode("ascii"), "[redacted]"), flush=True)
            for index, client in enumerate(clients):
                print(f"client {index} recent lines: {client.lines[-8:]!r}", flush=True)
            raise
        finally:
            for client in reversed(clients):
                client.close()
            try:
                for path in all_paths:
                    for pid in image_pids(path):
                        try:
                            os.kill(pid, 15)
                        except ProcessLookupError:
                            pass
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 20
                while any(image_pids(path) for path in all_paths) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
