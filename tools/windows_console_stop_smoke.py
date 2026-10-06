#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prove Ctrl+C and Ctrl+Break stop every Windows shard before and after Helix.

The outer process starts a hidden console worker so this also runs from an
ordinary non-console CI shell. Ctrl+Break targets the daemon's process group;
Ctrl+C reaches the worker and daemon in their dedicated shared console.

Usage: python -B tools/windows_console_stop_smoke.py zig-out/bin/onyx-server.exe
"""

import argparse
import atexit
import ctypes
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from windows_helix_smoke import authenticate_account, image_pids, sole_image_pid
from windows_private_account_dir import create_private_directory


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(sock: socket.socket, needle: bytes, deadline: float) -> bytes:
    data = bytearray()
    while time.monotonic() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(f"IRC socket closed before {needle!r}: {data[-1000:]!r}")
        data.extend(chunk)
        if needle in data:
            return bytes(data)
    raise TimeoutError(f"IRC response missing {needle!r}: {data[-1000:]!r}")


def worker(binary: Path, helix: bool, ctrl_c: bool) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetConsoleCtrlHandler.argtypes = (ctypes.c_void_p, ctypes.c_int)
    kernel32.SetConsoleCtrlHandler.restype = ctypes.c_int
    kernel32.GenerateConsoleCtrlEvent.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    kernel32.GenerateConsoleCtrlEvent.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    # CTRL_C_EVENT is sent to the whole console. Keep this fixture worker alive
    # while the daemon handles its copy of the same event.
    worker_handler = None
    worker_event = threading.Event()
    signal_sent = False
    if ctrl_c:
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
        def on_worker_console(code: int) -> int:
            if code != 0:
                return 0
            worker_event.set()
            return 1

        worker_handler = handler_type(on_worker_console)
        if not kernel32.SetConsoleCtrlHandler(worker_handler, 1):
            raise OSError(ctypes.get_last_error(), "worker console handler install failed")
        # Keep the ctypes callback alive until process exit, including every
        # setup/cleanup exception path and asynchronous console dispatch.
        def unregister_worker_handler() -> None:
            if signal_sent:
                worker_event.wait(timeout=5)
            kernel32.SetConsoleCtrlHandler(worker_handler, 0)

        atexit.register(unregister_worker_handler)
    with tempfile.TemporaryDirectory(prefix="onyx-windows-console-stop-") as temporary:
        root = Path(temporary)
        staged_binary = root / "onyx-server.exe"
        shutil.copy2(binary, staged_binary)
        port = free_port()
        config = root / "onyx-server.local.toml"
        password = secrets.token_urlsafe(22)
        if helix:
            private = root / "private"
            create_private_directory(private)
        config.write_text(
            '[node]\nid = 1\n'
            + (f'secret_key = "{secrets.token_hex(32)}"\n' if helix else '')
            + (f'[cloak]\nsecret = "{secrets.token_urlsafe(32)}"\n' if helix else '')
            + f'[listen]\nhost = "127.0.0.1"\nirc = {port}\n'
            + '[limits]\nnum_shards = 3\n'
            + (f'[sasl]\naccount_db = "{(private / "accounts.wal").as_posix()}"\n'
               '[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_restart"]\n'
               '[[opers]]\naccount = "stopadmin"\nclass = "netadmin"\n' if helix else ''),
            encoding="ascii",
        )
        log_path = root / "daemon.log"
        with log_path.open("wb") as log:
            daemon = subprocess.Popen(
                [str(staged_binary), str(config)], cwd=root, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT,
                creationflags=0 if ctrl_c else subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        successor_handle = None
        oper = None
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except OSError:
                    if daemon.poll() is not None:
                        raise AssertionError(f"daemon exited before listening: {log_path.read_bytes()[-4000:]!r}")
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"daemon did not listen: {log_path.read_bytes()[-4000:]!r}")
                    time.sleep(0.05)
            with sock:
                sock.settimeout(2)
                sock.sendall(b"NICK stopprobe\r\nUSER smoke 0 * :console stop\r\n")
                wait_for(sock, b" 001 stopprobe ", time.monotonic() + 5)
                sock.sendall(b"PING :before-stop\r\n")
                wait_for(sock, b" PONG onyx.local :before-stop", time.monotonic() + 5)
                if helix:
                    sock.sendall(f"REGISTER stopadmin * {password}\r\n".encode("ascii"))
                    wait_for(sock, b"REGISTER SUCCESS", time.monotonic() + 10)
                    oper = authenticate_account(port, b"stopadmin", password.encode("ascii"), b"stopoper")
                    oper.wait(b" 381 ", start=0)
                    oper.send(b"UPGRADE")
                    successor_pid = sole_image_pid(staged_binary, different_from=daemon.pid)
                    if daemon.wait(timeout=10) != 0:
                        raise AssertionError("Helix predecessor did not exit cleanly")
                    oper.ping(b"after-upgrade")
                    successor_handle = kernel32.OpenProcess(0x0010_1000, 0, successor_pid)
                    if not successor_handle:
                        raise OSError(ctypes.get_last_error(), "OpenProcess successor failed")
                event = 0 if ctrl_c else 1
                group = 0 if ctrl_c else daemon.pid
                if not kernel32.GenerateConsoleCtrlEvent(event, group):
                    raise OSError(ctypes.get_last_error(), "GenerateConsoleCtrlEvent failed")
                signal_sent = True
                if successor_handle:
                    if kernel32.WaitForSingleObject(successor_handle, 15000) != 0:
                        raise AssertionError("Helix successor ignored console stop")
                    exit_code = ctypes.c_uint32()
                    if not kernel32.GetExitCodeProcess(successor_handle, ctypes.byref(exit_code)):
                        raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
                    code = exit_code.value
                else:
                    code = daemon.wait(timeout=15)
                if code != 0:
                    raise AssertionError(f"console stop exit code {code}: {log_path.read_bytes()[-4000:]!r}")
                try:
                    if sock.recv(1):
                        raise AssertionError("IRC socket remained open after cooperative stop")
                except ConnectionResetError:
                    # Windows may reset an IRC socket that still had unread data.
                    pass
            with socket.socket() as rebound:
                rebound.bind(("127.0.0.1", port))
            stage = "after Helix" if helix else "on cold start"
            signal = "Ctrl+C" if ctrl_c else "Ctrl+Break"
            print(f"PASS: {signal} {stage} cleanly stopped all three Windows reactor shards and released the IRC listener", flush=True)
        finally:
            if oper is not None:
                oper.close()
            if daemon.poll() is None:
                daemon.kill()
                daemon.wait(timeout=5)
            for pid in image_pids(staged_binary):
                handle = kernel32.OpenProcess(0x0010_1001, 0, pid)
                if handle:
                    kernel32.TerminateProcess(handle, 125)
                    kernel32.CloseHandle(handle)
            if successor_handle:
                kernel32.CloseHandle(successor_handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--helix", action="store_true", help="stop a successor after a held-client Helix swap")
    parser.add_argument("--ctrl-c", action="store_true", help="send Ctrl+C to the dedicated console")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    if sys.platform != "win32":
        parser.error("this smoke requires Windows")
    if args.worker:
        worker(binary, args.helix, args.ctrl_c)
        return 0
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    result = subprocess.run(
        [sys.executable, "-B", __file__, str(binary), "--worker"]
        + (["--helix"] if args.helix else []) + (["--ctrl-c"] if args.ctrl_c else []),
        creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup,
        capture_output=True, text=True, timeout=65,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
