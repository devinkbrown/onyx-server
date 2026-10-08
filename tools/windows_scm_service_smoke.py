#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the real Windows SCM host on a disposable elevated machine.

Usage: python -B tools/windows_scm_service_smoke.py zig-out/bin/onyx-server.exe --allow-service-install

The exact ``onyx-server`` service must be absent. The script creates a demand
service with a copied temporary image and config, and only controls/deletes the
service handle returned by its own CreateServiceW call. ``--preflight`` checks
for an existing service without installing one.
"""

from __future__ import annotations

import argparse
from contextlib import suppress
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from windows_helix_smoke import Client, free_port, image_pids
from windows_private_account_dir import create_private_directory
from windows_scm_smoke import operator, port_rebound, wait_gone


SERVICE_NAME = "onyx-server"
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
DELETE = 0x00010000
SERVICE_WIN32_OWN_PROCESS = 0x0010
SERVICE_DEMAND_START = 3
SERVICE_ERROR_NORMAL = 1
SERVICE_CONTROL_STOP = 1
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SC_STATUS_PROCESS_INFO = 0
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0


class ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("service_type", wintypes.DWORD),
        ("state", wintypes.DWORD),
        ("controls_accepted", wintypes.DWORD),
        ("win32_exit_code", wintypes.DWORD),
        ("service_exit_code", wintypes.DWORD),
        ("checkpoint", wintypes.DWORD),
        ("wait_hint", wintypes.DWORD),
    ]


class ServiceStatusProcess(ctypes.Structure):
    _fields_ = ServiceStatus._fields_ + [
        ("pid", wintypes.DWORD),
        ("flags", wintypes.DWORD),
    ]


class Scm:
    def __init__(self, *, create: bool):
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        api.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        api.OpenSCManagerW.restype = wintypes.HANDLE
        api.OpenServiceW.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
        api.OpenServiceW.restype = wintypes.HANDLE
        api.CreateServiceW.argtypes = (
            wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
            wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR,
            wintypes.LPCWSTR, wintypes.LPCWSTR,
        )
        api.CreateServiceW.restype = wintypes.HANDLE
        api.StartServiceW.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p)
        api.StartServiceW.restype = wintypes.BOOL
        api.QueryServiceStatusEx.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        api.QueryServiceStatusEx.restype = wintypes.BOOL
        api.ControlService.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ServiceStatus))
        api.ControlService.restype = wintypes.BOOL
        api.DeleteService.argtypes = (wintypes.HANDLE,)
        api.DeleteService.restype = wintypes.BOOL
        api.CloseServiceHandle.argtypes = (wintypes.HANDLE,)
        api.CloseServiceHandle.restype = wintypes.BOOL
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        )
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        self.api = api
        self.kernel = kernel
        self.manager = api.OpenSCManagerW(
            None, None, SC_MANAGER_CONNECT | (SC_MANAGER_CREATE_SERVICE if create else 0)
        )
        if not self.manager:
            raise ctypes.WinError(ctypes.get_last_error())
        self.service = None
        self.created = False

    def absent(self) -> None:
        handle = self.api.OpenServiceW(self.manager, SERVICE_NAME, SERVICE_QUERY_STATUS)
        if handle:
            self.api.CloseServiceHandle(handle)
            raise RuntimeError(f"refusing to touch existing {SERVICE_NAME!r} service")
        error = ctypes.get_last_error()
        if error != ERROR_SERVICE_DOES_NOT_EXIST:
            raise ctypes.WinError(error)

    def create(self, binary: Path, config: Path) -> None:
        if self.service is not None:
            raise RuntimeError("service already created by this fixture")
        if not binary.is_absolute() or not config.is_absolute():
            raise ValueError("SCM image and config paths must be absolute")
        # Windows paths cannot contain quotes. Keep both operands quoted so
        # spaces in the runner's temporary directory remain one argument.
        command = f'"{binary}" --windows-service "{config}"'
        self.service = self.api.CreateServiceW(
            self.manager, SERVICE_NAME, "Onyx Server SCM acceptance smoke",
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            command, None, None, None, None, None,
        )
        if not self.service:
            raise ctypes.WinError(ctypes.get_last_error())
        self.created = True

    def start(self) -> None:
        if not self.api.StartServiceW(self.service, 0, None):
            raise ctypes.WinError(ctypes.get_last_error())

    def query(self) -> ServiceStatusProcess:
        status = ServiceStatusProcess()
        size = wintypes.DWORD()
        if not self.api.QueryServiceStatusEx(
            self.service, SC_STATUS_PROCESS_INFO, ctypes.byref(status),
            ctypes.sizeof(status), ctypes.byref(size),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return status

    def wait_state(self, wanted: int, timeout: float) -> ServiceStatusProcess:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.query()
            if status.state == wanted:
                return status
            if wanted == SERVICE_RUNNING and status.state == SERVICE_STOPPED:
                raise AssertionError(
                    f"service stopped before RUNNING (Win32 exit {status.win32_exit_code})"
                )
            time.sleep(0.25)
        status = self.query()
        raise TimeoutError(f"service did not reach state {wanted}; state={status.state}")

    def stop(self) -> None:
        if not self.created:
            return
        status = self.query()
        if status.state == SERVICE_STOPPED:
            if status.win32_exit_code:
                raise AssertionError(
                    f"SCM stopped with Win32 exit {status.win32_exit_code}, "
                    f"service exit {status.service_exit_code}"
                )
            return
        if status.state == SERVICE_START_PENDING:
            try:
                status = self.wait_state(SERVICE_RUNNING, 130)
            except AssertionError:
                if self.query().state == SERVICE_STOPPED:
                    return self.stop()
                raise
        if status.state == SERVICE_RUNNING:
            old = ServiceStatus()
            if not self.api.ControlService(self.service, SERVICE_CONTROL_STOP, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
        elif status.state != SERVICE_STOP_PENDING:
            raise AssertionError(f"cannot safely stop unexpected SCM state {status.state}")
        status = self.wait_state(SERVICE_STOPPED, 150)
        if status.win32_exit_code:
            raise AssertionError(
                f"SCM stopped with Win32 exit {status.win32_exit_code}, "
                f"service exit {status.service_exit_code}"
            )

    def terminate_verified_host(self, binary: Path) -> None:
        """Only terminate the pinned PID still reported by our created service."""
        if not self.created:
            raise RuntimeError("no fixture-created service to recover")
        status = self.query()
        if status.state == SERVICE_STOPPED:
            return
        pid = status.pid
        if not pid:
            raise RuntimeError("SCM did not expose a host PID; refusing fallback termination")
        process = self.kernel.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
            False, pid,
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            image = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(image))
            if not self.kernel.QueryFullProcessImageNameW(process, 0, image, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            actual = image.value
            if actual.startswith("\\\\?\\"):
                actual = actual[4:]
            if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(str(binary)):
                raise RuntimeError(f"SCM PID {pid} image is not the fixture image: {actual!r}")
            if not os.path.samefile(actual, binary):
                raise RuntimeError(f"SCM PID {pid} image file identity changed")
            again = self.query()
            if again.state == SERVICE_STOPPED:
                return
            if again.pid != pid:
                raise RuntimeError(f"SCM host PID changed from {pid} to {again.pid}; refusing kill")
            print(f"SCM stop stalled; terminating verified fixture host PID {pid}", flush=True)
            if not self.kernel.TerminateProcess(process, 125):
                if self.kernel.WaitForSingleObject(process, 0) != WAIT_OBJECT_0:
                    raise ctypes.WinError(ctypes.get_last_error())
            if self.kernel.WaitForSingleObject(process, 20_000) != WAIT_OBJECT_0:
                raise TimeoutError(f"verified SCM host PID {pid} did not exit")
            self.wait_state(SERVICE_STOPPED, 30)
        finally:
            self.kernel.CloseHandle(process)

    def delete_owned(self) -> None:
        if self.created:
            if not self.api.DeleteService(self.service):
                raise ctypes.WinError(ctypes.get_last_error())
            if not self.api.CloseServiceHandle(self.service):
                raise ctypes.WinError(ctypes.get_last_error())
            self.service = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                handle = self.api.OpenServiceW(self.manager, SERVICE_NAME, SERVICE_QUERY_STATUS)
                if handle:
                    self.api.CloseServiceHandle(handle)
                else:
                    error = ctypes.get_last_error()
                    if error == ERROR_SERVICE_DOES_NOT_EXIST:
                        self.created = False
                        return
                    if error != ERROR_SERVICE_MARKED_FOR_DELETE:
                        raise ctypes.WinError(error)
                time.sleep(0.25)
            raise TimeoutError(f"SCM did not remove fixture-created {SERVICE_NAME!r} service")

    def close(self) -> None:
        if self.service:
            self.api.CloseServiceHandle(self.service)
            self.service = None
        if self.manager:
            self.api.CloseServiceHandle(self.manager)
            self.manager = None


def wait_worker(binary: Path, host_pid: int, previous: int | None = None,
                timeout: float = 50) -> int:
    deadline = time.monotonic() + timeout
    last: set[int] = set()
    while time.monotonic() < deadline:
        last = image_pids(binary)
        if host_pid not in last:
            raise AssertionError(f"SCM host PID {host_pid} vanished: {last}")
        workers = last - {host_pid}
        if len(workers) == 1:
            worker = next(iter(workers))
            if worker != previous:
                return worker
        time.sleep(0.25)
    raise TimeoutError(f"worker did not replace {previous}; live image PIDs={last}")


def message(sender: Client, recipient: Client, marker: bytes) -> None:
    start = len(recipient.lines)
    sender.send(b"PRIVMSG scmpeer :" + marker)
    recipient.wait(b"PRIVMSG scmpeer :" + marker, start=start)


def exercise(scm: Scm, binary: Path, port: int, password: str,
             clients: list[Client]) -> None:
    scm.start()
    status = scm.wait_state(SERVICE_RUNNING, 130)
    host_pid = status.pid
    if not host_pid:
        raise AssertionError("RUNNING SCM service has no host PID")
    worker = wait_worker(binary, host_pid)
    held = Client(port)
    clients.append(held)
    held.register(b"scmheld")
    peer = Client(port)
    clients.append(peer)
    peer.register(b"scmpeer")
    held.ping(b"scm-before")
    peer.ping(b"scm-before")
    message(held, peer, b"scm-before-swap")
    held.command(f"REGISTER scmadmin * {password}".encode(), b"REGISTER SUCCESS", timeout=45)
    oper = operator(port, password)
    clients.append(oper)
    print(f"PASS: SCM RUNNING host {host_pid}, worker {worker}, held IRC clients", flush=True)

    oper.send(b"UPGRADE")
    next_worker = wait_worker(binary, host_pid, worker)
    status = scm.query()
    if status.state != SERVICE_RUNNING or status.pid != host_pid:
        raise AssertionError(f"SCM host changed during Helix: state={status.state}, pid={status.pid}")
    for client in clients:
        client.ping(b"scm-after-swap")
    message(held, peer, b"scm-after-swap")
    fresh = Client(port)
    clients.append(fresh)
    fresh.register(b"scmfresh")
    fresh.ping(b"scm-fresh-after-swap")
    print(f"PASS: Helix worker {worker} -> {next_worker}; SCM host and held sockets survived", flush=True)


def failure_diagnostics(scm: Scm, binary: Path, trace: Path, root: Path) -> None:
    print(f"SCM fixture directory: {root}", flush=True)
    if scm.created:
        try:
            status = scm.query()
            print(
                f"SCM state={status.state} pid={status.pid} "
                f"Win32 exit={status.win32_exit_code} checkpoint={status.checkpoint}",
                flush=True,
            )
        except Exception as exc:
            print(f"SCM status unavailable: {exc}", flush=True)
    try:
        print(f"fixture image PIDs: {sorted(image_pids(binary))}", flush=True)
    except Exception as exc:
        print(f"fixture process query unavailable: {exc}", flush=True)
    if trace.is_file():
        try:
            print(f"flight recorder tail:\n{trace.read_text(encoding='utf-8', errors='replace')[-8000:]}", flush=True)
        except OSError as exc:
            print(f"flight recorder unavailable: {exc}", flush=True)
    else:
        print("no fault flight recorder was written", flush=True)


def remove_fixture(root: Path, temporary_parent: Path) -> None:
    # Verify again at deletion time in case a path was rebound meanwhile.
    resolved = root.resolve(strict=True)
    if (resolved != root or resolved.parent != temporary_parent or
            not resolved.name.startswith("onyx-windows-real-scm-")):
        raise RuntimeError(f"refusing recursive cleanup outside fixture parent: {resolved}")
    shutil.rmtree(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, nargs="?")
    parser.add_argument("--preflight", action="store_true", help="read-only exact service absence check")
    parser.add_argument("--allow-service-install", action="store_true",
                        help="install a temporary demand-start service on this disposable elevated host")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    if args.preflight:
        if args.allow_service_install or args.binary:
            parser.error("--preflight takes no binary or installation flag")
        scm = Scm(create=False)
        try:
            scm.absent()
        finally:
            scm.close()
        print(f"PASS: exact {SERVICE_NAME!r} service is absent; no changes made")
        return 0
    if not args.allow_service_install or args.binary is None:
        parser.error("an executable and --allow-service-install are required")
    original = args.binary.resolve(strict=True)
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    # Probe exact-name absence before asking SCM for creation rights. A race
    # still fails closed at CreateServiceW and never deletes another service.
    scm = Scm(create=False)
    try:
        scm.absent()
    finally:
        scm.close()
    scm = Scm(create=True)
    try:
        scm.absent()
        temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix="onyx-windows-real-scm-", dir=temporary_parent)).resolve(strict=True)
        if root.parent != temporary_parent or not root.name.startswith("onyx-windows-real-scm-"):
            raise RuntimeError(f"unexpected fixture directory: {root}")
        binary = root / "onyx-server.exe"
        trace = root / "flight.log"
        clients: list[Client] = []
        problems: list[BaseException] = []
        try:
            shutil.copy2(original, binary)
            private = root / "private"
            create_private_directory(private)
            config = root / "server.toml"
            port = free_port()
            port_rebound(port)
            password = secrets.token_urlsafe(22)
            config.write_text(
                "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
                "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
                "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
                "[limits]\nnum_shards = 3\nsweep_interval = \"1s\"\n"
                f"[listen]\nirc = {port}\n"
                f"[sasl]\naccount_db = \"{(private / 'accounts.wal').as_posix()}\"\n"
                f"[trace]\nfile = \"{trace.as_posix()}\"\n"
                "[[oper_groups]]\nname = \"netadmin\"\n"
                "privileges = [\"server_restart\", \"server_admin\"]\n"
                "[[opers]]\naccount = \"scmadmin\"\nclass = \"netadmin\"\n",
                encoding="utf-8",
            )
            checked = subprocess.run(
                [str(binary), "--check-config", str(config)], cwd=root,
                text=True, capture_output=True, timeout=30,
            )
            if checked.returncode:
                raise AssertionError(f"temporary SCM config rejected: {checked.stdout}\n{checked.stderr}")
            scm.create(binary, config)
            exercise(scm, binary, port, password, clients)
        except BaseException as exc:
            problems.append(exc)
        finally:
            if scm.created:
                try:
                    try:
                        scm.stop()
                    except Exception as exc:
                        problems.append(exc)
                        print(f"SCM cooperative stop failed: {exc}", flush=True)
                        scm.terminate_verified_host(binary)
                    wait_gone(binary)
                    for client in clients:
                        with suppress(OSError):
                            client.close()
                    clients.clear()
                    try:
                        port_rebound(port)
                    except Exception as exc:
                        problems.append(exc)
                    scm.delete_owned()
                    print("PASS: SCM STOPPED; host and worker exited; fixture service deleted", flush=True)
                except BaseException as exc:
                    problems.append(exc)
            for client in clients:
                with suppress(OSError):
                    client.close()
            if problems:
                failure_diagnostics(scm, binary, trace, root)
            if scm.created:
                print(
                    f"INCOMPLETE CLEANUP: retained {SERVICE_NAME!r} service and fixture {root}; "
                    "service deletion requires a verified stopped host and no fixture processes",
                    flush=True,
                )
            else:
                try:
                    remove_fixture(root, temporary_parent)
                except BaseException as exc:
                    problems.append(exc)
                    print(f"fixture cleanup failed; retained {root}: {exc}", flush=True)
        if problems:
            raise BaseExceptionGroup("real SCM smoke failed", problems)
    finally:
        scm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
