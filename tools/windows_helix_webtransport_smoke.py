# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise two Windows Helix swaps with the same WebTransport UDP listener.

With --active, one registered browser WebTransport stream stays connected
across both swaps. The default keeps the existing fresh-browser idle smoke.

Usage: python -B tools/windows_helix_webtransport_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import windows_helix_smoke as helix
import windows_helix_tls_smoke as helix_tls
import windows_webtransport_smoke as wt
from windows_private_account_dir import create_private_directory

_LOOPBACK_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def browser_message(root: Path, port: int, cert_hash: str, browser: Path) -> None:
    env = os.environ.copy()
    env["TMPDIR"] = str(root)
    result = subprocess.run(
        [shutil.which("node") or "node", str(wt.HARNESS), "--port", str(port),
         "--certhash", cert_hash, "--chromium", str(browser), "--timeout-ms", "30000"],
        cwd=root, env=env, capture_output=True, text=True, timeout=45, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"real browser WebTransport failed after Helix (exit {result.returncode}):\n"
            f"{(result.stdout + result.stderr)[-12000:]}"
        )


def held_control(port: int, path: str, payload: dict | None = None) -> dict | None:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body,
        headers={"content-type": "application/json"} if body is not None else {},
        method="POST" if body is not None or path == "/finish" else "GET",
    )
    with _LOOPBACK_HTTP.open(request, timeout=3) as response:
        return None if response.status == 204 else json.load(response)


def held_log_tail(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")[-12000:] if path.exists() else ""


def wait_held_status(proc: subprocess.Popen, control_port: int, phase: int,
                     log_path: Path, timeout: float = 35) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"held browser exited {proc.returncode} before phase {phase}:\n{held_log_tail(log_path)}")
        try:
            status = held_control(control_port, "/status")
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last = str(exc)
            time.sleep(0.15)
            continue
        if not isinstance(status, dict):
            raise AssertionError(f"held browser returned invalid status: {status!r}")
        if status.get("ok") is False:
            raise AssertionError(f"held browser phase {phase} failed: {status.get('detail')}\n{held_log_tail(log_path)}")
        if status.get("ok") is True and status.get("phase") == phase:
            return status
        if isinstance(status.get("phase"), int) and status["phase"] > phase:
            raise AssertionError(f"held browser skipped phase {phase}: {status}")
        time.sleep(0.15)
    raise AssertionError(f"held browser phase {phase} timed out ({last}):\n{held_log_tail(log_path)}")


def require_held_identity(status: dict, session_id: str) -> None:
    if status.get("sessionId") != session_id:
        raise AssertionError("held browser replaced its WebTransport session")
    lines = status.get("lines")
    if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines) or \
            sum(" 001 webuser " in line for line in lines) != 1:
        raise AssertionError("held browser did not retain exactly one IRC registration")
    if sum(" JOIN " in line and "#web" in line for line in lines) != 1:
        raise AssertionError("held browser rejoined or lost its original IRC stream")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--chromium", type=Path)
    parser.add_argument("--generated", action="store_true",
                        help="exercise the daemon's process-random bootstrap TLS material")
    parser.add_argument("--active", action="store_true",
                        help="hold one registered browser WebTransport stream across both upgrades")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    binary_source = args.binary.resolve()
    if not binary_source.is_file():
        parser.error(f"binary not found: {binary_source}")
    pwsh = shutil.which("pwsh")
    if not pwsh or not shutil.which("node"):
        parser.error("PowerShell 7 and Node.js are required for this browser fixture")
    browser = wt.browser_path(args.chromium)

    with wt.disposable_run_dir() as root:
        binary = root / "onyx-server.exe"
        shutil.copy2(binary_source, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        cert_hash = None if args.generated else wt.make_certificate(root, pwsh)
        with closing(wt.udp_socket()) as reserved:
            wt_port = reserved.getsockname()[1]
        ports = wt.tcp_ports(3 if args.active else 2)
        irc_port, tls_port = ports[:2]
        control_port = ports[2] if args.active else None
        password = secrets.token_urlsafe(22)
        config = root / "server.toml"
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\n"
            f"[listen]\nhost = \"127.0.0.1\"\nirc = {irc_port}\nwebtransport = {wt_port}\n"
            f"[tls]\nenabled = true\nport = {tls_port}\ndns_name = \"localhost\"\n"
            + ("" if args.generated else
               "cert_path = \"leaf.pem\"\nkey_path = \"keys-private/server.key\"\n")
            + "[sasl]\nenabled = true\naccount_db = \"private/accounts.wal\"\n"
            "[accounts]\npbkdf2_rounds = 10000\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disposable short-lived fixture.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        log_path = root / "daemon.log"
        with log_path.open("wb") as log:
            parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log,
                                      stderr=subprocess.STDOUT)
            clients: list[helix.Client] = []
            observer_socket: socket.socket | None = None
            held_proc: subprocess.Popen | None = None
            held_log = None
            held_log_path = root / "held-browser.log"
            try:
                wt.wait_ready(parent, irc_port, log_path)
                owner = helix_tls.connect_tls(tls_port, context, parent)
                clients.append(owner)
                if args.generated:
                    cert_hash = owner.certificate_digest().hex()
                owner.register(b"tlsowner")
                owner.command(f"REGISTER helixadmin * {password}".encode(),
                              b"REGISTER SUCCESS", timeout=45)

                oper = helix_tls.connect_tls(tls_port, context, parent)
                clients.append(oper)
                oper.command(b"CAP LS 302", b" LS ")
                oper.command(b"CAP REQ :sasl", b" ACK ")
                oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
                proof = base64.b64encode(b"\0helixadmin\0" + password.encode())
                oper.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
                start = len(oper.lines)
                oper.send(b"CAP END")
                oper.send(b"NICK admin")
                oper.send(b"USER smoke 0 * :Windows WebTransport Helix operator")
                oper.wait(b" 381 ", start=start)
                token = helix_tls.token(oper)

                observer_socket = socket.create_connection(("127.0.0.1", irc_port), timeout=5)
                observer = wt.IrcObserver(observer_socket)
                observer_socket.sendall(b"NICK wtobserver\r\nUSER smoke 0 * :WT Observer\r\n")
                observer.until(lambda line: b" 001 wtobserver " in line, 8)
                observer_socket.sendall(b"JOIN #web\r\n")
                observer.until(lambda line: b" 366 wtobserver #web " in line, 8)

                held_session_id = None
                if args.active:
                    env = os.environ.copy()
                    env["TMPDIR"] = str(root)
                    held_log = held_log_path.open("wb")
                    held_proc = subprocess.Popen(
                        [shutil.which("node") or "node", str(wt.HARNESS),
                         "--port", str(wt_port), "--certhash", cert_hash,
                         "--chromium", str(browser), "--http-port", str(control_port),
                         "--timeout-ms", "240000", "--held"],
                        cwd=root, env=env, stdout=held_log, stderr=subprocess.STDOUT,
                    )
                    ready = wait_held_status(held_proc, control_port, 0, held_log_path)
                    held_session_id = ready.get("sessionId")
                    if not isinstance(held_session_id, str) or not held_session_id:
                        raise AssertionError("held browser omitted session identity")
                    require_held_identity(ready, held_session_id)
                    observer.until(
                        lambda line: line.startswith(b":webuser!")
                        and b"PRIVMSG #web :wt-held-baseline" in line, 10,
                    )
                    baseline_count = sum(
                        line.startswith(b":webuser!")
                        and b"PRIVMSG #web :wt-held-baseline" in line
                        for line in observer.lines
                    )
                    if baseline_count != 1:
                        raise AssertionError(f"expected one held browser baseline delivery, got {baseline_count}")

                serving_pid = parent.pid
                held_nonces: list[bytes] = []
                for sequence in (1, 2):
                    oper.send(b"UPGRADE")
                    next_pid = helix.sole_image_pid(binary, different_from=serving_pid)
                    marker = f"wt-helix-{sequence}".encode()
                    owner.ping(marker)
                    oper.ping(marker)
                    observer_socket.sendall(b"PING :" + marker + b"\r\n")
                    observer.until(lambda line: b" PONG " in line and marker in line, 10)
                    if helix_tls.token(oper) != token:
                        raise AssertionError("held local session token changed across Helix")
                    fresh = helix_tls.connect_tls(tls_port, context, None)
                    try:
                        if fresh.certificate_digest().hex() != cert_hash:
                            raise AssertionError("WebTransport serving certificate changed across Helix")
                    finally:
                        fresh.close()
                    if args.active:
                        nonce = f"wt-held-{sequence}-{secrets.token_hex(4)}".encode()
                        probe = held_control(control_port, "/probe", {
                            "phase": sequence, "nonce": nonce.decode("ascii"),
                        })
                        if probe != {"phase": sequence, "nonce": nonce.decode("ascii")}:
                            raise AssertionError(f"held browser probe was not accepted: {probe}")
                        status = wait_held_status(held_proc, control_port, sequence,
                                                  held_log_path, timeout=25)
                        require_held_identity(status, held_session_id)
                        if status.get("nonce") != nonce.decode("ascii"):
                            raise AssertionError("held browser acknowledged a different post-upgrade probe")
                        held_nonces.append(nonce)
                        observer.until(
                            lambda line: line.startswith(b":webuser!")
                            and b"PRIVMSG #web :" + nonce in line, 10,
                        )
                    else:
                        browser_message(root, wt_port, cert_hash, browser)
                        observer.until(
                            lambda line: line.startswith(b":webuser!")
                            and b"PRIVMSG #web :hello from a browser" in line, 10,
                        )
                    delivery_cut = f"delivery-cut-{sequence}".encode()
                    observer_socket.sendall(b"PING :" + delivery_cut + b"\r\n")
                    observer.until(lambda line: b" PONG " in line and delivery_cut in line, 10)
                    if args.active:
                        for expected in held_nonces:
                            deliveries = sum(
                                line.startswith(b":webuser!") and
                                b"PRIVMSG #web :" + expected in line
                                for line in observer.lines
                            )
                            if deliveries != 1:
                                raise AssertionError(
                                    f"expected one delivery for {expected!r}, got {deliveries}"
                                )
                    else:
                        deliveries = sum(b"PRIVMSG #web :hello from a browser" in line
                                         and line.startswith(b":webuser!") for line in observer.lines)
                        if deliveries != sequence:
                            raise AssertionError(f"expected {sequence} exact browser deliveries, got {deliveries}")
                    mode = "same registered browser stream" if args.active else "fresh browser UDP"
                    print(f"PASS: Windows WebTransport Helix swap {sequence}, "
                          f"{serving_pid} -> {next_pid}; held IRC/TLS and {mode}", flush=True)
                    serving_pid = next_pid
                    if sequence == 1 and not args.active:
                        # Wait for the browser's closed QUIC connection to leave
                        # the source demux before the next strictly idle capture.
                        time.sleep(32)
                if args.active:
                    held_control(control_port, "/finish")
                    if held_proc.wait(timeout=10) != 0:
                        raise AssertionError(f"held browser exited {held_proc.returncode}:\n{held_log_tail(held_log_path)}")
                if parent.wait(timeout=2) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                return 0
            except Exception:
                log.flush()
                contents = log_path.read_text(encoding="utf-8", errors="replace")[-16000:]
                print(contents.encode("ascii", "backslashreplace").decode("ascii"))
                raise
            finally:
                if held_proc is not None and held_proc.poll() is None:
                    try:
                        held_control(control_port, "/finish")
                        held_proc.wait(timeout=5)
                    except (OSError, urllib.error.URLError, subprocess.TimeoutExpired):
                        if held_proc.poll() is None:
                            subprocess.run(["taskkill", "/PID", str(held_proc.pid), "/T", "/F"],
                                           capture_output=True, text=True, timeout=10, check=False)
                            if held_proc.poll() is None:
                                held_proc.kill()
                            held_proc.wait(timeout=10)
                if held_log is not None:
                    held_log.close()
                if observer_socket is not None:
                    observer_socket.close()
                for client in clients:
                    client.close()
                try:
                    for pid in helix.image_pids(binary):
                        os.kill(pid, 15)
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=10)
                    log.close()


if __name__ == "__main__":
    raise SystemExit(main())
