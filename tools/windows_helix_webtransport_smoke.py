# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise two Windows Helix swaps with the same WebTransport UDP listener.

Usage: python -B tools/windows_helix_webtransport_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import windows_helix_smoke as helix
import windows_helix_tls_smoke as helix_tls
import windows_webtransport_smoke as wt
from windows_private_account_dir import create_private_directory


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--chromium", type=Path)
    parser.add_argument("--generated", action="store_true",
                        help="exercise the daemon's process-random bootstrap TLS material")
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

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-wt-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(binary_source, binary)
        create_private_directory(root / "private")
        create_private_directory(root / "keys-private")
        cert_hash = None if args.generated else wt.make_certificate(root, pwsh)
        with closing(wt.udp_socket()) as reserved:
            wt_port = reserved.getsockname()[1]
        irc_port, tls_port = wt.tcp_ports(2)
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

                serving_pid = parent.pid
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
                    browser_message(root, wt_port, cert_hash, browser)
                    observer.until(
                        lambda line: line.startswith(b":webuser!")
                        and b"PRIVMSG #web :hello from a browser" in line, 10,
                    )
                    observer_socket.sendall(b"PING :delivery-cut\r\n")
                    observer.until(lambda line: b" PONG " in line and b"delivery-cut" in line, 10)
                    deliveries = sum(b"PRIVMSG #web :hello from a browser" in line
                                     and line.startswith(b":webuser!") for line in observer.lines)
                    if deliveries != sequence:
                        raise AssertionError(f"expected {sequence} exact browser deliveries, got {deliveries}")
                    print(f"PASS: Windows WebTransport Helix swap {sequence}, "
                          f"{serving_pid} -> {next_pid}; held IRC/TLS and fresh browser UDP", flush=True)
                    serving_pid = next_pid
                    if sequence == 1:
                        # Wait for the browser's closed QUIC connection to leave
                        # the source demux before the next strictly idle capture.
                        time.sleep(32)
                if parent.wait(timeout=2) != 0:
                    raise AssertionError("original predecessor did not exit cleanly")
                return 0
            except Exception:
                log.flush()
                contents = log_path.read_text(encoding="utf-8", errors="replace")[-16000:]
                print(contents.encode("ascii", "backslashreplace").decode("ascii"))
                raise
            finally:
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
