#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the native Windows daemon's WebTransport IRC bridge.

Creates a seven-day ECDSA certificate, runs configuration and bind-failure
checks, then uses a real headless Chromium WebTransport client to register,
join, and send a message that a second IRC client receives. All files and
browser profile data live in a disposable temporary directory.

Usage: python -B tools/windows_webtransport_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from contextlib import closing, contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from windows_private_account_dir import create_private_directory


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"
HARNESS = ROOT / "tools" / "quic_interop_irc_browser.mjs"
HOST = "127.0.0.1"


def tcp_ports(count, host=HOST):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    held = [socket.socket(family, socket.SOCK_STREAM) for _ in range(count)]
    try:
        for sock in held:
            sock.bind((host, 0))
        return [sock.getsockname()[1] for sock in held]
    finally:
        for sock in held:
            sock.close()


def udp_socket():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", 0))
    return sock


def config_text(irc_port, tls_port, wt_port, *, tls=True, irc_host=HOST):
    lines = [
        "[node]", "id = 1", "",
        "[listen]", f'host = "{irc_host}"', f"irc = {irc_port}",
        f"webtransport = {wt_port}", "",
    ]
    if tls:
        lines += [
            "[tls]", "enabled = true", f"port = {tls_port}",
            'dns_name = "localhost"', 'cert_path = "leaf.pem"',
            'key_path = "keys-private/server.key"', "",
        ]
    return "\n".join(lines)


def make_certificate(run_dir, powershell):
    # Chrome's serverCertificateHashes path requires a short-lived ECDSA cert.
    script = r"""
$ErrorActionPreference = 'Stop'
$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
$key = [System.Security.Cryptography.ECDsa]::Create($curve)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=127.0.0.1', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
    $san.AddDnsName('localhost')
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $cert = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddHours(-1), [System.DateTimeOffset]::UtcNow.AddDays(7))
    try {
        [System.IO.File]::WriteAllText('leaf.pem', $cert.ExportCertificatePem())
        [System.IO.File]::WriteAllText('keys-private/server.key', $key.ExportPkcs8PrivateKeyPem())
    } finally { $cert.Dispose() }
} finally { $key.Dispose() }
"""
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=run_dir, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"certificate fixture failed: {(result.stdout + result.stderr).strip()}")
    pem = (run_dir / "leaf.pem").read_text(encoding="ascii")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def browser_path(requested):
    if requested:
        path = Path(requested).expanduser().resolve()
        if path.is_file():
            return path
        raise FileNotFoundError(f"Chromium browser not found: {path}")
    candidates = [
        shutil.which("chrome"), shutil.which("msedge"),
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise FileNotFoundError("Chrome or Edge is required for native WebTransport acceptance")


def check_config(binary, run_dir, path, *, accepted, label):
    result = subprocess.run(
        [str(binary), "--check-config", str(path)], cwd=run_dir,
        capture_output=True, text=True, timeout=20, check=False,
    )
    if (result.returncode == 0) != accepted:
        raise AssertionError(
            f"{label}: expected {'accept' if accepted else 'reject'}, exit {result.returncode}: "
            f"{(result.stdout + result.stderr).strip()}"
        )
    return result.stdout + result.stderr


def wait_ready(proc, irc_port, log, irc_host=HOST):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"daemon exited during WebTransport boot ({proc.returncode}): {log.read_text(errors='replace')}")
        if "WebTransport listening on UDP" in log.read_text(errors="replace"):
            try:
                conn = socket.create_connection((irc_host, irc_port), timeout=0.5)
                conn.close()
                return
            except OSError:
                pass
        time.sleep(0.05)
    raise TimeoutError(f"WebTransport/IRC listeners did not report readiness: {log.read_text(errors='replace')}")


class IrcObserver:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""
        self.lines = []

    def until(self, predicate, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                line = line.rstrip(b"\r")
                self.lines.append(line)
                if predicate(line):
                    return line
            self.sock.settimeout(max(0.1, min(1, deadline - time.monotonic())))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError(f"IRC observer disconnected: {self.lines!r}")
            self.pending += chunk
        raise TimeoutError(f"IRC observer timed out; received {self.lines!r}")


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@contextmanager
def disposable_run_dir():
    path = Path(tempfile.mkdtemp(prefix="onyx-wt-windows-"))
    try:
        yield path
    finally:
        # The browser harness kills Chromium after posting its verdict, but on
        # Windows its child processes can retain profile files for a moment.
        deadline = time.monotonic() + 10
        while path.exists():
            try:
                shutil.rmtree(path)
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--chromium", type=Path, help="Chrome/Edge executable")
    parser.add_argument("--ipv6-irc", action="store_true", help="bind the IRC bridge on ::1 while WebTransport remains dual-stack")
    parser.add_argument("--irc-host", help="bind the IRC bridge to a specific local interface address")
    parser.add_argument("--debug-trace", action="store_true", help="verify native Windows QUIC/HTTP3 diagnostic tracing")
    args = parser.parse_args()
    if args.ipv6_irc and args.irc_host:
        parser.error("choose --ipv6-irc or --irc-host")
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    powershell = shutil.which("pwsh")
    node = shutil.which("node")
    if not powershell or not node:
        parser.error("PowerShell 7 and Node.js are required for the disposable browser fixture")
    chromium = browser_path(args.chromium)
    irc_host = args.irc_host or ("::1" if args.ipv6_irc else HOST)

    with disposable_run_dir() as run_dir:
        create_private_directory(run_dir / "keys-private")
        cert_hash = make_certificate(run_dir, powershell)
        with closing(udp_socket()) as reserved:
            wt_port = reserved.getsockname()[1]
        irc_port, tls_port = tcp_ports(2, irc_host)
        valid = run_dir / "webtransport.toml"
        invalid = run_dir / "without-tls.toml"
        valid.write_text(config_text(irc_port, tls_port, wt_port, irc_host=irc_host), encoding="utf-8")
        invalid.write_text(config_text(irc_port, tls_port, wt_port, tls=False, irc_host=irc_host), encoding="utf-8")
        check_config(binary, run_dir, valid, accepted=True, label="valid WebTransport/TLS config")
        refused = check_config(binary, run_dir, invalid, accepted=False, label="WebTransport without TLS")
        if "WebTransport" not in refused or "TLS" not in refused:
            raise AssertionError(f"no-TLS preflight failed for the wrong reason: {refused.strip()}")
        print("PASS: WebTransport/TLS config accepted; missing TLS rejected by preflight")

        log = run_dir / "daemon.log"
        proc = None
        try:
            daemon_env = os.environ.copy()
            if args.debug_trace:
                daemon_env["ONYX_QUIC_DEBUG"] = "1"
            with log.open("w", encoding="utf-8") as output:
                proc = subprocess.Popen([str(binary), str(valid)], cwd=run_dir,
                                        stdout=output, stderr=subprocess.STDOUT,
                                        env=daemon_env)
                wait_ready(proc, irc_port, log, irc_host)
                with closing(socket.create_connection((irc_host, irc_port), timeout=3)) as sock:
                    observer = IrcObserver(sock)
                    sock.sendall(b"NICK wtobserver\r\nUSER wtobserver 0 * :WT Observer\r\n")
                    observer.until(lambda line: b" 001 wtobserver " in line, 8)
                    sock.sendall(b"JOIN #web\r\n")
                    observer.until(lambda line: b" 366 wtobserver #web " in line, 8)
                    env = os.environ.copy()
                    env["TMPDIR"] = str(run_dir)
                    result = subprocess.run(
                        [node, str(HARNESS), "--port", str(wt_port), "--certhash", cert_hash,
                         "--chromium", str(chromium), "--timeout-ms", "30000"],
                        cwd=run_dir, env=env, capture_output=True, text=True,
                        timeout=40, check=False,
                    )
                    if result.returncode != 0:
                        raise AssertionError(
                            f"real browser WebTransport IRC failed (exit {result.returncode}):\n"
                            f"{(result.stdout + result.stderr)[-12000:]}\n"
                            f"daemon log:\n{log.read_text(errors='replace')[-12000:]}"
                        )
                    observer.until(
                        lambda line: b"PRIVMSG #web :hello from a browser" in line
                        and line.startswith(b":webuser!"), 8,
                    )
                    if proc.poll() is not None:
                        raise AssertionError(f"daemon exited after browser session: {log.read_text(errors='replace')}")
                    if args.debug_trace:
                        expected = ("[quic-dbg]", "[quic-conn]", "[h3]")
                        deadline = time.monotonic() + 5
                        while True:
                            trace = log.read_text(encoding="utf-8", errors="replace")
                            missing = [marker for marker in expected if marker not in trace]
                            if not missing:
                                break
                            if time.monotonic() >= deadline:
                                raise AssertionError(f"Windows QUIC debug markers missing: {missing}; daemon log:\n{trace[-12000:]}")
                            time.sleep(0.1)
                        print("PASS: Windows QUIC, HTTP/3 and WebTransport diagnostic tracing enabled")
            print("PASS: Chrome/Edge WebTransport registered, joined, and delivered IRC PRIVMSG to a second client")
        finally:
            stop(proc)

        with closing(udp_socket()) as held:
            blocked_port = held.getsockname()[1]
            occupied = run_dir / "occupied.toml"
            blocked_irc, blocked_tls = tcp_ports(2)
            occupied.write_text(config_text(blocked_irc, blocked_tls, blocked_port), encoding="utf-8")
            check_config(binary, run_dir, occupied, accepted=True, label="occupied UDP port preflight")
            failed = subprocess.run([str(binary), str(occupied)], cwd=run_dir,
                                    capture_output=True, text=True, timeout=15, check=False)
            output = failed.stdout + failed.stderr
            if failed.returncode == 0 or "WebTransport bind failed" not in output:
                raise AssertionError(f"occupied UDP port did not fail closed (exit {failed.returncode}): {output[-8000:]}")
        print("PASS: occupied WebTransport UDP port caused strict daemon startup failure")


if __name__ == "__main__":
    main()
