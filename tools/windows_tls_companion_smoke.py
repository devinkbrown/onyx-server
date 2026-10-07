#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe native Windows ACME/OCSP preflight and live TLS worker startup.

The disposable certificate has no issuer or OCSP URL and is not due for
renewal. This checks the workers without sending any ACME or OCSP request.

Usage: python -B tools/windows_tls_companion_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from contextlib import closing
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
HOST = "127.0.0.1"


def reserve_ports(count):
    held = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(count)]
    try:
        for sock in held:
            sock.bind((HOST, 0))
        return [sock.getsockname()[1] for sock in held]
    finally:
        for sock in held:
            sock.close()


def create_fixture(run_dir):
    """Create an ECDSA leaf and PKCS#8 key with the OS .NET crypto provider."""
    power_shell = shutil.which("pwsh")
    if power_shell is None:
        raise RuntimeError("PowerShell 7 is required to create the disposable TLS fixture")
    script = r"""
$ErrorActionPreference = 'Stop'
$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
$key = [System.Security.Cryptography.ECDsa]::Create($curve)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $certificate = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(100))
    try {
        [System.IO.File]::WriteAllText('leaf.pem', $certificate.ExportCertificatePem())
        [System.IO.File]::WriteAllText('roots.pem', $certificate.ExportCertificatePem())
        [System.IO.File]::WriteAllText('keys-private/server.key', $key.ExportPkcs8PrivateKeyPem())
    } finally { $certificate.Dispose() }
} finally { $key.Dispose() }
"""
    result = subprocess.run(
        [power_shell, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=run_dir, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"TLS fixture generation failed: {(result.stdout + result.stderr).strip()}")
    if not (run_dir / "leaf.pem").is_file() or not (run_dir / "keys-private/server.key").is_file():
        raise AssertionError("TLS fixture generator returned success without writing the pair")


def config_text(irc_port, tls_port, challenge_port, *, key_path="keys-private/server.key",
                ca_path="roots.pem", acme=True, ocsp=True, tls12=False):
    lines = [
        "[node]", "id = 1", "",
        "[listen]", f'host = "{HOST}"', f"irc = {irc_port}", "",
        "[tls]", "enabled = true", f"enable_tls12 = {'true' if tls12 else 'false'}", f"port = {tls_port}",
        'dns_name = "localhost"', 'cert_path = "leaf.pem"',
        f'key_path = "{key_path}"', "",
        "[acme]", f"enabled = {'true' if acme else 'false'}",
        'domain = "localhost"', f'ca_bundle_path = "{ca_path}"',
        'check_interval = "1s"', "renew_before_days = 1",
        f"challenge_port = {challenge_port}", "",
        "[ocsp]", f"enabled = {'true' if ocsp else 'false'}",
        'check_interval = "1s"', "",
    ]
    return "\n".join(lines)


def command(binary, run_dir, *args):
    return subprocess.run([str(binary), *map(str, args)], cwd=run_dir,
                          capture_output=True, text=True, timeout=20, check=False)


def expect_config(binary, run_dir, config, accepted, label):
    result = command(binary, run_dir, "--check-config", config)
    if (result.returncode == 0) != accepted:
        raise AssertionError(
            f"{label}: expected {'accept' if accepted else 'reject'}, got exit "
            f"{result.returncode}: {(result.stdout + result.stderr).strip()}"
        )


def connect(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"daemon exited before TLS listener opened ({process.returncode})")
        try:
            connection = socket.create_connection((HOST, port), timeout=0.5)
            connection.settimeout(5)
            return connection
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("TLS listener did not open")


def await_tls_registration(secure):
    secure.sendall(b"NICK tlscompanions\r\nUSER tlscompanions 0 * :TLS Companions\r\n")
    pending = b""
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        chunk = secure.recv(4096)
        if not chunk:
            raise ConnectionError("TLS connection closed before registration")
        pending += chunk
        while b"\n" in pending:
            reply, pending = pending.split(b"\n", 1)
            if b" 001 tlscompanions " in reply:
                secure.sendall(b"PING :tlscompanions\r\n")
                while time.monotonic() < deadline:
                    while b"\n" not in pending:
                        chunk = secure.recv(4096)
                        if not chunk:
                            raise ConnectionError("TLS connection closed before PONG")
                        pending += chunk
                    response, pending = pending.split(b"\n", 1)
                    if b"PONG" in response and b"tlscompanions" in response:
                        return
                raise TimeoutError("TLS registration succeeded but PONG was absent")
    raise TimeoutError("TLS registration did not complete")


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def probe(binary):
    irc_port, tls_port, challenge_port = reserve_ports(3)
    with tempfile.TemporaryDirectory(prefix="onyx-windows-tls-companions-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "keys-private")
        (run_dir / "broad").mkdir()
        create_fixture(run_dir)
        shutil.copyfile(run_dir / "keys-private/server.key", run_dir / "broad/server.key")

        private = run_dir / "private.toml"
        broad = run_dir / "broad.toml"
        missing_ca = run_dir / "missing-ca.toml"
        ocsp_missing_ca = run_dir / "ocsp-missing-ca.toml"
        private.write_text(config_text(irc_port, tls_port, challenge_port), encoding="utf-8")
        broad.write_text(config_text(irc_port, tls_port, challenge_port,
                                     key_path="broad/server.key"), encoding="utf-8")
        missing_ca.write_text(config_text(irc_port, tls_port, challenge_port,
                                          ca_path="missing-roots.pem"), encoding="utf-8")
        ocsp_missing_ca.write_text(config_text(irc_port, tls_port, challenge_port,
                                               ca_path="missing-roots.pem", acme=False),
                                   encoding="utf-8")

        expect_config(binary, run_dir, private, True, "private ACME/OCSP preflight")
        expect_config(binary, run_dir, broad, False, "broad ACME key directory")
        expect_config(binary, run_dir, missing_ca, False, "missing ACME/OCSP trust bundle")
        expect_config(binary, run_dir, ocsp_missing_ca, False, "missing OCSP trust bundle")
        print("PASS: private ACME/OCSP preflight; broad key and missing trust rejected")

        out = run_dir / "keys-private/unissued.pem"
        failed_cli = command(binary, run_dir, "acme-issue", "--domain", "localhost",
                             "--out", out, "--key-out", run_dir / "keys-private/unissued.key",
                             "--ca-bundle", run_dir / "missing-roots.pem", "--port", challenge_port)
        if failed_cli.returncode == 0 or out.exists() or out.with_suffix(".key").exists():
            raise AssertionError("ACME CLI accepted a missing trust bundle or wrote output")
        print("PASS: Windows ACME CLI fails before issuing with a missing trust bundle")

        log = run_dir / "daemon.log"
        process = None
        try:
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen([str(binary), str(private)], cwd=run_dir,
                                           stdout=output, stderr=subprocess.STDOUT)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # Disposable self-signed leaf.
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                with closing(connect(process, tls_port)) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as secure:
                        await_tls_registration(secure)
                required = (
                    "acme renewal scheduler enabled",
                    "ocsp staple scheduler enabled",
                    "acme renewal not due for localhost",
                    "ocsp staple disabled: cert file",
                )
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    contents = log.read_text(encoding="utf-8", errors="replace")
                    if all(marker in contents for marker in required):
                        break
                    if process.poll() is not None:
                        raise AssertionError(f"daemon exited during worker checks ({process.returncode})")
                    time.sleep(0.05)
                else:
                    raise AssertionError(f"ACME/OCSP worker markers absent: {contents}")
                print("PASS: native TLS registration and ACME/OCSP scheduler lifecycle")
        except Exception:
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    probe(binary)


if __name__ == "__main__":
    main()
