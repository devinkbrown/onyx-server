#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Live Windows OCSP fetch and exact stapled-DER TLS handshake acceptance.

Uses a disposable .NET issuer/leaf, a Python standard-library HTTP responder,
and the project's native Zig TLS 1.2 client. No OpenSSL CLI or library is used.
"""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Event, Thread
import time

from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import (
    DEFAULT_BINARY, HOST, ROOT, config_text, connect, reserve_ports, stop,
)


FIXTURE_SCRIPT = Path(__file__).with_name("windows_ocsp_fixture.ps1")
CLIENT = ROOT / "zig-out" / "bin" / "windows-ocsp-client.exe"


def der(tag, body):
    if len(body) < 128:
        length = bytes((len(body),))
    else:
        encoded = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        length = bytes((0x80 | len(encoded),)) + encoded
    return bytes((tag,)) + length + body


def sequence(*parts):
    return der(0x30, b"".join(parts))


def tlv(data, offset=0):
    start = offset
    if offset + 2 > len(data):
        raise ValueError("truncated DER tag")
    tag = data[offset]
    offset += 1
    count = data[offset]
    offset += 1
    if count & 0x80:
        size = count & 0x7f
        if size == 0 or size > 4 or offset + size > len(data):
            raise ValueError("invalid DER length")
        count = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    end = offset + count
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], data[start:end], end


def children(body):
    result = []
    offset = 0
    while offset < len(body):
        part = tlv(body, offset)
        result.append(part)
        offset = part[3]
    return result


def cert_fields(encoded):
    tag, cert, _, end = tlv(encoded)
    if tag != 0x30 or end != len(encoded):
        raise ValueError("not a DER certificate")
    tbs = children(cert)[0]
    fields = children(tbs[1])
    has_version = fields[0][0] == 0xa0
    base = 1 if has_version else 0
    serial = fields[base][1]
    issuer = fields[base + 2][2]
    subject = fields[base + 4][2]
    spki = children(fields[base + 5][1])
    if spki[1][0] != 0x03 or spki[1][1][:1] != b"\0":
        raise ValueError("invalid subjectPublicKey BIT STRING")
    return serial, issuer, subject, spki[1][1][1:]


def ocsp_material(leaf_der, issuer_der):
    serial, leaf_issuer, _, _ = cert_fields(leaf_der)
    _, _, issuer_subject, issuer_key = cert_fields(issuer_der)
    if leaf_issuer != issuer_subject:
        raise AssertionError("disposable leaf issuer does not match issuer subject")
    sha1_algorithm = sequence(der(0x06, bytes.fromhex("2b0e03021a")), der(0x05, b""))
    cert_id = sequence(
        sha1_algorithm,
        der(0x04, hashlib.sha1(issuer_subject).digest()),
        der(0x04, hashlib.sha1(issuer_key).digest()),
        der(0x02, serial),
    )
    request = sequence(sequence(sequence(cert_id)))
    return cert_id, issuer_subject, request


def fixture_command(run_dir, action, *extra):
    power_shell = shutil.which("pwsh")
    if power_shell is None:
        raise RuntimeError("PowerShell 7 is required for disposable .NET OCSP fixtures")
    result = subprocess.run(
        [power_shell, "-NoProfile", "-NonInteractive", "-File", str(FIXTURE_SCRIPT),
         "-Action", action, "-Directory", str(run_dir), *extra],
        cwd=run_dir, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise AssertionError(f".NET OCSP fixture {action} failed: {(result.stdout + result.stderr).strip()}")


def make_response(run_dir, cert_id, issuer_subject):
    now = datetime.now(timezone.utc)
    generalized = lambda instant: der(0x18, instant.strftime("%Y%m%d%H%M%SZ").encode("ascii"))
    single = sequence(
        cert_id, der(0x80, b""), generalized(now - timedelta(minutes=1)),
        der(0xa0, generalized(now + timedelta(hours=1))),
    )
    tbs = sequence(der(0xa1, issuer_subject), generalized(now), sequence(single))
    (run_dir / "ocsp-tbs.der").write_bytes(tbs)
    fixture_command(run_dir, "sign")
    signature = (run_dir / "ocsp-signature.der").read_bytes()
    if not signature or signature[0] != 0x30:
        raise AssertionError(".NET issuer returned a non-DER ECDSA signature")
    ecdsa_sha256 = sequence(der(0x06, bytes.fromhex("2a8648ce3d040302")))
    basic = sequence(tbs, ecdsa_sha256, der(0x03, b"\0" + signature))
    response_bytes = sequence(
        der(0x06, bytes.fromhex("2b0601050507300101")), der(0x04, basic),
    )
    return sequence(der(0x0a, b"\0"), der(0xa0, response_bytes))


class OcspServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, expected_request, response):
        super().__init__(address, OcspHandler)
        self.expected_request = expected_request
        self.response = response
        self.request_seen = Event()
        self.release_response = Event()
        self.errors = []


class OcspHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if self.path != "/ocsp" or not 0 <= length <= 4096:
                raise AssertionError("unexpected OCSP endpoint or body length")
            body = self.rfile.read(length)
            if body != self.server.expected_request:
                raise AssertionError(
                    f"OCSP CertID mismatch: expected {self.server.expected_request.hex()}, got {body.hex()}")
            if self.headers.get("Content-Type") != "application/ocsp-request":
                raise AssertionError("OCSP request has the wrong content type")
            self.server.request_seen.set()
            if not self.server.release_response.wait(8):
                raise TimeoutError("negative-control response gate was not released")
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(self.server.response)))
            self.end_headers()
            self.wfile.write(self.server.response)
        except Exception as exc:
            self.server.errors.append(str(exc))
            self.send_error(400)

    def log_message(self, *_args):
        pass


def ensure_client():
    # The custom build step is cached. Resolve the pinned toolchain on Windows
    # CI hosts where zig.exe is intentionally absent from PATH.
    zig = shutil.which("zig")
    if zig is None:
        base = Path(os.environ.get("LOCALAPPDATA", "")) / "onyx-server-toolchain"
        candidates = sorted(base.glob("zig-*/zig.exe"))
        zig = str(candidates[-1]) if candidates else None
    if zig is None:
        raise RuntimeError("Zig 0.17 toolchain is required to build windows-ocsp-client")
    result = subprocess.run(
        [zig, "build", "windows-ocsp-client", "-Dwindows-self-hosted"],
        cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
    )
    if result.returncode or not CLIENT.is_file():
        raise AssertionError(f"native OCSP client build failed: {(result.stdout + result.stderr).strip()}")


def client_result(port, issuer_der, response):
    return subprocess.run(
        [str(CLIENT), str(port), issuer_der.hex(), response.hex(), str(int(time.time()))],
        capture_output=True, text=True, timeout=10, check=False,
    )


def probe(binary):
    ensure_client()
    irc_port, tls_port, challenge_port, ocsp_port = reserve_ports(4)
    with tempfile.TemporaryDirectory(prefix="onyx-windows-ocsp-live-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "keys-private")
        aia_url = f"http://{HOST}:{ocsp_port}/ocsp".encode("ascii")
        aia = sequence(sequence(
            der(0x06, bytes.fromhex("2b06010505073001")), der(0x86, aia_url),
        ))
        fixture_command(run_dir, "create", "-AiaDerBase64", base64.b64encode(aia).decode("ascii"))
        leaf_der = (run_dir / "leaf.der").read_bytes()
        issuer_der = (run_dir / "issuer.der").read_bytes()
        cert_id, issuer_subject, expected_request = ocsp_material(leaf_der, issuer_der)
        response = make_response(run_dir, cert_id, issuer_subject)

        config = run_dir / "live.toml"
        config.write_text(config_text(irc_port, tls_port, challenge_port, acme=False, tls12=True), encoding="utf-8")
        check = subprocess.run([str(binary), "--check-config", str(config)], cwd=run_dir,
                               capture_output=True, text=True, timeout=20, check=False)
        if check.returncode:
            raise AssertionError(f"OCSP fixture config rejected: {(check.stdout + check.stderr).strip()}")

        responder = OcspServer((HOST, ocsp_port), expected_request, response)
        worker = Thread(target=responder.serve_forever, daemon=True)
        worker.start()
        log = run_dir / "daemon.log"
        process = None
        try:
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen([str(binary), str(config)], cwd=run_dir,
                                           stdout=output, stderr=subprocess.STDOUT)
                with connect(process, tls_port):
                    pass
                if not responder.request_seen.wait(15):
                    raise AssertionError(f"daemon never POSTed the expected OCSP CertID: {responder.errors}")
                absent = client_result(tls_port, issuer_der, response)
                if absent.returncode == 0 or "BadCertificate" not in absent.stderr:
                    raise AssertionError(
                        "must-staple client did not reject the unstapled handshake: "
                        + absent.stdout + absent.stderr)
                responder.release_response.set()
                deadline = time.monotonic() + 20
                last = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise AssertionError(f"daemon exited during OCSP acceptance ({process.returncode})")
                    last = client_result(tls_port, issuer_der, response)
                    if last.returncode == 0 and f"OCSP_STAPLE_MATCH={len(response)}" in last.stderr:
                        break
                    time.sleep(0.2)
                else:
                    raise AssertionError(
                        "native TLS handshake never received exact OCSP DER: "
                        + (last.stdout + last.stderr if last else "no client attempt"))
                contents = log.read_text(encoding="utf-8", errors="replace")
                if "ocsp staple published" not in contents:
                    raise AssertionError("TLS handshake succeeded without a worker publication marker")
                if responder.errors:
                    raise AssertionError(f"OCSP responder rejected request: {responder.errors}")
                print(f"PASS: Windows daemon fetched signed OCSP and native TLS handshake stapled exact {len(response)}-byte DER")
        except Exception:
            if log.exists():
                print(log.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            responder.release_response.set()
            stop(process)
            responder.shutdown()
            responder.server_close()
            worker.join(timeout=5)


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
