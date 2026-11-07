#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Headless-Chromium TCP TLS smoke for the daemon's wss:// listener.

Boots a private onyx-server (temp config, temp PKI, loopback ports — like
tools/upgrade_smoke.py) with `[listen] ws` (the secure-WebSocket listener that
runs the SAME Armor TLS engine as the implicit-TLS port) and drives a REAL
browser at it:

  1. an ECDSA P-256 leaf issued by a throwaway CA (Chromium has no Ed25519
     certificate support, so the daemon's bootstrap leaf cannot be used); the
     browser trusts it only through --ignore-certificate-errors-spki-list
     pinned to that leaf's SPKI hash — no blanket certificate bypass;
  2. a page served from a stdlib HTTP server opens
     `new WebSocket("wss://localhost:<ws>/", "text.ircv3.net")`, registers
     (NICK/USER), waits for RPL_WELCOME 001, round-trips PING/PONG, and POSTs
     its verdict back;
  3. Chromium's NetLog (--log-net-log) is parsed for the SSL_CONNECT result:
     the TLS version must be 1.3 and the negotiated key-exchange group must be
     X25519MLKEM768 (codepoint 0x11EC = 4588, draft-ietf-tls-ecdhe-mlkem).

Usage:
  python3 tools/browser_tls_smoke.py [path-to-onyx-server]
Env:
  CHROMIUM=/path/to/chromium   browser binary (default: chromium on PATH)
  ONYX_SMOKE_KEEP=1            keep the temp dir (netlog, daemon log)

Exit 0 = PASS, 1 = FAIL, 77 = SKIP (no chromium / openssl). Never touches an
installed service.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
X25519MLKEM768 = 0x11EC  # draft-ietf-tls-ecdhe-mlkem / IANA TLS Supported Groups
TLS13_VERSION = 0x0304
SKIP = 77


def log(msg: str) -> None:
    print(f"[browser-tls] {msg}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, **kw)


def make_pki(pki: Path, openssl: str) -> str:
    """Throwaway CA + ECDSA P-256 leaf for localhost; returns the leaf SPKI pin."""
    pki.mkdir(parents=True)
    ext = pki / "leaf.ext"
    ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
    )
    run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.pem"), "-days", "2",
         "-subj", "/CN=onyx-browser-smoke-ca",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    run([openssl, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", str(pki / "leaf.key"), "-out", str(pki / "leaf.csr"), "-subj", "/CN=localhost"])
    run([openssl, "x509", "-req", "-in", str(pki / "leaf.csr"), "-CA", str(pki / "ca.pem"),
         "-CAkey", str(pki / "ca.key"), "-CAcreateserial", "-out", str(pki / "leaf.pem"),
         "-days", "2", "-extfile", str(ext)])
    run([openssl, "pkcs8", "-topk8", "-nocrypt", "-in", str(pki / "leaf.key"),
         "-out", str(pki / "leaf.p8")])
    # base64(SHA-256(SubjectPublicKeyInfo)) — Chromium's SPKI pin format.
    spki = run([openssl, "x509", "-in", str(pki / "leaf.pem"), "-noout", "-pubkey"]).stdout
    der = run([openssl, "pkey", "-pubin", "-outform", "DER"], input=spki).stdout
    digest = run([openssl, "dgst", "-sha256", "-binary"], input=der).stdout
    return run([openssl, "base64", "-A"], input=digest).stdout.decode().strip()


PAGE = """<!doctype html>
<meta charset="utf-8"><title>onyx wss smoke</title>
<script>
const report = (verdict) => fetch('/result', {method: 'POST', body: JSON.stringify(verdict)});
const lines = [];
let welcomed = false, ponged = false;
const timer = setTimeout(() => report({ok: false, why: 'timeout', lines}), 15000);
try {
  const ws = new WebSocket('wss://localhost:__WS_PORT__/', 'text.ircv3.net');
  ws.onopen = () => {
    ws.send('NICK browser' + Math.floor(Math.random() * 1e6));
    ws.send('USER browser 0 * :headless chromium');
  };
  ws.onmessage = (ev) => {
    const line = String(ev.data).replace(/\\r?\\n$/, '');
    lines.push(line);
    if (/^PING /.test(line)) ws.send('PONG ' + line.slice(5));
    if (!welcomed && / 001 /.test(line)) { welcomed = true; ws.send('PING :browser-tls-smoke'); }
    if (welcomed && !ponged && /PONG .*browser-tls-smoke/.test(line)) {
      ponged = true;
      clearTimeout(timer);
      ws.send('QUIT :done');
      report({ok: true, protocol: ws.protocol, lines});
    }
  };
  ws.onerror = () => { clearTimeout(timer); report({ok: false, why: 'websocket error', lines}); };
  ws.onclose = (ev) => {
    if (!ponged) { clearTimeout(timer); report({ok: false, why: 'closed ' + ev.code, lines}); }
  };
} catch (e) {
  clearTimeout(timer);
  report({ok: false, why: String(e), lines});
}
</script>
"""


class Harness(http.server.BaseHTTPRequestHandler):
    page = b""
    verdict: dict | None = None
    done = threading.Event()

    def log_message(self, *_args) -> None:  # keep stdout for the verdict
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.page)))
        self.end_headers()
        self.wfile.write(self.page)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            Harness.verdict = json.loads(body)
        except ValueError:
            Harness.verdict = {"ok": False, "why": "unparseable verdict"}
        self.send_response(204)
        self.end_headers()
        Harness.done.set()


def netlog_ssl_results(path: Path, remote: str) -> list[dict]:
    """SSL_CONNECT end-event params for sockets connected to `remote`.

    Chromium writes the constants table first, then one event object per
    line; a killed browser leaves the trailing `]}` off, so parse per line.
    The browser also opens its own background TLS connections (component
    updates, Google endpoints), so each SSL_CONNECT result is attributed to
    its socket source and kept only when that socket's TCP connect reached
    `remote` ("127.0.0.1:<port>").
    """
    remote_by_source: dict[int, str] = {}
    ssl_by_source: list[tuple[int, dict]] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{") or '"source"' not in line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        params = event.get("params") or {}
        source = (event.get("source") or {}).get("id")
        if source is None:
            continue
        if "remote_address" in params:
            remote_by_source[source] = params["remote_address"]
        if "key_exchange_group" in params:
            ssl_by_source.append((source, params))
    return [params for source, params in ssl_by_source if remote_by_source.get(source) == remote]


def main() -> int:
    openssl = shutil.which("openssl")
    chromium = os.environ.get("CHROMIUM") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium or not openssl:
        log("SKIP: need chromium and openssl")
        return SKIP
    # Resolved now: the daemon is started with cwd=<temp dir>, where a relative
    # path would no longer name the binary.
    daemon = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ONYX_BIN", ROOT / "zig-out/bin/onyx-server")).resolve()
    if not daemon.is_file():
        log(f"FAIL: daemon binary not found: {daemon} (zig build -Doptimize=ReleaseSafe)")
        return 1
    version = subprocess.run([chromium, "--version"], capture_output=True, text=True).stdout.strip()
    log(f"browser: {version}")

    work = Path(tempfile.mkdtemp(prefix="onyx-browser-tls."))
    procs: list[subprocess.Popen] = []
    httpd = None
    try:
        spin = make_pki(work / "pki", openssl)
        irc_port, tls_port, ws_port, http_port = (free_port() for _ in range(4))
        cfg = work / "onyx.toml"
        cfg.write_text(
            "[node]\nid = 1\n"
            "[limits]\nnum_shards = 1\n"
            f"[listen]\nirc = {irc_port}\nws = {ws_port}\n"
            f"[tls]\nenabled = true\nport = {tls_port}\n"
            f"cert_path = \"{work / 'pki/leaf.pem'}\"\n"
            f"key_path = \"{work / 'pki/leaf.p8'}\"\n"
            "dns_name = \"localhost\"\n"
        )

        def raise_stack() -> None:
            # A Debug daemon with [tls] enabled needs a large stack (see
            # tools/upgrade_smoke.py); harmless for release builds.
            want = 512 * 1024 * 1024
            _, hard = resource.getrlimit(resource.RLIMIT_STACK)
            resource.setrlimit(resource.RLIMIT_STACK, (want if hard == resource.RLIM_INFINITY else min(want, hard), hard))
            os.umask(0o077)

        dlog = open(work / "daemon.log", "wb")
        procs.append(subprocess.Popen([str(daemon), str(cfg)], cwd=work, stdout=dlog,
                                      stderr=subprocess.STDOUT, preexec_fn=raise_stack))
        if not wait_port(ws_port, 20):
            log("FAIL: daemon did not open the wss port")
            log((work / "daemon.log").read_text(errors="replace")[-2000:])
            return 1
        log(f"daemon wss=127.0.0.1:{ws_port} (tls={tls_port})")

        Harness.page = PAGE.replace("__WS_PORT__", str(ws_port)).encode()
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", http_port), Harness)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        netlog = work / "netlog.json"
        args = [
            chromium,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--disable-background-networking",
            "--disable-component-update",
            # Loopback only: the smoke must not depend on (or leak to) the network.
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
            f"--user-data-dir={work / 'chrome-profile'}",
            f"--ignore-certificate-errors-spki-list={spin}",
            f"--log-net-log={netlog}",
            "--net-log-capture-mode=Default",
            f"http://127.0.0.1:{http_port}/",
        ]
        log("launching headless chromium")
        # Chromium puts its ProcessSingleton socket under $TMPDIR and aborts if
        # that AF_UNIX path exceeds ~108 bytes; keep it short.
        chrome_env = dict(os.environ)
        if len(os.environ.get("TMPDIR", "")) > 40 and os.path.isdir("/tmp"):
            chrome_env["TMPDIR"] = "/tmp"
        procs.append(subprocess.Popen(args, cwd=work, env=chrome_env, stdout=subprocess.DEVNULL,
                                      stderr=open(work / "chromium.log", "wb")))
        if not Harness.done.wait(30):
            log("FAIL: the page never reported a verdict")
            return 1
        verdict = Harness.verdict or {}
        # Let Chromium flush the NetLog, then stop it gracefully (SIGTERM ends
        # the log cleanly; the per-line parser tolerates a truncated tail).
        time.sleep(1.0)
        browser = procs.pop()
        browser.send_signal(signal.SIGTERM)
        try:
            browser.wait(10)
        except subprocess.TimeoutExpired:
            browser.kill()
            browser.wait()

        failures = []
        if not verdict.get("ok"):
            failures.append(f"page verdict: {verdict.get('why')} (last lines: {verdict.get('lines', [])[-3:]})")
        else:
            welcome = next((l for l in verdict["lines"] if " 001 " in l), "")
            log(f"PASS: wss IRC session registered and PING/PONG round-tripped ({welcome[:80]!r})")
            if verdict.get("protocol") != "text.ircv3.net":
                failures.append(f"subprotocol {verdict.get('protocol')!r} != 'text.ircv3.net'")

        ssl = netlog_ssl_results(netlog, f"127.0.0.1:{ws_port}") if netlog.exists() else []
        if not ssl:
            failures.append(f"no SSL_CONNECT result for 127.0.0.1:{ws_port} in the NetLog")
        for params in ssl:
            group = params.get("key_exchange_group")
            ver = params.get("version")
            ver_num = int(ver, 0) if isinstance(ver, str) and ver.startswith("0x") else ver
            suite = params.get("cipher_suite")
            log(f"netlog SSL_CONNECT: version={ver} cipher_suite={suite} key_exchange_group={group}")
            if group != X25519MLKEM768:
                failures.append(f"key_exchange_group {group} != X25519MLKEM768 ({X25519MLKEM768})")
            if ver_num not in (TLS13_VERSION, "TLS 1.3"):
                failures.append(f"TLS version {ver!r} is not 1.3")
        if failures:
            for f in failures:
                log(f"FAIL: {f}")
            return 1
        log(f"PASS: Chromium negotiated TLS 1.3 with X25519MLKEM768 ({len(ssl)} handshake(s))")
        return 0
    finally:
        if httpd is not None:
            httpd.shutdown()
        for p in procs:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        if os.environ.get("ONYX_SMOKE_KEEP") == "1":
            log(f"kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
