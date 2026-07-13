#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Live Helix UPGRADE smoke test.

Boots a Orochi daemon with an account DB + an [[opers]] binding, registers an
operator account, logs in over SASL (auto-elevates to oper), issues UPGRADE, and
verifies the hot re-exec:

  * the operator elevation works (RPL_YOUREOPER 381),
  * the daemon execve's --supervisor and ADOPTS the inherited listener (log),
  * session state is carried across the handoff (sealed/recovered log lines),
  * the port stays bound (same PID) and still serves IRC after the upgrade.

Usage: python3 tools/upgrade_smoke.py [path-to-orochi-binary]
Exit code 0 = PASS.
"""
import base64
import os
import re
import resource
import socket
import ssl
import subprocess
import sys
import time

PORT = 16720
TLS_PORT = 16721
WS_PORT = 16722
HOST = "127.0.0.1"
ACCT = "admin"
PASSWORD = "secretpass0"
BOUNCE_ACCT = "bounce"
BOUNCE_PASSWORD = "secretpass1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "zig-out", "bin", "orochi")
DB = "/tmp/mz_upgrade_accts.db"
CONF = "/tmp/mz_upgrade.toml"
LOG = "/tmp/mz_upgrade.log"


def recv_until(sock, needle, timeout=4.0):
    sock.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if needle in buf:
            break
    return buf.decode("utf-8", "replace")


def connect():
    return socket.create_connection((HOST, PORT), timeout=4)


def tls_connect(port):
    """A TLS client that accepts the daemon's bootstrap self-signed cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, port), timeout=4)
    return ctx.wrap_socket(raw)


def ws_frame(payload: bytes) -> bytes:
    """One masked client-to-server text frame (RFC 6455)."""
    mask = os.urandom(4)
    header = bytearray([0x81])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    else:
        header += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    return bytes(header) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))


def ws_recv_text(sock, needle: bytes, timeout=4.0) -> str:
    """Accumulate unmasked server frames; return joined text payloads."""
    sock.settimeout(timeout)
    buf = b""
    text = b""
    end = time.time() + timeout
    while time.time() < end and needle not in text:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 2:
            n = buf[1] & 0x7F
            off = 2
            if n == 126:
                if len(buf) < 4:
                    break
                n = int.from_bytes(buf[2:4], "big")
                off = 4
            elif n == 127:
                if len(buf) < 10:
                    break
                n = int.from_bytes(buf[2:10], "big")
                off = 10
            if len(buf) < off + n:
                break
            opcode = buf[0] & 0x0F
            if opcode in (1, 2):
                text += buf[off : off + n] + b"\n"
            buf = buf[off + n :]
    return text.decode("utf-8", "replace")


def ws_connect(port):
    """Open a wss connection and complete the WebSocket upgrade handshake."""
    s = tls_connect(port)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET / HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    s.sendall(req.encode())
    resp = recv_until(s, b"\r\n\r\n")
    if "101" not in resp:
        raise RuntimeError(f"WebSocket upgrade refused: {resp!r}")
    return s


def fail(msg, proc=None):
    print(f"FAIL: {msg}")
    try:
        with open(LOG) as f:
            print("--- daemon log ---")
            print(f.read())
    except OSError:
        pass
    cleanup(proc)
    sys.exit(1)


def cleanup(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    for p in (CONF, LOG, DB, DB + ".wal"):
        try:
            os.remove(p)
        except OSError:
            pass


def main():
    if not os.path.exists(BIN):
        fail(f"binary not found: {BIN} (run `zig build` first)")
    for p in (DB, DB + ".wal"):
        try:
            os.remove(p)
        except OSError:
            pass
    with open(CONF, "w") as f:
        f.write(
            "[node]\nid = 1\n"
            f"[listen]\nirc = {PORT}\nws = {WS_PORT}\n"
            f"[tls]\nenabled = true\nport = {TLS_PORT}\n"
            f"[sasl]\naccount_db = \"{DB}\"\n"
            # An oper class must name a defined [[oper_groups]] group, or the
            # binding is skipped at boot ("unknown or empty class") and the 381
            # elevation never happens. UPGRADE requires the server_restart priv.
            "[[oper_groups]]\nname = \"netadmin\"\n"
            "privileges = [\"server_restart\", \"server_rehash\", \"server_admin\", \"mesh_admin\"]\n"
            f"[[opers]]\naccount = \"{ACCT}\"\nclass = \"netadmin\"\n"
        )

    def raise_stack_limit():
        # PRE-EXISTING (also at 746eff0): a Debug build with `[tls] enabled`
        # overflows the default 8 MiB stack inside LinuxServer.init and
        # segfaults at boot (ReleaseFast is unaffected — production runs fine).
        # Give the daemon a generous stack so the Debug smoke can exercise the
        # TLS + wss carry paths; execve preserves rlimits, so the successor
        # keeps it across the UPGRADE.
        want = 512 * 1024 * 1024
        _, hard = resource.getrlimit(resource.RLIMIT_STACK)
        cap = want if hard == resource.RLIM_INFINITY else min(want, hard)
        resource.setrlimit(resource.RLIMIT_STACK, (cap, hard))

    proc = subprocess.Popen(
        [BIN, CONF],
        stdout=open(LOG, "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=raise_stack_limit,
    )
    time.sleep(2.5)
    if proc.poll() is not None:
        fail("daemon exited during boot", proc)
    pid_before = proc.pid

    # Conn A: register the operator account. It is kept OPEN until after the
    # UPGRADE: closing it would leave a detached ghost session for the account,
    # and conn B's SASL login would then RECLAIM that ghost — replacing B's
    # freshly-elevated oper session with the ghost's non-oper state, so the
    # UPGRADE would 481 (pre-existing reclaim-clobbers-elevation behavior).
    a = connect()
    a.sendall(b"NICK regger\r\nUSER reg 0 * :reg\r\n")
    if " 001 " not in recv_until(a, b" 001 "):
        fail("conn A did not register (no 001)", proc)
    a.sendall(f"REGISTER {ACCT} * {PASSWORD}\r\n".encode())
    reg = recv_until(a, b"REGISTER", timeout=20)  # argon2 hash is slow in Debug
    if "REGISTER SUCCESS" not in reg and "FAIL" not in reg:
        fail(f"unexpected REGISTER reply: {reg!r}", proc)

    # Register a second, non-oper account for the bouncer-session check.
    a2 = connect()
    a2.sendall(b"NICK survivor\r\nUSER reg2 0 * :reg2\r\n")
    if " 001 " not in recv_until(a2, b" 001 "):
        fail("conn A2 did not register (no 001)", proc)
    a2.sendall(f"REGISTER {BOUNCE_ACCT} * {BOUNCE_PASSWORD}\r\n".encode())
    reg2 = recv_until(a2, b"REGISTER", timeout=20)  # argon2 hash is slow in Debug
    if "REGISTER SUCCESS" not in reg2 and "FAIL" not in reg2:
        fail(f"unexpected REGISTER reply for bounce: {reg2!r}", proc)
    a2.close()

    # Conn B: SASL login -> auto-elevate to oper -> UPGRADE.
    b = connect()
    b.sendall(b"CAP LS 302\r\n")
    recv_until(b, b"CAP")
    b.sendall(b"CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
    if "AUTHENTICATE +" not in recv_until(b, b"AUTHENTICATE +"):
        fail("server did not prompt AUTHENTICATE +", proc)
    token = base64.b64encode(b"\0" + ACCT.encode() + b"\0" + PASSWORD.encode()).decode()
    b.sendall(f"AUTHENTICATE {token}\r\n".encode())
    sasl = recv_until(b, b"90", timeout=20)  # argon2 verify is slow in Debug
    if " 903 " not in sasl and " 900 " not in sasl:
        fail(f"SASL login failed: {sasl!r}", proc)
    b.sendall(b"CAP END\r\nNICK admin\r\nUSER admin 0 * :admin\r\n")
    welcome = recv_until(b, b" 381 ")
    if " 381 " not in welcome:
        fail(f"operator not elevated (no 381): {welcome!r}", proc)
    print("PASS: operator elevated via SASL (381)")

    # Conn D: a plain registered client we keep OPEN across the UPGRADE to prove
    # its TCP connection (fd) is re-attached, not dropped. It logs in via SASL
    # (bouncer session), joins a channel, sets +i, and arms MONITOR + SILENCE
    # so the successor must restore ALL of that per-client state.
    d = connect()
    d.sendall(b"CAP LS 302\r\n")
    recv_until(d, b"CAP")
    d.sendall(b"CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
    if "AUTHENTICATE +" not in recv_until(d, b"AUTHENTICATE +"):
        fail("conn D: no AUTHENTICATE + prompt", proc)
    dtoken = base64.b64encode(
        b"\0" + BOUNCE_ACCT.encode() + b"\0" + BOUNCE_PASSWORD.encode()
    ).decode()
    d.sendall(f"AUTHENTICATE {dtoken}\r\n".encode())
    dsasl = recv_until(d, b"90", timeout=20)  # argon2 verify is slow in Debug
    if " 903 " not in dsasl and " 900 " not in dsasl:
        fail(f"conn D SASL login failed: {dsasl!r}", proc)
    d.sendall(b"CAP END\r\nNICK survivor\r\nUSER survivor 0 * :survivor\r\n")
    if " 001 " not in recv_until(d, b" 001 "):
        fail("conn D did not register before UPGRADE", proc)
    d.sendall(b"JOIN #durable\r\n")
    recv_until(d, b" 366 ")  # end of NAMES — join complete
    d.sendall(b"MODE survivor +i\r\nMONITOR + watchtarget\r\nSILENCE +bad!*@*\r\n")
    recv_until(d, b" 731 ")  # MONOFFLINE for the (offline) watch target
    d.sendall(b"SESSION TOKEN\r\n")
    tok_reply = recv_until(d, b"SESSION TOKEN ")
    m = re.search(r"SESSION TOKEN ([0-9a-fA-F]+)", tok_reply)
    if not m:
        fail(f"conn D: no SESSION TOKEN before UPGRADE: {tok_reply!r}", proc)
    token_before = m.group(1)

    # Conn T: a TLS client kept OPEN across the UPGRADE — its live TLS engine
    # state must ride the .tls_session capsule and resume on the successor.
    t = tls_connect(TLS_PORT)
    t.sendall(b"NICK tlssurv\r\nUSER tlssurv 0 * :tlssurv\r\n")
    if " 001 " not in recv_until(t, b" 001 "):
        fail("conn T (TLS) did not register before UPGRADE", proc)
    print("PASS: TLS client registered before UPGRADE")

    # Conn W: a wss browser-style client kept OPEN across the UPGRADE — and
    # deliberately left MID-FRAME: half a masked PING frame is sent before the
    # swap, the rest after. The v2 .ws_session capsule must carry the partial
    # deframer bytes so the reassembled frame still executes on the successor.
    w = ws_connect(WS_PORT)
    w.sendall(ws_frame(b"NICK wssurv"))
    w.sendall(ws_frame(b"USER wssurv 0 * :wssurv"))
    if " 001 " not in ws_recv_text(w, b" 001 "):
        fail("conn W (wss) did not register before UPGRADE", proc)
    print("PASS: wss client registered before UPGRADE")
    midframe = ws_frame(b"PING :midframe")
    w.sendall(midframe[:7])  # header + mask + first payload byte: mid-frame
    time.sleep(0.5)  # let the daemon buffer the partial frame in its deframer

    b.sendall(b"UPGRADE\r\n")
    # Read the requester's progress NOTICE before the socket dies at execve —
    # it surfaces a refusal ("UPGRADE refused/failed: ...") that would otherwise
    # look like a silent no-op.
    note = recv_until(b, b"UPGRADE", timeout=3)
    for line in note.splitlines():
        if "UPGRADE" in line:
            print(f"note: {line.strip()}")
    b.close()

    # Give the execve time to land + the successor to adopt + boot.
    time.sleep(2.5)

    if proc.poll() is not None:
        fail("daemon process died across UPGRADE (execve should preserve PID)", proc)
    if proc.pid != pid_before:
        fail("PID changed — execve should keep the same PID", proc)
    print(f"PASS: daemon survived UPGRADE (same PID {proc.pid})")

    with open(LOG) as f:
        log = f.read()
    if "adopting inherited listener fd" not in log:
        fail("successor did not adopt the inherited listener", proc)
    print("PASS: successor adopted the inherited listener socket")
    # The successor logs how many carried-over connections it re-attached; >=1
    # proves session state + the client fd both crossed the handoff.
    if "re-attached" in log and "re-attached 0 client" not in log:
        print("PASS: successor re-attached carried-over connection(s) (state + fd)")
    else:
        fail("successor did not re-attach any client connection", proc)
    mre = re.search(r"re-attached (\d+) client connection\(s\) \((\d+) TLS, (\d+) wss\)", log)
    if not mre:
        fail("successor resume log missing the TLS/wss breakdown", proc)
    n_clients, n_tls, n_wss = (int(x) for x in mre.groups())
    if n_clients < 3 or n_tls < 2 or n_wss < 1:
        fail(
            f"expected >=3 clients (>=2 TLS, >=1 wss) re-attached, got {n_clients} ({n_tls} TLS, {n_wss} wss)",
            proc,
        )
    print("PASS: successor re-attached the plain + TLS + wss clients (log breakdown)")

    # Conn D was kept open across the upgrade: its TCP connection must survive,
    # with recv re-armed — a PING gets a PONG from the new image.
    try:
        d.sendall(b"PING :survive\r\n")
        pong = recv_until(d, b"PONG")
    except OSError as e:
        fail(f"survivor connection broke across UPGRADE: {e}", proc)
    if "PONG" not in pong:
        fail(f"survivor connection did not answer PING after UPGRADE: {pong!r}", proc)
    print("PASS: pre-upgrade connection SURVIVED the swap (PING/PONG)")

    # The TLS client must survive with its resumed record stream intact.
    try:
        t.sendall(b"PING :tls-survive\r\n")
        tls_pong = recv_until(t, b"PONG")
    except OSError as e:
        fail(f"TLS connection broke across UPGRADE: {e}", proc)
    if "PONG" not in tls_pong:
        fail(f"TLS client did not answer PING after UPGRADE: {tls_pong!r}", proc)
    print("PASS: TLS connection SURVIVED the swap (PING/PONG over resumed engine)")

    # The wss client was left MID-FRAME: send the rest of the split PING frame.
    # The successor's restored deframer must reassemble it with the carried
    # partial bytes and answer — no lost bytes, no reconnect.
    try:
        w.sendall(midframe[7:])
        ws_pong = ws_recv_text(w, b"PONG")
    except OSError as e:
        fail(f"wss connection broke across UPGRADE: {e}", proc)
    if "PONG" not in ws_pong or "midframe" not in ws_pong:
        fail(f"wss client mid-frame PING not answered after UPGRADE: {ws_pong!r}", proc)
    print("PASS: wss connection SURVIVED the swap MID-FRAME (split-frame PING/PONG)")
    w.close()
    t.close()

    # The bouncer session must re-track under the SAME reclaim token.
    d.sendall(b"SESSION TOKEN\r\n")
    tok_reply2 = recv_until(d, b"SESSION TOKEN ")
    m2 = re.search(r"SESSION TOKEN ([0-9a-fA-F]+)", tok_reply2)
    if not m2:
        fail(f"conn D: no SESSION TOKEN after UPGRADE: {tok_reply2!r}", proc)
    if m2.group(1) != token_before:
        fail(
            f"bouncer session token changed across UPGRADE: {token_before} -> {m2.group(1)}",
            proc,
        )
    print("PASS: bouncer session kept the SAME reclaim token across UPGRADE")

    # Per-client state carried by the v4 .clients capsule + list capsules:
    # +i umode, the MONITOR watch list, and the SILENCE mask list.
    d.sendall(b"MODE survivor\r\n")
    umode = recv_until(d, b" 221 ")
    if " 221 " not in umode or "i" not in umode.split(" 221 ", 1)[1]:
        fail(f"+i umode lost across UPGRADE: {umode!r}", proc)
    print("PASS: client-set umode (+i) survived the UPGRADE")
    d.sendall(b"MONITOR L\r\n")
    monlist = recv_until(d, b" 733 ")
    if "watchtarget" not in monlist:
        fail(f"MONITOR list lost across UPGRADE: {monlist!r}", proc)
    print("PASS: MONITOR watch list survived the UPGRADE")
    d.sendall(b"SILENCE\r\n")
    sil = recv_until(d, b" 272 ")
    if "bad!*@*" not in sil:
        fail(f"SILENCE list lost across UPGRADE: {sil!r}", proc)
    print("PASS: SILENCE mask list survived the UPGRADE")

    # The survivor's nick must be re-registered in the new image's world: a fresh
    # client can WHOIS it and get RPL_WHOISUSER (311).
    c2 = connect()
    c2.sendall(b"NICK whoiser\r\nUSER whoiser 0 * :whoiser\r\n")
    recv_until(c2, b" 001 ")
    c2.sendall(b"WHOIS survivor\r\n")
    whois = recv_until(c2, b" 318 ")
    c2.close()
    # NB: keep `d` (survivor) OPEN — closing it would drop it from #durable before
    # the channel-membership check below.
    if " 311 " not in whois:
        fail(f"carried nick not re-registered in world (no WHOIS 311): {whois!r}", proc)
    print("PASS: carried nick re-registered in the new image's world (WHOIS 311)")

    # Channel membership must survive: a fresh client joining #durable sees the
    # carried-over survivor in the NAMES list (RPL_NAMREPLY 353).
    e = connect()
    e.sendall(b"NICK joiner\r\nUSER joiner 0 * :joiner\r\n")
    recv_until(e, b" 001 ")
    e.sendall(b"JOIN #durable\r\n")
    names = recv_until(e, b" 366 ")
    e.close()
    d.close()
    if "survivor" not in names:
        fail(f"carried channel membership lost (survivor not in #durable NAMES): {names!r}", proc)
    print("PASS: carried channel membership survived (NAMES shows survivor in #durable)")

    a.close()  # the registering oper conn, held open so no ghost session existed

    # Conn C: a fresh client must connect + register after the upgrade.
    time.sleep(0.3)
    c = connect()
    c.sendall(b"NICK after\r\nUSER after 0 * :after\r\n")
    if " 001 " not in recv_until(c, b" 001 "):
        fail("post-upgrade client could not register (port not serving)", proc)
    c.close()
    print("PASS: port stayed bound and serves IRC after UPGRADE")

    cleanup(proc)
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
