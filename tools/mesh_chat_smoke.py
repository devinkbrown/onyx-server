#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dual-node IRC chat smoke — prove cross-mesh PRIVMSG both directions.

Connects two clients (default: local plain 127.0.0.1:6667 + remote TLS :6697),
negotiates CAP (optional SASL PLAIN), JOINs a shared channel, and exchanges
unique PRIVMSG payloads both ways.

Auth modes:
  * SASL (default when creds present) — CAP REQ sasl + AUTHENTICATE PLAIN;
    fail-closed on SASL failure (902/904–907 or missing sasl CAP).
  * Guest — CAP END without SASL; unique NICK+USER only. Used when SASL env is
    unset (auto-fallback) or MESH_SMOKE_ALLOW_GUEST=1. Suitable when the
    network allows unregistered nicks (001 without 464/465).

stdlib only (socket / ssl). Does not print secrets.

Usage:
  # SASL (preferred when accounts exist)
  export MESH_SMOKE_SASL_USER=account
  export MESH_SMOKE_SASL_PASS=secret   # or ANNOUNCE_SASL_*
  python3 tools/mesh_chat_smoke.py [A_HOST:PORT] [B_HOST:PORT]

  # Guest (no credentials; auto when SASL unset, or force with ALLOW_GUEST=1)
  MESH_SMOKE_B=peer.example:6697 MESH_SMOKE_INSECURE_TLS=1 \\
    python3 tools/mesh_chat_smoke.py

  # defaults: A=127.0.0.1:6667 (plain), B from MESH_SMOKE_B or argv (TLS)

Env:
  MESH_SMOKE_SASL_USER / MESH_SMOKE_SASL_PASS  (fallback: ANNOUNCE_SASL_*)
  MESH_SMOKE_ALLOW_GUEST   if set/truthy, allow guest when SASL unset (also auto)
  MESH_SMOKE_REQUIRE_SASL  if set/truthy, refuse guest auto-fallback (exit 2)
  MESH_SMOKE_CHANNEL   default #root
  MESH_SMOKE_A         default 127.0.0.1:6667  (plain unless MESH_SMOKE_A_TLS=1)
  MESH_SMOKE_B         required if not passed as argv  (TLS unless MESH_SMOKE_B_TLS=0)
  MESH_SMOKE_TIMEOUT   seconds, default 45
  MESH_SMOKE_INSECURE_TLS  if set, skip cert verification on TLS endpoints

Exit 0 = both directions OK; 1 = exchange/register/join failed;
      2 = usage / missing SASL when required / guest not permitted.
"""
from __future__ import annotations

import base64
import os
import select
import socket
import ssl
import sys
import time
import uuid


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v is not None and v != "":
            return v
    return default


def _truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


CHANNEL = _env("MESH_SMOKE_CHANNEL", default="#root")
TIMEOUT = float(_env("MESH_SMOKE_TIMEOUT", default="45"))
INSECURE_TLS = _truthy("MESH_SMOKE_INSECURE_TLS", default=True)

SASL_USER = _env("MESH_SMOKE_SASL_USER", "ANNOUNCE_SASL_USER")
SASL_PASS = _env("MESH_SMOKE_SASL_PASS", "ANNOUNCE_SASL_PASS")
ALLOW_GUEST = _truthy("MESH_SMOKE_ALLOW_GUEST", default=False)
REQUIRE_SASL = _truthy("MESH_SMOKE_REQUIRE_SASL", default=False)


def parse_endpoint(spec: str) -> tuple[str, int]:
    spec = spec.strip()
    if not spec:
        raise ValueError("empty endpoint")
    if spec.startswith("["):
        # [ipv6]:port
        host, _, port_s = spec[1:].partition("]:")
        if not port_s:
            raise ValueError(f"bad IPv6 endpoint: {spec!r}")
        return host, int(port_s)
    if ":" in spec:
        host, _, port_s = spec.rpartition(":")
        return host, int(port_s)
    raise ValueError(f"endpoint must be host:port, got {spec!r}")


class IrcClient:
    """Minimal blocking IRC client with CAP LS + optional SASL PLAIN."""

    def __init__(
        self,
        label: str,
        host: str,
        port: int,
        *,
        use_tls: bool,
        nick: str,
        sasl_user: str,
        sasl_pass: str,
        use_sasl: bool,
    ) -> None:
        self.label = label
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.nick = nick
        self.sasl_user = sasl_user
        self.sasl_pass = sasl_pass
        self.use_sasl = use_sasl
        self.sock: socket.socket | ssl.SSLSocket | None = None
        self.buf = b""
        self.registered = False
        self.joined = False
        self.sasl_ok = False
        self.cap_ended = False
        self.cap_ls: set[str] = set()
        self.seen_privmsgs: list[str] = []
        self.last_err: str | None = None
        self.reg_numerics: list[str] = []

    def connect(self, timeout: float = 15.0) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=timeout)
        raw.settimeout(timeout)
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if INSECURE_TLS:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx.load_default_certs()
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw
        self._send("CAP LS 302")
        self._send(f"NICK {self.nick}")
        self._send(f"USER {self.nick} 0 * :mesh-chat-smoke {self.label}")

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self._send("QUIT :mesh-chat-smoke done")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _send(self, line: str) -> None:
        assert self.sock is not None
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def fileno(self) -> int:
        assert self.sock is not None
        return self.sock.fileno()

    def pump(self) -> None:
        """Read available data and process complete lines."""
        assert self.sock is not None
        try:
            chunk = self.sock.recv(8192)
        except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
            return
        if not chunk:
            self.last_err = "eof"
            return
        self.buf += chunk
        while b"\r\n" in self.buf:
            raw, self.buf = self.buf.split(b"\r\n", 1)
            line = raw.decode("utf-8", "replace")
            self._handle(line)

    def _handle(self, line: str) -> None:
        if not line:
            return
        # Strip IRCv3 tags if present.
        work = line[1:] if line.startswith("@") and " " in line else line
        if work.startswith("@"):
            work = work.split(" ", 1)[1]

        parts = work.split()
        if not parts:
            return

        # PING
        if parts[0] == "PING" or (len(parts) > 1 and parts[1] == "PING"):
            token = work.split("PING", 1)[1].strip()
            if token.startswith(":"):
                token = token[1:]
            self._send(f"PONG :{token}")
            return

        # AUTHENTICATE + (SASL only)
        if parts[0] == "AUTHENTICATE" and len(parts) >= 2 and parts[1] == "+":
            if not self.use_sasl:
                return
            payload = base64.b64encode(
                f"{self.sasl_user}\0{self.sasl_user}\0{self.sasl_pass}".encode("utf-8")
            ).decode("ascii")
            self._send(f"AUTHENTICATE {payload}")
            return

        # CAP
        if len(parts) >= 4 and parts[1] == "CAP":
            self._handle_cap(work, parts)
            return

        if len(parts) >= 2 and parts[1].isdigit():
            code = parts[1]
            if code not in self.reg_numerics:
                self.reg_numerics.append(code)
            if code == "903":
                self.sasl_ok = True
                self._cap_end()
            elif code in ("902", "904", "905", "906", "907"):
                if self.use_sasl:
                    self.last_err = f"sasl failed ({code})"
                self._cap_end()
            elif code in ("001",):
                self.registered = True
                self._send(f"JOIN {CHANNEL}")
            elif code in ("433", "436"):
                self.nick = self.nick + "_"
                self._send(f"NICK {self.nick}")
            elif code in ("464", "465"):
                mode = "guest" if not self.use_sasl else "auth"
                self.last_err = f"register rejected ({code}, {mode})"
            return

        # JOIN echo: :nick!user@host JOIN :#chan  or JOIN #chan
        if len(parts) >= 3 and parts[1] == "JOIN":
            src = parts[0][1:] if parts[0].startswith(":") else parts[0]
            join_nick = src.split("!", 1)[0]
            chan = parts[2][1:] if parts[2].startswith(":") else parts[2]
            if join_nick.lower() == self.nick.lower() and chan.lower() == CHANNEL.lower():
                self.joined = True
            return

        # PRIVMSG
        if len(parts) >= 4 and parts[1] == "PRIVMSG":
            # :nick!u@h PRIVMSG #chan :text
            trailing = work.split(" :", 1)
            text = trailing[1] if len(trailing) == 2 else ""
            self.seen_privmsgs.append(text)
            return

    def _cap_end(self) -> None:
        if not self.cap_ended:
            self.cap_ended = True
            self._send("CAP END")

    def _handle_cap(self, line: str, parts: list[str]) -> None:
        sub = parts[3] if len(parts) > 3 else ""
        offered = line.split(" :", 1)[1].split() if " :" in line else []
        if sub == "LS":
            more = len(parts) > 4 and parts[4] == "*"
            self.cap_ls |= {c.split("=")[0] for c in offered}
            if more:
                return
            if self.use_sasl:
                if "sasl" in self.cap_ls:
                    self._send("CAP REQ :sasl")
                else:
                    self.last_err = "server did not offer sasl"
                    self._cap_end()
            else:
                # Guest: finish CAP without authenticating.
                self._cap_end()
        elif sub == "ACK":
            if not self.use_sasl:
                self._cap_end()
                return
            if any(c.split("=")[0] == "sasl" for c in offered):
                self._send("AUTHENTICATE PLAIN")
            else:
                self.last_err = "sasl not ACKed"
                self._cap_end()
        elif sub == "NAK":
            if self.use_sasl:
                self.last_err = "CAP REQ NAK"
            self._cap_end()

    def send_privmsg(self, text: str) -> None:
        self._send(f"PRIVMSG {CHANNEL} :{text}")


def wait_until(
    clients: list[IrcClient],
    pred,
    deadline: float,
    label: str,
) -> bool:
    """select-loop until pred() or deadline. Returns True if pred satisfied."""
    while time.time() < deadline:
        if pred():
            return True
        if any(c.last_err for c in clients):
            return False
        socks = [c for c in clients if c.sock is not None]
        if not socks:
            return False
        rlist, _, _ = select.select(socks, [], [], 0.5)
        for c in rlist:
            c.pump()
        # Non-blocking drain if data already buffered mid-line is rare; also
        # poke any client that might have partial progress.
        for c in clients:
            if c.sock is not None and c.sock not in rlist:
                # Don't force-read; select is authoritative.
                pass
    return bool(pred())


def resolve_endpoints(argv: list[str]) -> tuple[tuple[str, int, bool], tuple[str, int, bool]]:
    """Return ((host, port, tls), ...) for A and B."""
    a_spec = _env("MESH_SMOKE_A", default="127.0.0.1:6667")
    b_spec = _env("MESH_SMOKE_B", default="")
    a_tls = _truthy("MESH_SMOKE_A_TLS", default=False)
    b_tls = _truthy("MESH_SMOKE_B_TLS", default=True)

    args = argv[1:]
    if len(args) >= 2:
        a_spec, b_spec = args[0], args[1]
    elif len(args) == 1:
        b_spec = args[0]
    elif not b_spec:
        print(
            "usage: mesh_chat_smoke.py [A_HOST:PORT] B_HOST:PORT\n"
            "  SASL: MESH_SMOKE_SASL_USER + MESH_SMOKE_SASL_PASS\n"
            "        (or ANNOUNCE_SASL_USER + ANNOUNCE_SASL_PASS)\n"
            "  guest: omit SASL (auto) or MESH_SMOKE_ALLOW_GUEST=1\n"
            "  force SASL-only: MESH_SMOKE_REQUIRE_SASL=1\n"
            "  B also via MESH_SMOKE_B=host:port (TLS by default)",
            file=sys.stderr,
        )
        sys.exit(2)

    ah, ap = parse_endpoint(a_spec)
    bh, bp = parse_endpoint(b_spec)
    return (ah, ap, a_tls), (bh, bp, b_tls)


def resolve_auth_mode() -> tuple[bool, str | None]:
    """Return (use_sasl, skip_reason_or_None).

    skip_reason non-None means main should exit 2 with that one-liner.
    """
    has_sasl = bool(SASL_USER and SASL_PASS)
    if has_sasl:
        return True, None
    if REQUIRE_SASL:
        return False, (
            "mesh_chat_smoke: skip — MESH_SMOKE_REQUIRE_SASL=1 but "
            "MESH_SMOKE_SASL_USER/PASS (or ANNOUNCE_SASL_*) unset"
        )
    # Guest auto-fallback when credentials are absent (SASL unset).
    # MESH_SMOKE_ALLOW_GUEST=1 is an explicit opt-in name for the same path.
    return False, None


def main(argv: list[str]) -> int:
    use_sasl, skip = resolve_auth_mode()
    if skip is not None:
        print(skip, file=sys.stderr)
        return 2

    try:
        a_ep, b_ep = resolve_endpoints(argv)
    except ValueError as e:
        print(f"mesh_chat_smoke: bad endpoint: {e}", file=sys.stderr)
        return 2

    deadline = time.time() + TIMEOUT
    tag = uuid.uuid4().hex[:12]
    nick_a = f"mcs{tag[:6]}a"
    nick_b = f"mcs{tag[:6]}b"
    msg_a = f"mesh-chat-smoke A->{tag}"
    msg_b = f"mesh-chat-smoke B->{tag}"
    if use_sasl:
        auth_label = "sasl"
    elif ALLOW_GUEST:
        auth_label = "guest"  # MESH_SMOKE_ALLOW_GUEST=1
    else:
        auth_label = "guest"  # auto when SASL env unset

    a = IrcClient(
        "A",
        a_ep[0],
        a_ep[1],
        use_tls=a_ep[2],
        nick=nick_a,
        sasl_user=SASL_USER,
        sasl_pass=SASL_PASS,
        use_sasl=use_sasl,
    )
    b = IrcClient(
        "B",
        b_ep[0],
        b_ep[1],
        use_tls=b_ep[2],
        nick=nick_b,
        sasl_user=SASL_USER,
        sasl_pass=SASL_PASS,
        use_sasl=use_sasl,
    )

    print(
        f"mesh_chat_smoke: A={a_ep[0]}:{a_ep[1]}{'/tls' if a_ep[2] else '/plain'} "
        f"B={b_ep[0]}:{b_ep[1]}{'/tls' if b_ep[2] else '/plain'} "
        f"chan={CHANNEL} auth={auth_label} timeout={TIMEOUT}s"
    )

    try:
        try:
            a.connect(timeout=min(15.0, TIMEOUT))
            b.connect(timeout=min(15.0, TIMEOUT))
        except OSError as e:
            print(f"FAIL: connect: {e}", file=sys.stderr)
            return 1

        # Register both (CAP [+ SASL] + 001 + JOIN).
        if not wait_until(
            [a, b],
            lambda: a.joined and b.joined,
            deadline,
            "register+join",
        ):
            errs = [f"{c.label}:{c.last_err}" for c in (a, b) if c.last_err]
            # Guest-only reject: clear skip-style message when 464/465.
            guest_blocked = (not use_sasl) and any(
                c.last_err and "register rejected (46" in c.last_err for c in (a, b)
            )
            if guest_blocked:
                print(
                    "mesh_chat_smoke: skip — guest NICK+USER rejected "
                    f"(A nums={a.reg_numerics} B nums={b.reg_numerics}; "
                    f"errs={errs}). Set MESH_SMOKE_SASL_USER/PASS "
                    "(or ANNOUNCE_SASL_*) for SASL PLAIN.",
                    file=sys.stderr,
                )
                return 2
            print(
                f"FAIL: register/join incomplete "
                f"(A reg={a.registered} sasl={a.sasl_ok} join={a.joined}; "
                f"B reg={b.registered} sasl={b.sasl_ok} join={b.joined}"
                + (f"; errs={errs}" if errs else "")
                + f"; A nums={a.reg_numerics} B nums={b.reg_numerics})",
                file=sys.stderr,
            )
            return 1
        sasl_note = (
            f" sasl_ok A={a.sasl_ok} B={b.sasl_ok}" if use_sasl else " (guest)"
        )
        print(
            f"PASS: both clients registered + joined {CHANNEL} "
            f"(nicks {a.nick}, {b.nick}){sasl_note}"
        )

        # A -> B
        a.send_privmsg(msg_a)
        if not wait_until(
            [a, b],
            lambda: any(msg_a in t for t in b.seen_privmsgs),
            deadline,
            "A->B",
        ):
            print(
                f"FAIL: B did not receive A's PRIVMSG within timeout "
                f"(B saw {b.seen_privmsgs!r})",
                file=sys.stderr,
            )
            return 1
        print(f"PASS: A→B PRIVMSG delivered ({msg_a})")

        # B -> A
        b.send_privmsg(msg_b)
        if not wait_until(
            [a, b],
            lambda: any(msg_b in t for t in a.seen_privmsgs),
            deadline,
            "B->A",
        ):
            print(
                f"FAIL: A did not receive B's PRIVMSG within timeout "
                f"(A saw {a.seen_privmsgs!r})",
                file=sys.stderr,
            )
            return 1
        print(f"PASS: B→A PRIVMSG delivered ({msg_b})")
        print("ALL CHECKS PASSED")
        return 0
    finally:
        a.close()
        b.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
