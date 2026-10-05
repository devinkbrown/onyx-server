#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise two native Windows Helix swaps with held IRC sockets and a WAL.

Usage: python -B tools/windows_helix_smoke.py zig-out/bin/onyx-server.exe
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

from windows_private_account_dir import create_private_directory


class Client:
    def __init__(self, port: int):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.socket.settimeout(0.2)
        self.buffer = b""
        self.lines: list[bytes] = []

    def close(self) -> None:
        self.socket.close()

    def send(self, line: bytes) -> None:
        self.socket.sendall(line + b"\r\n")

    def wait(self, fragment: bytes, *, start: int | None = None, timeout: float = 30) -> bytes:
        if start is None:
            start = len(self.lines)
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            for line in self.lines[start:]:
                if fragment in line:
                    return line
            try:
                chunk = self.socket.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError(f"held IRC socket closed while waiting for {fragment!r}")
            self.buffer += chunk
            while b"\r\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\r\n", 1)
                if line.startswith(b"PING "):
                    self.send(b"PONG " + line[5:])
                self.lines.append(line)
        raise TimeoutError(f"missing {fragment!r}; recent lines={self.lines[-10:]!r}")

    def command(self, line: bytes, fragment: bytes, timeout: float = 30) -> bytes:
        start = len(self.lines)
        self.send(line)
        return self.wait(fragment, start=start, timeout=timeout)

    def register(self, nick: bytes) -> None:
        start = len(self.lines)
        self.send(b"NICK " + nick)
        self.send(b"USER smoke 0 * :Windows Helix smoke")
        self.wait(b" 001 ", start=start)

    def ping(self, marker: bytes) -> None:
        reply = self.command(b"PING :" + marker, b" :" + marker)
        if b" PONG " not in reply:
            raise AssertionError(f"expected PONG, got {reply!r}")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def image_pids(binary: Path) -> set[int]:
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='onyx-server.exe'\" | "
        "ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.ExecutablePath }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True, text=True, capture_output=True, timeout=15,
    )
    pids = set()
    for line in result.stdout.splitlines():
        pid, separator, executable = line.partition("|")
        if not separator or not pid.isdigit() or not executable:
            continue
        try:
            if os.path.samefile(binary, executable):
                pids.add(int(pid))
        except OSError:
            continue
    return pids


def sole_image_pid(binary: Path, *, different_from: int | None = None, timeout: float = 35) -> int:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        pids = image_pids(binary)
        if len(pids) == 1:
            pid = next(iter(pids))
            if pid != different_from:
                return pid
        time.sleep(0.3)
    raise TimeoutError(f"successor PID did not replace {different_from}; live={image_pids(binary)}")


def authenticate_account(port: int, account: bytes, password: bytes, nick: bytes) -> Client:
    client = Client(port)
    try:
        client.command(b"CAP LS 302", b" LS ")
        client.command(b"CAP REQ :sasl", b" ACK ")
        client.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
        proof = base64.b64encode(b"\0" + account + b"\0" + password)
        client.command(b"AUTHENTICATE " + proof, b" 903 ", timeout=45)
        start = len(client.lines)
        client.send(b"CAP END")
        client.send(b"NICK " + nick)
        client.send(b"USER smoke 0 * :Windows Helix WAL verification")
        client.wait(b" 001 ", start=start)
        return client
    except Exception:
        client.close()
        raise


def wait_log_contains(path: Path, fragment: str, timeout: float = 35) -> None:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if path.exists() and fragment in path.read_text(encoding="utf-8", errors="replace"):
            return
        time.sleep(0.2)
    raise TimeoutError(f"daemon did not report {fragment!r}")


def assert_nick_held(port: int, nick: bytes, timeout: float = 10) -> None:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        probe = Client(port)
        try:
            probe.send(b"NICK " + nick)
            probe.send(b"USER probe 0 * :nick delay probe")
            try:
                probe.wait(b" 437 ", timeout=1)
                return
            except TimeoutError:
                pass
        finally:
            probe.close()
        time.sleep(0.1)
    raise AssertionError(f"released nick {nick!r} was not held")


def assert_silenced(sender: Client, receiver: Client, line: bytes, marker: bytes) -> None:
    start = len(receiver.lines)
    sender.send(line)
    sender.ping(b"silence-" + marker)
    try:
        receiver.wait(marker, start=start, timeout=0.8)
    except TimeoutError:
        return
    raise AssertionError(f"silenced message {marker!r} reached its target")


def abuse_value(oper: Client, nick: bytes, field: bytes) -> int:
    prefix = b"ABUSE " + nick + b": " + field
    line = oper.command(b"ABUSE " + nick, prefix)
    value = line.split(prefix, 1)[1].split()[0]
    return int(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this fixture requires native Windows")
    original = args.binary.resolve()
    if not original.is_file():
        parser.error(f"binary not found: {original}")

    with tempfile.TemporaryDirectory(prefix="onyx-windows-helix-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server.exe"
        shutil.copy2(original, binary)
        private = root / "private"
        create_private_directory(private)
        chanstats_dir = root / "channel-stats"
        chanstats_dir.mkdir()
        config = root / "server.toml"
        port = free_port()
        password = secrets.token_urlsafe(22)
        config.write_text(
            "[node]\nid = 1\nsecret_key = \"" + secrets.token_hex(32) + "\"\n"
            "[cloak]\nsecret = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[limits]\nnum_shards = 2\nthrottle_connects = 5\nthrottle_window = \"10s\"\nmax_clones_per_ip_net = 6\nnick_delay = \"5m\"\n"
            "handshake_timeout = \"6s\"\nsweep_interval = \"1s\"\nreputation_refuse_threshold = 1000\nreputation_half_life = \"24h\"\n"
            "[class.user]\nflood_lines = 4\nflood_window = \"1m\"\nflood_excess = 1000\n"
            "[mesh]\npass = \"" + secrets.token_urlsafe(32) + "\"\n"
            "[dnsbl]\nenabled = true\nzones = [\"dnsbl.invalid\"]\n"
            f"[stats]\nchannel_dir = \"{chanstats_dir.as_posix()}\"\ninterval = \"10m\"\n"
            f"[listen]\nirc = {port}\n"
            f"[sasl]\naccount_db = \"{(private / 'accounts.wal').as_posix()}\"\n"
            "[[oper_groups]]\nname = \"netadmin\"\nprivileges = [\"server_restart\", \"server_admin\", \"client_moderate\", \"service_admin\"]\n"
            "[[opers]]\naccount = \"helixadmin\"\nclass = \"netadmin\"\n",
            encoding="utf-8",
        )
        log = (root / "parent.log").open("wb")
        parent = subprocess.Popen([str(binary), str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
        clients: list[Client] = []
        try:
            until = time.monotonic() + 30
            while True:
                try:
                    owner = Client(port)
                    clients.append(owner)
                    break
                except OSError:
                    if parent.poll() is not None or time.monotonic() >= until:
                        raise RuntimeError(f"daemon did not listen; exit={parent.poll()}")
                    time.sleep(0.2)
            owner.register(b"owner")
            owner.command(f"REGISTER helixadmin * {password}".encode(), b"REGISTER SUCCESS", timeout=45)

            survivor = Client(port)
            clients.append(survivor)
            survivor.register(b"survivor")

            oper = Client(port)
            clients.append(oper)
            oper.command(b"CAP LS 302", b" LS ")
            oper.command(b"CAP REQ :sasl", b" ACK ")
            oper.command(b"AUTHENTICATE PLAIN", b"AUTHENTICATE +")
            encoded = base64.b64encode(b"\0helixadmin\0" + password.encode())
            oper.command(b"AUTHENTICATE " + encoded, b" 903 ", timeout=45)
            start = len(oper.lines)
            oper.send(b"CAP END")
            oper.send(b"NICK admin")
            oper.send(b"USER smoke 0 * :Windows Helix operator")
            oper.wait(b" 381 ", start=start)
            oper.command(b"IRCX", b" 800 admin 1 0 ")
            token_before = oper.command(b"SESSION TOKEN", b" :SESSION TOKEN ").split(b" :SESSION TOKEN ", 1)[1].split()[0]
            owner.command(b"AUTOJOIN ADD #helix-settings", b"AUTOJOIN added")
            owner.command(b"GROUP ADD owner-alt", b"GROUP nick added")
            oper.command(b"WELCOME ADD :held welcome line", b"WELCOME line added")

            serving_pid = parent.pid
            registered_after_swap: list[tuple[bytes, bytes]] = []
            # Force a candidate-only config proof mismatch after the parent
            # has booted. Its authenticated transfer must abort before COMMIT,
            # and the serving predecessor must resume every socket and WAL.
            original_config = config.read_text(encoding="utf-8")
            changed_config = original_config.replace("num_shards = 2", "num_shards = 3", 1)
            if changed_config == original_config:
                raise AssertionError("rollback fixture did not change config")
            config.write_text(changed_config, encoding="utf-8")
            oper.send(b"UPGRADE")
            try:
                wait_log_contains(root / "parent.log", "deferred UPGRADE failed")
            finally:
                config.write_text(original_config, encoding="utf-8")
            if image_pids(binary) != {serving_pid}:
                raise AssertionError("failed Helix left a successor or lost predecessor")
            for held in clients:
                held.ping(b"after-aborted-helix")
            rollback_account = b"walafterabort"
            rollback_secret = secrets.token_urlsafe(22).encode()
            rollback_writer = Client(port)
            clients.append(rollback_writer)
            rollback_writer.register(b"rollbackwriter")
            rollback_writer.command(b"REGISTER " + rollback_account + b" * " + rollback_secret, b"REGISTER SUCCESS", timeout=45)
            registered_after_swap.append((rollback_account, rollback_secret))
            departed = Client(port)
            departed.register(b"heldnick")
            departed.close()
            assert_nick_held(port, b"heldnick")
            owner.command(b"IRCX", b" 800 owner 1 0 ")
            owner.command(b"JOIN #slow-helix", b" 366 ")
            survivor.command(b"JOIN #slow-helix", b" 366 ")
            owner.send(b"PROP #slow-helix SLOWMODE :300")
            owner.ping(b"slowmode-configured")
            survivor.send(b"PRIVMSG #slow-helix :slow-first")
            owner.wait(b"PRIVMSG #slow-helix :slow-first")
            survivor.command(b"PRIVMSG #slow-helix :slow-second", b"slowmode")
            owner.command(b"CHANSTATS RECORD #slow-helix", b"messages=1")
            owner.command(b"ACCESS #slow-helix ADD DENY badaccess*!*@*", b"badaccess*!*@*")
            owner.command(b"CAP REQ :draft/metadata-2", b" ACK ")
            owner.command(b"METADATA * SET win-key * :held-value", b" 761 ")
            oper.command(b"CHANNEL REGISTER #mlock-helix", b"registered to helixadmin")
            oper.command(b"CHANNEL SET #mlock-helix MLOCK +nt", b"MLOCK set to +nt")
            oper.command(b"CHANNEL REGISTER #akick-helix", b"registered to helixadmin")
            oper.command(b"CHANNEL AKICK #akick-helix ADD bad*!*@* held-akick", b"AKICK added on #akick-helix")
            oper.command(b"RESV #resv-helix 0 :held-resv", b"RESV added: #resv-helix")
            oper.command(b"JUPE bad-helix.example 0 :held-jupe", b"JUPE added: bad-helix.example")
            oper.send(b"WARD ADD realname warden-helix node quarantine 0 :held-ward")
            oper.command(b"WARD LIST", b"WARD realname warden-helix node/quarantine")
            oper.command(b"SACCESS ADD HOLDNICK holdhelix-*", b"HOLDNICK holdhelix-*")
            shunned = Client(port)
            clients.append(shunned)
            shunned.register(b"shunprobe")
            start = len(owner.lines)
            shunned.send(b"PRIVMSG owner :before-shun")
            owner.wait(b"PRIVMSG owner :before-shun", start=start)
            oper.send(b"SHUN shunprobe 0 :held-shun")
            oper.command(b"SHUN", b"SHUN shunprobe by admin :held-shun")
            oper.command(b"FILTER ADD heldfilterword", b"FILTER: pattern added")
            oper.command(b"SPAMTRAP ADD NICK heldtrap", b"SPAMTRAP ADD NICK heldtrap")
            survivor.send(b"PRIVMSG heldtrap :first-trip")
            survivor.ping(b"first-trap-recorded")
            oper.command(b"SPAMTRAP LIST", b"1 offender(s), 1 total trip(s)")

            # One registration timeout creates a nonzero decaying reputation
            # row. A separate authenticated connection earns an account abuse
            # score from the configured non-disconnecting flood throttle.
            unregistered = Client(port)
            try:
                unregistered.wait(b"Registration timeout", timeout=15)
            finally:
                unregistered.close()
            if abuse_value(oper, b"survivor", b"reputation ") <= 0:
                raise AssertionError("registration timeout did not produce live reputation")
            abuse_probe = Client(port)
            clients.append(abuse_probe)
            abuse_probe.register(b"abuseprobe")
            abuse_secret = secrets.token_urlsafe(22).encode()
            abuse_probe.command(b"REGISTER heldabuse * " + abuse_secret, b"REGISTER SUCCESS", timeout=45)
            owner.command(b"MEMO FORWARD heldabuse", b"MEMO: Forwarding your offline memos to heldabuse")
            owner.command(b"MEMO IGNORE ADD heldabuse", b"MEMO: now ignoring memos from heldabuse")
            for _ in range(20):
                abuse_probe.send(b"WHO nobody")
            abuse_probe.ping(b"account-abuse-recorded")
            account_score = abuse_value(oper, b"abuseprobe", b"account heldabuse score=")
            if account_score <= 0:
                raise AssertionError("flood throttle did not produce live account abuse")
            oper.command(b"MODE survivor +z", b"MODE survivor +z")
            print("PASS: rejected Windows Helix candidate left held sockets and WAL writable", flush=True)
            for sequence in (1, 2):
                if sequence == 2:
                    oper.command(b"MODE survivor +z", b"MODE survivor +z")
                    oper.command(b"DRAIN", b"DRAIN enabled")
                oper.send(b"UPGRADE")
                next_pid = sole_image_pid(binary, different_from=serving_pid)
                marker = f"windows-helix-{sequence}".encode()
                for held in clients:
                    held.ping(marker)
                token_after = oper.command(b"SESSION TOKEN", b" :SESSION TOKEN ").split(b" :SESSION TOKEN ", 1)[1].split()[0]
                if token_after != token_before:
                    raise AssertionError("local reusable session token changed across Helix")
                if sequence == 2:
                    draining_probe = Client(port)
                    try:
                        try:
                            draining_probe.send(b"NICK drainprobe")
                            draining_probe.send(b"USER smoke 0 * :DRAIN probe")
                            draining_probe.wait(b" 001 ", timeout=5)
                        except TimeoutError as err:
                            raise AssertionError("DRAIN did not promptly refuse a fresh connection") from err
                        except (ConnectionError, OSError):
                            pass
                        else:
                            raise AssertionError("DRAIN admitted a fresh connection after Helix")
                    finally:
                        draining_probe.close()
                    oper.command(b"DRAIN OFF", b"DRAIN disabled")
                # GAG binds to the source IP. Test a new connection to prove
                # the restored set, then clear it before other message probes.
                gag_fresh = Client(port)
                clients.append(gag_fresh)
                gag_fresh.register(f"gagfresh{sequence}".encode())
                gag_marker = f"held-gag-{sequence}".encode()
                assert_silenced(gag_fresh, owner, b"PRIVMSG owner :" + gag_marker, gag_marker)
                oper.command(b"MODE survivor -z", b"MODE survivor -z")
                clean_marker = f"gag-cleared-{sequence}".encode()
                start = len(owner.lines)
                survivor.send(b"PRIVMSG owner :" + clean_marker)
                owner.wait(clean_marker, start=start)
                shun_marker = f"held-shun-{sequence}".encode()
                assert_silenced(shunned, owner, b"PRIVMSG owner :" + shun_marker, shun_marker)
                filter_marker = f"heldfilterword-{sequence}".encode()
                assert_silenced(survivor, owner, b"PRIVMSG owner :" + filter_marker, filter_marker)
                oper.command(b"SHUN", b"SHUN shunprobe by admin :held-shun")
                oper.command(b"FILTER LIST", b"FILTER LIST #1 heldfilterword")
                if abuse_value(oper, b"survivor", b"reputation ") <= 0:
                    raise AssertionError("IP reputation row vanished across Helix")
                if abuse_value(oper, b"abuseprobe", b"account heldabuse score=") < account_score:
                    raise AssertionError("account abuse score regressed across Helix")
                oper.command(b"SPAMTRAP LIST", f"1 offender(s), {sequence} total trip(s)".encode())
                survivor.send(b"PRIVMSG heldtrap :after-upgrade-trip")
                survivor.ping(f"trap-after-upgrade-{sequence}".encode())
                assert_nick_held(port, b"heldnick")
                survivor.command(b"PRIVMSG #slow-helix :slow-after-upgrade", b"slowmode")
                owner.command(b"METADATA * GET win-key", b"held-value")
                oper.command(b"CHANNEL INFO #mlock-helix", b"mlock=+nt")
                oper.command(b"CHANNEL AKICK #akick-helix LIST", b"AKICK #akick-helix bad*!*@* :held-akick")
                oper.command(b"RESV LIST", b"RESV #resv-helix :held-resv")
                oper.command(b"JUPE LIST", b"JUPE bad-helix.example (by admin) :held-jupe")
                oper.command(b"WARD LIST", b"WARD realname warden-helix node/quarantine")
                oper.command(b"WARD TEST realname warden-helix", b"WARD TEST: matched realname warden-helix")
                oper.command(b"SACCESS LIST HOLDNICK", b"HOLDNICK holdhelix-*")
                owner.command(b"ACCESS #slow-helix LIST", b"badaccess*!*@*")
                owner.command(b"AUTOJOIN LIST", b"AUTOJOIN #helix-settings")
                owner.command(b"GROUP LIST", b"GROUP owner-alt")
                oper.command(b"WELCOME SHOW", b"WELCOME :held welcome line")
                owner.command(b"MEMO FORWARD", b"MEMO: Forwarding your offline memos to heldabuse")
                owner.command(b"MEMO IGNORE LIST", b"MEMO: ignoring heldabuse")
                owner.command(b"CHANSTATS RECORD #slow-helix", b"messages=1")
                fresh = Client(port)
                clients.append(fresh)
                fresh.register(f"fresh{sequence}".encode())
                fresh.ping(marker)
                fresh.command(b"JOIN #resv-helix", b"held-resv")
                blocked = Client(port)
                try:
                    blocked.register(f"bad{sequence}".encode())
                    blocked.command(b"JOIN #akick-helix", b" 474 ")
                finally:
                    blocked.close()
                held_nick = Client(port)
                try:
                    held_nick.send(f"NICK holdhelix-{sequence}".encode())
                    held_nick.send(b"USER smoke 0 * :held SACCESS probe")
                    held_nick.wait(b" 432 ")
                finally:
                    held_nick.close()
                access_probe = Client(port)
                try:
                    access_probe.register(f"badaccess{sequence}".encode())
                    access_probe.command(b"JOIN #slow-helix", b" 474 ")
                finally:
                    access_probe.close()
                for earlier, (account, secret) in enumerate(registered_after_swap, 1):
                    verified = authenticate_account(port, account, secret, f"walold{sequence}{earlier}".encode())
                    clients.append(verified)
                account = f"walafter{sequence}".encode()
                secret = secrets.token_urlsafe(22).encode()
                fresh.command(b"REGISTER " + account + b" * " + secret, b"REGISTER SUCCESS", timeout=45)
                registered_after_swap.append((account, secret))
                verified = authenticate_account(port, account, secret, f"walnew{sequence}".encode())
                clients.append(verified)
                print(f"PASS: Windows Helix swap {sequence}, {serving_pid} -> {next_pid}; sockets, token and WAL reads/writes survived")
                serving_pid = next_pid
            oper.command(b"POLICY", b"POLICY: ward=2 filter=2 class=1 ban=1")
            oper.command(b"POLICY ROLLBACK", b"POLICY: rolled filter back to generation 1")
            oper.command(b"FILTER LIST", b"FILTER: End of filter list (0)")
            rollback_marker = b"heldfilterword-after-policy-rollback"
            start = len(owner.lines)
            survivor.send(b"PRIVMSG owner :" + rollback_marker)
            owner.wait(rollback_marker, start=start)
            if parent.wait(timeout=2) != 0:
                raise AssertionError("original predecessor did not exit cleanly")
            return 0
        except Exception:
            log.flush()
            print((root / "parent.log").read_text(encoding="utf-8", errors="replace")[-8000:])
            for index, client in enumerate(clients):
                print(f"client {index} recent lines: {client.lines[-5:]!r}")
                client.socket.settimeout(0.1)
                try:
                    while chunk := client.socket.recv(65536):
                        print(f"client {index} pending: {chunk!r}")
                except (OSError, TimeoutError):
                    pass
            raise
        finally:
            for client in clients:
                client.close()
            try:
                for pid in image_pids(binary):
                    os.kill(pid, 15)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=10)
                until = time.monotonic() + 10
                while image_pids(binary) and time.monotonic() < until:
                    time.sleep(0.1)
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
