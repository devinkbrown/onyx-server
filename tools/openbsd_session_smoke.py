#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise accounts, reusable attachments and Helix in an isolated OpenBSD VM.

Creates three private fixtures under /tmp/onyx-session-native, with a secured
A-B-C line on ports 33500/33510/33520. Run from the host, through SSH loopback
forwards. Private loopback aliases model three distinct hosts; their address
baseline and the temporary packet-filter policy are restored on exit. The guest
binary is copied and pinned before use. All fixture processes and forwards are
stopped on exit; credentials and protocol transcripts are never printed. This
deliberately exercises configured SRM1 multi-attachment issuance.

--same-ip-reciprocal uses existing 127.0.0.1 with distinct ports and reciprocal
dials, at the normal 8 MiB stack limit. It requires --skip-partition: the
default address-based PF partition cannot isolate peers sharing one address.
"""

import argparse
import base64
import json
import re
import secrets
import shlex
import socket
import subprocess
import time
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openbsd_runtime_smoke import Client


CAPS = b"message-tags server-time echo-message onyx/session-sync"
ROOM = b"#native-sessions"


class Probe(Client):
    def __init__(self, port):
        super().__init__(port, "tls13")
        self.sock.settimeout(.05)
        self.label = "unregistered"

    def pump(self):
        try:
            lines = self.collect()
        except (socket.timeout, TimeoutError):
            return
        for line in lines:
            if line.startswith(b"PING "):
                self.send(b"PONG " + line[5:] + b"\r\n")

    def wait(self, predicate, start, operation, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for line in self.seen[start:]:
                if predicate(line):
                    return line
            self.pump()
        raise TimeoutError(f"{self.label}: {operation} response absent")

    def command(self, command, needle, operation, timeout=20):
        start = len(self.seen)
        self.send(command + b"\r\n")
        return self.wait(lambda line: needle in line, start, operation, timeout)

    def register(self, nick, account=None, password=None, opaque=None):
        self.label = nick
        self.command(b"CAP LS 302", b" LS ", "capability discovery")
        caps = CAPS + (b" sasl" if account else b"")
        response = self.command(b"CAP REQ :" + caps, b" CAP ", "capability negotiation")
        if b" ACK " not in response or not all(cap in response for cap in caps.split()):
            raise RuntimeError(f"{nick}: required capability refused")
        if account:
            mechanism = b"SESSION-TOKEN" if opaque else b"PLAIN"
            self.command(b"AUTHENTICATE " + mechanism, b"AUTHENTICATE +", "SASL challenge")
            raw = account.encode() + b"\0" + opaque if opaque else (
                b"\0" + account.encode() + b"\0" + password.encode())
            start = len(self.seen)
            self.send(b"AUTHENTICATE " + base64.b64encode(raw) + b"\r\n")
            response = self.wait(lambda line: any(b" " + code + b" " in line
                                                for code in (b"903", b"904", b"905", b"906", b"907")),
                                 start, "SASL completion")
            if b" 903 " not in response:
                code = next(code for code in (b"904", b"905", b"906", b"907")
                            if b" " + code + b" " in response)
                raise RuntimeError(f"{nick}: SASL refused (numeric {code.decode()})")
        start = len(self.seen)
        self.send(b"CAP END\r\nNICK " + nick.encode() +
                  b"\r\nUSER fixture 0 * :isolated native session fixture\r\n")
        welcome = self.wait(lambda line: b" 001 " in line, start, "registration")
        fields = welcome.split()
        self.nick = fields[fields.index(b"001") + 1]

    def wait_nick(self, nick):
        # Registration is local; wait for the separately replicated remote
        # nickname route before asking the daemon to admit a direct message.
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            start = len(self.seen)
            self.send(b"WHOIS " + nick + b"\r\n")
            self.wait(lambda line: b" 318 " in line, start, "nickname route convergence")
            if any(b" 311 " in line for line in self.seen[start:]):
                return
            time.sleep(.25)
        raise TimeoutError(f"{self.label}: independent recipient nickname route absent")

    def join(self):
        self.command(b"JOIN " + ROOM, b" 366 ", "channel membership")

    def tokens(self):
        start = len(self.seen)
        self.send(b"SESSION TOKEN\r\n")
        local = self.wait(lambda line: b" :SESSION TOKEN " in line, start, "local session token")
        mesh = self.wait(lambda line: b" :SESSION MTOKEN " in line, start, "portable session token")
        return (local.split(b" :SESSION TOKEN ", 1)[1].split()[0],
                mesh.split(b" :SESSION MTOKEN ", 1)[1].split()[0])

    def resume(self, credential):
        end = time.monotonic() + 40
        reported_redirect = False
        while time.monotonic() < end:
            start = len(self.seen)
            self.send(b"SESSION RESUME " + credential + b"\r\n")
            response = self.wait(lambda line: b"SESSION RESUME:" in line or
                                 b"SESSION REDIRECT:" in line or
                                 b"FAIL SESSION " in line or b"WARN SESSION " in line,
                                 start, "session attachment",
                                 timeout=min(20, max(.001, end - time.monotonic())))
            if b"SESSION RESUME:" in response and any(word in response for word in
                                                      (b"attached", b"restored")):
                return
            if b"SESSION REDIRECT:" in response:
                # The SRM1 handler marks this exact outcome retryable while its
                # authenticated replica is still converging. Continue with the
                # same credential and require actual attachment within 40s.
                if not reported_redirect:
                    print(f"WAIT {self.label}: SESSION REDIRECT while the signed replica converges", flush=True)
                    reported_redirect = True
            elif b"WARN SESSION " not in response:
                raise RuntimeError(f"{self.label}: reusable attachment refused")
            time.sleep(.25)
        raise TimeoutError(f"{self.label}: reusable attachment never became ready")


class Fixture:
    binary = "/tmp/onyx-full-native/onyx-server"

    def __init__(self, args):
        self.args = args
        self.source_binary = args.binary
        self.ssh = ["ssh", "-p", str(args.ssh_port), "-i", args.identity,
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=" + args.known_hosts, "root@127.0.0.1"]
        self.directory = "/tmp/onyx-session-native/" + secrets.token_hex(8)
        self.binary = self.directory + "/onyx-server"
        self.tunnel = None
        self.clients = []
        self.expected_events = []
        self.pf_active = False
        self.pf_original_hash = None
        self.pf_original_rules = None
        self.hosts = (("127.0.0.1",) * 3 if args.same_ip_reciprocal else
                      ("127.0.0.31", "127.0.0.32", "127.0.0.33"))
        self.alias_baseline = None
        self.owned_aliases = []
        self.account = "nativesession"
        self.password = secrets.token_urlsafe(24)
        self.configs = [f"{self.directory}/node{i + 1}.toml" for i in range(3)]

    def remote(self, command, data=None):
        result = subprocess.run(self.ssh + [command], input=data, text=True,
                                capture_output=True, timeout=20)
        if result.returncode:
            # Remote error text may contain private successor argv or a token.
            raise RuntimeError("isolated VM operation failed (exit " + str(result.returncode) + ")")
        return result.stdout.strip()

    def pids(self, index):
        pattern = "^" + re.escape(self.binary) + " .*" + re.escape(self.configs[index]) + "$"
        result = subprocess.run(self.ssh + ["pgrep -f " + shlex.quote(pattern)],
                                text=True, capture_output=True, timeout=10)
        if result.returncode not in (0, 1) or any(not pid.isdigit() for pid in result.stdout.split()):
            raise RuntimeError("isolated process query failed")
        return set(result.stdout.split())

    def loopback_addresses(self):
        return tuple(sorted(line.strip() for line in self.remote("ifconfig lo0").splitlines()
                            if line.strip().startswith(("inet ", "inet6 "))))

    def setup_aliases(self):
        self.alias_baseline = self.loopback_addresses()
        present = {line.split()[1] for line in self.alias_baseline}
        if self.args.same_ip_reciprocal:
            if "127.0.0.1" not in present:
                raise RuntimeError("standard loopback address absent")
            return
        if any(host in present for host in self.hosts):
            raise RuntimeError("a private fixture loopback alias is already owned")
        for host in self.hosts:
            # Record the attempted addition first, so even a partial remote
            # operation is cleaned up. All three addresses were absent above.
            self.owned_aliases.append(host)
            self.remote("ifconfig lo0 inet " + host + " netmask 255.255.255.255 alias")
        if not set(self.hosts).issubset({line.split()[1] for line in self.loopback_addresses()}):
            raise RuntimeError("private fixture loopback alias installation failed")

    def restore_aliases(self):
        failures = []
        for host in self.owned_aliases:
            try:
                if host in {line.split()[1] for line in self.loopback_addresses()}:
                    self.remote("ifconfig lo0 inet " + host + " -alias")
            except (RuntimeError, subprocess.TimeoutExpired):
                failures.append(host)
        if failures:
            raise RuntimeError("private loopback alias cleanup failed")
        self.owned_aliases.clear()
        if self.alias_baseline is not None and self.loopback_addresses() != self.alias_baseline:
            raise RuntimeError("loopback address baseline changed during the fixture")

    def boot(self, index):
        config = shlex.quote(self.configs[index])
        log = shlex.quote(f"{self.directory}/node{index + 1}.log")
        stack_kib = 8192 if self.args.same_ip_reciprocal else 65536
        self.remote(f"ulimit -s {stack_kib} || exit 1; nohup {self.binary} {config} </dev/null >>{log} 2>&1 &")
        # Bring up the downstream listener before its upstream node dials it.
        # A forwarded host socket alone proves only SSH accepted the channel.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if len(self.pids(index)) != 1:
                    time.sleep(.1)
                    continue
                self.remote("nc -z -w 1 " + self.hosts[index] + " " + str(33500 + index * 10))
                if len(self.pids(index)) != 1:
                    raise RuntimeError("fixture listener lacks its unique owning process")
                return
            except RuntimeError:
                time.sleep(.1)
        raise TimeoutError(f"node {index + 1}: actual guest listener absent")

    def setup(self):
        if self.remote("uname -s") != "OpenBSD":
            raise RuntimeError("fixture requires an OpenBSD VM")
        self.remote("umask 077; mkdir -p " + shlex.quote(self.directory))
        # Every boot and successor executes this private snapshot. Verify the
        # copied image, so a concurrent shared-artifact refresh cannot change
        # the image after its acceptance digest was checked.
        self.remote("cp " + shlex.quote(self.source_binary) + " " +
                    shlex.quote(self.binary) + "; chmod 500 " + shlex.quote(self.binary))
        digest = self.remote("sha256 -q " + shlex.quote(self.binary))
        if digest != self.args.expected_sha256:
            raise RuntimeError("native artifact differs from required build digest")
        print("ARTIFACT native daemon sha256=" + digest, flush=True)
        # Default aliases model separate hosts. The reciprocal mode exercises
        # endpoint bindings when all peers share one address.
        self.setup_aliases()
        for node, host in enumerate(self.hosts):
            for offset in (0, 1, 3, 4):
                port = str(33500 + node * 10 + offset)
                self.remote("if nc -z -w 1 " + host + " " + port +
                            "; then exit 1; fi")
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        public = [key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw).hex() for key in keys]
        mesh_pass = secrets.token_urlsafe(32)
        for i, key in enumerate(keys):
            base = 33500 + i * 10
            neighbors = (1,) if i != 1 else (0, 2)
            connections = ([f"{self.hosts[n]}:{33503 + n * 10}" for n in neighbors]
                           if self.args.same_ip_reciprocal else
                           [f"{self.hosts[i + 1]}:{33513 if i == 0 else 33523}"] if i < 2 else [])
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption()).hex()
            config = f'''[node]
id = {31 + i}
secret_key = "{seed}"
public_key = "{public[i]}"
[network]
server_name = "session-{i + 1}.openbsd.test"
[listen]
host = "{self.hosts[i]}"
irc = {base}
s2s = {base + 3}
[tls]
enabled = true
port = {base + 1}
dns_name = "session-{i + 1}.openbsd.test"
[mesh]
realm = "native-session-acceptance"
mesh_pass = "{mesh_pass}"
require_secured = true
trust_roots = {json.dumps([public[n] for n in neighbors])}
connect = {json.dumps(connections)}
relay_v2_authoring = "active"
relay_v2_activation_epoch = 1
relay_v2_roster = {json.dumps(public)}
[limits]
num_shards = 2
max_clients = 32
[sasl]
enabled = true
account_db = "{self.directory}/accounts-{i + 1}.wal"
[sessions]
resume_composite_issuance = false
[metrics]
listen = {base + 4}
bind = "{self.hosts[i]}"
[cloak]
secret = "{mesh_pass}"
'''
            self.remote("umask 077; cat >" + shlex.quote(self.configs[i]), config)
            self.remote(f"{self.binary} --check-config {shlex.quote(self.configs[i])} >{shlex.quote(self.directory + '/check-' + str(i) + '.log')} 2>&1")
        forwards = []
        for i in range(3):
            for offset in (1, 4):
                forwards += ["-L", f"127.0.0.1:{self.args.local_base + 10 * i + offset}:{self.hosts[i]}:{33500 + 10 * i + offset}"]
        self.tunnel = subprocess.Popen(self.ssh[:-1] + ["-o", "ExitOnForwardFailure=yes", "-N"] +
                                       forwards + self.ssh[-1:], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        time.sleep(.3)
        if self.tunnel.poll() is not None:
            raise RuntimeError("isolated SSH forwards failed")
        for i in (2, 1, 0):
            self.boot(i)
        self.health()
        topology = ("one IP, distinct ports, reciprocal dials, stack 8192 KiB"
                    if self.args.same_ip_reciprocal else "three distinct addresses")
        print(f"PASS OpenBSD three pinned nodes: {topology}; secured A-B-C line, degrees 1/2/1", flush=True)

    def health(self, degrees=(1, 2, 1), timeout=45):
        deadline = time.monotonic() + timeout
        observed = []
        while time.monotonic() < deadline:
            try:
                observed = []
                for i, expected in enumerate(degrees):
                    if len(self.pids(i)) != 1:
                        raise RuntimeError("mesh health lacks its unique fixture process")
                    port = self.args.local_base + i * 10 + 4
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
                        text = response.read().decode()
                    match = re.search(r"^onyx_s2s_links_active (\d+)$", text, re.M)
                    observed.append(int(match[1]) if match else -1)
                if observed != list(degrees):
                    raise ValueError("secured topology incomplete")
                return
            except (OSError, ValueError):
                time.sleep(.2)
        raise TimeoutError("secured line did not converge; observed degrees=" +
                           "/".join(map(str, observed)))

    def client(self, node, nick, authenticated=True, opaque=None):
        client = Probe(self.args.local_base + 10 * node + 1)
        self.clients.append(client)
        client.register(nick, self.account if authenticated else None, self.password, opaque)
        return client

    def accounts(self):
        for node in range(3):
            client = self.client(node, f"Registrar{node}", authenticated=False)
            client.command(b"REGISTER " + self.account.encode() + b" * " + self.password.encode(),
                           b"REGISTER SUCCESS ", "durable account registration", timeout=30)
        print("PASS REGISTER: separate durable account stores on all three native nodes", flush=True)

    def event(self, source, clients, target, marker, immediate=None):
        required = clients if immediate is None else immediate
        if not required or source not in required or any(client not in clients for client in required):
            raise ValueError("event observation lacks its author or an eligible recipient")
        starts = [len(client.seen) for client in clients]
        source.send(b"PRIVMSG " + target + b" :" + marker + b"\r\n")
        needle = b"PRIVMSG " + target + b" :" + marker
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            for client in clients:
                client.pump()
            if all(any(needle in line for line in client.seen[starts[clients.index(client)]:])
                   for client in required):
                break
        else:
            missing = [client.label for client in required
                       if not any(needle in line for line in client.seen[starts[clients.index(client)]:])]
            outcomes = []
            for line in source.seen[starts[clients.index(source)]:]:
                parts = line.split()
                for index, word in enumerate(parts):
                    if word in (b"FAIL", b"WARN") and index + 2 < len(parts):
                        outcomes.append(parts[index + 1].decode("ascii", "replace") + ":" +
                                        parts[index + 2].decode("ascii", "replace"))
                    elif len(word) == 3 and word.isdigit():
                        outcomes.append("numeric:" + word.decode())
            raise TimeoutError("accepted event absent at " + ",".join(missing) +
                               "; sender outcomes=" + ",".join(outcomes))
        end = time.monotonic() + .35
        while time.monotonic() < end:
            for client in clients:
                client.pump()
        identities = []
        for client in required:
            start = starts[clients.index(client)]
            lines = [line for line in client.seen[start:] if needle in line]
            if len(lines) != 1:
                raise RuntimeError(f"{client.label}: event count {len(lines)}, expected one")
            if not lines[0].startswith(b"@"):
                raise RuntimeError("event identity tags absent")
            tags = dict(tag.split(b"=", 1) for tag in lines[0][1:].split(b" ", 1)[0].split(b";") if b"=" in tag)
            if not tags.get(b"msgid") or not tags.get(b"time"):
                raise RuntimeError("accepted msgid/server-time absent")
            identities.append((tags[b"msgid"], tags[b"time"]))
        if len(set(identities)) != 1:
            raise RuntimeError("accepted event identity differs between physical attachments")
        self.expected_events.append((needle, tuple(clients), identities[0]))

    def block_far_link(self):
        baseline = self.remote("cat /etc/pf.conf")
        if not re.search(r"^set skip on lo\s*$", baseline, re.M):
            raise RuntimeError("VM packet-filter baseline differs from the isolated fixture contract")
        if not self.remote("pfctl -s info").startswith("Status: Enabled"):
            raise RuntimeError("VM packet filter must already be enabled")
        self.pf_original_hash = self.remote("sha256 -q /etc/pf.conf")
        self.pf_original_rules = self.remote("pfctl -sr")
        self.remote("umask 077; cat >" + shlex.quote(self.directory + "/baseline.pf"),
                    baseline + "\n")
        # Only C's S2S listener is cut. Keep A-B, SSH, original client sockets,
        # metrics and the other isolated probes passing, including midstreams.
        baseline = re.sub(r"^set skip on lo\s*$", "", baseline, flags=re.M)
        rules = ("block return-rst quick on lo0 proto tcp from any port 33523 to any\n"
                 "block return-rst quick on lo0 proto tcp from any to any port 33523\n"
                 "pass quick on lo0 all flags any no state\n" + baseline + "\n")
        path = shlex.quote(self.directory + "/partition.pf")
        self.remote("umask 077; cat >" + path, rules)
        self.remote("pfctl -nf " + path)
        self.pf_active = True  # partial-load failure must also restore baseline
        self.remote("pfctl -f " + path)
        if "skip" in self.remote("pfctl -s Interfaces -i lo0 -v"):
            raise RuntimeError("loopback packet filtering remained bypassed")

    def restore_pf(self):
        if not self.pf_active:
            return
        # Restore first; a later integrity diagnostic must never leave the cut
        # active. The original configuration file itself was never overwritten.
        self.remote("pfctl -f " + shlex.quote(self.directory + "/baseline.pf"))
        self.pf_active = False
        if self.remote("sha256 -q /etc/pf.conf") != self.pf_original_hash:
            raise RuntimeError("VM packet-filter baseline changed during the fixture")
        if self.remote("pfctl -sr") != self.pf_original_rules:
            raise RuntimeError("VM packet-filter rules differ after restoration")
        if "skip" not in self.remote("pfctl -s Interfaces -i lo0 -v"):
            raise RuntimeError("original loopback packet-filter bypass was not restored")

    def partition(self, attached, observer, token):
        clients = attached + [observer]
        first = len(self.expected_events)
        self.block_far_link()
        try:
            near = attached[:3]
            far = attached[3]
            self.event(attached[0], clients, ROOM, b"partition-near-channel", near)
            self.event(attached[0], attached, attached[0].nick, b"partition-near-direct", near)
            self.event(far, clients, ROOM, b"partition-far-channel", [far, observer])
            self.event(far, attached, attached[0].nick, b"partition-far-direct", [far])
            # PF may also drop a synthesized RST in the opposite direction.
            # Mooring's normal idle timeout is 45s and its daemon health stall
            # is 60s; observe their existing deadlines plus a 10s poll margin.
            try:
                self.health((1, 1, 0), timeout=70)
            except TimeoutError:
                self.partition_diagnostic("cut")
                raise
            for client in clients:
                tag = b"partition-original-physical-ping-" + client.label.encode()
                client.command(b"PING :" + tag, tag, "physical attachment during partition")
            # The first near event was accepted on A/B but could not cross to C.
            if any(self.expected_events[first][0] in line for line in far.seen):
                raise RuntimeError("far-link cut did not isolate the expected event")
            print("PASS actual B-C partition: secured degrees 1/1/0, all original client sockets answer PING; channel/direct events retained on both sides", flush=True)
        finally:
            self.restore_pf()
        try:
            self.health()
        except TimeoutError:
            self.partition_diagnostic("rejoin")
            raise
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            for client in clients:
                client.pump()
            if all(any(needle in line for line in client.seen)
                   for needle, recipients, _ in self.expected_events[first:]
                   for client in recipients):
                break
        else:
            raise TimeoutError("retained partition events did not converge after rejoin")
        self.cumulative_events(clients)
        for client in attached:
            if client.tokens()[0] != token:
                raise RuntimeError("reusable token changed across link partition/rejoin")
        print("PASS B-C rejoin: secured degrees 1/2/1; retained channel/direct deliveries converge exactly once with equal msgid/time and original tokens", flush=True)

    def partition_diagnostic(self, phase):
        # Keep diagnostics bounded to fixture metrics and TCP/PF state. A
        # diagnostic failure must not replace the original acceptance failure.
        try:
            path = shlex.quote(self.directory + "/partition-" + phase + ".log")
            self.remote("pfctl -vvsr >" + path +
                        "; pfctl -s Interfaces -i lo0 -v >>" + path +
                        "; netstat -an -p tcp | grep 33523 >>" + path + " || true")
            for node in range(3):
                port = self.args.local_base + node * 10 + 4
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
                    metrics = response.read().decode()
                target = shlex.quote(self.directory + f"/partition-{phase}-node{node + 1}.metrics")
                self.remote("umask 077; cat >" + target, metrics)
            print(f"DIAGNOSTIC partition {phase}: bounded metrics/PF/TCP state retained with fixture logs", flush=True)
        except Exception as error:
            print(f"DIAGNOSTIC partition {phase} capture failed: {type(error).__name__}", flush=True)

    def cumulative_events(self, clients):
        # A response barrier plus a bounded final drain checks every earlier
        # marker, including duplicates delayed across intervening upgrades.
        for index, client in enumerate(clients):
            tag = f"cumulative-delivery-barrier-{index}".encode()
            client.command(b"PING :" + tag, tag, "cumulative delivery barrier")
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            for client in clients:
                client.pump()
        for needle, recipients, identity in self.expected_events:
            for client in recipients:
                lines = [line for line in client.seen if needle in line]
                if len(lines) != 1:
                    raise RuntimeError(f"{client.label}: cumulative event count {len(lines)}, expected one")
                tags = dict(tag.split(b"=", 1) for tag in lines[0][1:].split(b" ", 1)[0].split(b";") if b"=" in tag)
                if (tags.get(b"msgid"), tags.get(b"time")) != identity:
                    raise RuntimeError("cumulative accepted event identity changed")
        deliveries = sum(len(recipients) for _, recipients, _ in self.expected_events)
        print(f"PASS cumulative delivery oracle: {len(self.expected_events)} accepted events, {deliveries} exact recipient deliveries through final finite drain", flush=True)

    def participation(self, attached, observer, phase):
        clients = attached + [observer]
        for index, source in enumerate(attached):
            self.event(source, clients, ROOM, f"{phase}-channel-{index}".encode())
            if self.args.foreign_nick_proof:
                self.event(source, clients, observer.nick, f"{phase}-direct-{index}".encode())
            else:
                # Direct traffic to the exact shared session identity reaches
                # every attachment; the independent observer is not a recipient.
                self.event(source, attached, attached[0].nick, f"{phase}-direct-{index}".encode())
        self.event(observer, clients, attached[0].nick, f"{phase}-recipient-session".encode())
        for index, client in enumerate(clients):
            tag = f"{phase}-physical-ping-{index}".encode()
            client.command(b"PING :" + tag, tag, "original socket PING")
        print(f"PASS {phase}: {len(attached)} original shared attachments, independent channel/direct participation; one equal msgid/time per recipient", flush=True)

    def upgrade(self, node):
        old = self.pids(node)
        if len(old) != 1:
            raise RuntimeError("fixture predecessor count differs from one")
        old_pid = next(iter(old))
        self.remote("kill -USR2 " + old_pid)
        end = time.monotonic() + 45
        while time.monotonic() < end:
            current = self.pids(node)
            if len(current) == 1 and old_pid not in current:
                self.health()
                print(f"PASS native fork/exec COMMIT on node {node + 1}: predecessor exited, secured line recovered", flush=True)
                return
            time.sleep(.2)
        raise TimeoutError(f"node {node + 1}: native Helix COMMIT absent")

    def dial_counts(self):
        # Return only controlled counters, never private daemon log contents.
        result = []
        for node in range(3):
            log = shlex.quote(f"{self.directory}/node{node + 1}.log")
            count = self.remote("awk '/\\(dial initiated\\)/ {n++} END {print n+0}' " + log)
            if not count.isdigit():
                raise RuntimeError("fixture dial counter malformed")
            result.append(int(count))
        return tuple(result)

    def stable_dials(self, phase, expected=None):
        # Two complete ten-second retry intervals must pass without a dial.
        before = self.dial_counts()
        if sum(before) < 4:
            raise RuntimeError("reciprocal dial diagnostics absent")
        if expected is not None and before != expected:
            raise RuntimeError("configured dial churn during sequential Helix")
        deadline = time.monotonic() + 22
        while time.monotonic() < deadline:
            self.health()
            for client in self.clients:
                client.pump()
            time.sleep(.2)
        if self.dial_counts() != before:
            raise RuntimeError("configured dial churn " + phase)
        print("PASS same-IP endpoint bindings: no new dial across two periodic redial intervals " + phase, flush=True)
        return before

    def stop(self, node):
        for pid in self.pids(node):
            self.remote("kill -TERM " + pid)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.pids(node):
            time.sleep(.1)
        for pid in self.pids(node):
            self.remote("kill -KILL " + pid)
        if self.pids(node):
            raise RuntimeError("isolated fixture process could not be stopped")

    def cleanup(self):
        failures = []
        try:
            self.restore_pf()
        except (RuntimeError, subprocess.TimeoutExpired):
            failures.append("packet-filter restoration")
        for client in self.clients:
            try:
                client.sock.close()
            except OSError:
                failures.append("client close")
        self.clients.clear()
        for node in range(3):
            try:
                self.stop(node)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                failures.append(f"node {node + 1} process stop")
        if self.tunnel:
            try:
                self.tunnel.terminate()
                try:
                    self.tunnel.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.tunnel.kill()
                    self.tunnel.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                failures.append("SSH forward cleanup")
        try:
            self.restore_aliases()
        except (RuntimeError, subprocess.TimeoutExpired):
            failures.append("loopback alias restoration")
        if failures:
            raise RuntimeError("fixture cleanup incomplete: " + ", ".join(failures))
        print("CLEANUP fixture PIDs: zero; loopback/PF baseline restored; private configs/WAL/logs retained at " + self.directory, flush=True)

    def run(self):
        self.setup()
        self.accounts()
        origin = self.client(0, "Origin")
        origin.join()
        local, portable = origin.tokens()
        if len(local) != 32 or not re.fullmatch(b"[0-9a-f]{32}", local):
            raise RuntimeError("configured reusable SRM1 local credential absent")
        origin.command(b"SESSIONTOKEN", b" :SESSIONTOKEN ", "opaque account reconnect token")
        sibling = self.client(0, "NearSibling")
        sibling.resume(local)
        middle = self.client(1, "MiddleAttachment")
        middle.resume(portable)
        far = self.client(2, "FarAttachment")
        far.resume(portable)
        attached = [origin, sibling, middle, far]
        registrar = self.client(2, "ObserverRegistrar", authenticated=False)
        observer_account = "nativeobserver"
        registrar.command(b"REGISTER " + observer_account.encode() + b" * " + self.password.encode(),
                          b"REGISTER SUCCESS ", "independent recipient account registration", timeout=30)
        observer = Probe(self.args.local_base + 21)
        self.clients.append(observer)
        observer.register("Observer", observer_account, self.password)
        observer.join()
        observer.tokens()  # publish signed reusable identity before cross-node DM
        if self.args.foreign_nick_proof:
            for client in attached:
                client.wait_nick(observer.nick)
            observer.wait_nick(origin.nick)
        for client in attached:
            if client.tokens()[0] != local:
                raise RuntimeError("shared token differs after reusable attachment")
        print("PASS PLAIN SASL before NICK + SESSIONTOKEN + four reusable same-token physical attachments across all nodes", flush=True)
        self.participation(attached, observer, "before-upgrade")
        if self.args.skip_partition:
            print("SKIP partition: this run isolates sequential Helix/session acceptance", flush=True)
        else:
            self.partition(attached, observer, local)
        settled_dials = (self.stable_dials("before upgrades")
                         if self.args.same_ip_reciprocal else None)
        for node in range(3):
            self.upgrade(node)
            if settled_dials is not None and self.dial_counts() != settled_dials:
                raise RuntimeError(f"configured dial churn during node {node + 1} Helix")
            for client in attached:
                if client.tokens()[0] != local:
                    raise RuntimeError("local group token changed across sequential Helix")
            self.participation(attached, observer, f"after-node-{node + 1}")
        if self.args.same_ip_reciprocal:
            self.stable_dials("after all three native upgrades", settled_dials)
        fifth = self.client(2, "LaterFarAttachment")
        fifth.resume(portable)
        attached.append(fifth)
        if fifth.tokens()[0] != local:
            raise RuntimeError("portable credential ceased to be reusable after Helix")
        self.participation(attached, observer, "fifth-far-resume")
        self.cumulative_events(attached + [observer])
        # Each password login intentionally rotates this account's opaque token.
        # Persist the final issued token after all such logins, and verify it
        # before the next password login can legitimately revoke it.
        opaque_line = origin.command(b"SESSIONTOKEN", b" :SESSIONTOKEN ", "final durable account reconnect token")
        expiry = re.search(rb" expires=(\d+)", opaque_line)
        if expiry is None or int(expiry[1]) <= int(self.remote("date +%s")):
            raise RuntimeError("issued opaque credential is already expired in the Unix clock domain")
        opaque = opaque_line.split(b" :SESSIONTOKEN ", 1)[1].split()[1]
        for client in self.clients:
            client.sock.close()
        self.clients.clear()
        for node in range(3):
            self.stop(node)
        for node in (2, 1, 0):
            self.boot(node)
        self.health()
        reconnect = self.client(0, "ColdOpaqueProof", opaque=opaque)
        reconnect.command(b"PING :cold-opaque", b"cold-opaque", "durable SESSION-TOKEN proof")
        cold = self.client(0, "ColdPasswordProof")
        cold.command(b"PING :cold-account", b"cold-account", "cold account proof")
        print("PASS cold restart: stored account/password and issued opaque SESSION-TOKEN authenticate from durable WAL", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--ssh-port", type=int, default=2225)
    parser.add_argument("--local-base", type=int, default=43500)
    parser.add_argument("--foreign-nick-proof", action="store_true",
                        help="add far-only nickname convergence and separate-recipient DM coverage")
    parser.add_argument("--skip-partition", action="store_true",
                        help="isolate sequential Helix evidence; default includes actual B-C partition")
    parser.add_argument("--same-ip-reciprocal", action="store_true",
                        help="use one IP and reciprocal dials; requires --skip-partition")
    parser.add_argument("--binary", choices=("/tmp/onyx-full-native/onyx-server", "/tmp/onyx-session-native/onyx-server"),
                        default="/tmp/onyx-full-native/onyx-server")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        parser.error("required build digest must be lowercase SHA-256")
    if not 1024 <= args.local_base <= 65510 or not 1 <= args.ssh_port <= 65535:
        parser.error("invalid loopback port range")
    if args.same_ip_reciprocal and not args.skip_partition:
        parser.error("--same-ip-reciprocal requires --skip-partition; PF cannot isolate shared-IP peers")
    fixture = Fixture(args)
    try:
        fixture.run()
    finally:
        fixture.cleanup()


if __name__ == "__main__":
    main()
