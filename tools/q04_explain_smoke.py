#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private loopback Q04 TCP/TLS proof. Never targets an existing daemon.

Requires a SHA256-pinned candidate and a NEW artifacts directory below a private
0700 directory. Captures stay private; stdout contains only fixed stages/counts.
Uses the retained setup review protocol and account-bound operator elevation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import time
from setup_review_client import run_review

LIMIT = 1024 * 1024
HOST = '127.0.0.1'

class Failure(Exception):
    pass

def require(condition, code='assertion'):
    if not condition:
        raise Failure(code)

def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)

def pin_binary(source, destination, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected) is not None, 'hash_format')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= 512 * LIMIT, 'binary_custody')
        digest = hashlib.sha256()
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        with os.fdopen(out, 'wb') as target:
            while block := stream.read(1024 * 1024):
                digest.update(block)
                target.write(block)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'binary_changed')
        require(digest.hexdigest() == expected, 'binary_hash')
    os.chmod(destination, 0o500)

def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * LIMIT, 4 * LIMIT))

def stop(process):
    if process is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue
    raise Failure('cleanup_timeout')

def free_ports():
    held = []
    try:
        for _ in range(3):
            item = socket.socket()
            item.bind((HOST, 0))
            held.append(item)
        return [item.getsockname()[1] for item in held]
    finally:
        for item in held:
            item.close()

def explain(lines):
    return [line.split(b' :ACCESS EXPLAIN ', 1)[1] for line in lines
            if b' :ACCESS EXPLAIN ' in line]

def contains(lines, needle):
    require(any(needle in line for line in lines), 'missing_reply')

def labeled(lines, label):
    # Existing protocol renderer uses one request-local suzu-label batch ref.
    wanted = b'@label=' + label + b' BATCH +suzu-label labeled-response'
    selected = [line for line in lines if line == wanted or
                line == b'BATCH -suzu-label' or b'ACCESS EXPLAIN' in line]
    require(len(selected) >= 4 and selected[0] == wanted and
            selected[-1] == b'BATCH -suzu-label', 'label_envelope')
    require(sum(line == wanted for line in lines) == 1 and
            sum(line == b'BATCH -suzu-label' for line in lines) == 1, 'label_count')
    for line in selected[1:-1]:
        require(line.startswith(b'@batch=suzu-label :'), 'label_payload')
    require(all(len(line) + 2 <= 512 for line in lines), 'wire_budget')
    return explain(selected)

class Client:
    def __init__(self, port, transcript):
        raw = socket.create_connection((HOST, port), timeout=2)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # child-owned fresh loopback certificate
        try:
            self.sock = context.wrap_socket(raw, server_hostname='q04.example.test')
        except BaseException:
            raw.close()
            raise
        self.pending = b''
        self.log = transcript
        self.total = 0
        self.serial = 0
    def send(self, text):
        encoded = text.encode()
        require(b'\r' not in encoded and b'\n' not in encoded and len(encoded) <= 510, 'client_line')
        self.sock.sendall(encoded + b'\r\n')
    def line(self, deadline):
        while b'\r\n' not in self.pending:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'reply_timeout')
            self.sock.settimeout(remaining)
            block = self.sock.recv(8192)
            require(bool(block), 'connection_closed')
            self.pending += block
            require(len(self.pending) <= 65536, 'recv_bound')
        line, self.pending = self.pending.split(b'\r\n', 1)
        require(len(line) + 2 <= 512, 'wire_budget')
        self.total += len(line) + 2
        require(self.total <= LIMIT, 'transcript_bound')
        self.log.write(line + b'\r\n')
        self.log.flush()
        if line.startswith(b'PING '):
            self.send('PONG ' + line[5:].decode('ascii'))
        return line
    def until(self, marker, timeout=15):
        deadline = time.monotonic() + timeout
        lines = []
        while True:
            line = self.line(deadline)
            lines.append(line)
            require(len(lines) <= 512, 'reply_count')
            if marker in line:
                return lines
    def command(self, command):
        self.serial += 1
        marker = 'q04_barrier_' + str(self.serial)
        self.send(command)
        self.send('PING :' + marker)
        result = self.until(marker.encode())
        require(b' PONG ' in result[-1], 'ping_correlation')
        return result[:-1]
    def register(self, nick):
        self.send('CAP REQ :message-tags batch labeled-response')
        self.until(b' ACK :message-tags batch labeled-response')
        self.send('NICK ' + nick)
        self.send('USER q04 0 * :Q04 private smoke')
        self.send('CAP END')
        self.until(b' 001 ' + nick.encode() + b' ')
        contains(self.command('IRCX'), b' 800 ' + nick.encode() + b' 1 ')
    def close(self):
        self.sock.close()

def finish(root, result, clients, process, logs):
    # Never let one failed close skip another resource or the daemon stop.
    errors = []
    for client in clients:
        try:
            client.close()
        except BaseException:
            if 'client_close' not in errors:
                errors.append('client_close')
    try:
        stop(process)
    except BaseException:
        errors.append('process_stop')
    for log in logs:
        try:
            log.close()
        except BaseException:
            if 'log_close' not in errors:
                errors.append('log_close')
    if errors:
        result = {'ok': False, 'stage': 'cleanup', 'class': 'cleanup_failed',
                  'cleanup_errors': errors, 'checks': result['checks']}
    private_file(root / 'result.json', (json.dumps(result, sort_keys=True) + '\n').encode())
    return result

def run(args):
    parent = args.artifacts.parent.resolve(strict=True)
    st = parent.stat()
    require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'artifact_parent')
    require(not args.artifacts.is_symlink(), 'artifact_symlink')
    root = parent / args.artifacts.name
    root.mkdir(mode=0o700)  # create-only; never reuse a previous campaign
    process = None
    clients = []
    logs = []
    stage = 'pin'
    checks = 0
    started = time.monotonic()
    try:
        binary = root / 'onyx-server'
        pin_binary(args.binary, binary, args.sha256)
        irc, tls, media = free_ports()
        stage = 'setup'
        env = {'PATH': os.defpath, 'TERM': 'dumb', 'NO_COLOR': ''}
        completed, review, _ = run_review([
            str(binary), 'setup', '--new', '--hostname', 'q04.example.test',
            '--listen', HOST, '--irc-port', str(irc), '--tls-port', str(tls),
            '--media-port', str(media), '--node-id', '1', '--bundle', 'bundle', '--json',
        ], root, env, preexec_fn=limits)
        require(completed.returncode == 0 and review is not None, 'setup_failed')
        config = root / 'bundle' / 'onyx-server.toml'
        text = config.read_text()
        require('[limits]\n' in text, 'config_shape')
        text = text.replace('[limits]\n', '[limits]\nthrottle_connects = 0\nmax_clones_per_ip_net = 16\n', 1)
        text += ('\n[sasl]\nenabled = true\naccount_db = "accounts.wal"\n'
                 '[accounts]\npbkdf2_rounds = 10000\n'
                 '[class.user]\nflood_lines = 1000\nflood_window = "1s"\nflood_excess = 1000\n'
                 '[[oper_groups]]\nname = "q04audit"\nprivileges = ["audit_read"]\n'
                 '[[oper_groups]]\nname = "q04service"\nprivileges = ["audit_read", "service_admin"]\n'
                 '[[opers]]\naccount = "q04audit"\nclass = "q04audit"\n'
                 '[[opers]]\naccount = "q04service"\nclass = "q04service"\n')
        config.write_text(text)
        config.chmod(0o600)
        stage = 'config'
        with open(root / 'config-check.log', 'xb') as check_log:
            os.chmod(root / 'config-check.log', 0o600)
            checked = subprocess.run([str(binary), '--check-config', str(config)],
                                     cwd=config.parent, env=env, stdin=subprocess.DEVNULL,
                                     stdout=check_log, stderr=check_log, timeout=20,
                                     start_new_session=True, preexec_fn=limits)
        require(checked.returncode == 0, 'config_failed')
        stage = 'start'
        daemon_log = open(root / 'daemon.log', 'xb', buffering=0)
        os.chmod(root / 'daemon.log', 0o600)
        logs.append(daemon_log)
        process = subprocess.Popen([str(binary), str(config)], cwd=config.parent, env=env,
                                   stdin=subprocess.DEVNULL, stdout=daemon_log, stderr=daemon_log,
                                   start_new_session=True, preexec_fn=limits)
        deadline = time.monotonic() + 30
        for nick in ('Q04Owner', 'Q04Subject', 'Q04Audit', 'Q04Service'):
            log = open(root / (nick + '.irc'), 'xb', buffering=0)
            os.chmod(root / (nick + '.irc'), 0o600)
            logs.append(log)
            while True:
                require(process.poll() is None, 'daemon_exit')
                try:
                    client = Client(tls, log)
                    break
                except OSError:
                    require(time.monotonic() < deadline, 'listen_timeout')
                    time.sleep(.05)
            clients.append(client)
            client.register(nick)
        owner, subject, audit, service = clients
        stage = 'roles'
        for client, account in ((audit, 'q04audit'), (service, 'q04service')):
            password = secrets.token_urlsafe(24)
            client.send('REGISTER ' + account + ' * ' + password)
            lines = client.until(b' 381 ', timeout=45)
            contains(lines, b'REGISTER SUCCESS')
        checks += 2
        stage = 'privacy'
        contains(owner.command('JOIN #q04'), b' JOIN ')
        contains(subject.command('JOIN #q04hidden'), b' JOIN ')
        subject.command('MODE #q04hidden +s')
        require(explain(owner.command('ACCESS #q04 EXPLAIN Q04Subject')) == [b'unavailable'], 'named_authority')
        require(explain(owner.command('ACCESS #q04 EXPLAIN AbsentSubject')) == [b'unavailable'], 'nick_oracle')
        for client, suffix in ((owner, ''), (audit, ' Q04Subject')):
            hidden = explain(client.command('ACCESS #q04hidden EXPLAIN' + suffix))
            unknown = explain(client.command('ACCESS #q04unknown EXPLAIN' + suffix))
            require(hidden == unknown == [b'unavailable'], 'hidden_oracle')
        checks += 4
        stage = 'expiry_before'
        before = int(time.time())
        contains(owner.command('ACCESS #q04 ADD DENY Q04Subject!*@* 8'), b' 801 ')
        own = explain(subject.command('ACCESS #q04 EXPLAIN'))
        require(len(own) == 1, 'self_report_count')
        match = re.search(rb'rule=access_deny expiry=absolute_unix_seconds:(\d+) details=redacted', own[0])
        require(match is not None, 'self_expiry')
        expiry = int(match[1])
        require(before + 8 <= expiry <= int(time.time()) + 8, 'absolute_expiry')
        require(all(b'mask=' not in row and b'issuer=' not in row for row in own), 'self_details')
        contains(subject.command('JOIN #q04'), b' 474 ')
        checks += 3
        stage = 'expiry_after'
        require(0 <= expiry - time.time() <= 9, 'expiry_budget')
        while time.time() < expiry + .1:
            require(time.monotonic() - started < 200, 'deadline')
            time.sleep(.05)
        contains(subject.command('ACCESS #q04 EXPLAIN'), b'result=policy_allow rule=allow')
        contains(subject.command('JOIN #q04'), b' JOIN ')
        checks += 2
        stage = 'saccess'
        contains(service.command('SACCESS ADD GAG Q04Subject!*@* 30 :Q04PrivateReason'), b' 801 ')
        redacted = audit.command('ACCESS #q04 EXPLAIN Q04Subject')
        contains(redacted, b'rule=connection_saccess_gag expiry=unknown details=redacted')
        require(not any(b'Q04PrivateReason' in row or b'mask=' in row for row in redacted), 'saccess_read_gate')
        detailed = service.command('ACCESS #q04 EXPLAIN Q04Subject')
        contains(detailed, b'rule=connection_saccess_gag expiry=unknown details=authorized')
        contains(detailed, b'mask=Q04Subject!*@*')
        contains(detailed, b'reason=Q04PrivateReason')
        checks += 3
        stage = 'labels'
        for label in ('q04-first', 'q04-second'):
            wire = audit.command('@label=' + label + ' ACCESS #q04 EXPLAIN Q04Subject')
            rows = labeled(wire, label.encode())
            require(len(rows) == 2, 'multiline_count')
            require(any(b'connection_saccess_gag' in row for row in rows) and
                    any(b'rule=already_member' in row for row in rows), 'multiline_sources')
            if label == 'q04-second':
                require(not any(b'q04-first' in row for row in wire), 'old_label')
        bare = audit.command('ACCESS #q04 EXPLAIN Q04Subject')
        require(not any(b'@label=' in row or b'@batch=' in row or b'BATCH ' in row for row in bare), 'label_bleed')
        checks += 3
        stage = 'liveness'
        for client in clients:
            client.command('PING :q04-final-held')
        checks += 4
        require(process.poll() is None, 'daemon_exit')
        stage = 'complete'
        result = {'ok': True, 'stage': stage, 'checks': checks, 'clients': len(clients),
                  'binary_sha256': args.sha256, 'q04': 'partial_legacy_saccess_expiry_unknown'}
    except BaseException as error:
        if isinstance(error, Exception):
            code = str(error) if isinstance(error, Failure) else type(error).__name__
        else:
            code = 'interrupted'
        # Failure values are exclusively fixed labels defined in this source.
        result = {'ok': False, 'stage': stage, 'class': code, 'checks': checks}
    return finish(root, result, clients, process, logs)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Failure('deadline')))
    signal.alarm(240)
    try:
        result = run(args)
    except Exception as error:
        result = {'ok': False, 'stage': 'custody_or_cleanup', 'class': type(error).__name__}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
