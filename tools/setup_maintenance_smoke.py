#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Owned loopback fixture for EXISTING-runtime setup maintenance.

Product selection is exercised only with this fixture's existing child PID.
No arbitrary PID/unit/host option, package installation or live service access.
Private evidence is retained; stdout has fixed classes/counts only.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pty
import re
import resource
import select
import shutil
import signal
import socket
import stat
import sys
import struct
import subprocess
import termios
import time
from setup_review_client import run_review
from q04_explain_smoke import Client, contains, free_ports, limits, pin_binary, private_file, require, Failure

MAX_CAPTURE = 1024 * 1024
MAINTENANCE_FILE_LIMIT = 64 * 1024 * 1024
FIXTURE_DRIFT = b"fixture-drift"

def validate_artifact_size(size):
    require(0 < size <= MAINTENANCE_FILE_LIMIT - len(FIXTURE_DRIFT), "artifact_size")

def validate_input_artifact(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'binary_custody')
        validate_artifact_size(info.st_size)
    finally:
        os.close(fd)

def maintenance_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAINTENANCE_FILE_LIMIT, MAINTENANCE_FILE_LIMIT))

phase = "arguments"

class CleanupFailure(Failure):
    def __init__(self, errors):
        super().__init__('cleanup_failed')
        self.errors = tuple(errors)


def process_status(process):
    """Observe without reaping: keep the owned leader PID/PGID unreusable."""
    if process.returncode is not None:
        return process.returncode
    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if status is None:
        return None
    return status.si_status if status.si_code == os.CLD_EXITED else -status.si_status


def live_group_members(pgid):
    """Only live tasks; exited zombies cannot execute or retain socket work."""
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            data = (entry / 'stat').read_text()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        fields = data[data.rfind(')') + 2:].split()
        if len(fields) >= 4 and int(fields[2]) == pgid and int(fields[3]) == pgid and fields[0] not in ('Z', 'X'):
            result.append(int(entry.name))
    return result


def cleanup_attempts(actions):
    """Every resource is attempted even on failures/interrupts; no raw errors."""
    blocked = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    errors = []
    try:
        for label, action in actions:
            try:
                action()
            except BaseException as error:
                errors.append({'resource': label, 'class': type(error).__name__})
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return errors


def retire_group(process):
    """TERM then unconditional KILL before reaping, including exited leaders.

    All callers launch start_new_session=True and observe with WNOWAIT. Keeping
    the leader unreaped prevents numeric PGID reuse while signals are issued.
    Reap the leader and any adopted/direct group children after live retirement.
    """
    if process is None or getattr(process, '_owned_group_retired', False):
        return
    if process.returncode is not None:
        raise CleanupFailure([{'resource': 'group', 'class': 'LeaderAlreadyReaped'}])
    # ECHILD here fails closed: never signal an unowned/reused numeric group.
    process_status(process)
    if os.getpgid(process.pid) != process.pid:
        raise CleanupFailure([{'resource': 'group', 'class': 'WrongProcessGroup'}])
    errors = []
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except BaseException as error:
        errors.append({'resource': 'group_term', 'class': type(error).__name__})
    deadline = time.monotonic() + .25
    try:
        while time.monotonic() < deadline and live_group_members(process.pid):
            time.sleep(.02)
    except BaseException as error:
        errors.append({'resource': 'group_grace', 'class': type(error).__name__})
    # Do not return after the leader exits: descendants may ignore TERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as error:
        errors.append({'resource': 'group_kill', 'class': type(error).__name__})
    deadline = time.monotonic() + 5
    live = True
    try:
        while time.monotonic() < deadline:
            if not live_group_members(process.pid):
                live = False
                break
            time.sleep(.02)
        if live:
            errors.append({'resource': 'group', 'class': 'LiveGroupTimeout'})
    except BaseException as error:
        errors.append({'resource': 'group_observe', 'class': type(error).__name__})
    reaped = False
    try:
        process.wait(timeout=5)
        reaped = True
    except BaseException as error:
        errors.append({'resource': 'leader_reap', 'class': type(error).__name__})
    # No signals occur after this reap. Collect direct/adopted children when
    # available; orphan zombie reaping remains their kernel parent’s duty.
    try:
        while True:
            try:
                child, _ = os.waitpid(-process.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if child == 0:
                break
    except BaseException as error:
        errors.append({'resource': 'group_reap', 'class': type(error).__name__})
    if reaped and not live:
        process._owned_group_retired = True
    if errors:
        raise CleanupFailure(errors)


def cleanup_resources(wizards, clients, process, logs):
    actions = [('wizard', item.close) for item in wizards]
    actions += [('client', item.close) for item in clients]
    actions.append(('daemon_group', lambda: retire_group(process)))
    actions += [('capture', item.close) for item in logs]
    errors = cleanup_attempts(actions)
    if errors:
        raise CleanupFailure(errors)


class Wizard:
    def __init__(self, binary, daemon, config, target, backup, scratch, root, name):
        self.master = None
        self.log = None
        self.process = None
        self.data = b''
        self.closed = False
        slave = None
        try:
            self.master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 120, 0, 0))
            self.log = open(root / (name + '.pty'), 'xb', buffering=0)
            os.chmod(root / (name + '.pty'), 0o600)
            self.process = subprocess.Popen([
                str(binary), 'setup', '--maintenance', '--interactive', '--linear', str(config),
                '--pid', str(daemon.pid), '--target', str(target), '--backup', str(backup),
                '--restore-into', str(scratch),
            ], cwd=config.parent, stdin=slave, stdout=slave, stderr=slave,
               env={'PATH': os.defpath, 'TERM': 'dumb', 'NO_COLOR': '', 'COLUMNS': '120'},
               start_new_session=True, preexec_fn=maintenance_limits)
            os.close(slave)
            slave = None
            self.until(b'maintenance> ')
        except BaseException:
            actions = [('wizard', self.close)]
            if slave is not None:
                actions.append(('wizard_slave', lambda: os.close(slave)))
            errors = cleanup_attempts(actions)
            if errors:
                raise CleanupFailure(errors) from None
            raise
    def send(self, text):
        os.write(self.master, text.encode() + b'\n')
    def until(self, marker, start=0, timeout=45):
        deadline = time.monotonic() + timeout
        while marker not in self.data[start:]:
            require(time.monotonic() < deadline, 'wizard_timeout')
            ready, _, _ = select.select([self.master], [], [], .1)
            if ready:
                try:
                    block = os.read(self.master, 4096)
                except OSError:
                    block = b''
                if not block:
                    raise Failure('wizard_eof')
                self.data += block
                require(len(self.data) <= MAX_CAPTURE, 'wizard_capture_bound')
                self.log.write(block)
            elif process_status(self.process) is not None:
                raise Failure('wizard_exit')
        return self.data[start:]
    def review(self):
        start = len(self.data)
        self.send('review')
        data = self.until(b'review> ', start)
        match = re.search(rb'Review id\s+([0-9a-f]{32})', data)
        require(match is not None, 'review_id')
        for marker in (b'Backup coverage', b'Backup exclusions', b'Expected client impact',
                       b'Recovery boundary', b'Previous artifact retention path', b'Maintenance journal'):
            require(marker in data, 'review_fields')
        return match[1].decode()
    def finish(self, command=None, eof=False, timeout=45):
        if eof:
            os.write(self.master, b'\x04')
        elif command:
            self.send(command)
        deadline = time.monotonic() + timeout
        while process_status(self.process) is None:
            require(time.monotonic() < deadline, 'wizard_exit_timeout')
            ready, _, _ = select.select([self.master], [], [], .1)
            if ready:
                try:
                    block = os.read(self.master, 4096)
                except OSError:
                    block = b''
                self.data += block
                require(len(self.data) <= MAX_CAPTURE, 'wizard_capture_bound')
                self.log.write(block)
        # Drain terminal output after WNOWAIT observes exit before the last
        # receipt bytes are drained from the PTY.
        for _ in range(256):
            ready, _, _ = select.select([self.master], [], [], .05)
            if not ready:
                break
            try:
                block = os.read(self.master, 4096)
            except OSError:
                break
            if not block:
                break
            self.data += block
            require(len(self.data) <= MAX_CAPTURE, 'wizard_capture_bound')
            self.log.write(block)
        return process_status(self.process)
    def close(self):
        if self.closed:
            return
        def close_process():
            retire_group(self.process)
            self.process = None
        def close_master():
            if self.master is not None:
                os.close(self.master)
                self.master = None
        def close_log():
            if self.log is not None:
                self.log.close()
                self.log = None
        errors = cleanup_attempts([('wizard_group', close_process), ('wizard_pty', close_master), ('wizard_capture', close_log)])
        if errors:
            # Successfully closed individual resources are cleared; a retry
            # never closes a reused fd, and closed is set only on full success.
            raise CleanupFailure(errors)
        self.closed = True

def exe_identity(process):
    st = os.stat('/proc/' + str(process.pid) + '/exe')
    return st.st_dev, st.st_ino

def socket_inodes(process):
    result = set()
    for item in Path('/proc', str(process.pid), 'fd').iterdir():
        try:
            value = os.readlink(item)
        except FileNotFoundError:
            continue
        if value.startswith('socket:['):
            result.add(value)
    return result

def normalized_address(address):
    value = ipaddress.ip_address(address)
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None:
        value = value.ipv4_mapped
    return str(value)

def proc_endpoint(encoded, family):
    address, port = encoded.split(':')
    raw = bytes.fromhex(address)
    require(len(raw) == (4 if family == 'tcp' else 16), 'socket_table_format')
    raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return (normalized_address(str(ipaddress.ip_address(raw))), int(port, 16))

def socket_rows(process):
    owned = socket_inodes(process)
    rows = []
    for family in ('tcp', 'tcp6'):
        with open('/proc/' + str(process.pid) + '/net/' + family) as source:
            next(source)
            for line in source:
                fields = line.split()
                require(len(fields) >= 10, 'socket_table_format')
                inode = 'socket:[' + fields[9] + ']'
                if inode not in owned:
                    continue
                rows.append({'inode': inode, 'state': fields[3],
                             'local': proc_endpoint(fields[1], family),
                             'remote': proc_endpoint(fields[2], family)})
    return rows

def client_socket_witness(rows, clients):
    result = []
    for client in clients:
        local = (normalized_address(client.sock.getsockname()[0]), client.sock.getsockname()[1])
        remote = (normalized_address(client.sock.getpeername()[0]), client.sock.getpeername()[1])
        candidates = {row['inode'] for row in rows if row['state'] == '01' and row['local'] == remote and row['remote'] == local}
        require(len(candidates) == 1, 'server_socket_endpoint')
        result.append(next(iter(candidates)))
    require(len(set(result)) == len(clients), 'server_socket_duplicate')
    return result

def require_client_socket_custody(expected, rows, clients):
    require(expected == client_socket_witness(rows, clients), 'physical_socket_custody')

def listener_socket_witness(rows, port):
    matches = {row['inode'] for row in rows if row['state'] == '0A' and row['local'][1] == port}
    require(len(matches) == 1, 'listener_socket_endpoint')
    return next(iter(matches))

def wait_backup(process, directory):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        require(process_status(process) is None, 'daemon_exit')
        if (directory / 'latest.json').is_file():
            data = json.loads((directory / 'latest.json').read_bytes())
            require(data.get('files'), 'backup_nonvacuous')
            if all((directory / row['name']).is_file() for row in data['files']):
                return
        time.sleep(.1)
    raise Failure('backup_timeout')

def held(clients):
    for client in clients:
        client.command('PING :maintenance-held')

def campaign(binary, expected, root, refusal=False):
    global phase
    phase = "prepare"
    root.mkdir(mode=0o700)
    runtime_dir = root / 'runtime'
    runtime_dir.mkdir(mode=0o700)
    runtime = runtime_dir / 'onyx-server'
    target = root / 'candidate'
    pin_binary(binary, runtime, expected)
    pin_binary(binary, target, expected)
    irc, tls, media = free_ports()
    env = {'PATH': os.defpath, 'TERM': 'dumb', 'NO_COLOR': ''}
    phase = 'setup'
    done, review, _ = run_review([
        str(binary), 'setup', '--new', '--hostname', 'maintenance.example.test', '--listen', '127.0.0.1',
        '--irc-port', str(irc), '--tls-port', str(tls), '--media-port', str(media),
        '--node-id', '1', '--bundle', 'bundle', '--json',
    ], root, env, preexec_fn=limits)
    require(done.returncode == 0 and review is not None, 'setup_failed')
    config = root / 'bundle' / 'onyx-server.toml'
    backup = root / 'periodic-backup'
    backup.mkdir(mode=0o700)
    original = config.read_bytes() + (
        '\n[sasl]\nenabled = true\naccount_db = "accounts.wal"\n'
        '[accounts]\npbkdf2_rounds = 10000\n'
        '[class.user]\nflood_lines = 1000\nflood_window = "1s"\nflood_excess = 1000\n'
        '[backup]\ndir = "' + str(backup) + '"\ninterval = "2s"\n'
    ).encode()
    config.write_bytes(original)
    config.chmod(0o600)
    log = open(root / 'daemon.log', 'xb', buffering=0)
    phase = 'daemon_start'
    process = None
    clients = []
    logs = []
    wizards = []
    checks = 0
    try:
        os.chmod(root / 'daemon.log', 0o600)
        process = subprocess.Popen([str(runtime), '--strict-existing-identity', str(config)], cwd=config.parent,
                                   env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   start_new_session=True, preexec_fn=limits)
        deadline = time.monotonic() + 30
        for nick in ('MaintenanceOwner', 'MaintenanceObserver'):
            capture = open(root / (nick + '.irc'), 'xb', buffering=0)
            logs.append(capture)
            os.chmod(root / (nick + '.irc'), 0o600)
            while True:
                require(process_status(process) is None, 'daemon_exit')
                try:
                    client = Client(tls, capture)
                    break
                except OSError:
                    require(time.monotonic() < deadline, 'listen_timeout')
                    time.sleep(.05)
            clients.append(client)
            client.register(nick)
        phase = 'register_and_backup'
        clients[0].send('REGISTER maintenancefixture * fixture-only-private-password-83')
        clients[0].until(b'REGISTER SUCCESS', timeout=45)
        contains(clients[0].command('JOIN #maintenance'), b' JOIN ')
        contains(clients[1].command('JOIN #maintenance'), b' JOIN ')
        wait_backup(process, backup)
        # Freeze actual child-produced backup bytes, not a fabricated snapshot.
        frozen = root / 'backup-input'
        shutil.copytree(backup, frozen)
        frozen.chmod(0o700)
        for path in frozen.iterdir():
            require(path.is_file() and not path.is_symlink(), 'backup_custody')
            path.chmod(0o600)
        before = exe_identity(process)
        socket_before = socket_rows(process)
        held_sockets = client_socket_witness(socket_before, clients)
        irc_listener = listener_socket_witness(socket_before, irc)
        tls_listener = listener_socket_witness(socket_before, tls)
        private_file(root / 'socket-before.json', (json.dumps({'rows': socket_before, 'clients': held_sockets, 'irc_listener': irc_listener, 'tls_listener': tls_listener}, sort_keys=True) + '\n').encode())
        client_inodes = [os.fstat(client.sock.fileno()).st_ino for client in clients]
        def wizard(name):
            global phase
            phase = "wizard_" + name
            item = Wizard(binary, process, config, target, frozen, root / ('verify-' + name), root, name)
            wizards.append(item)
            return item
        if not refusal:
            cancelled = wizard('cancel')
            require(cancelled.finish('cancel') == 0, 'cancel_status')
            require(exe_identity(process) == before, 'cancel_exec')
            require(hashlib.sha256(runtime.read_bytes()).hexdigest() == expected, 'runtime_artifact_changed')
            held(clients)
            checks += 1
            back = wizard('back')
            old_id = back.review()
            start = len(back.data)
            back.send('back')
            back.until(b'maintenance> ', start)
            start = len(back.data)
            back.send('apply ' + old_id)
            back.until(b'maintenance> ', start)
            start = len(back.data)
            back.send('set restore-into ' + str(root / 'verify-back-again'))
            back.until(b'maintenance> ', start)
            require(back.review() != old_id, 'fresh_review_id')
            require(back.finish('cancel') == 0, 'back_status')
            require(exe_identity(process) == before, 'back_exec')
            require(hashlib.sha256(runtime.read_bytes()).hexdigest() == expected, 'runtime_artifact_changed')
            held(clients)
            checks += 1
            eof = wizard('eof')
            eof.review()
            require(eof.finish(eof=True) == 0, 'eof_status')
            require(exe_identity(process) == before, 'eof_exec')
            require(hashlib.sha256(runtime.read_bytes()).hexdigest() == expected, 'runtime_artifact_changed')
            held(clients)
            checks += 1
            drift = wizard('drift')
            review_id = drift.review()
            target.chmod(0o700)
            with target.open('ab') as stream:
                stream.write(FIXTURE_DRIFT)
            require(drift.finish('apply ' + review_id) != 0, 'drift_refusal')
            require(exe_identity(process) == before, 'drift_exec')
            require(hashlib.sha256(runtime.read_bytes()).hexdigest() == expected, 'runtime_artifact_changed')
            held(clients)
            checks += 1
            # Fresh ordinary fixture input repair; never reset daemon guards.
            target = root / 'candidate-repaired'
            pin_binary(binary, target, expected)
        else:
            # Deliberately change on-disk realm BEFORE review. Static file
            # checks cannot attest live memory; daemon final guard must refuse.
            config.write_bytes(original + b'\n[mesh]\nrealm = "maintenance-refusal"\n')
        apply = wizard('refusal' if refusal else 'apply')
        review_id = apply.review()
        rc = apply.finish('apply ' + review_id, timeout=60)
        require(rc == 0, 'action_receipt')
        require(b'previous_artifact_retained=yes' in apply.data, 'retained_previous')
        deadline = time.monotonic() + 30
        phase = 'observe_final_guard' if refusal else 'observe_exec'
        if refusal:
            while time.monotonic() < deadline:
                if b'ChangedNodeRealm' in (root / 'daemon.log').read_bytes():
                    break
                held(clients)
                time.sleep(.1)
            require(b'ChangedNodeRealm' in (root / 'daemon.log').read_bytes(), 'final_guard_refusal')
            require(exe_identity(process) == before, 'refusal_predecessor')
            config.write_bytes(original)
        else:
            while time.monotonic() < deadline and exe_identity(process) == before:
                require(process_status(process) is None, 'daemon_exit')
                time.sleep(.1)
            require(exe_identity(process) != before, 'exec_inode')
            require(b'exec_observed' in apply.data, 'exec_receipt')
        previous = runtime_dir / '.onyx-maintenance-previous'
        journal = runtime_dir / '.onyx-maintenance-journal'
        require(previous.is_file() and journal.is_file(), 'recovery_references')
        require(previous.stat().st_ino == before[1], 'previous_inode')
        require(hashlib.sha256(previous.read_bytes()).hexdigest() == expected, 'previous_hash')
        lines = journal.read_bytes().splitlines(keepends=True)
        require(len(lines) == 2 and lines[1] == b'sha256=' + hashlib.sha256(lines[0]).hexdigest().encode() + b'\n', 'journal_checksum')
        scratch = root / ('verify-refusal' if refusal else 'verify-apply')
        require((scratch / 'config.toml').is_file() and (scratch / 'input/latest.json').is_file() and
                (scratch / 'drill/restored.wal.snap').is_file(), 'retained_recovery_witnesses')
        socket_after = socket_rows(process)
        private_file(root / 'socket-after.json', (json.dumps({'rows': socket_after}, sort_keys=True) + '\n').encode())
        require_client_socket_custody(held_sockets, socket_after, clients)
        require(irc_listener == listener_socket_witness(socket_after, irc), 'listener_socket_custody')
        listener_socket_witness(socket_after, tls)
        require(client_inodes == [os.fstat(client.sock.fileno()).st_ino for client in clients], 'client_socket_custody')
        held(clients)
        checks += 3
        return checks
    finally:
        # A primary failure or interrupt cannot skip later owned resources.
        cleanup_resources(wizards, clients, process, logs + [log])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = {'ok': False, 'stage': 'custody'}
    def timeout(*_):
        raise Failure('campaign_deadline')
    signal.signal(signal.SIGALRM, timeout)
    signal.signal(signal.SIGTERM, timeout)
    signal.alarm(420)
    try:
        parent = args.artifacts.parent.resolve(strict=True)
        info = parent.stat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'artifacts_parent')
        require(not args.artifacts.is_symlink(), 'artifacts_symlink')
        root = parent / args.artifacts.name
        root.mkdir(mode=0o700)
        binary = root / 'controller'
        validate_input_artifact(args.binary)
        pin_binary(args.binary, binary, args.sha256)
        validate_artifact_size(binary.stat().st_size)
        result['stage'] = 'existing_runtime_success'
        count = campaign(binary, args.sha256, root / 'success')
        result['stage'] = 'existing_runtime_final_guard_refusal'
        count += campaign(binary, args.sha256, root / 'refusal', refusal=True)
        require(count == 10, 'native_check_count')
        result = {'ok': True, 'stage': 'complete', 'checks': count, 'runtimes': 2,
                  'scope': 'Linux_same_uid_existing_foreground_only'}
        private_file(root / 'result.json', (json.dumps(result, sort_keys=True) + '\n').encode())
    except BaseException as error:
        result['ok'] = False
        result['stage'] = phase
        result['class'] = str(error) if isinstance(error, Failure) else type(error).__name__
        if isinstance(error, CleanupFailure):
            result['cleanup_errors'] = len(error.errors)
        if 'root' in locals() and root.is_dir() and not (root / 'result.json').exists():
            private_file(root / 'result.json', (json.dumps(result, sort_keys=True) + '\n').encode())
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
