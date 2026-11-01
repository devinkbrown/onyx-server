#!/usr/bin/env python3
"""Build and test two APKs inside one disposable, offline Alpine guest."""
import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ISO_PIN = 'cdc1bc0efc64d8d611bf3733f54868172a545888dfd726f518bf279bcb0ff1af'
WORKSPACE = Path('/home/kain/onyx-server')
MAX_SIZE = 512 * 1024 * 1024
RUNTIME_CODES = frozenset('outside_workspace private_directory shared_directory invalid_regular_file invalid_file_owner input_pin origin_pin origin_binding service_diagnostic_bound service_transfer_invalid service_transfer_truncated service_transfer_missing prerequisites output_exists input_copy unexpected_output output_bound output_changed output_digest'.split())
FAILS = frozenset('cleanup_daemon cleanup_syslog runtime_guard runtime_guard_setup boot_socket_type boot_syslog_status boot_syslog_identity boot_socket_owner boot_syslog_stop boot_syslog_retirement boot_stale_identity boot_socket_binding boot_stale_remove syslog_ready prereq openssl_prereq keygen account build build_limit build_input build_output install signature_trusted signature_wrong_key signature_unsigned_setup signature_unsigned signature_tamper_setup signature_tampered signature_mutation system_layout snapshot preflight new_identity upgrade preservation daemon identity_load service_setup service_start service_stop custody missing_identity_start unrelated_maintenance guest_mount_or_script identity_capture profile_source profile_refusal helix_client helix_exec helix_socket helix_carry'.split())


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private_directory(path):
    path = Path(os.path.abspath(path))
    parent = path.parent.resolve(strict=True)
    if not parent.is_relative_to(WORKSPACE) or parent != path.parent:
        raise RuntimeError('outside_workspace')
    try: path.mkdir(mode=0o700)
    except FileExistsError: pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError('private_directory')
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(WORKSPACE):
        raise RuntimeError('outside_workspace')
    return resolved


def regular(path, *, owner=None, bound=MAX_SIZE):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > bound:
        raise RuntimeError('invalid_regular_file')
    if owner is not None and info.st_uid != owner:
        raise RuntimeError('invalid_file_owner')
    return info


STRICT_IDENTITY_BANNER = b'onyx-server: strict service identity source: existing_keyfile'
def classify_identity(data):
    if b'node identity generated + persisted to ' in data: return 'generated'
    return 'strict_validated' if data.splitlines().count(STRICT_IDENTITY_BANNER) == 1 else 'other'

SERVICE_FRAME = re.compile(rb'^ONYX_PRIVATE_SERVICE (runtime_denied|initial|missing_before|missing_after|postupgrade|mode_file|mode_inline|mode_env|mode_ref|cleanup|identity) (start|status|stop|probe) ([A-Za-z0-9+/=]{0,87384})\r?$')


def capture_service(line, directory, captures):
    match = SERVICE_FRAME.fullmatch(line)
    if match is None: raise RuntimeError('service_transfer_invalid')
    phase, operation = (part.decode('ascii') for part in match.group(1, 2))
    name = (phase, operation)
    if (phase == 'identity') != (operation == 'probe'): raise RuntimeError('service_transfer_invalid')
    if name in captures or len(captures) >= 32: raise RuntimeError('service_transfer_invalid')
    encoded = match.group(3)
    try: data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError): raise RuntimeError('service_transfer_invalid') from None
    if len(data) > 65536 or base64.b64encode(data) != encoded:
        raise RuntimeError('service_transfer_invalid')
    path = directory / (phase + '.' + operation + '.log')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise RuntimeError('service_transfer_invalid')
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    captures[name] = {'phase': phase, 'operation': operation, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    if phase == 'identity': captures[name]['identity_source'] = classify_identity(data)


PROFILE_FRAME = re.compile(rb'^ONYX_PRIVATE_PROFILE (file|inline|env|ref) ([A-Za-z0-9+/=]{0,87384})\r?$')
def capture_profile(line, directory, captures):
    match = PROFILE_FRAME.fullmatch(line)
    if match is None: raise RuntimeError('service_transfer_invalid')
    mode = match.group(1).decode('ascii')
    if mode in captures or len(captures) >= 4: raise RuntimeError('service_transfer_invalid')
    try: data = base64.b64decode(match.group(2), validate=True)
    except (ValueError, binascii.Error): raise RuntimeError('service_transfer_invalid') from None
    if len(data) > 65536 or base64.b64encode(data) != match.group(2): raise RuntimeError('service_transfer_invalid')
    path = directory / ('profile-' + mode + '.log')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid(): raise RuntimeError('service_transfer_invalid')
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    captures[mode] = {'mode': mode, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def parse_helix_observations(buffer):
    pattern = re.compile(rb'ONYX_HELIX (file|inline|env|ref) ([0-9]{1,10}) ([0-9]{1,20}) ([0-9]{1,20}) ([0-9]{1,20}) ([0-9]{1,20}):([0-9]{1,20}) strict ([01]) same\r?')
    rows = []; modes = set()
    for line in buffer.splitlines():
        if not line.startswith(b'ONYX_HELIX'): continue
        match = pattern.fullmatch(line)
        if match is None: raise RuntimeError('service_diagnostic_bound')
        mode = match.group(1).decode('ascii'); values = [int(part) for part in match.groups()[1:]]
        pid, start, client_socket, server_socket, device, inode, carry = values
        if mode in modes or pid <= 1 or min(start, client_socket, server_socket, device, inode) <= 0 or client_socket == server_socket or carry != int(mode == 'env'): raise RuntimeError('service_diagnostic_bound')
        modes.add(mode); rows.append({'mode':mode,'pid':pid,'start':start,'client_socket_inode':client_socket,'server_socket_inode':server_socket,'target_device':device,'target_inode':inode,'strict_flag':True,'explicit_env_bindings':carry,'physical_and_exec_unchanged':True})
    if len(rows) != 4: raise RuntimeError('service_transfer_missing')
    return rows

def parse_socket_diagnostic(buffer):
    pattern = re.compile(rb'ONYX_DIAG socket (file|inline|env|ref) (client_multiple|client_absent|server_multiple|server_absent|table_unreadable) (unknown|[0-9]{1,3}) (unknown|[0-9]{1,3}) ([0-9]{1,3}) ([0-9]{1,3}) initial\r?')
    lines = [line for line in buffer.splitlines() if line.startswith(b'ONYX_DIAG socket')]
    if not lines: return None
    if len(lines) != 1: raise RuntimeError('service_diagnostic_bound')
    match = pattern.fullmatch(lines[0])
    if match is None: raise RuntimeError('service_diagnostic_bound')
    mode, stage = (v.decode('ascii') for v in match.group(1,2))
    counts = [None if v == b'unknown' else int(v) for v in match.group(3,4,5,6)]
    return {'mode':mode, 'stage':stage, 'tcp4_established':counts[0], 'tcp6_established':counts[1], 'client_fd_unreadable':counts[2], 'server_fd_unreadable':counts[3]}


def parse_apk_phase(buffer):
    pattern = re.compile(rb'ONYX_DIAG apkphase (old|new) (source|copy|capability) (invalid_file|setup|copy_failed|chmod_failed|hash_mismatch|command_failed|oversized|missing_token|read_error) ([0-9]{1,3})\r?')
    lines = [line for line in buffer.splitlines() if line.startswith(b'ONYX_DIAG apkphase')]
    if not lines: return None
    if len(lines) != 1: raise RuntimeError('service_diagnostic_bound')
    match = pattern.fullmatch(lines[0])
    if match is None or not 1 <= int(match.group(4)) <= 255: raise RuntimeError('service_diagnostic_bound')
    stage, phase, classification = (value.decode('ascii') for value in match.group(1, 2, 3))
    allowed = {'source': {'invalid_file', 'hash_mismatch'}, 'copy': {'setup', 'copy_failed', 'chmod_failed', 'hash_mismatch'}, 'capability': {'command_failed', 'oversized', 'missing_token', 'read_error'}}
    if classification not in allowed[phase]: raise RuntimeError('service_diagnostic_bound')
    return {'stage':stage, 'phase':phase, 'class':classification, 'exit':int(match.group(4))}


def profiles_complete(buffer, captures):
    pattern = re.compile(rb'ONYX_PROFILE (file|inline|env|ref) strict socket exe carry pass\r?')
    lines = [line for line in buffer.splitlines() if line.startswith(b'ONYX_PROFILE')]
    modes = []
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None: raise RuntimeError('service_diagnostic_bound')
        modes.append(match.group(1).decode('ascii'))
    if len(modes) != 4 or set(modes) != {'file','inline','env','ref'} or set(captures) != set(modes): raise RuntimeError('service_transfer_missing')
    refusals = [line for line in buffer.splitlines() if line.startswith(b'ONYX_REFUSAL')]
    expected = {b'ONYX_REFUSAL key ChangedNodeIdentity retained socket pong', b'ONYX_REFUSAL realm ChangedNodeRealm retained socket pong', b'ONYX_REFUSAL env ChangedBootEnvironment retained socket pong'}
    if len(refusals) != 3 or set(line.rstrip(b'\r') for line in refusals) != expected: raise RuntimeError('service_transfer_missing')

def unlink_created(path, identity):
    try:
        info = path.lstat()
        if (info.st_dev, info.st_ino) == identity and stat.S_ISREG(info.st_mode):
            path.unlink()
    except FileNotFoundError:
        pass


def recover(source, target, expected):
    before = regular(source, owner=os.geteuid(), bound=8192 if source.name == 'fixture.pub' else MAX_SIZE)
    read_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    write_fd = None
    created_identity = None
    h = hashlib.sha256()
    try:
        opened = os.fstat(read_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise RuntimeError('output_changed')
        write_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = os.fstat(write_fd)
        created_identity = (created.st_dev, created.st_ino)
        with os.fdopen(read_fd, 'rb') as src, os.fdopen(write_fd, 'wb') as dst:
            read_fd = write_fd = None
            for block in iter(lambda: src.read(1024 * 1024), b''):
                h.update(block); dst.write(block)
            dst.flush(); os.fsync(dst.fileno())
        if h.hexdigest() != expected or digest(source) != expected or digest(target) != expected:
            raise RuntimeError('output_digest')
        return created_identity
    except BaseException:
        if write_fd is not None: os.close(write_fd)
        if read_fd is not None: os.close(read_fd)
        if created_identity is not None: unlink_created(target, created_identity)
        raise


SERVICE_DIAG = re.compile(rb'ONYX_DIAG service (runtime_denied|initial|missing_before|missing_after|postupgrade|mode_file|mode_inline|mode_env|mode_ref|cleanup) (start|status|stop) ([0-9]{1,3}) ([0-9]{1,3}) ([0-9]{1,3}) ([0-9]{1,3}) (started|stopped|stopping|starting|inactive|crashed|unknown) (present|absent) (other|truncated|permission|runtime_preflight|identity_guard|config|dependency|supervisor|already)')
CUSTODY_DIAG = re.compile(rb'ONYX_DIAG custody (runtime_denied|initial|missing_before|missing_after|postupgrade|mode_file|mode_inline|mode_env|mode_ref|cleanup) (start|status|stop) (present|absent|unknown) (valid|absent|invalid|unknown) (valid|absent|invalid|unknown)')
def parse_diagnostics(buffer, prefix, pattern):
    rows = []
    pairs = set()
    for line in buffer.splitlines():
        if not line.startswith(prefix): continue
        match = pattern.fullmatch(line)
        if match is None or len(rows) >= 40: raise RuntimeError('service_diagnostic_bound')
        parts = [v.decode('ascii') for v in match.groups()]
        pair = tuple(parts[:2])
        if pair in pairs: raise RuntimeError('service_diagnostic_bound')
        pairs.add(pair)
        if pattern is SERVICE_DIAG:
            phase, operation, op_rc, root_rc, runtime_rc, config_rc, state, failed, reason = parts
            if any(int(v) > 255 for v in (op_rc, root_rc, runtime_rc, config_rc)): raise RuntimeError('service_diagnostic_bound')
            rows.append({'phase': phase, 'operation': operation, 'rc': int(op_rc), 'root_guard_rc': int(root_rc), 'runtime_preflight_rc': int(runtime_rc), 'config_check_rc': int(config_rc), 'service_state': state, 'failed_marker': failed, 'log_reason': reason})
        else:
            phase, operation, helper, supervisor, child = parts
            rows.append({'phase': phase, 'operation': operation, 'helper_registration': helper, 'supervisor': supervisor, 'daemon': child})
    return rows

def validate_correspondence(rows, custody, captures):
    if any(row['log_reason'] == 'truncated' for row in rows): raise RuntimeError('service_transfer_truncated')
    pairs = {(row['phase'], row['operation']) for row in rows}
    if pairs != (set(captures) - {('identity', 'probe')}) or pairs != {(row['phase'], row['operation']) for row in custody}: raise RuntimeError('service_transfer_missing')


def mark(result, stage):
    result['stage'] = stage
    print('ONYX_STAGE ' + stage, file=sys.stderr, flush=True)


def run(args, result):
    mark(result, 'validate_paths')
    root = args.repo_root.resolve(strict=True)
    if not root.is_relative_to(WORKSPACE): raise RuntimeError('outside_workspace')
    work_dir = private_directory(args.work_dir)
    out_dir = private_directory(args.output_dir)
    if work_dir == out_dir: raise RuntimeError('shared_directory')
    for name in ('old.apk', 'new.apk', 'fixture.pub'):
        if (out_dir / name).exists() or (out_dir / name).is_symlink(): raise RuntimeError('output_exists')
    iso = args.iso
    regular(iso)
    binary = args.binary
    regular(binary, owner=os.geteuid())
    mark(result, 'validate_binary_iso')
    if digest(binary) != args.expected_binary_sha256 or digest(iso) != ISO_PIN:
        raise RuntimeError('input_pin')
    if not all(shutil.which(tool) for tool in ('qemu-system-x86_64', 'xorriso')) or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise RuntimeError('prerequisites')
    mark(result, 'validate_inputs')
    candidate = Path(__file__).resolve().parents[2]
    paths = {'onyx-server': binary, 'packaging/alpine/onyx-server.openrc': candidate / 'packaging/alpine/onyx-server.openrc',
             'etc/openrc/onyx-server.confd': root / 'etc/openrc/onyx-server.confd',
             'make-apk.sh': candidate / 'packaging/alpine/make-apk.sh',
             'identity-guard': candidate / 'packaging/alpine/identity-guard',
             'packaging/alpine/guarded-start': candidate / 'packaging/alpine/guarded-start',
             'packaging/alpine/runtime-preflight': candidate / 'packaging/alpine/runtime-preflight',
             'upgrade.sh': candidate / 'packaging/alpine/upgrade.sh',
             'guest.sh': Path(__file__).resolve().with_name('guest.sh')}
    for source in paths.values(): regular(source, owner=os.geteuid())
    pins = {name: digest(source) for name, source in paths.items()}
    capture_dir = work_dir / 'service-logs'
    capture_dir.mkdir(mode=0o700)
    private_directory(capture_dir)
    captures = {}
    profile_captures = {}
    result.update(result='guest_timeout', inputs=pins, iso_sha256=ISO_PIN,
                  expected_binary_sha256=args.expected_binary_sha256,
                  scope='guest-signed APK install/upgrade; no release or deployment claim')
    mark(result, 'stage_inputs')
    with tempfile.TemporaryDirectory(prefix='alpine-package-', dir=work_dir) as name:
        work = Path(name); share = work / 'share'; share.mkdir(mode=0o700)
        output = work / 'output'; output.mkdir(mode=0o700)
        for relative, source in paths.items():
            target = share / relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target); target.chmod(0o400)
            if digest(source) != pins[relative] or digest(target) != pins[relative]: raise RuntimeError('input_copy')
        (share / 'expected.sha256').write_text(args.expected_binary_sha256 + '\n')
        (share / 'expected.sha256').chmod(0o400)
        kernel = work / 'kernel'; initrd = work / 'initrd'
        mark(result, 'extract_kernel')
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract', '/boot/vmlinuz-virt', str(kernel), '-extract', '/boot/initramfs-virt', str(initrd)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        command = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-m', '2048', '-smp', '2', '-nic', 'none', '-nographic', '-no-reboot', '-kernel', str(kernel), '-initrd', str(initrd), '-append', 'console=ttyS0 alpine_dev=sr0 modules=loop,squashfs,sd-mod,9p,9pnet_virtio', '-cdrom', str(iso), '-virtfs', f'local,path={share},mount_tag=fixture,security_model=none,readonly=on', '-virtfs', f'local,path={output},mount_tag=output,security_model=none']
        mark(result, 'launch_qemu')
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        result['cleanup_attempted'] = True
        mark(result, 'guest_boot')
        buffer = b''; serial_pending = b''; stage = 0; artifact_hashes = None; deadline = time.monotonic() + 360
        try:
            while time.monotonic() < deadline and process.poll() is None:
                for entry in output.iterdir():
                    if entry.name not in ('old.apk', 'new.apk', 'fixture.pub'): raise RuntimeError('unexpected_output')
                    info = entry.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > (8192 if entry.name == 'fixture.pub' else MAX_SIZE): raise RuntimeError('output_bound')
                if not select.select([process.stdout], [], [], 0.25)[0]: continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk: break
                if stage != 2:
                    buffer = (buffer + chunk)[-65536:]
                    if stage == 0 and b'login:' in buffer:
                        process.stdin.write(b'root\n'); process.stdin.flush(); stage = 1; buffer = b''; mark(result, 'guest_login')
                    elif stage == 1 and (b'~ #' in buffer or b':~# ' in buffer):
                        process.stdin.write(b'mkdir -p /fixture /output; mount -t 9p -o trans=virtio,version=9p2000.L,ro fixture /fixture && mount -t 9p -o trans=virtio,version=9p2000.L output /output && sh /fixture/guest.sh || echo ONYX_RESULT FAIL guest_mount_or_script\n'); process.stdin.flush(); stage = 2; buffer = b''; mark(result, 'guest_run')
                    continue
                serial_pending += chunk
                while b'\n' in serial_pending:
                    line, serial_pending = serial_pending.split(b'\n', 1)
                    if len(line) > 87500: raise RuntimeError('service_transfer_invalid')
                    if line.startswith(b'ONYX_PRIVATE_PROFILE'):
                        capture_profile(line, capture_dir, profile_captures)
                        result['profile_captures'] = list(profile_captures.values())
                    elif line.startswith(b'ONYX_PRIVATE_SERVICE'):
                        capture_service(line, capture_dir, captures)
                        result['service_captures'] = list(captures.values())
                        result['service_capture_count'] = len(captures)
                    else:
                        buffer = (buffer + line + b'\n')[-65536:]
                if len(serial_pending) > 87500: raise RuntimeError('service_transfer_invalid')
                decoded = parse_diagnostics(buffer, b'ONYX_DIAG service', SERVICE_DIAG)
                custody = parse_diagnostics(buffer, b'ONYX_DIAG custody', CUSTODY_DIAG)
                result['service_diagnostics'] = decoded
                result['custody_diagnostics'] = custody
                identity_lines = [line for line in buffer.splitlines() if line.startswith(b'ONYX_DIAG identity')]
                if len(identity_lines) > 1: raise RuntimeError('service_diagnostic_bound')
                if identity_lines:
                    identity_match = re.fullmatch(rb'ONYX_DIAG identity ([0-9]{1,3}) (loaded|strict_validated|generated|other|read_error) (present|absent) (within|outside|unknown)', identity_lines[0])
                    if identity_match is None or int(identity_match.group(1)) > 255: raise RuntimeError('service_diagnostic_bound')
                    result['identity_diagnostic'] = {'exit': int(identity_match.group(1)), 'source': identity_match.group(2).decode('ascii'), 'remaining_daemon': identity_match.group(3).decode('ascii'), 'watchdog_window': identity_match.group(4).decode('ascii')}
                hashes = re.findall(rb'(?:^|\n)ONYX_ARTIFACT ([0-9a-f]{64}) ([0-9a-f]{64}) ([0-9a-f]{64})\r?\n', buffer)
                if len(hashes) == 1 and artifact_hashes is None:
                    artifact_hashes = [x.decode('ascii') for x in hashes[0]]; mark(result, 'guest_artifacts')
                failure = re.search(rb'(?:^|\n)ONYX_RESULT FAIL ([a-z_]{1,40})\r?\n', buffer)
                match = re.search(rb'(?:^|\n)ONYX_RESULT PASS package\r?\n', buffer)
                if failure or match:
                    validate_correspondence(decoded, custody, captures)
                if failure:
                    code = failure.group(1).decode('ascii')
                    result.update(result='guest_failure', failure=code if code in FAILS else 'unknown')
                    if code == 'helix_socket':
                        result['socket_diagnostic'] = parse_socket_diagnostic(buffer)
                    if code == 'install':
                        diagnostics = re.findall(rb'(?:^|\n)ONYX_DIAG install ([0-9]{1,3}) (other|non_repository|trust|option|missing|permission|truncated)\r?\n', buffer)
                        if len(diagnostics) == 1 and 1 <= int(diagnostics[0][0]) <= 255:
                            result['install_diagnostic'] = {'exit': int(diagnostics[0][0]), 'class': diagnostics[0][1].decode('ascii')}
                    if code == 'build':
                        result['apk_phase_diagnostic'] = parse_apk_phase(buffer)
                        diagnostics = re.findall(rb'(?:^|\n)ONYX_DIAG build (old|new) ([0-9]{1,3}) (none|[0-9]{1,3}) (reported|not_reported|unknown) (complete|truncated|unknown)\r?\n', buffer)
                        if len(diagnostics) == 1:
                            stage_name, pipeline, apk_exit, option, log = (v.decode('ascii') for v in diagnostics[0])
                            if 1 <= int(pipeline) <= 255 and (apk_exit == 'none' or 1 <= int(apk_exit) <= 255):
                                result['build_diagnostic'] = {'stage': stage_name, 'build_exit': int(pipeline), 'apk_exit': None if apk_exit == 'none' else int(apk_exit), 'unsupported_option': option, 'log': log}
                    break
                if match:
                    profiles_complete(buffer, profile_captures)
                    result['helix_observations'] = parse_helix_observations(buffer)
                    if captures.get(('identity','probe'), {}).get('identity_source') != 'strict_validated': raise RuntimeError('service_transfer_invalid')
                    result['result'] = 'pass' if artifact_hashes else 'invalid_artifact_receipt'; break
        finally:
            print('ONYX_STAGE guest_cleanup', file=sys.stderr, flush=True)
            try:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError: break
                    time.sleep(0.05)
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
                until = time.monotonic() + 5; gone = False
                while time.monotonic() < until:
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError: gone = True; break
                    time.sleep(0.05)
                result['cleanup_ok'] = process.poll() is not None and gone
            except OSError as exc:
                result['cleanup_ok'] = False
                result['cleanup_error'] = 'os_error'
                result['cleanup_errno'] = exc.errno if isinstance(exc.errno, int) and 0 <= exc.errno <= 4095 else None
            finally:
                for stream in (process.stdin, process.stdout):
                    try: stream.close()
                    except OSError as exc:
                        result['cleanup_ok'] = False
                        result['cleanup_error'] = 'stream_close'
                        result['cleanup_errno'] = exc.errno if isinstance(exc.errno, int) and 0 <= exc.errno <= 4095 else None
        mark(result, 'verify_inputs')
        if any(digest(source) != pins[key] or digest(share / key) != pins[key] for key, source in paths.items()) or digest(iso) != ISO_PIN or (share / 'expected.sha256').read_text() != args.expected_binary_sha256 + '\n':
            result['result'] = 'input_changed'
        if not result['cleanup_ok']: result['result'] = 'cleanup_failed'
        if artifact_hashes and result['cleanup_ok']:
            mark(result, 'recover_artifacts')
            recovered = []
            try:
                for file, expected in zip(('old.apk', 'new.apk', 'fixture.pub'), artifact_hashes):
                    identity = recover(output / file, out_dir / file, expected); recovered.append((out_dir / file, identity))
            except BaseException:
                for file, identity in recovered: unlink_created(file, identity)
                raise
            result['artifacts'] = dict(zip(('old.apk', 'new.apk', 'fixture.pub'), artifact_hashes))
    mark(result, 'complete')
    return result


def binary_sha256(value):
    if re.fullmatch(r'[0-9a-f]{64}', value) is None: raise argparse.ArgumentTypeError('expected lowercase 64-character SHA-256')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-root', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--expected-binary-sha256', required=True, type=binary_sha256)
    parser.add_argument('--iso', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    result = {'result': 'driver_failure', 'stage': 'parse', 'failure': None,
              'cleanup_attempted': False, 'cleanup_ok': None, 'cleanup_error': None, 'cleanup_errno': None,
              'error_class': None, 'error_code': None, 'errno': None,
              'artifacts': None, 'build_diagnostic': None, 'apk_phase_diagnostic': None, 'socket_diagnostic': None, 'install_diagnostic': None, 'service_diagnostics': [], 'service_captures': [], 'service_capture_count': 0, 'custody_diagnostics': [], 'identity_diagnostic': None}
    try:
        run(args, result)
    except OSError as exc:
        result.update(result='driver_failure', error_class='os_error', errno=exc.errno if isinstance(exc.errno, int) and 0 <= exc.errno <= 4095 else None)
    except subprocess.TimeoutExpired:
        result.update(result='driver_failure', error_class='subprocess_timeout')
    except subprocess.CalledProcessError as exc:
        result.update(result='driver_failure', error_class='subprocess_exit', error_code=exc.returncode if isinstance(exc.returncode, int) and -255 <= exc.returncode <= 255 else None)
    except subprocess.SubprocessError:
        result.update(result='driver_failure', error_class='subprocess_error')
    except (ValueError, IndexError, KeyError, UnicodeError):
        result.update(result='driver_failure', error_class='origin_format')
    except RuntimeError as exc:
        code = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) and exc.args[0] in RUNTIME_CODES else 'unknown'
        result.update(result='driver_failure', error_class='runtime_error', error_code=code)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
