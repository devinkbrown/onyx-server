#!/usr/bin/env python3
"""Private disposable Alpine OpenRC logger delivery proof; fixed output only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import tempfile
import time

ISO_PIN = 'cdc1bc0efc64d8d611bf3733f54868172a545888dfd726f518bf279bcb0ff1af'
SERVICE_PIN = 'c7d409bd2962b2eb3136124273a6d7476460f47e77907d252af39ab10bcc354e'
CONFD_PIN = '07615e4bd87d0256b51a455dd3f105d27ee39e96c2f1c024c823257ce9810d1f'
FAILS = frozenset('prerequisites occupied_socket boot_socket_type boot_syslog_status boot_syslog_identity boot_socket_owner boot_stale_identity boot_socket_binding boot_stale_remove boot_syslog_stop boot_syslog_retirement syslog_ready account openrc networking config service_user_config service_start supervisor logger_identity daemon_identity pipe_identity canary_scan metrics_ready metrics_read canary burst log_bound summary canary_leak syslog_died stop syslog_stop guest_mount_or_script'.split())


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args):
    root = args.repo_root.resolve(strict=True)
    guest = args.guest_script.resolve(strict=True)
    paths = {'onyx-server': args.binary.resolve(strict=True),
             'service': root / 'etc/openrc/onyx-server',
             'confd': root / 'etc/openrc/onyx-server.confd', 'guest.sh': guest}
    expected = {'onyx-server': args.expected_binary_sha256, 'service': SERVICE_PIN, 'confd': CONFD_PIN}
    iso = args.iso.resolve(strict=True)
    pins = {key: digest(path) for key, path in paths.items()}
    if digest(iso) != ISO_PIN or any(pins[key] != value for key, value in expected.items()):
        raise RuntimeError('input_pin')
    if not all(shutil.which(tool) for tool in ('qemu-system-x86_64', 'xorriso')) or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise RuntimeError('prerequisites')
    result = {'result': 'guest_timeout', 'failure': None, 'cleanup_ok': False,
              'inputs': pins, 'expected_binary_sha256': args.expected_binary_sha256, 'iso_sha256': ISO_PIN, 'accepted_delta': None,
              'suppressed_delta': None, 'summaries': None, 'attempt': None, 'retirement': None, 'metrics_diagnostic': None, 'lifetime_diagnostic': None,
              'scope': 'isolated guest default OpenRC logger delivery; no retention or mesh claim'}
    with tempfile.TemporaryDirectory(prefix='alpine-logger-', dir=args.work_dir) as work:
        work = Path(work); share = work / 'share'; share.mkdir(mode=0o700)
        for name, source in paths.items():
            shutil.copyfile(source, share / name)
            (share / name).chmod(0o500 if name == 'onyx-server' else 0o400)
            if digest(source) != pins[name] or digest(share / name) != pins[name]:
                raise RuntimeError('input_copy')
        kernel = work / 'kernel'; initrd = work / 'initrd'
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract', '/boot/vmlinuz-virt', str(kernel), '-extract', '/boot/initramfs-virt', str(initrd)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        command = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-m', '1024', '-smp', '2', '-nic', 'none', '-nographic', '-no-reboot', '-kernel', str(kernel), '-initrd', str(initrd), '-append', 'console=ttyS0 alpine_dev=sr0 modules=loop,squashfs,sd-mod,9p,9pnet_virtio', '-cdrom', str(iso), '-virtfs', f'local,path={share},mount_tag=fixture,security_model=none,readonly=on']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        buffer = b''; stage = 0; deadline = time.monotonic() + 180
        try:
            while time.monotonic() < deadline and process.poll() is None:
                if not select.select([process.stdout], [], [], 0.25)[0]:
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk: break
                buffer = (buffer + chunk)[-65536:]
                if stage == 0 and b'login:' in buffer:
                    process.stdin.write(b'root\n'); process.stdin.flush(); stage = 1; buffer = b''
                elif stage == 1 and (b'~ #' in buffer or b':~# ' in buffer):
                    process.stdin.write(b'mkdir -p /fixture; mount -t 9p -o trans=virtio,version=9p2000.L,ro fixture /fixture && sh /fixture/guest.sh || echo ONYX_RESULT FAIL guest_mount_or_script\n'); process.stdin.flush(); stage = 2; buffer = b''
                match = re.search(rb'(?:^|\n)ONYX_RESULT PASS logger ([0-9]{1,6}) ([0-9]{1,6}) ([0-9]{1,6}) ([1-3])\r?\n', buffer)
                failure = re.search(rb'(?:^|\n)ONYX_RESULT FAIL ([a-z_]{1,40})\r?\n', buffer)
                if stage != 2:
                    continue
                if failure:
                    code = failure.group(1).decode('ascii')
                    result.update(result='guest_failure', failure=code if code in FAILS else 'unknown')
                    if code == 'boot_syslog_retirement':
                        diagnostics = re.findall(rb'(?:^|\n)ONYX_DIAG retirement (gone|changed|zombie|live|unknown) (started|stopped|unknown) (absent|socket|symlink|other)\r?\n', buffer)
                        if len(diagnostics) == 1:
                            result['retirement'] = dict(zip(('process', 'service', 'socket'), (part.decode('ascii') for part in diagnostics[0])))
                    if code == 'metrics_ready':
                        diagnostics = re.findall(rb'(?:^|\n)ONYX_DIAG metrics (alive|changed|gone|unknown) (started|stopped|unknown) (success|timeout|other) (200|other|absent) (valid|missing|duplicate|malformed) (valid|missing|duplicate|malformed) (present|absent|read_error)\r?\n', buffer)
                        if len(diagnostics) == 1:
                            keys = ('daemon', 'service', 'nc', 'http', 'accepted', 'suppressed', 'disabled_log')
                            result['metrics_diagnostic'] = dict(zip(keys, (part.decode('ascii') for part in diagnostics[0])))
                        lifetime = re.findall(rb'(?:^|\n)ONYX_DIAG lifetime (unknown|exit|signal) ([0-9]{1,3}) (same|changed|gone|unknown) (none|present|unknown) (panic|out_of_memory|access_denied|address_in_use|unknown) (yes|unknown)\r?\n', buffer)
                        if len(lifetime) == 1:
                            outcome, number, supervisor, replacement, marker, oom = (part.decode('ascii') for part in lifetime[0])
                            number = int(number)
                            if ((outcome == 'unknown' and number == 0) or (outcome == 'exit' and number <= 255) or (outcome == 'signal' and 1 <= number <= 64)):
                                result['lifetime_diagnostic'] = {'outcome': outcome, 'code': number if outcome != 'unknown' else None, 'supervisor': supervisor, 'replacement': replacement, 'uncorrelated_log_marker': marker, 'kernel_pid_oom': oom}
                    break
                if match:
                    accepted, suppressed, summaries, attempt = map(int, match.groups())
                    if accepted > 128 and suppressed > 0 and summaries > 0:
                        result.update(result='pass', accepted_delta=accepted, suppressed_delta=suppressed, summaries=summaries, attempt=attempt)
                    else: result.update(result='guest_invalid_sentinel')
                    break
        finally:
            try:
                # The private process group may outlive its leader. Always
                # signal the group, even if Popen has already reaped QEMU.
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
                deadline_cleanup = time.monotonic() + 5
                while time.monotonic() < deadline_cleanup:
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError: break
                    time.sleep(0.05)
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
                deadline_cleanup = time.monotonic() + 5
                group_gone = False
                while time.monotonic() < deadline_cleanup:
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        group_gone = True
                        break
                    time.sleep(0.05)
                result['cleanup_ok'] = process.poll() is not None and group_gone
            finally:
                process.stdin.close(); process.stdout.close()
        if any(digest(source) != pins[name] or digest(share / name) != pins[name] for name, source in paths.items()) or digest(iso) != ISO_PIN:
            result['result'] = 'input_changed'
        if not result['cleanup_ok']:
            result['result'] = 'cleanup_failed'
    return result


def binary_sha256(value):
    if re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise argparse.ArgumentTypeError('expected a lowercase 64-character SHA-256')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-root', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--expected-binary-sha256', required=True, type=binary_sha256)
    parser.add_argument('--iso', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--guest-script', type=Path, default=Path(__file__).resolve().with_name('guest.sh'))
    args = parser.parse_args()
    try:
        result = run(args)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        result = {'result': 'driver_failure'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
