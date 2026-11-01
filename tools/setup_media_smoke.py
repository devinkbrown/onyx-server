#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native PTY review/cancel checks; no service start or publication."""
import argparse
import errno
import fcntl
import json
import os
import pathlib
import pty
import re
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--scratch-dir', type=pathlib.Path, required=True)
args = parser.parse_args()
binary = str(args.binary.resolve(strict=True))
args.scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)


def compact(data):
    data = re.sub(rb'\x1b\[[0-9;]*m', b'', data)
    return re.sub(rb'\s+', b'', data)


def run_case(directory, profile, port, width, colored):
    names = {1: 'private', 2: 'community', 3: 'media'}
    base_args = [binary, 'setup', '--new', '--profile', names[profile], '--media-port', str(port)]
    headless = subprocess.run(base_args + ['--json'], cwd=directory, capture_output=True, timeout=120)
    assert headless.returncode == 0, ('headless JSON status', headless.returncode)
    plan = json.loads(headless.stdout)
    assessment = plan['media_assessment']
    assert plan['readiness'] == 'unknown'
    textual = subprocess.run(base_args, cwd=directory, capture_output=True, timeout=120)
    assert textual.returncode == 0, ('headless text status', textual.returncode)
    assert b'Media assessment:' in textual.stdout
    for value in assessment.values():
        if isinstance(value,str): assert value.encode() in textual.stdout
    assert not list(pathlib.Path(directory).iterdir()), 'headless preview left artifacts'
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, width, 0, 0))
    env = dict(os.environ, TERM='xterm-256color', COLUMNS=str(width))
    if colored:
        env.pop('NO_COLOR', None)
    else:
        env['NO_COLOR'] = ''
    child = subprocess.Popen([binary, 'setup', '--new', '--interactive', '--bundle', 'cancelled'],
                             cwd=directory, env=env, stdin=slave, stdout=slave, stderr=slave,
                             start_new_session=True)
    os.close(slave)
    transcript = bytearray()
    sent = False
    try:
        deadline = time.monotonic() + 120
        while child.poll() is None:
            if time.monotonic() > deadline:
                raise AssertionError('PTY timeout')
            if select.select([master], [], [], 0.05)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                transcript.extend(chunk)
                if len(transcript) > 2_000_000:
                    raise AssertionError('PTY output limit')
                if not sent and b'choice> ' in transcript:
                    commands = f'{profile}\nset media-port {port}\nreview\ncancel\n'.encode()
                    os.write(master, commands)
                    sent = True
        child.wait(timeout=2)
        while select.select([master], [], [], 0)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            transcript.extend(chunk)
        assert sent and child.returncode == 0, ('PTY status', child.returncode)
        assert (b'\x1b[' in transcript) == colored
        text = compact(transcript)
        for value in assessment.values():
            if isinstance(value,str): assert compact(value.encode()) in text
        assert compact(b'Media network') in text
        assert compact(b'unknown; no network checks') in text
        if profile == 3:
            assert compact(b'Media enabled yes') in text
            assert compact(b'IPv4 wildcard UDP') in text
            assert compact(b'OS chooses an ephemeral port' if port == 0 else b'configured media port is used') in text
            assert compact(b'separate ephemeral native media port') in text
            assert compact(b'default 127.0.0.1 is local-only') in text
            assert compact(b'NAT, firewall and reachability unknown') in text
            assert compact(b'listener is not configured here') in text
        else:
            assert compact(b'Media enabled no') in text
            assert compact(b'configured media port is not bound') in text
            assert compact(b'no native media UDP socket') in text
        assert not list(pathlib.Path(directory).iterdir()), 'cancel left artifacts'
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        os.close(master)


with tempfile.TemporaryDirectory(prefix='setup-media-', dir=args.scratch_dir) as base:
    os.chmod(base, 0o700)
    for profile, port, width, color in [(3, 0, 20, False), (3, 7100, 80, True),
                                         (1, 7100, 38, False), (2, 0, 80, False)]:
        run_case(base, profile, port, width, color)
print('PASS: four native PTY media review/cancel cases')
