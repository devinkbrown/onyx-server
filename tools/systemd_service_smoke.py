#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise shipped unit command ordering without a manager or listening daemon."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "etc/systemd/onyx-server.service"


def directives() -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] = {}
    for line in UNIT.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            current = sections.setdefault(line[1:-1], {})
        else:
            key, value = line.split('=', 1)
            current.setdefault(key, []).append(value)
    return sections


class ServiceContract(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix='onyx-systemd-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.trace = self.work / 'trace'
        self.config = self.work / 'candidate.toml'
        self.config.write_text('valid\n')
        self.daemon = self.work / 'daemon'
        self.daemon.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$TRACE"
[ "$#" = 2 ] && [ "$1" = --check-config ] || exit 99
[ "$(cat "$2")" = valid ]
''')
        self.daemon.chmod(0o700)
        self.signal = self.work / 'signal'
        self.signal.write_text('''#!/bin/sh
[ "$1" = -USR2 ] && [ "$2" = 12345 ] || exit 99
printf 'signal\\n' >> "$TRACE"
''')
        self.signal.chmod(0o700)

    def run_phase(self, phase: str) -> int:
        for command in directives()['Service'][phase]:
            args = [str(self.daemon) if a == '/usr/local/bin/onyx-server'
                    else str(self.signal) if a == '/bin/kill'
                    else str(self.config) if a == '/etc/onyx-server/onyx-server.toml'
                    else '12345' if a == '$MAINPID' else a
                    for a in shlex.split(command)]
            result = subprocess.run(args, cwd=self.work,
                                    env={'PATH': os.defpath, 'TRACE': str(self.trace)},
                                    capture_output=True, timeout=5)
            if result.returncode:
                return result.returncode
        return 0

    def test_preflight_and_start_share_candidate(self) -> None:
        service = directives()['Service']
        self.assertEqual(self.run_phase('ExecStartPre'), 0)
        self.assertEqual(shlex.split(service['ExecStart'][0]), [
            '/usr/local/bin/onyx-server', '/etc/onyx-server/onyx-server.toml'])
        self.assertEqual(service['User'], ['onyx-server'])
        self.assertEqual(service['Group'], ['onyx-server'])

    def test_reload_validates_before_signalling(self) -> None:
        self.assertEqual(self.run_phase('ExecReload'), 0)
        self.assertEqual(self.trace.read_text().splitlines(), [
            '--check-config ' + str(self.config), 'signal'])

    def test_invalid_candidate_blocks_start_and_signal(self) -> None:
        self.config.write_text('invalid\n')
        self.assertNotEqual(self.run_phase('ExecStartPre'), 0)
        self.assertNotEqual(self.run_phase('ExecReload'), 0)
        self.assertNotIn('signal', self.trace.read_text())

    def test_missing_candidate_blocks_signal(self) -> None:
        self.config.unlink()
        self.assertNotEqual(self.run_phase('ExecReload'), 0)
        self.assertNotIn('signal', self.trace.read_text())

    def test_limits_and_native_runtime_contract(self) -> None:
        unit = directives()
        service = unit['Service']
        self.assertEqual(unit['Unit']['StartLimitIntervalSec'], ['60'])
        self.assertEqual(unit['Unit']['StartLimitBurst'], ['5'])
        self.assertNotIn('StartLimitBurst', service)
        self.assertEqual(service['CapabilityBoundingSet'], [''])
        self.assertEqual(service['UMask'], ['0077'])
        self.assertEqual(service['KillMode'], ['mixed'])
        allowed = service['SystemCallFilter'][0].split()
        for syscall in ('io_uring_setup', 'io_uring_enter', 'io_uring_register',
                        'memfd_create', 'execveat', 'pidfd_open', 'pidfd_send_signal'):
            self.assertIn(syscall, allowed)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze unavailable')
    def test_native_unit_parser(self) -> None:
        # Retain the full sandbox/directives; replace only the absent installed
        # executable. verify parses units and never starts a service.
        candidate = self.work / 'onyx-server.service'
        candidate.write_text(UNIT.read_text().replace('/usr/local/bin/onyx-server', '/bin/true'))
        result = subprocess.run(['systemd-analyze', 'verify', str(candidate)],
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
