#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cleanup controls only: owned Python children, no daemon or network campaign."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import setup_maintenance_smoke as smoke


class Resource:
    def __init__(self, label, calls, error=None):
        self.label, self.calls, self.error = label, calls, error

    def close(self):
        self.calls.append(self.label)
        if self.error:
            raise self.error('fixture-private-payload-must-not-escape')


@unittest.skipUnless(sys.platform == 'linux', 'Linux /proc and owned PGID controls')
class CleanupControls(unittest.TestCase):
    def test_maintenance_artifact_limit_is_bounded_and_prechecked(self):
        with mock.patch.object(smoke.resource, 'setrlimit') as set_limit:
            smoke.maintenance_limits()
        set_limit.assert_any_call(smoke.resource.RLIMIT_CORE, (0, 0))
        set_limit.assert_any_call(smoke.resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        self.assertEqual(set_limit.call_count, 2)
        max_original = smoke.MAINTENANCE_FILE_LIMIT - len(smoke.FIXTURE_DRIFT)
        smoke.validate_artifact_size(max_original)
        for size in (0, max_original + 1):
            with self.assertRaises(smoke.Failure) as caught:
                smoke.validate_artifact_size(size)
            self.assertEqual(str(caught.exception), 'artifact_size')
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'large'
            with binary.open('wb') as stream:
                stream.truncate(max_original + 1)
            with self.assertRaises(smoke.Failure) as caught:
                smoke.validate_input_artifact(binary)
            self.assertEqual(str(caught.exception), 'artifact_size')

    def test_server_socket_witness_rejects_endpoint_and_inode_replacement(self):
        self.assertEqual(smoke.proc_endpoint('0100007F:1F90', 'tcp'), ('127.0.0.1', 8080))
        self.assertEqual(smoke.proc_endpoint('0000000000000000FFFF00000100007F:1F90', 'tcp6'), ('127.0.0.1', 8080))
        def client(port):
            return SimpleNamespace(sock=SimpleNamespace(
                getsockname=lambda: ('127.0.0.1', port),
                getpeername=lambda: ('127.0.0.1', 8080)))
        clients = [client(40001), client(40002)]
        rows = [
            {'inode': 'socket:[1]', 'state': '01', 'local': ('127.0.0.1', 8080), 'remote': ('127.0.0.1', 40001)},
            {'inode': 'socket:[2]', 'state': '01', 'local': ('127.0.0.1', 8080), 'remote': ('127.0.0.1', 40002)},
            {'inode': 'socket:[3]', 'state': '0A', 'local': ('0.0.0.0', 8080), 'remote': ('0.0.0.0', 0)},
        ]
        before = smoke.client_socket_witness(rows, clients)
        self.assertEqual(before, ['socket:[1]', 'socket:[2]'])
        swapped = [dict(row) for row in rows]
        swapped[0]['remote'], swapped[1]['remote'] = swapped[1]['remote'], swapped[0]['remote']
        with self.assertRaises(smoke.Failure):
            smoke.require_client_socket_custody(before, swapped, clients)
        replaced = [dict(row) for row in rows]
        replaced[0]['inode'] = 'socket:[9]'
        with self.assertRaises(smoke.Failure):
            smoke.require_client_socket_custody(before, replaced, clients)
        missing = [dict(row) for row in rows]
        missing[0]['remote'] = ('127.0.0.1', 49999)
        with self.assertRaises(smoke.Failure):
            smoke.client_socket_witness(missing, clients)
        self.assertEqual(smoke.listener_socket_witness(rows, 8080), 'socket:[3]')

    def test_every_resource_attempted_after_failure_and_interrupt(self):
        calls = []
        for error in (OSError, KeyboardInterrupt):
            calls.clear()
            with mock.patch.object(smoke, 'retire_group', side_effect=lambda _: calls.append('group')):
                with self.assertRaises(smoke.CleanupFailure) as caught:
                    smoke.cleanup_resources(
                        [Resource('wizard1', calls, error), Resource('wizard2', calls)],
                        [Resource('client1', calls, OSError), Resource('client2', calls)],
                        object(), [Resource('log1', calls, OSError), Resource('log2', calls)])
            self.assertEqual(calls, ['wizard1', 'wizard2', 'client1', 'client2', 'group', 'log1', 'log2'])
            self.assertEqual(len(caught.exception.errors), 3)
            self.assertNotIn('fixture-private-payload', str(caught.exception.errors))

    def test_wizard_close_attempts_all_resources_and_retry_is_safe(self):
        calls = []
        wizard = smoke.Wizard.__new__(smoke.Wizard)
        wizard.closed, wizard.process, wizard.master = False, object(), 823
        wizard.log = Resource('capture', calls)
        with mock.patch.object(smoke, 'retire_group', side_effect=OSError('private')):
            with mock.patch.object(smoke.os, 'close', side_effect=lambda _: calls.append('pty')):
                with self.assertRaises(smoke.CleanupFailure):
                    wizard.close()
        self.assertFalse(wizard.closed)
        self.assertEqual(calls, ['pty', 'capture'])
        self.assertIsNone(wizard.master)
        self.assertIsNone(wizard.log)
        with mock.patch.object(smoke, 'retire_group') as retire:
            with mock.patch.object(smoke.os, 'close') as close:
                wizard.close()
                wizard.close()
        self.assertTrue(wizard.closed)
        retire.assert_called_once()
        close.assert_not_called()

    def test_wizard_constructor_failure_retires_partial_resources(self):
        read_fd, write_fd = os.pipe()
        process = object()
        capture = io.BytesIO()
        with mock.patch.object(smoke.pty, 'openpty', return_value=(read_fd, write_fd)):
            with mock.patch.object(smoke.fcntl, 'ioctl'), mock.patch('builtins.open', return_value=capture):
                with mock.patch.object(smoke.os, 'chmod'), mock.patch.object(smoke.subprocess, 'Popen', return_value=process):
                    with mock.patch.object(smoke.Wizard, 'until', side_effect=KeyboardInterrupt):
                        with mock.patch.object(smoke, 'retire_group') as retire:
                            with self.assertRaises(KeyboardInterrupt):
                                smoke.Wizard(Path('/unused'), mock.Mock(pid=1), Path('/unused/config'),
                                             Path('/unused/target'), Path('/unused/backup'), Path('/unused/scratch'),
                                             Path('/unused'), 'fixture')
        retire.assert_called_once_with(process)
        self.assertTrue(capture.closed)
        for fd in (read_fd, write_fd):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def start_child(self, source):
        process = subprocess.Popen([sys.executable, '-I', '-u', '-c', source],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(process.stdout.close)
        # Register emergency retirement before reading any readiness bytes.
        self.addCleanup(smoke.retire_group, process)
        self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'child readiness deadline')
        line = process.stdout.readline()
        self.assertTrue(line, 'child readiness')
        return process, line

    def test_term_ignoring_leader_is_killed_and_reaped(self):
        process, _ = self.start_child('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(30)')
        start = time.monotonic()
        smoke.retire_group(process)
        self.assertLess(time.monotonic() - start, 12)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(smoke.live_group_members(process.pid), [])
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_exited_unreaped_leader_does_not_hide_term_ignoring_descendant(self):
        child_source = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(30)'
        source = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-I","-u","-c",' +
                  repr(child_source) + '],stdout=subprocess.PIPE); p.stdout.readline(); print(p.pid,flush=True)')
        process, line = self.start_child(source)
        descendant = int(line)
        deadline = time.monotonic() + 5
        while smoke.process_status(process) is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(smoke.process_status(process), 0)
        self.assertIsNone(process.returncode, 'leader must remain unreaped')
        self.assertIn(descendant, smoke.live_group_members(process.pid))
        smoke.retire_group(process)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(smoke.live_group_members(process.pid), [])
        # A nonchild zombie, if any, is reaped by its kernel parent, not this tool.

    def test_interrupt_during_term_still_kills_reaps_and_refuses_success(self):
        process, _ = self.start_child('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(30)')
        real_killpg = os.killpg
        signals = []
        def interrupt_term(pgid, sig):
            signals.append(sig)
            if sig == signal.SIGTERM:
                raise KeyboardInterrupt
            real_killpg(pgid, sig)
        with mock.patch.object(smoke.os, 'killpg', side_effect=interrupt_term):
            with self.assertRaises(smoke.CleanupFailure) as caught:
                smoke.retire_group(process)
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(caught.exception.errors, ({'resource': 'group_term', 'class': 'KeyboardInterrupt'},))
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(smoke.live_group_members(process.pid), [])

    def test_already_reaped_leader_is_never_signalled(self):
        process = SimpleNamespace(returncode=0)
        with mock.patch.object(smoke.os, 'killpg') as kill:
            with self.assertRaises(smoke.CleanupFailure):
                smoke.retire_group(process)
        kill.assert_not_called()

    def test_cleanup_failure_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            parent.chmod(0o700)
            artifacts = parent / 'artifacts'
            binary = parent / 'fixture-binary'
            binary.write_bytes(b'fixture executable bytes')
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            argv = ['fixture', '--binary', str(binary), '--sha256', digest, '--artifacts', str(artifacts)]
            output = io.StringIO()
            error = smoke.CleanupFailure([{'resource': 'capture', 'class': 'OSError'}])
            with mock.patch.object(sys, 'argv', argv):
                with mock.patch.object(smoke, 'campaign', side_effect=error) as campaign:
                    with mock.patch.object(smoke.signal, 'signal'), mock.patch.object(smoke.signal, 'alarm'):
                        with contextlib.redirect_stdout(output):
                            status = smoke.main()
            self.assertEqual(status, 1)
            campaign.assert_called_once()
            result = json.loads(output.getvalue())
            self.assertFalse(result['ok'])
            self.assertEqual(result['cleanup_errors'], 1)
            self.assertNotIn('checks', result)
            self.assertEqual(json.loads((artifacts / 'result.json').read_text()), result)


if __name__ == '__main__':
    unittest.main()
