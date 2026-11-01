# SPDX-License-Identifier: AGPL-3.0-or-later
"""Direct helper controls only; no daemon, sockets, credentials or live state."""
import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import q04_explain_smoke as smoke

class Helpers(unittest.TestCase):
    def wire(self):
        return [b'@label=q BATCH +suzu-label labeled-response',
                b'@batch=suzu-label :server NOTICE viewer :ACCESS EXPLAIN result=connection_context',
                b'@batch=suzu-label :server NOTICE viewer :ACCESS EXPLAIN result=policy_allow',
                b'BATCH -suzu-label']
    def test_extract_ignores_unrelated_messages(self):
        self.assertEqual(smoke.explain([b':s NOTICE n :other', b':s NOTICE n :ACCESS EXPLAIN unavailable']), [b'unavailable'])
    def test_valid_multiline_batch(self):
        self.assertEqual(len(smoke.labeled(self.wire(), b'q')), 2)
    def test_missing_close_refuses(self):
        with self.assertRaises(smoke.Failure):
            smoke.labeled(self.wire()[:-1], b'q')
    def test_unbatched_payload_refuses(self):
        wire = self.wire()
        wire[1] = b':s NOTICE n :ACCESS EXPLAIN result=connection_context'
        with self.assertRaises(smoke.Failure):
            smoke.labeled(wire, b'q')
    def test_wrong_request_label_refuses(self):
        with self.assertRaises(smoke.Failure):
            smoke.labeled(self.wire(), b'other')
    def test_duplicate_close_refuses(self):
        with self.assertRaises(smoke.Failure):
            smoke.labeled(self.wire() + [b'BATCH -suzu-label'], b'q')
    def test_wire_budget_includes_crlf(self):
        wire = self.wire()
        wire[1] += b'x' * 512
        with self.assertRaises(smoke.Failure):
            smoke.labeled(wire, b'q')
    def test_cleanup_failure_attempts_every_resource_and_invalidates_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = []
            class Resource:
                def __init__(self, name, fails=False):
                    self.name, self.fails = name, fails
                def close(self):
                    self_test.assertFalse((root / 'result.json').exists())
                    events.append(self.name)
                    if self.fails:
                        raise OSError('private error content')
            self_test = self
            clients = [Resource('client1', True), Resource('client2')]
            logs = [Resource('log1'), Resource('log2')]
            process = object()
            def fake_stop(actual):
                self.assertIs(actual, process)
                self.assertFalse((root / 'result.json').exists())
                events.append('process')
            success = {'ok': True, 'stage': 'complete', 'checks': 21}
            def fake_run(_args):
                return smoke.finish(root, success, clients, process, logs)
            stdout = io.StringIO()
            with patch.object(smoke, 'stop', side_effect=fake_stop), \
                 patch.object(smoke, 'run', side_effect=fake_run), \
                 patch('sys.argv', ['smoke', '--binary', 'unused', '--sha256', 'unused', '--artifacts', 'unused']), \
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(smoke.main(), 1)
            self.assertEqual(events, ['client1', 'client2', 'process', 'log1', 'log2'])
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result, json.loads(stdout.getvalue()))
            self.assertEqual(result['ok'], False)
            self.assertEqual(result['class'], 'cleanup_failed')
            self.assertEqual(result['cleanup_errors'], ['client_close'])
            self.assertNotIn('private error content', stdout.getvalue())
            self.assertNotIn('private error content', (root / 'result.json').read_text())

    def test_interrupt_after_spawn_stops_daemon_and_closes_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / 'campaign'
            opened = []
            real_open = builtins.open
            def tracked_open(*args, **kwargs):
                stream = real_open(*args, **kwargs)
                opened.append(stream)
                return stream
            def setup(_argv, workdir, _env, **_kwargs):
                bundle = workdir / 'bundle'
                bundle.mkdir()
                (bundle / 'onyx-server.toml').write_text('[limits]\n')
                return SimpleNamespace(returncode=0), object(), None
            args = SimpleNamespace(artifacts=campaign, binary=root / 'unused', sha256='0' * 64)
            class Child:
                def poll(self):
                    return None
            process = Child()
            with patch.object(smoke, 'pin_binary'), \
                 patch.object(smoke, 'free_ports', return_value=[1, 2, 3]), \
                 patch.object(smoke, 'run_review', side_effect=setup), \
                 patch.object(smoke.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(smoke.subprocess, 'Popen', return_value=process), \
                 patch.object(smoke, 'Client', side_effect=KeyboardInterrupt('private interrupt')), \
                 patch.object(smoke, 'stop') as stopped, \
                 patch.object(smoke, 'open', side_effect=tracked_open, create=True):
                result = smoke.run(args)
            stopped.assert_called_once_with(process)
            self.assertGreaterEqual(len(opened), 3)
            self.assertTrue(all(stream.closed for stream in opened))
            self.assertFalse(result['ok'])
            self.assertEqual(result['class'], 'interrupted')
            self.assertEqual(result, json.loads((campaign / 'result.json').read_text()))
            self.assertNotIn('private interrupt', (campaign / 'result.json').read_text())

    def test_pinned_copy_create_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'candidate')
            digest = hashlib.sha256(b'candidate').hexdigest()
            target = root / 'target'
            smoke.pin_binary(source, target, digest)
            self.assertEqual(target.read_bytes(), b'candidate')
            self.assertEqual(target.stat().st_mode & 0o777, 0o500)
            with self.assertRaises(FileExistsError):
                smoke.pin_binary(source, target, digest)
    def test_wrong_hash_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'candidate')
            with self.assertRaises(smoke.Failure):
                smoke.pin_binary(root / 'source', root / 'target', '0' * 64)
    def test_symlink_and_hardlink_source_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'candidate')
            digest = hashlib.sha256(b'candidate').hexdigest()
            (root / 'symlink').symlink_to(source)
            with self.assertRaises(OSError):
                smoke.pin_binary(root / 'symlink', root / 'target', digest)
            os.link(source, root / 'hardlink')
            with self.assertRaises(smoke.Failure):
                smoke.pin_binary(source, root / 'target2', digest)

if __name__ == '__main__':
    unittest.main()
