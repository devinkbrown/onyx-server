# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path
import tempfile
import unittest

import roadmap_checkpoint_audit as audit


class CheckpointAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkpoint = self.root / 'current.json'
        self.ledger = self.root / 'ledger.md'
        self.ledger.write_text('| P01 | Requirement | accepted | Proof |\n| P02 | Other | open | Proof |\n')
        self.current = {
            'jobs': [],
            'acceptance_ledger_counts': {'accepted': 1, 'partial': 0, 'open': 1},
            'actual_source': {'sha256': 'current'},
            'release': {'full_verification': 'full.json', 'current_full_suite': 'parent only; current full pending'},
        }
        self.write('full.json', {'manifest_sha256': 'parent'})

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def run_audit(self):
        self.checkpoint.write_text(json.dumps(self.current))
        return audit.audit(self.root, self.checkpoint, self.ledger)

    def job(self, status, record=None):
        self.current['jobs'] = [{'name': 'sample', 'wave': 1, 'state': 'running'}]
        self.write('.zig-cache/wave-1/sample-supervisor/status.json', {'status': status})
        if record is not None:
            self.write('.zig-cache/wave-1/sample.json', record)

    def test_running_job_terminal(self):
        self.job('terminal')
        self.assertEqual(self.run_audit()['issues'][0]['kind'], 'running_job_terminal')

    def test_live_job_and_empty_receipt_are_not_complete(self):
        self.job('running')
        (self.root / '.zig-cache/wave-1/sample.json').write_text('')
        result = self.run_audit()
        self.assertEqual(result['issues'], [])
        self.assertEqual(result['unknown'], [])

    def test_completed_receipt_while_listed_running(self):
        self.job('running', {'exit_code': 0})
        self.assertEqual(self.run_audit()['issues'][0]['kind'], 'running_job_completed_receipt')

    def test_missing_and_unknown_status_are_unknown(self):
        self.current['jobs'] = [{'name': 'sample', 'wave': 1, 'state': 'running'}]
        self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'job_status_unavailable')
        self.job('unexpected')
        self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'job_status_unknown')

    def test_non_string_and_non_object_status_are_unknown(self):
        self.current['jobs'] = [{'name': 'sample', 'wave': 1, 'state': 'running'}]
        path = '.zig-cache/wave-1/sample-supervisor/status.json'
        for status in (None, [], {}, 42):
            with self.subTest(status=status):
                self.write(path, {'status': status})
                self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'job_status_unknown')
        for document in ([], None, 'running'):
            with self.subTest(document=document):
                self.write(path, document)
                self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'job_status_unavailable')

    def test_non_string_second_status_is_unknown(self):
        self.job('running', {'exit_code': 0})
        real_read = audit.read_json
        calls = 0
        def read_with_changed_status(path):
            nonlocal calls
            if path.name == 'status.json':
                calls += 1
                if calls == 2:
                    return {'status': []}
            return real_read(path)
        from unittest.mock import patch
        with patch.object(audit, 'read_json', side_effect=read_with_changed_status):
            result = self.run_audit()
        self.assertEqual(result['issues'], [])
        self.assertEqual(result['unknown'][0]['kind'], 'job_status_unknown')

    def test_missing_full_evidence_is_unknown(self):
        (self.root / 'full.json').unlink()
        self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'full_suite_evidence_unavailable')

    def test_bad_and_duplicate_rows_and_counts(self):
        self.ledger.write_text('| P01 | A | accepted | Proof |\n| P01 | B | open | Proof |\n| P2 | C | accepted | Proof |\n| P03 | D | broken | Proof |\n')
        kinds = {i['kind'] for i in self.run_audit()['issues']}
        self.assertEqual(kinds, {'ledger_duplicate_id', 'ledger_row_malformed', 'ledger_counts_mismatch'})

    def test_full_suite_wrong_manifest_versus_qualified_parent(self):
        self.assertEqual(self.run_audit()['issues'], [])
        self.current['release']['current_full_suite'] = 'Current full suite is green and passed'
        self.assertEqual(self.run_audit()['issues'][0]['kind'], 'full_suite_wrong_manifest')
        self.current['actual_source']['sha256'] = 'parent'
        self.assertEqual(self.run_audit()['issues'], [])

    def secret_kinds(self):
        return [i for i in self.run_audit()['issues'] if i['kind'] == 'checkpoint_secret_pattern']

    def test_bearer_token_is_flagged_without_leaking_value(self):
        token = 'eyJhbGciOiJIUzI1NiJ9abcdefgh12345678'
        self.current['note'] = f'Authorization: Bearer {token}'
        found = self.secret_kinds()
        self.assertEqual([i['pattern'] for i in found], ['bearer_token'])
        self.assertNotIn(token, json.dumps(self.run_audit()))

    def test_private_key_block_is_flagged(self):
        self.current['note'] = '-----BEGIN RSA PRIVATE KEY-----'
        self.assertEqual([i['pattern'] for i in self.secret_kinds()], ['private_key'])
        self.current['note'] = '-----BEGIN PRIVATE KEY-----'
        self.assertEqual([i['pattern'] for i in self.secret_kinds()], ['private_key'])

    def test_secret_and_password_assignments_are_flagged(self):
        for key, value in (('db_password', 'hunter2-real-value'), ('client_secret', 'supersecretvalue'),
                           ('api_token', 'token-live-123456'), ('api_key', 'key-live-123456')):
            with self.subTest(key=key):
                self.current.pop('extra', None)
                self.current['extra'] = {key: value}
                self.assertEqual([i['pattern'] for i in self.secret_kinds()], ['secret_assignment'])

    def test_secret_assignment_in_checkpoint_history_is_flagged(self):
        history = self.root / '.zig-cache/checkpoints/old.json'
        history.parent.mkdir(parents=True, exist_ok=True)
        history.write_text('MESH_SECRET=mesh-live-secret-value\n')
        found = self.secret_kinds()
        self.assertEqual([i['pattern'] for i in found], ['secret_assignment'])
        self.assertEqual(found[0]['source'], '.zig-cache/checkpoints/old.json')

    def test_hashes_and_digests_are_not_flagged(self):
        digest = 'a' * 64
        self.current['actual_source']['sha256'] = digest
        self.current['artifact_sha256'] = 'b' * 64
        self.current['artifact_hash'] = 'c' * 40
        self.current['client_secret'] = digest
        self.assertEqual(self.secret_kinds(), [])

    def test_secret_word_in_prose_is_not_flagged(self):
        self.current['note'] = 'the cloak secret rotation is handled elsewhere'
        self.assertEqual(self.secret_kinds(), [])

    def test_placeholder_assignments_are_not_flagged(self):
        for value in ('redacted', '[REDACTED]', '<password>', '***', 'xxxxxxxx',
                      '${DB_PASSWORD}', '$MESH_SECRET', 'changeme', 'placeholder-value', 'example-secret'):
            with self.subTest(value=value):
                self.current['extra'] = {'db_password': value}
                self.assertEqual(self.secret_kinds(), [])

    def test_non_secret_and_suffixed_keys_are_not_flagged(self):
        self.current['extra'] = {'secret_count': 42, 'token_parent': 'some-live-value-here',
                                 'password_hash': 'hunter2-real-value', 'has_secret': True}
        self.assertEqual(self.secret_kinds(), [])

    def test_bearer_placeholder_is_not_flagged(self):
        self.current['note'] = 'Authorization: Bearer redacted'
        self.assertEqual(self.secret_kinds(), [])

    def test_bad_job_name_does_not_escape_root(self):
        self.current['jobs'] = [{'name': '../escape', 'wave': 1, 'state': 'running'}]
        self.assertEqual(self.run_audit()['unknown'][0]['kind'], 'job_identifier_invalid')


if __name__ == '__main__':
    unittest.main()
