#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial harness-only tests. Static fake WALs carry NO persistence evidence."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('retirement_nonempty_smoke', HERE / 'retirement_nonempty_smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

# This subprocess supplies only syntactically valid harness inputs, deliberately
# not a production WAL. Real acceptance uses the separate Zig fixture generator.
GENERATOR = r'''
from pathlib import Path
selected = '11' * 32
retired = '22' * 32
Path('manifest.toml').write_text(f'selected="{selected}"\nretired="{retired}"\nexpected_grants=2\nsource_facts=4\ntoken_bytes=16\n')
rows = ''.join('[[mesh.retired_session_group_fences]]\ngroup_key = "' + key * 32 + '"\nissuer_key = "' + selected + '"\nfact_digest = "' + fact * 32 + '"\n\n' for key, fact in [('33', '44'), ('55', '66')])
Path('expected.toml').write_text(rows)
Path('candidate.toml').write_text('# Static harness oracle only\n')
for name in ('good', 'missing', 'altered', 'retired-new'):
    Path(name, 'accounts.wal').write_bytes(b'STATIC HARNESS ORACLE; NOT A WAL')
'''


class PrivacyTests(unittest.TestCase):
    def exercise(self, payload, message):
        with tempfile.TemporaryDirectory(prefix='onyx-privacy-test-') as directory:
            root = Path(directory)
            generator = root / 'generator'
            binary = root / 'malicious-cli'
            generator.write_text('#!' + sys.executable + '\n' + GENERATOR)
            binary.write_text('#!' + sys.executable + '\nimport os\nos.write(1, ' + repr(payload) + ')\n')
            generator.chmod(0o700)
            binary.chmod(0o700)
            # Require the precise privacy Failure. JSON parse errors, invalid
            # baseline shape, and other unrelated failures cannot pass this test.
            with self.assertRaises(smoke.Failure) as raised:
                smoke.run(binary, generator)
            self.assertEqual(str(raised.exception), message)

    def test_raw_16_byte_token_from_cli_is_rejected(self):
        self.exercise(bytes([35]) * 16, 'private fixture data leaked')

    def test_hex_32_character_token_from_cli_is_rejected(self):
        self.exercise((bytes([36]) * 16).hex().encode(), 'private fixture data leaked')


if __name__ == '__main__':
    unittest.main()
