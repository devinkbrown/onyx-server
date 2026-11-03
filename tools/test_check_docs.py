#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Small independent fixtures for documentation checks; no compiler required."""
import tempfile
import unittest
from pathlib import Path
from check_docs import anchors, check_file


class DocumentationChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'README.md'

    def check(self, text):
        self.path.write_text(text)
        return check_file(self.root, self.path)[0]

    def test_catches_missing_target_and_anchor(self):
        (self.root / 'guide.md').write_text('# Available\n')
        issues = self.check('[missing](missing.md)\n[bad](guide.md#absent)\n[good](guide.md#available)')
        self.assertEqual(len(issues), 2)
        self.assertTrue(any('missing local target' in x for x in issues))
        self.assertTrue(any('missing Markdown anchor' in x for x in issues))

    def test_duplicate_headings_and_custom_anchor(self):
        text = '# Name\n# Name\n<a id="special"></a>\n[one](#name) [two](#name-1) [custom](#special)'
        self.assertEqual(self.check(text), [])
        self.assertIn('name-1', anchors(text))

    def test_fenced_html_does_not_create_rendered_anchor(self):
        (self.root / "guide.md").write_text("```html\n<a id=\"fake\"></a>\n```\n<a id=\"real\"></a>\n")
        issues = self.check("[fake](guide.md#fake) [real](guide.md#real)")
        self.assertEqual(len(issues), 1)
        self.assertIn("guide.md#fake", issues[0])

    def test_ignores_fenced_placeholder_links_and_external_urls(self):
        text = '```md\n[example](missing.md)\n```\n[remote](https://example.invalid/page#anchor)'
        self.assertEqual(self.check(text), [])

    def test_shorter_fence_does_not_end_longer_code_block(self):
        text = "````md\n```\n[example](missing.md)\n````\n[real](missing.md)"
        issues = self.check(text)
        self.assertEqual(len(issues), 1)
        self.assertIn("missing local target", issues[0])

    def test_validates_decoded_paths_and_line_ranges(self):
        (self.root / 'a b.zig').write_text('one\ntwo\n')
        self.assertEqual(self.check('[ok](a%20b.zig#L1-L2)'), [])
        self.assertEqual(len(self.check('[bad](a%20b.zig#L3)')), 1)

    def test_rejects_repository_escape_and_old_mode(self):
        self.assertEqual(len(self.check('[escape](../outside.md)\n```sh\nzig build test -Doptimize=ReleaseSafe\n```')), 2)

    def test_reference_definition_and_setext_heading(self):
        (self.root / 'guide.md').write_text('Heading\n=======\n')
        self.assertEqual(self.check('[guide]: guide.md#heading\n[guide]'), [])
        self.assertEqual(len(self.check('[guide]: guide.md#absent')), 1)


if __name__ == '__main__':
    unittest.main()
