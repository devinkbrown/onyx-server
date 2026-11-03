#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check repository documentation links and inventory human-readable text.

Offline checks deliberately do not certify external sites or prose semantics.
Ignored/generated/private files and unrelated untracked evidence are excluded.
"""
from __future__ import annotations

import argparse
import collections
import html
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ('docs/audit/evidence/',)
LINK = re.compile(r'!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[\"\'][^\n]*?[\"\'])?\s*\)')
FENCE = re.compile(r'^\s{0,3}(`{3,}|~{3,})')
OLD_MODE = re.compile(r'-Doptimize=(?:ReleaseSafe|ReleaseFast|ReleaseSmall|Debug)\b')


def without_fences(text: str) -> str:
    lines = []
    fence = None
    for line in text.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match[1][0]
            if fence is None:
                fence = (marker, len(match[1]))
            elif fence[0] == marker and len(match[1]) >= fence[1] and not line[match.end():].strip():
                fence = None
            lines.append('')
        else:
            lines.append(line if fence is None else '')
    return '\n'.join(lines)


def anchors(text: str) -> set[str]:
    text = without_fences(text)
    result = set(re.findall(r'<a\s+(?:[^>]*?\s)?(?:id|name)=[\"\']([^\"\']+)', text, re.I))
    seen: collections.Counter[str] = collections.Counter()
    lines = without_fences(text).splitlines()
    for index, line in enumerate(lines):
        heading = re.match(r'^\s{0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$', line)
        title = heading[1] if heading else None
        if title is None and index + 1 < len(lines) and re.fullmatch(r'\s*(?:=+|-+)\s*', lines[index + 1]) and line.strip() and not line.startswith(('|', '>')):
            title = line
        if title is None:
            continue
        title = re.sub(r'<[^>]+>', '', html.unescape(title)).lower().strip()
        title = re.sub(r'[^\w\- ]', '', title).replace(' ', '-')
        suffix = f'-{seen[title]}' if seen[title] else ''
        result.add(title + suffix)
        seen[title] += 1
    return result


def check_file(root: Path, path: Path) -> tuple[list[str], int]:
    text = path.read_text(encoding='utf-8')
    prose = without_fences(text)
    urls = [(m.start(), m[1].strip('<>')) for m in LINK.finditer(prose)]
    # Definitions are checked even if a reference label is used implicitly.
    urls += [(m.start(), m[1].strip('<>')) for m in re.finditer(r'^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)', prose, re.M)]
    urls += [(m.start(), m[1]) for m in re.finditer(r'<(?:a|img)\s+[^>]*?(?:href|src)=[\"\']([^\"\']+)', prose, re.I)]
    issues = []
    checked = 0
    for offset, raw in urls:
        parsed = urlsplit(html.unescape(raw))
        if parsed.scheme or parsed.netloc:
            continue
        base = root if parsed.path.startswith('/') else path.parent
        target = (base / unquote(parsed.path).lstrip('/')).resolve() if parsed.path else path.resolve()
        location = f'{path.relative_to(root)}:{prose[:offset].count(chr(10)) + 1}'
        if not target.is_relative_to(root.resolve()):
            issues.append(f'{location}: link leaves repository: {raw}')
            continue
        checked += 1
        if not target.exists():
            issues.append(f'{location}: missing local target: {raw}')
            continue
        if not parsed.fragment or target.is_dir():
            continue
        fragment = unquote(parsed.fragment)
        line = re.fullmatch(r'L(\d+)(?:-L?(\d+))?', fragment)
        if line:
            count = len(target.read_text(encoding='utf-8').splitlines())
            if not 1 <= int(line[1]) <= int(line[2] or line[1]) <= count:
                issues.append(f'{location}: invalid source line range: {raw}')
        elif target.suffix.lower() == '.md' and fragment not in anchors(target.read_text(encoding='utf-8')):
            issues.append(f'{location}: missing Markdown anchor: {raw}')
    for match in OLD_MODE.finditer(text):
        issues.append(f'{path.relative_to(root)}:{text[:match.start()].count(chr(10)) + 1}: obsolete Zig optimization spelling: {match[0]}')
    return issues, checked


def paths(root: Path) -> list[Path]:
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root, check=True, capture_output=True)
    return [root / name for name in sorted(set(result.stdout.decode().split('\0'))) if name and not name.startswith(PRIVATE) and (root / name).is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory-json', type=Path, help='save file classifications; never certifies prose')
    args = parser.parse_args()
    tracked = paths(ROOT)
    inventory = []
    issues = []
    links = 0
    for path in tracked:
        relative = str(path.relative_to(ROOT))
        try:
            data = path.read_bytes()
            if b'\0' in data:
                continue
            data.decode('utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        kind = 'markdown' if path.suffix.lower() == '.md' else 'source' if path.suffix in ('.zig', '.py', '.sh', '.mjs', '.ps1') else 'configuration' if path.suffix in ('.toml', '.yaml', '.yml', '.confd', '.service', '.zon', '.ini') else 'text-or-fixture'
        inventory.append({'path': relative, 'kind': kind})
        if kind == 'markdown':
            found, checked = check_file(ROOT, path)
            issues.extend(found)
            links += checked
    if args.inventory_json:
        args.inventory_json.parent.mkdir(parents=True, exist_ok=True)
        args.inventory_json.write_text(json.dumps({'files':inventory, 'counts':dict(collections.Counter(x['kind'] for x in inventory)), 'local_links_checked':links, 'issues':issues, 'scope':'Repository-owned nonignored text; no semantic or external URL certification.'}, indent=2) + '\n')
    for issue in issues:
        print(issue)
    count = sum(x['kind'] == 'markdown' for x in inventory)
    print(f'documentation: {count} Markdown files, {links} local links, {len(inventory)} text files inventoried, {len(issues)} issues')
    return bool(issues)


if __name__ == '__main__':
    raise SystemExit(main())
