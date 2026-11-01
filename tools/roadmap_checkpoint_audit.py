#!/usr/bin/env python3
"""Read-only, conservative consistency audit of the local roadmap handoff.

This tool reports contradictions and unknown evidence; it never accepts a gate,
checks live process identity, modifies a checkpoint, or controls a process.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 4 * 1024 * 1024
NAME = re.compile(r'[a-z0-9][a-z0-9_.-]{0,99}\Z')
ROW = re.compile(r'^\|\s*([A-Z][0-9]+)\s*\|')
STATES = ('accepted', 'partial', 'open')
TERMINAL = {'terminal', 'terminal_with_survivors', 'supervisor_failed'}
ACTIVE = {'starting', 'running'}
BEARER = re.compile(r'(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,})')
PRIVATE_KEY = re.compile(r'-----BEGIN (?:[A-Z][A-Z0-9 ]*)?PRIVATE KEY-----')
ASSIGNMENT = re.compile(r'''(?ix)
    (?:^|(?<=[{,;]))\s*
    ["']?(?P<key>[A-Za-z0-9_.\-]{1,100})["']?
    \s*[:=]\s*
    (?P<value>"[^"]*"|'[^']*'|[^\s,}\]{]+)
''')
HEX_DIGEST = re.compile(r'(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\Z')
PLACEHOLDERS = {
    '', '*', '**', '***', 'redacted', '[redacted]', '<redacted>', 'placeholder',
    'example', 'changeme', 'change-me', 'change_me', 'none', 'null', 'nil',
    'true', 'false', 'todo', 'n/a', 'na', 'dummy', 'sample', 'fake', 'mock',
    'xxx', 'xxxx', 'xxxxxxxx', 'your-secret-here', 'your_secret_here',
    'your-password-here', 'your_password_here', 'insert-here', 'not-set',
}
NON_SECRET_SUFFIXES = {'hash', 'digest', 'sha', 'sha256', 'sha512', 'md5',
                       'fingerprint', 'checksum', 'count', 'length', 'exists',
                       'enabled', 'required', 'policy', 'scanning', 'scan'}
SECRET_SUFFIXES = {'secret', 'secrets', 'password', 'passwd', 'pwd', 'token', 'apikey', 'passphrase'}
REFERENCE = re.compile(r'(?:\$|\$\{|env[:.(]|process\.env\.|os\.environ|getenv)', re.IGNORECASE)


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in PLACEHOLDERS:
        return True
    if any(word in lowered for word in ('placeholder', 'redacted', 'example', 'changeme', 'change-me', 'xxxx', '****')):
        return True
    if re.fullmatch(r'(?:\*+|x+|\.+|-+|_+|<[^>]*>|\[[^\]]*\])', value):
        return True
    if REFERENCE.search(value):
        return True
    if HEX_DIGEST.fullmatch(value):
        return True
    if re.fullmatch(r'(?:-?\d+|true|false|null|none)', lowered):
        return True
    return False


def is_secret_key(key: str) -> bool:
    lowered = key.lower().strip('\'"')
    parts = [part for part in re.split(r'[_\-.]', lowered) if part]
    if not parts or parts[-1] in NON_SECRET_SUFFIXES:
        return False
    camel = [part.lower() for part in re.findall(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+', key)]
    if camel and camel[-1] in NON_SECRET_SUFFIXES:
        return False
    if parts[-1] in SECRET_SUFFIXES or (camel and camel[-1] in SECRET_SUFFIXES):
        return True
    if parts[-1] == 'key' and len(parts) >= 2 and parts[-2] in {'api', 'access', 'private', 'secret'}:
        return True
    return lowered in {'api_key', 'apikey', 'access_key', 'private_key'}


def scan_secrets(text: str, source: str) -> list:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if PRIVATE_KEY.search(line):
            found.append(issue('checkpoint_secret_pattern', source=source, pattern='private_key', line=number))
        bearer = BEARER.search(line)
        if bearer and not is_placeholder(bearer.group(1)):
            found.append(issue('checkpoint_secret_pattern', source=source, pattern='bearer_token', line=number))
        for match in ASSIGNMENT.finditer(line):
            if not is_secret_key(match.group('key')):
                continue
            value = match.group('value').strip().rstrip(',').strip('\'"')
            if len(value) >= 4 and not is_placeholder(value):
                found.append(issue('checkpoint_secret_pattern', source=source, pattern='secret_assignment', line=number))
                break
    return found


def secret_scan(root: Path, checkpoint: Path, issues: list, unknown: list) -> None:
    sources, seen = [], set()
    candidates = [checkpoint, root / '.zig-cache' / 'CURRENT.json']
    history = root / '.zig-cache' / 'checkpoints'
    if history.is_dir():
        candidates.extend(sorted(history.glob('*.json')))
    for path in candidates:
        try:
            marker = path.resolve()
        except OSError:
            marker = path
        if marker in seen:
            continue
        seen.add(marker)
        sources.append(path)
    for path in sources:
        try:
            source = path.relative_to(root).as_posix()
        except ValueError:
            source = path.name
        try:
            text = read_text(path)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError):
            # The primary checkpoint is already reported unreadable by audit();
            # any other unscannable checkpoint artifact fails closed as unknown.
            if path != checkpoint:
                unknown.append(issue('checkpoint_secret_scan_unavailable', source=source))
            continue
        issues.extend(scan_secrets(text, source))


def read_text(path: Path) -> str:
    with path.open('rb') as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('oversized')
    return data.decode('utf-8')


def read_json(path: Path):
    return json.loads(read_text(path))


def issue(kind: str, **fields):
    return {'kind': kind, **fields}


def audit(root: Path, checkpoint: Path, ledger: Path) -> dict:
    issues, unknown = [], []
    try:
        current = read_json(checkpoint)
        if not isinstance(current, dict):
            raise ValueError('not_object')
    except (OSError, UnicodeError, ValueError):
        return {'issues': [], 'unknown': [issue('checkpoint_unreadable')], 'counts': None}

    secret_scan(root, checkpoint, issues, unknown)
    jobs = current.get('jobs')
    if not isinstance(jobs, list):
        unknown.append(issue('jobs_missing_or_invalid'))
    else:
        for job in jobs:
            if not isinstance(job, dict) or job.get('state') != 'running':
                continue
            wave, name = job.get('wave'), job.get('name')
            if type(wave) is not int or wave < 1 or not isinstance(name, str) or not NAME.fullmatch(name):
                unknown.append(issue('job_identifier_invalid'))
                continue
            evidence = root / '.zig-cache' / f'wave-{wave}'
            status_path = evidence / f'{name}-supervisor' / 'status.json'
            record_path = evidence / f'{name}.json'
            try:
                status = read_json(status_path).get('status')
            except (OSError, UnicodeError, ValueError, AttributeError):
                unknown.append(issue('job_status_unavailable', job=name, wave=wave))
                continue
            if not isinstance(status, str):
                unknown.append(issue('job_status_unknown', job=name, wave=wave))
                continue
            if status in TERMINAL:
                issues.append(issue('running_job_terminal', job=name, wave=wave, supervisor=status))
                continue
            if status not in ACTIVE:
                unknown.append(issue('job_status_unknown', job=name, wave=wave))
                continue
            # An empty/partially written gate receipt is expected while running.
            try:
                record = read_json(record_path)
            except (OSError, UnicodeError, ValueError):
                continue
            if isinstance(record, dict) and type(record.get('exit_code')) is int:
                # Supervisor may have finished between the two reads; check again.
                try:
                    latest = read_json(status_path).get('status')
                except (OSError, UnicodeError, ValueError, AttributeError):
                    unknown.append(issue('job_status_unavailable', job=name, wave=wave))
                    continue
                if not isinstance(latest, str):
                    unknown.append(issue('job_status_unknown', job=name, wave=wave))
                elif latest in TERMINAL:
                    issues.append(issue('running_job_terminal', job=name, wave=wave, supervisor=latest))
                elif latest in ACTIVE:
                    issues.append(issue('running_job_completed_receipt', job=name, wave=wave))
                else:
                    unknown.append(issue('job_status_unknown', job=name, wave=wave))

    counts = Counter({state: 0 for state in STATES})
    ids = set()
    try:
        lines = read_text(ledger).splitlines()
    except (OSError, UnicodeError, ValueError):
        unknown.append(issue('ledger_unreadable'))
        lines = None
    if lines is not None:
        for number, line in enumerate(lines, 1):
            match = ROW.match(line)
            if not match:
                continue
            fields = line.split('|')
            ident = match.group(1)
            if not re.fullmatch(r'[A-Z][0-9]{2}', ident) or len(fields) != 6 or not fields[2].strip() or not fields[4].strip() or fields[3].strip() not in STATES:
                issues.append(issue('ledger_row_malformed', id=ident, line=number))
                continue
            if ident in ids:
                issues.append(issue('ledger_duplicate_id', id=ident, line=number))
                continue
            ids.add(ident)
            counts[fields[3].strip()] += 1
        if not ids:
            unknown.append(issue('ledger_no_rows'))
        claimed = current.get('acceptance_ledger_counts')
        if not isinstance(claimed, dict) or any(type(claimed.get(s)) is not int for s in STATES):
            unknown.append(issue('ledger_counts_unavailable'))
        elif ids and any(claimed[s] != counts[s] for s in STATES):
            issues.append(issue('ledger_counts_mismatch', claimed={s: claimed[s] for s in STATES}, actual=dict(counts)))

    actual = current.get('actual_source')
    release = current.get('release')
    if not isinstance(actual, dict) or not isinstance(release, dict):
        unknown.append(issue('full_suite_context_unavailable'))
    else:
        full = release.get('full_verification')
        actual_sha = actual.get('sha256')
        claim = release.get('current_full_suite')
        if not isinstance(full, str) or not isinstance(actual_sha, str) or not isinstance(claim, str):
            unknown.append(issue('full_suite_context_unavailable'))
        else:
            path = (root / full).resolve()
            if not path.is_relative_to(root.resolve()):
                unknown.append(issue('full_suite_evidence_outside_root'))
            else:
                try:
                    evidence_sha = read_json(path).get('manifest_sha256')
                except (OSError, UnicodeError, ValueError, AttributeError):
                    evidence_sha = None
                if not isinstance(evidence_sha, str):
                    unknown.append(issue('full_suite_evidence_unavailable'))
                elif evidence_sha != actual_sha:
                    # Deliberately narrow: do not interpret arbitrary prose as certification.
                    normalized = claim.lower()
                    asserts_current_green = (re.search(r'\bcurrent\b.*\b(?:full|suite)\b', normalized) and
                                             re.search(r'\b(?:green|passed)\b', normalized))
                    qualified = re.search(r'\b(?:parent|historical|pending|not current)\b', normalized)
                    if asserts_current_green and not qualified:
                        issues.append(issue('full_suite_wrong_manifest'))
    return {'issues': issues, 'unknown': unknown, 'counts': dict(counts) if lines is not None else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--checkpoint', type=Path)
    parser.add_argument('--ledger', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    result = audit(root, args.checkpoint or root / '.zig-cache/CURRENT.json',
                   args.ledger or root / 'docs/ops/roadmap-acceptance-ledger-2026-10-26.md')
    print(json.dumps(result, sort_keys=True))
    return 1 if result['issues'] else 2 if result['unknown'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
