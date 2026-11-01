#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native nonempty export acceptance using an explicit production-encoder fixture.

Uses public deterministic fixture keys. Does not start a daemon or establish
operational retirement completeness for a running mesh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import tomllib

LIMIT = 2 << 20


class Failure(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Failure(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    os.umask(0o077)


def snapshot(path):
    return {str(p.relative_to(path)): (digest(p), p.stat().st_mode & 0o777, p.stat().st_size)
            for p in sorted(path.rglob('*')) if p.is_file()}


def run(binary, generator):
    require(sys.platform == 'linux' and os.geteuid() != 0, 'requires non-root Linux')
    artifacts = {str(p): digest(p) for p in (binary, generator)}
    with tempfile.TemporaryDirectory(prefix='onyx-nonempty-retirement-') as temporary:
        root = Path(temporary)
        names = ('good', 'missing', 'altered', 'retired-new')
        for name in names:
            (root / name).mkdir(mode=0o700)
        env = {'PATH': os.defpath, 'TMPDIR': str(root), 'NO_COLOR': '1'}

        def invoke(executable, args, label):
            captures = [root / (label + suffix) for suffix in ('.out', '.err')]
            with captures[0].open('xb') as out, captures[1].open('xb') as err:
                for capture in captures:
                    capture.chmod(0o600)
                result = subprocess.run([str(executable), *args], cwd=root, env=env,
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        timeout=120, preexec_fn=bounded)
            require(all(p.stat().st_size < LIMIT for p in captures), 'capture bound exceeded')
            return result.returncode, *(p.read_bytes() for p in captures)

        code, out, err = invoke(generator, [], 'generator')
        require(code == 0 and out == b'' and err == b'', 'fixture generator failed')
        manifest = tomllib.loads((root / 'manifest.toml').read_text())
        require(manifest.get('token_bytes') == 16, 'fixture token width mismatch')
        token_bytes = manifest['token_bytes']
        expected_bytes = (root / 'expected.toml').read_bytes()
        expected = tomllib.loads(expected_bytes.decode())['mesh']['retired_session_group_fences']
        require(len(expected) == manifest['expected_grants'] == 2, 'invalid fixture oracle')
        require(expected == sorted(expected, key=lambda g: (g['group_key'], g['issuer_key'], g['fact_digest'])),
                'fixture oracle not canonical')
        require(all(set(g) == {'group_key', 'issuer_key', 'fact_digest'} and
                    all(len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in g.values())
                    and g['issuer_key'] == manifest['selected'] for g in expected), 'invalid grant oracle')
        config = root / 'candidate.toml'
        config.chmod(0o600)
        for name in names:
            baseline = root / name
            require(sorted(p.name for p in baseline.iterdir()) == ['accounts.wal'], 'unexpected baseline files')
            (baseline / 'accounts.wal').chmod(0o400)
            baseline.chmod(0o500)
        before = {name: snapshot(root / name) for name in names}
        config_before = digest(config)
        cases = [('good', manifest['selected'], None),
                 ('good', manifest['retired'], 'IssuerNotActive'),
                 ('missing', manifest['selected'], 'MissingRequiredFence'),
                 ('altered', manifest['selected'], 'UntrustedOrigin'),
                 ('retired-new', manifest['selected'], 'UntrustedOrigin')]
        try:
            for index, (name, issuer, reason) in enumerate(cases):
                output = root / f'policy-{index}.toml'
                code, stdout, stderr = invoke(binary,
                    ['session-fences', 'export', str(config), '--baseline', str(root / name),
                     '--issuer', issuer, '--output', str(output)], f'cli-{index}')
                private = [b'FixturePrivate', str(root).encode(), *[bytes([n]) * token_bytes for n in range(34, 39)],
                           *[(bytes([n]) * token_bytes).hex().encode() for n in range(34, 39)]]
                require(not any(value in stdout + stderr for value in private), 'private fixture data leaked')
                if reason is not None:
                    require(code == 1 and not output.exists(), 'failed export published policy')
                    require(stderr == (f'session-fences: export refused ({reason}); '
                                       'no policy content is printed\n').encode(), 'refusal reason mismatch')
                else:
                    require(code == 0 and stderr == b'', 'nonempty export failed')
                    published = output.read_bytes()
                    summary = json.loads(stdout)
                    require(published == expected_bytes, 'nonempty export differs from canonical complete oracle')
                    require(set(summary) == {'mode', 'grants', 'sha256', 'source'}
                            and summary.get('source') == 'private_offline_baseline'
                            and summary.get('mode') == 'retirement_policy_exported' and summary.get('grants') == 2
                            and summary.get('sha256') == hashlib.sha256(published).hexdigest(), 'summary mismatch')
                    require(output.stat().st_mode & 0o777 == 0o600, 'policy publication not private')
                    require(not any(value in published for value in private), 'private data in policy')
                    require(manifest['retired'].encode() not in published, 'prior retired issuer re-exported')
                require(digest(config) == config_before and
                        all(snapshot(root / n) == before[n] for n in names), 'source changed during export')
        finally:
            for name in names:
                (root / name).chmod(0o700)
    require(all(digest(Path(p)) == sha for p, sha in artifacts.items()), 'artifact changed')
    return {'artifacts': artifacts, 'cases': len(cases), 'grants': 2,
            'checks': ['nonempty-canonical-complete', 'selected-current-issuer-only',
                       'composable-existing-retired-pin', 'missing-required-group-refusal',
                       'altered-retired-fact-refusal', 'new-retired-signature-refusal',
                       'no-account-token-output', 'source-wal-byte-identical'],
            'limitations': ['deterministic-offline-fixture', 'no-live-mesh-retirement-completeness-claim']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--generator', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.binary.resolve(strict=True), args.generator.resolve(strict=True)), indent=2))
    except Failure as failure:
        # Failure messages are fixed internal strings, never captured child output.
        parser.exit(1, f'retirement nonempty smoke: {failure}\n')
    except Exception:
        parser.exit(1, 'retirement nonempty smoke: fixture failed; private captures omitted\n')
