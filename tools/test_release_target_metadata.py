# SPDX-License-Identifier: AGPL-3.0-or-later
"""Script controls using synthetic git/compiler stubs; no compiler or release."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'packaging').mkdir()
        (self.root / 'bin').mkdir()
        for script in ('release.sh', 'verify-release.sh'):
            shutil.copy2(ROOT / 'packaging' / script, self.root / 'packaging' / script)
        (self.root / 'build.zig.zon').write_text('.version = "1.2.3"\n')
        self.stub('git', '''#!/bin/sh
case "$1 $2 $3" in
 'status --porcelain '*) printf '%s' "${TEST_DIRTY:-}" ;;
 'rev-parse --short HEAD') printf 'aaaaaaaaaaaa\\n' ;;
 'rev-parse HEAD '*) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n' ;;
 'show -s --format=%ct') printf '123\\n' ;;
 'show -s --format=%cI') printf '2020-01-01T00:00:00+00:00\\n' ;;
 *) exit 1 ;;
esac
''')
        self.stub('zig', '''#!/bin/sh
if [ "$1" = version ]; then printf '0.17.0-test\\n'; exit 0; fi
[ "$1" = build ] || exit 1
target= cpu= prefix=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -Dtarget=*) target=${1#-Dtarget=} ;;
  -Dcpu=*) cpu=${1#-Dcpu=} ;;
  --prefix) shift; prefix=$1 ;;
 esac
 shift
done
[ "$cpu" = baseline ] && [ -n "$target" ] && [ -n "$prefix" ] || exit 1
mkdir -p "$prefix/bin"
printf 'fixture:%s:%s' "$target" "$cpu" > "$prefix/bin/onyx-server"
''')
        self.env = os.environ.copy()
        self.env['PATH'] = str(self.root / 'bin') + os.pathsep + os.defpath
        self.env.pop('COSIGN_KEY', None)
        self.env.pop('COSIGN_EXPERIMENTAL', None)
        for gate in ('ONYX_RELEASE_CT_CHECK', 'ONYX_RELEASE_INTEROP', 'ONYX_RELEASE_BOGO'):
            self.env.pop(gate, None)
        self.env['TMPDIR'] = str(self.root)

    def stub(self, name, content):
        p = self.root / 'bin' / name
        p.write_text(content)
        p.chmod(0o755)

    def invoke(self, script, *args):
        return subprocess.run(['bash', str(self.root / 'packaging' / script), *map(str, args)],
                              cwd=self.root, env=self.env, capture_output=True, timeout=15)

    def release(self, target):
        out = self.root / ('out-' + target)
        result = self.invoke('release.sh', out, target)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return out

    def test_both_targets_metadata_and_verification(self):
        for target, arch in [('x86_64-linux-musl', 'x86_64'), ('aarch64-linux-musl', 'aarch64')]:
            with self.subTest(target=target):
                out = self.release(target)
                meta = json.loads((out / 'onyx-server.build.json').read_text())
                self.assertEqual((meta['target'], meta['architecture'], meta['cpu']), (target, arch, 'baseline'))
                self.assertEqual(meta['zig_sha256'], hashlib.sha256((self.root / 'bin/zig').read_bytes()).hexdigest())
                self.assertEqual(meta['flags'], ['build', '-Dtarget=' + target, '-Dcpu=baseline', '--release=fast'])
                sbom = json.loads((out / 'onyx-server.cdx.json').read_text())
                self.assertIn('arch=' + arch, sbom['metadata']['component']['purl'])
                # The target artifact need not be the first checksum line.
                sums = out / 'SHA256SUMS'
                sums.write_text(''.join(reversed(sums.read_text().splitlines(keepends=True))))
                result = self.invoke('verify-release.sh', sums, target)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_metadata_tamper_with_rehashed_manifest_refuses(self):
        target = 'aarch64-linux-musl'
        out = self.release(target)
        meta = out / 'onyx-server.build.json'
        data = json.loads(meta.read_text())
        data['cpu'] = 'native'
        meta.write_text(json.dumps(data) + '\n')
        sums = out / 'SHA256SUMS'
        lines = sums.read_text().splitlines()
        digest = hashlib.sha256(meta.read_bytes()).hexdigest()
        sums.write_text('\n'.join((digest + '  onyx-server.build.json') if line.endswith('  onyx-server.build.json') else line for line in lines) + '\n')
        self.assertNotEqual(self.invoke('verify-release.sh', sums, target).returncode, 0)

    def test_wrong_target_duplicate_artifact_and_unsupported_refuse(self):
        out = self.release('x86_64-linux-musl')
        sums = out / 'SHA256SUMS'
        self.assertNotEqual(self.invoke('verify-release.sh', sums, 'aarch64-linux-musl').returncode, 0)
        first = sums.read_text().splitlines()[0]
        with sums.open('a') as stream:
            stream.write(first + '\n')
        self.assertNotEqual(self.invoke('verify-release.sh', sums, 'x86_64-linux-musl').returncode, 0)
        self.assertNotEqual(self.invoke('release.sh', self.root / 'bad', 'riscv64-linux-musl').returncode, 0)
        self.assertNotEqual(self.invoke('verify-release.sh', sums, 'riscv64-linux-musl').returncode, 0)

    def test_compiler_path_with_spaces_is_hashed_and_executed(self):
        spaced = self.root / 'compiler path with spaces'
        spaced.mkdir()
        compiler = spaced / 'zig'
        shutil.copy2(self.root / 'bin' / 'zig', compiler)
        self.env['PATH'] = str(spaced) + os.pathsep + self.env['PATH']
        target = 'aarch64-linux-musl'
        out = self.release(target)
        meta = json.loads((out / 'onyx-server.build.json').read_text())
        self.assertEqual(meta['zig_sha256'], hashlib.sha256(compiler.read_bytes()).hexdigest())
        self.assertEqual(self.invoke('verify-release.sh', out / 'SHA256SUMS', target).returncode, 0)

    def test_dirty_tree_refuses_both(self):
        out = self.release('x86_64-linux-musl')
        self.env['TEST_DIRTY'] = ' M tracked'
        self.assertNotEqual(self.invoke('release.sh', self.root / 'dirty').returncode, 0)
        self.assertNotEqual(self.invoke('verify-release.sh', out / 'SHA256SUMS').returncode, 0)

    def ct_check_stub(self, rc):
        # Record every ct-check invocation; exit with `rc` for it.
        stub = (self.root / 'bin' / 'zig').read_text().replace(
            '[ "$1" = build ] || exit 1\n',
            '[ "$1" = build ] || exit 1\n'
            'if [ "$2" = ct-check ]; then echo "$*" >> "$TMPDIR/ct-check.calls"; exit %d; fi\n' % rc)
        self.stub('zig', stub)

    def test_ct_check_gate_is_opt_in(self):
        self.ct_check_stub(0)
        self.release('x86_64-linux-musl')
        self.assertFalse((self.root / 'ct-check.calls').exists())

    def test_ct_check_gate_runs_and_fails_closed(self):
        self.env['ONYX_RELEASE_CT_CHECK'] = '1'
        self.ct_check_stub(0)
        self.release('x86_64-linux-musl')
        calls = (self.root / 'ct-check.calls').read_text().splitlines()
        self.assertEqual(len(calls), 1)
        # The harness measures the shipped target/cpu, not a host-native build.
        self.assertTrue(calls[0].startswith('build ct-check -Dtarget=x86_64-linux-musl -Dcpu=baseline '), calls[0])
        self.ct_check_stub(1)
        failed = self.invoke('release.sh', self.root / 'ct-fail', 'x86_64-linux-musl')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(b'ct-check gate failed', failed.stderr)
        self.assertFalse((self.root / 'ct-fail' / 'SHA256SUMS').exists())

    def test_ct_check_gate_refuses_foreign_target(self):
        self.env['ONYX_RELEASE_CT_CHECK'] = '1'
        self.ct_check_stub(0)
        foreign = 'aarch64-linux-musl' if platform.machine() != 'aarch64' else 'x86_64-linux-musl'
        failed = self.invoke('release.sh', self.root / 'ct-foreign', foreign)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(b'cannot run', failed.stderr)
        self.assertFalse((self.root / 'ct-check.calls').exists())

    def interop_stubs(self, rc=0):
        # Stub gate scripts that record their argv/env and check, from a
        # DIFFERENT cwd (as the real scripts do), that the binary resolves.
        (self.root / 'tools').mkdir(exist_ok=True)
        sh = self.root / 'tools' / 'openssl_interop.sh'
        sh.write_text('#!/usr/bin/env bash\n'
                      'printf "%s %s\\n" "$1" "${ONYX_INTEROP_STRICT:-0}" >> "$TMPDIR/interop.calls"\n'
                      'cd / && [[ -f "$1" ]] || exit 9\n'
                      'exit ' + str(rc) + '\n')
        sh.chmod(0o755)
        (self.root / 'tools' / 'browser_tls_smoke.py').write_text(
            'import os, sys\n'
            'open(os.path.join(os.environ["TMPDIR"], "browser.calls"), "a").write(sys.argv[1] + "\\n")\n'
            'os.chdir("/")\n'
            'sys.exit(0 if os.path.isfile(sys.argv[1]) else 9)\n')

    @unittest.skipUnless(platform.machine() == 'x86_64', 'gate needs a host that runs the target')
    def test_interop_gate_passes_absolute_artifact_with_relative_out(self):
        self.env['ONYX_RELEASE_INTEROP'] = '1'
        self.interop_stubs()
        # Default-style relative output directory, resolved against the repo root.
        result = self.invoke('release.sh', 'dist-rel', 'x86_64-linux-musl')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        art = str(self.root / 'dist-rel' / 'onyx-server-1.2.3-x86_64-linux-musl')
        self.assertEqual((self.root / 'interop.calls').read_text(), art + ' 1\n')
        self.assertEqual((self.root / 'browser.calls').read_text(), art + '\n')
        self.assertTrue((self.root / 'dist-rel' / 'SHA256SUMS').exists())

    @unittest.skipUnless(platform.machine() == 'x86_64', 'gate needs a host that runs the target')
    def test_interop_gate_failure_aborts_release(self):
        self.env['ONYX_RELEASE_INTEROP'] = '1'
        self.interop_stubs(rc=1)
        failed = self.invoke('release.sh', 'dist-fail', 'x86_64-linux-musl')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(b'OpenSSL interop gate failed', failed.stderr)
        self.assertFalse((self.root / 'browser.calls').exists())
        self.assertFalse((self.root / 'dist-fail' / 'SHA256SUMS').exists())

    def test_interop_gate_refuses_foreign_target(self):
        self.env['ONYX_RELEASE_INTEROP'] = '1'
        foreign = 'aarch64-linux-musl' if platform.machine() != 'aarch64' else 'x86_64-linux-musl'
        failed = self.invoke('release.sh', self.root / 'interop-foreign', foreign)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(b'cannot run', failed.stderr)

if __name__ == '__main__':
    unittest.main()
