#!/usr/bin/env python3
"""Private synthetic AKICK/WARD checkpoint audit and installed-matcher proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/home/kain/onyx-server')
CAP = 2 << 20
REFUSAL = b'cloak-audit: audit refused\n'
PRIVATE = (b'7171717171717171', b'7272727272727272', b'203.0.113.9', b'IssuerA', b'first')

class Failure(Exception): pass

def check(value, code):
    if not value: raise Failure(code)

def pin(value):
    if re.fullmatch(r'[0-9a-f]{64}', value) is None: raise argparse.ArgumentTypeError('invalid SHA-256')
    return value

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''): h.update(part)
    return h.hexdigest()

def regular(path, bound=CAP):
    st = path.lstat()
    check(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1 and 0 < st.st_size <= bound, 'input_custody')
    return st

def create(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())

def summary(labels):
    return b''.join(f'row={i} classification={label}\n'.encode() for i, label in enumerate(labels))

class Campaign:
    def __init__(self, args, root):
        self.args, self.root, self.count, self.stage = args, root, 0, 'initialize'
        self.fixtures = root / 'fixtures'; self.fixtures.mkdir(mode=0o700)
        self.captures = root / 'captures'; self.captures.mkdir(mode=0o700)
        self.owned = {}
    def invoke(self, stage, binary, args, success, stdout=None, refusal_out=None):
        self.stage = stage
        encoded_args = '\0'.join(args).encode()
        check(not any(token in encoded_args for token in PRIVATE), 'secret_in_argv')
        out = self.captures / f'{self.count:02d}-{stage}.out'
        err = self.captures / f'{self.count:02d}-{stage}.err'
        self.count += 1
        create(out, b''); create(err, b'')
        env = {'PATH': os.defpath, 'TMPDIR': str(self.root), 'NO_COLOR': '1'}
        check(not any(token in '\0'.join(env.values()).encode() for token in PRIVATE), 'secret_in_environment')
        def limits():
            os.umask(0o077)
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, CAP))
        proc = None
        with out.open('wb') as stdout_file, err.open('wb') as stderr_file:
            try:
                proc = subprocess.Popen([str(binary), *args], stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file, env=env, start_new_session=True, preexec_fn=limits)
                try: rc = proc.wait(timeout=30)
                except subprocess.TimeoutExpired: raise Failure('child_timeout') from None
            finally:
                if proc:
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: raise Failure('child_cleanup') from None
                    deadline = time.monotonic() + 3
                    while True:
                        try: os.killpg(proc.pid, 0)
                        except ProcessLookupError: break
                        if time.monotonic() >= deadline: raise Failure('child_cleanup')
                        time.sleep(0.02)
        for path in (out, err):
            st = path.lstat()
            check(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < CAP, 'capture_custody')
        data = out.read_bytes(); errors = err.read_bytes()
        check(not any(token in data or token in errors for token in PRIVATE), 'redaction')
        if success:
            check(rc == 0 and errors == b'', 'child_failure')
            if stdout is not None: check(data == stdout, 'summary')
        else: check(rc != 0 and data in (b'', refusal_out) and errors == REFUSAL, 'refusal')
    def run(self):
        self.invoke('generate', self.args.generator, ['generate', str(self.fixtures)], True, b'')
        for kind in ('akick', 'ward'):
            for suffix in ('input', 'expected', 'witness'):
                path = self.fixtures / f'{kind}.{suffix}'
                info = regular(path)
                check(stat.S_IMODE(info.st_mode) == 0o600, 'fixture_mode')
                self.owned[path] = (digest(path), info.st_mode, info.st_size)
        plans = {
            'akick': ['missing_witness', 'verified_replacement', 'verified_replacement', 'account_rule'],
            'ward': ['verified_replacement', 'verified_replacement', 'non_host_facet', 'non_host_facet', 'missing_witness'],
        }
        for kind in ('akick', 'ward'):
            inp = self.fixtures / f'{kind}.input'; wit = self.fixtures / f'{kind}.witness'; out = self.fixtures / f'{kind}.output'
            call = ['cloak-audit', '--kind', kind, '--input', str(inp), '--witness', str(wit), '--checkpoint-output', str(out)]
            self.invoke(kind + '_audit', self.args.binary, call, True, summary(plans[kind]))
            info = regular(out); check(stat.S_IMODE(info.st_mode) == 0o600, 'output_mode')
            check(digest(out) == digest(self.fixtures / f'{kind}.expected'), 'expected_bytes')
            self.invoke(kind + '_overwrite', self.args.binary, call, False, refusal_out=summary(plans[kind]))
            check(digest(out) == digest(self.fixtures / f'{kind}.expected'), 'overwrite_changed')
            wrong = self.fixtures / f'{kind}.wrong'
            other = 'ward' if kind == 'akick' else 'akick'
            self.invoke(kind + '_wrong_kind', self.args.binary, ['cloak-audit', '--kind', other, '--input', str(inp), '--witness', str(wit), '--checkpoint-output', str(wrong)], False)
            check(not wrong.exists() and not wrong.is_symlink(), 'wrong_kind_output')
            link = self.fixtures / f'{kind}.link'; link.symlink_to(out.name)
            self.invoke(kind + '_symlink_output', self.args.binary, call[:-1] + [str(link)], False, refusal_out=summary(plans[kind]))
            check(link.is_symlink() and digest(out) == digest(self.fixtures / f'{kind}.expected'), 'symlink_changed')
            hard = self.fixtures / f'{kind}.hard'; os.link(inp, hard)
            try: self.invoke(kind + '_hardlink_input', self.args.binary, ['cloak-audit', '--kind', kind, '--input', str(inp), '--witness', str(wit)], False)
            finally: hard.unlink()
            ilink = self.fixtures / f'{kind}.inputlink'; ilink.symlink_to(inp.name)
            self.invoke(kind + '_symlink_input', self.args.binary, ['cloak-audit', '--kind', kind, '--input', str(ilink), '--witness', str(wit)], False)
            os.chmod(wit, 0o644)
            try: self.invoke(kind + '_public_witness', self.args.binary, call[:-2], False)
            finally: os.chmod(wit, 0o600)
        self.invoke('matcher_verify', self.args.generator, ['verify', str(self.fixtures)], True, b'')
        for path, (old_hash, old_mode, old_size) in self.owned.items():
            st = regular(path)
            check(digest(path) == old_hash and st.st_mode == old_mode and st.st_size == old_size, 'source_changed')
        check(self.count == 16, 'case_count')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True); parser.add_argument('--binary-sha256', type=pin, required=True)
    parser.add_argument('--generator', type=Path, required=True); parser.add_argument('--generator-sha256', type=pin, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args(); result = {'result': 'fail', 'stage': 'validate', 'cases': 0}
    campaign = None
    try:
        for path, expected in ((args.binary,args.binary_sha256),(args.generator,args.generator_sha256)):
            regular(path, 512 << 20); check(digest(path) == expected, 'binary_pin')
        root = Path(os.path.abspath(args.work_dir)); parent = root.parent.resolve(strict=True)
        check(parent == root.parent and parent.is_relative_to(ROOT), 'workspace')
        root.mkdir(mode=0o700)
        st = root.lstat(); check(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700, 'workdir')
        campaign = Campaign(args, root); campaign.run()
        check(digest(args.binary) == args.binary_sha256 and digest(args.generator) == args.generator_sha256, 'binary_changed')
        result.update(result='pass', stage='complete', cases=campaign.count)
    except Failure as exc:
        result.update(stage=campaign.stage if campaign else 'validate', failure=exc.args[0], cases=campaign.count if campaign else 0)
    except OSError as exc:
        result.update(stage=campaign.stage if campaign else 'validate', failure='os_error', errno=exc.errno if isinstance(exc.errno,int) and 0 <= exc.errno <= 4095 else None, cases=campaign.count if campaign else 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'pass' else 1

if __name__ == '__main__': sys.exit(main())
