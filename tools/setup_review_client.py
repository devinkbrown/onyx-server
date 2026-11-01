# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded real headless review fixture; never displays private material."""
import json, os, pathlib, re, select, signal, subprocess, time

LIMIT=1024*1024

def run_review(argv, cwd, env=None, pass_fds=(), action='publish', mutate=None, preexec_fn=None, review_id_override=None):
    args=list(argv)
    if '--json' not in args: args.append('--json')
    args.append('--review-stdin')
    target_arg=pathlib.Path(args[args.index('--bundle')+1])
    target=target_arg if target_arg.is_absolute() else pathlib.Path(cwd)/target_arg
    existed=os.path.lexists(target)
    child=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds,start_new_session=True,preexec_fn=preexec_fn)
    record=None; prefix=b''
    try:
        deadline=time.monotonic()+120
        while b'\n' not in prefix:
            if time.monotonic()>deadline: raise AssertionError('review deadline')
            ready,_,_=select.select([child.stdout],[],[],min(.1,max(0,deadline-time.monotonic())))
            if ready:
                byte=os.read(child.stdout.fileno(),1)
                if not byte:break
                prefix+=byte
                if len(prefix)>LIMIT:raise AssertionError('review bound')
            elif child.poll() is not None: break
        if prefix:
            record=json.loads(prefix)
            assert record['mode']=='prepared_unpublished_bundle'
            rid=record['review_id'];assert re.fullmatch('[0-9a-f]{32}',rid)
            assert pathlib.Path(record['directory']) == target.resolve(strict=False) if not target.is_symlink() else True
            stages=list(pathlib.Path(cwd).glob('.onyx-setup-*'))
            assert len(stages)==1 and stages[0].stat().st_mode&0o7777==0o700
            assert record['directory_mode_octal']=='0700'
            assert len(record['node_public_key'])==64 and record['certificate_expires_unix']>time.time()
            assert record['certificate_subject'] and 'self-signed' in record['tls_provenance']
            assert all(row['mode_octal']=='0600' for row in record['files'])
            assert {pathlib.Path(row['path']).name for row in record['files']} == {p.name for p in stages[0].iterdir()}
            if not existed: assert not os.path.lexists(target)
            for name in ('onyx-server-node.key','cloak.secret','tls-key.der'):
                secret=(stages[0]/name).read_bytes().strip()
                assert secret not in prefix
            if mutate: mutate(stages[0],record)
            if action!='eof':
                chosen = review_id_override if review_id_override is not None else ('0'*32 if action=='wrong' else rid)
                payload=(json.dumps({'action':'cancel' if action=='cancel' else 'publish','review_id':chosen})+'\n').encode() if action!='malformed' else b'{bad}\n'
                child.stdin.write(payload);child.stdin.flush()
        output,err=child.communicate(timeout=max(1,deadline-time.monotonic()))
        assert len(output)<LIMIT and len(err)<LIMIT
        if record is not None and action=='publish' and child.returncode==0:
            plan=json.loads(output)
            assert plan['node_public_key']==record['node_public_key']
            assert plan['certificate_expires_unix']==record['certificate_expires_unix']
            assert target.is_dir()
        return subprocess.CompletedProcess(args,child.returncode,output,err),record,prefix
    finally:
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        if child.poll() is None: child.wait()
