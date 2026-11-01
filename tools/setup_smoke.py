#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Real configuration/setup CLI checks; never starts a network listener.
import os,json,pathlib,subprocess,tempfile,pty,time,select,errno,tomllib,fcntl,termios,struct,re,socket
from setup_review_client import run_review
import argparse
parser=argparse.ArgumentParser(description="Linux native/headless/PTY setup acceptance; private fixtures only, no live daemon or installed service actions.")
parser.add_argument("--binary",type=pathlib.Path,required=True)
parser.add_argument("--scratch-dir",type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/".zig-cache"/"setup-smoke")
args=parser.parse_args()
B=str(args.binary.resolve(strict=True))
args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
env={**os.environ,'NO_COLOR':'','TERM':'xterm-256color'}
cases=0
with tempfile.TemporaryDirectory(dir=args.scratch_dir) as base:
    root=pathlib.Path(base)
    def run(args,code=0):
        global cases
        try:
            if '--bundle' in args and '--interactive' not in args:
                p,_,_=run_review([B,*args],base,env)
            else:
                p=subprocess.run([B,*args],cwd=base,env=env,capture_output=True,timeout=120)
        except subprocess.TimeoutExpired:
            raise AssertionError(('CLI timeout',cases)) from None
        assert p.returncode==code,('CLI status mismatch', cases, p.returncode, len(p.stdout), len(p.stderr))
        assert b'\x1b' not in p.stdout+p.stderr
        cases+=1
        return p
    def clean_stage(): assert not list(root.glob('.onyx-setup-*'))
    flags=['--new','--profile','media','--hostname','irc.example.test','--listen','::1','--irc-port','7000','--node-id','17','--tls-port','7001','--max-clients','256','--media-port','7100']
    missing=subprocess.run([B,'setup','--new','--bundle','no-review','--json'],cwd=base,env=env,capture_output=True,timeout=10)
    assert missing.returncode==2 and not (root/'no-review').exists();clean_stage()
    for mode,executable,config,identity,cwd in (
        ('openrc','/usr/bin/onyx-server','/etc/onyx-server/onyx-server.toml','onyx-server:onyx-server','/var/lib/onyx-server'),
        ('systemd','/usr/local/bin/onyx-server','/etc/onyx-server/onyx-server.toml','onyx-server:onyx-server','/var/lib/onyx-server'),
        ('foreground','<reviewed-executable>','<reviewed-config>','unknown; chosen by operator','unknown; chosen by operator')):
        view=json.loads(run(['setup','--new','--service',mode,'--json']).stdout)['service_plan']
        template=view['template']
        assert view['selected']==mode and view['selection_basis']=='explicit selection'
        assert (template['executable'],template['config'],template['identity'],template['working_directory'])==(executable,config,identity,cwd)
        assert template['start_argv']==[executable,config]
        assert template['preflight_argv']==[executable,'--check-config',config]
        assert all(view[key].startswith('unknown') for key in ('host_paths','runtime_identity_access','manager_status','daemon_readiness','network_reachability','resource_ceilings'))
        assert view['container_template']['identity']=='10001:10001' and 'does not invoke' in view['container_template']['preflight_policy']
    p=run(['setup',*flags,'--json'])
    preview=json.loads(p.stdout); assert preview['settings']['hostname']=='irc.example.test'
    assert not list(root.iterdir())
    p=run(['setup',*flags,'--draft','choices.json','--json'])
    draft=json.loads((root/'choices.json').read_text())
    assert draft['version']==3 and draft['settings']['node_id']==17
    p=run(['setup','--resume','choices.json','--bundle','node','--json'])
    plan=json.loads(p.stdout); node=root/'node'
    assert plan['mode']=='bundle_provisioned' and plan['certificate_expires_unix']>time.time()
    assert plan['settings']==preview['settings'] and len(plan['node_public_key'])==64
    assert 'self-signed' in plan['tls_provenance'] and plan['readiness']=='unknown'
    names={'onyx-server.toml','onyx-server-node.key','cloak.secret','tls-cert.der','tls-key.der'}
    assert {x.name for x in node.iterdir()}==names
    assert node.stat().st_mode&0o777==0o700
    snapshot={x.name:x.read_bytes() for x in node.iterdir()}
    for f in node.iterdir(): assert f.stat().st_mode&0o777==0o600
    cfg=tomllib.loads(snapshot['onyx-server.toml'].decode())
    assert cfg['node']['id']==17 and cfg['network']['server_name']=='irc.example.test'
    assert cfg['listen']['host']=='::1' and cfg['listen']['irc']==7000 and cfg['listen']['media']==7100
    assert cfg['limits']['max_clients']==256 and cfg['tls']['port']==7001 and cfg['tls']['enabled']
    assert cfg['tls']['cert_path']==str(node/'tls-cert.der')
    assert cfg['tls']['key_path']==str(node/'tls-key.der')
    assert cfg['cloak']['secret']=='@file:'+str(node/'cloak.secret')
    assert '.onyx-setup-' not in snapshot['onyx-server.toml'].decode()
    for raw in [snapshot['onyx-server-node.key'].strip(),snapshot['cloak.secret'].strip()]:
        assert raw not in p.stdout+p.stderr+(root/'choices.json').read_bytes()
    # CWD-independent references, no runtime activation and no secret rotation.
    run(['--check-config',str(node/'onyx-server.toml')])
    shared_plan=json.loads(run(['setup',str(node/'onyx-server.toml'),'--json']).stdout)
    doctor_run=run(['doctor',str(node/'onyx-server.toml'),'--json'])
    doctor=json.loads(doctor_run.stdout)
    assert shared_plan['service_environment']==doctor['service_environment']
    text_setup=run(['setup',str(node/'onyx-server.toml')])
    text_doctor=run(['doctor',str(node/'onyx-server.toml')])
    assert b'Service environment:' in text_setup.stdout and b'doctor service_environment' in text_doctor.stderr
    assert shared_plan['service_environment']['manager_hint'] in ('openrc','systemd','unknown')
    explicit=json.loads(run(['setup',str(node/'onyx-server.toml'),'--service','foreground','--json']).stdout)
    assert explicit['service']=='foreground' and explicit['service_basis']=='explicit operator selection'
    for raw in [snapshot['onyx-server-node.key'].strip(),snapshot['cloak.secret'].strip()]:
        assert raw not in doctor_run.stdout+doctor_run.stderr
    run(['setup',*flags,'--bundle','node','--json'],1)
    assert snapshot=={x.name:x.read_bytes() for x in node.iterdir()}; clean_stage()
    (root/'occupied').write_text('preserve')
    run(['setup',*flags,'--bundle','occupied'],1)
    assert (root/'occupied').read_text()=='preserve'; clean_stage()
    os.symlink('occupied',root/'link')
    run(['setup',*flags,'--bundle','link'],1)
    assert (root/'link').is_symlink() and (root/'occupied').read_text()=='preserve'; clean_stage()
    for bad in [['--hostname','bad\nname'],['--listen','not-an-ip'],['--node-id','0'],['--irc-port','0'],['--tls-port','6680'],['--max-clients','32768']]:
        run(['setup','--new',*bad,'--bundle','bad'],2); assert not (root/'bad').exists(); clean_stage()
    (root/'unsafe').mkdir(mode=0o720); (root/'unsafe').chmod(0o720)
    run(['setup','--new','--bundle','unsafe/refused'],1)
    assert not list((root/'unsafe').iterdir())
    # Explicit old draft decoding plus fail-closed incompatible/new malformed schemas.
    old=root/'old.json'; old.write_text('{"version":1,"profile":"private","service":"foreground"}'); old.chmod(0o600)
    p=run(['setup','--resume','old.json','--json']); assert json.loads(p.stdout)['settings']['hostname']=='localhost'
    legacy_settings={key:value for key,value in draft['settings'].items() if key!='bootstrap'}
    legacy2=root/'old-v2.json';legacy2.write_text(json.dumps(dict(version=2,profile='media',service='openrc',settings=legacy_settings)));legacy2.chmod(0o600)
    legacy_plan=json.loads(run(['setup','--resume','old-v2.json','--json']).stdout)
    assert legacy_plan['settings']['hostname']=='irc.example.test' and legacy_plan['settings']['bootstrap']['account']==''
    for obj in [dict(version=2,profile='private',service='auto'),dict(version=3,profile='private',service='auto'),dict(version=4,profile='private',service='auto',settings=legacy_settings),dict(version=1,profile='private',service='auto',settings={}),dict(version=2,profile='private',service='auto',settings={**legacy_settings,'bootstrap':dict(account='legacy-injected-account',privileges='none')})]:
        bad=root/'bad-draft';bad.write_text(json.dumps(obj));bad.chmod(0o600)
        run(['setup','--resume','bad-draft','--bundle','refused'],1)
        assert not (root/'refused').exists(); clean_stage()
    # Every acknowledgement is bound to the actual unpublished stage.
    for action in ('cancel','eof','wrong','malformed'):
        target='review-'+action
        result,record,review=run_review([B,'setup','--new','--bundle',target,'--json'],base,env,action=action)
        assert record and not (root/target).exists() and not list(root.glob('.onyx-setup-*'))
        assert result.returncode == (0 if action=='cancel' else 1)
    first,previous,_=run_review([B,'setup','--new','--bundle','replay-first','--json'],base,env,action='cancel')
    assert first.returncode==0 and previous
    replay,current,_=run_review([B,'setup','--new','--bundle','replay-second','--json'],base,env,review_id_override=previous['review_id'])
    assert current and current['review_id']!=previous['review_id'] and replay.returncode!=0
    assert not (root/'replay-first').exists() and not (root/'replay-second').exists();clean_stage()
    def alter_stage(stage,record,kind):
        del record
        file=stage/'cloak.secret'
        if kind=='content': file.write_bytes(b'changed-private-value')
        elif kind=='mode': file.chmod(0o644)
        elif kind=='missing': file.unlink()
        elif kind=='symlink': file.unlink();file.symlink_to(root/'choices.json')
        elif kind=='replacement': file.unlink();file.write_bytes(b'replacement')
        elif kind=='fifo': file.unlink();os.mkfifo(file,0o600)
        elif kind=='extra': (stage/'unexpected').write_bytes(b'unexpected')
    for kind in ('content','mode','missing','symlink','replacement','extra','fifo'):
        result,record,review=run_review([B,'setup','--new','--bundle','review-tamper-'+kind,'--json'],base,env,mutate=lambda stage,record:alter_stage(stage,record,kind))
        assert record and result.returncode!=0 and not (root/('review-tamper-'+kind)).exists();clean_stage()
    # Replacing the stage pathname cannot cause cleanup to remove the replacement.
    replaced_stage=[]
    def swap_stage(stage,record):
        del record
        moved=stage.with_name('relocated-stage');stage.rename(moved)
        stage.mkdir(mode=0o700);(stage/'preserve').write_bytes(b'preserved')
        replaced_stage.append((stage,moved))
    result,record,_=run_review([B,'setup','--new','--bundle','review-dir-swap','--json'],base,env,mutate=swap_stage)
    assert record and result.returncode!=0 and not (root/'review-dir-swap').exists()
    replacement,moved=replaced_stage[0]
    assert (replacement/'preserve').read_bytes()==b'preserved' and not list(moved.iterdir())
    (replacement/'preserve').unlink();replacement.rmdir();moved.rmdir();clean_stage()
    # A closed output pipe returns an error and cleans the unpublished stage.
    broken=subprocess.Popen([B,'setup','--new','--bundle','closed-output','--json','--review-stdin'],cwd=base,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    broken.stdout.close()
    try:
        broken.wait(timeout=20)
        assert broken.returncode!=0 and not (root/'closed-output').exists();clean_stage()
    finally:
        if broken.poll() is None: broken.kill();broken.wait()
        broken.stdin.close();broken.stderr.close()
    # A reader that never drains stdout cannot leave private staging indefinitely.
    deep=root
    for index in range(24):
        deep=deep/('p'+str(index)+'x'*117);deep.mkdir(mode=0o700)
    blocked=deep/'blocked-node'
    output_read,output_write=os.pipe()
    fcntl.fcntl(output_read,fcntl.F_SETPIPE_SZ,4096)
    try:
        child=subprocess.Popen([B,'setup','--new','--bundle',str(blocked),'--json','--review-stdin'],cwd=base,env=env,stdin=subprocess.PIPE,stdout=output_write,stderr=subprocess.PIPE,start_new_session=True)
    finally: os.close(output_write)
    try:
        child.wait(timeout=75)
        partial=os.read(output_read,8192);diagnostic=child.stderr.read(8192)
        assert child.returncode!=0 and len(partial)==4096 and not blocked.exists()
        assert not list(deep.glob('.onyx-setup-*'))
    finally:
        if child.poll() is None: child.kill();child.wait()
        os.close(output_read);child.stdin.close();child.stderr.close()
    # If the controller acknowledges but stops reading the final plan, the
    # command exits on deadline; the already-published reviewed bytes remain.
    final_target=deep/'post-ack-node'
    final_read,final_write=os.pipe();fcntl.fcntl(final_read,fcntl.F_SETPIPE_SZ,4096)
    try:
        late=subprocess.Popen([B,'setup','--new','--bundle',str(final_target),'--json','--review-stdin'],cwd=base,env=env,stdin=subprocess.PIPE,stdout=final_write,stderr=subprocess.PIPE,start_new_session=True)
    finally: os.close(final_write)
    try:
        review=b'';deadline=time.monotonic()+30
        while not review.endswith(b'\n'):
            assert time.monotonic()<deadline
            if select.select([final_read],[],[],.2)[0]:
                byte=os.read(final_read,1);assert byte
                review+=byte;assert len(review)<65536
        metadata=json.loads(review)
        stages=list(deep.glob('.onyx-setup-*'));assert len(stages)==1 and not final_target.exists()
        reviewed={p.name:p.read_bytes() for p in stages[0].iterdir()}
        late.stdin.write((json.dumps({'action':'publish','review_id':metadata['review_id']})+'\n').encode());late.stdin.flush()
        late.wait(timeout=75)
        partial=os.read(final_read,8192);diagnostic=late.stderr.read(8192)
        assert len(partial)==4096 and late.returncode!=0
        assert b'bundle published; final result output failed' in diagnostic
        assert final_target.is_dir() and reviewed=={p.name:p.read_bytes() for p in final_target.iterdir()}
        assert not list(deep.glob('.onyx-setup-*'))
    finally:
        if late.poll() is None: late.kill();late.wait()
        os.close(final_read);late.stdin.close();late.stderr.close()
    # Terminal flows exercise retained borrowed setting lifetimes across many reads.
    def interact(args,commands,color=False,material_reply=b'publish\n',width=120,terminal='xterm-256color',echo=True,no_color=None,expected_code=0):
        global cases
        master,slave=pty.openpty(); e=dict(env)
        if color or no_color is False: e.pop('NO_COLOR',None)
        e['TERM']=terminal
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,width,0,0))
        if not echo:
            attrs=termios.tcgetattr(slave); attrs[3] &= ~termios.ECHO; termios.tcsetattr(slave,termios.TCSANOW,attrs)
        child=subprocess.Popen([B,'setup',*args],cwd=base,env=e,stdin=slave,stdout=slave,stderr=slave)
        os.close(slave); transcript=b''
        try:
            deadline=time.monotonic()+120
            sent=False
            material_sent=False
            prepared_secrets=[]
            reviewed_public=None
            while child.poll() is None:
                if time.monotonic()>deadline: raise AssertionError(('PTY timeout', cases, len(transcript)))
                if select.select([master],[],[],0.05)[0]:
                    try: chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno==errno.EIO: break
                        raise
                    transcript+=chunk
                    if not sent and b'choice> ' in transcript:
                        os.write(master,commands);sent=True
                    if not material_sent and b'Material action (publish/cancel)> ' in transcript.replace(b'\r\n',b''):
                        destination=root/args[args.index('--bundle')+1]
                        assert not destination.exists()
                        stages=list(root.glob('.onyx-setup-*'))
                        assert len(stages)==1 and len(list(stages[0].iterdir()))==5
                        prepared_secrets=[(stages[0]/name).read_bytes().strip() for name in ['cloak.secret','onyx-server-node.key']]
                        import re
                        material_flat=transcript.replace(b'\r\n',b'')
                        found=re.search(rb'"node_public_key":\s*"([0-9a-f]{64})"',material_flat)
                        assert found and b'"directory_mode_octal": "0700"' in material_flat
                        assert b'"mode_octal": "0600"' in material_flat and b'"certificate_expires_unix"' in material_flat
                        reviewed_public=found.group(1)
                        os.write(master,material_reply); material_sent=True
            child.wait(timeout=2)
            while select.select([master],[],[],0)[0]:
                try: chunk=os.read(master,65536)
                except OSError:break
                if not chunk:break
                transcript+=chunk
            assert child.returncode==expected_code,('PTY status mismatch', cases, child.returncode, len(transcript))
            assert (b'\x1b[' in transcript)==color
            for secret in prepared_secrets: assert secret not in transcript.replace(b'\r\n',b'')
            if material_sent and material_reply==b'publish\n':
                assert transcript.replace(b'\r\n',b'').count(reviewed_public)>=2
            cases+=1
            return transcript
        finally:
            if child.poll() is None: child.kill();child.wait()
            os.close(master)
    reviewed=interact(['--new','--interactive','--service','systemd'],b'review\ncancel\n',width=120,echo=False)
    before_prompt=reviewed.split(b'review> ',1)[0]
    assert b'Service plan' in before_prompt and b'/usr/local/bin/onyx-server' in before_prompt
    assert b'--check-config' in before_prompt and b'host resource ceilings are not verified' in before_prompt
    assert b'--foreground' not in before_prompt
    # Real PTY navigation and linear mode. ECHO is disabled so line-length
    # assertions measure program output, not arbitrarily long typed commands.
    for width,terminal,no_color in ((20,'dumb',False),(38,'xterm-256color',False),(38,'xterm-256color',True)):
        t=interact(['--interactive','--linear'],b'help\nsearch existing\nsearch max-clients\nreview\nback\nreview\ncancel\n',width=width,terminal=terminal,echo=False,no_color=no_color)
        assert b'\x1b' not in t
        plain=t.replace(b'\r',b'')
        assert all(len(line)<=width for line in plain.split(b'\n'))
        flattened=b' '.join(plain.split())
        assert b'Progress' in flattened and b'Choices' in flattened and b'Review' in flattened
        assert b'set config <path>' in flattened and b'max-clients' in flattened
        assert b'Matching profiles' in flattened and b'Setup cancelled' in flattened
    colored=interact(['--interactive'],b'help\nsearch existing\nreview\nback\ncancel\n',color=True,width=38,echo=False)
    stripped=re.sub(rb'\x1b\[[0-9;]*m',b'',colored).replace(b'\r',b'')
    assert all(len(line)<=38 for line in stripped.split(b'\n'))
    assert b'\x1b[' in colored
    # Final material paths retain repeated spaces, even when a long path or
    # public value spans terminal lines. Secrets must not appear across wraps.
    for width in (20,38):
        name='bundle  path %d'%width
        t=interact(['--new','--interactive','--linear','--bundle',name],b'review\ndone\n',width=width,echo=False)
        flat=t.replace(b'\r\n',b'')
        for filename in ('onyx-server.toml','onyx-server-node.key','cloak.secret','tls-cert.der','tls-key.der'):
            assert str(root/name/filename).encode() in flat
        for filename in ('onyx-server-node.key','cloak.secret'):
            assert (root/name/filename).read_bytes().strip() not in flat
        assert all(len(line)<=width for line in t.replace(b'\r',b'').split(b'\n'))
    (root/'existing-export').write_text('preserve')
    failure=interact(['--new','--interactive','--linear','--export','existing-export'],b'review\ndone\n',width=20,echo=False,expected_code=1)
    assert all(len(line)<=20 for line in failure.replace(b'\r',b'').split(b'\n'))
    assert b'cannot publish new private artifact:' in b' '.join(failure.split())
    assert (root/'existing-export').read_text()=='preserve'
    too_narrow_master,too_narrow_slave=pty.openpty()
    fcntl.ioctl(too_narrow_slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,19,0,0))
    narrow_child=subprocess.Popen([B,'setup','--interactive','--linear'],cwd=base,env=env,stdin=too_narrow_slave,stdout=too_narrow_slave,stderr=too_narrow_slave)
    os.close(too_narrow_slave)
    try:
        narrow_child.wait(timeout=30)
        narrow_output=b''
        while select.select([too_narrow_master],[],[],0)[0]:
            try: chunk=os.read(too_narrow_master,4096)
            except OSError: break
            if not chunk: break
            narrow_output+=chunk
        assert narrow_child.returncode==2 and b'below 20 columns' in narrow_output
    finally:
        if narrow_child.poll() is None: narrow_child.kill();narrow_child.wait()
        os.close(too_narrow_master)
    cases+=1
    redirected=run(['setup','--interactive','--linear'],2)
    assert b'requires a terminal' in redirected.stderr and b'--json' in redirected.stderr
    assert json.loads(run(['setup','--new','--json']).stdout)['readiness']=='unknown'
    # The same capacity override must suppress profile capacity changes in
    # headless JSON, human output, and interactive previous-profile review.
    headless=json.loads(run(['setup','--new','--profile','community','--max-clients','512','--json']).stdout)
    assert headless['profile_diff_baseline']=='private'
    assert headless['profile_diff']=='No effective profile changes.'
    assert headless['effective_profile']=={'max_clients':512,'media_enabled':False}
    plain=run(['setup','--new','--profile','community','--max-clients','512']).stdout
    assert b'Comparison baseline: private' in plain and b'Diff: No effective profile changes.' in plain
    assert b'Diff: limits.max_clients: 128 -> 1024' not in plain
    for color in (False,True):
        transcript=interact(['--new','--interactive','--export','diff-%s.toml'%color],
                            b'set max-clients 512\ncommunity\nmedia\nset max-clients 0\nreview\ndone\n',color=color)
        assert b'Comparison baseline: community' in transcript
        assert b'Diff: media.enabled: false -> true' in transcript
        assert b'Diff: limits.max_clients:' not in transcript
        assert b'Unknown command for this step' in transcript
        actual=tomllib.loads((root/('diff-%s.toml'%color)).read_text())
        assert actual['limits']['max_clients']==512 and actual['media']['enabled'] is True
    default=json.loads(run(['setup','--new','--profile','community','--json']).stdout)
    assert default['profile_diff']=='limits.max_clients: 128 -> 1024'
    assert default['effective_profile']=={'max_clients':1024,'media_enabled':False}
    mixed=json.loads(run(['setup','--new','--profile','media','--max-clients','512','--json']).stdout)
    assert mixed['profile_diff']=='media.enabled: false -> true'
    assert mixed['effective_profile']=={'max_clients':512,'media_enabled':True}
    # Existing media values come from the actual validated boot projection;
    # reporting them does not claim a bind, STUN response, or relay operation.
    media_text=("[node]\nid=17\n[network]\nname='Onyx'\nserver_name='irc.example.test'\n"
                "[listen]\nhost='::1'\nirc=7000\nmedia=7100\nnative_media=7101\n"
                "media_host='203.0.113.4'\nws=7443\n[media]\nenabled=true\n"
                "ws_media_relay=true\nstun_host='198.51.100.9'\nstun_port=3478\n"
                "[tls]\nenabled=false\nport=7444\n[mail]\npass='DO-NOT-PRINT-SECRET'\n")
    media_file=root/'existing-media.toml'; media_file.write_text(media_text)
    before_media=media_file.read_bytes()
    assessed=run(['setup','existing-media.toml','--json'])
    assert b'DO-NOT-PRINT-SECRET' not in assessed.stdout+assessed.stderr
    media_plan=json.loads(assessed.stdout); media=media_plan['media_assessment']; cfg_media=media['configured']
    assert cfg_media['enabled'] and cfg_media['media_port']==7100 and cfg_media['native_media_port']==7101
    assert cfg_media['advertised_host']=='203.0.113.4' and cfg_media['stun_host']=='198.51.100.9' and cfg_media['stun_port']==3478
    assert cfg_media['websocket_port']==7443 and cfg_media['websocket_media_relay']
    assert 'unknown' in media['relay'] and 'unverified' in media['fallback']
    net=media_plan['network_assessment']
    assert net['address_check']=='numeric IPv6 syntax valid' and net['irc_port']==7000
    assert not net['tls_enabled'] and net['tls_port']==7444
    assert all('unknown' in net[k] for k in ('hostname_resolution','address_ownership','port_availability','public_reachability'))
    terminal=interact(['--interactive','--linear'],b'existing\nset config existing-media.toml\nreview\ndone\n')
    assert b'DO-NOT-PRINT-SECRET' not in terminal
    compact=b' '.join(terminal.split())
    for expected in (b'Configured native UDP port',b'7101',b'203.0.113.4',b'198.51.100.9',b'unknown; no network probes were sent'):
        assert expected in compact
    review_prefix=terminal.split(b'review> ',1)[0]
    assert b'TLS enabled no' in b' '.join(review_prefix.split())
    assert b'TLS port 7444' in b' '.join(review_prefix.split())
    assert media_file.read_bytes()==before_media
    off_file=root/'existing-media-off.toml';off_file.write_text(media_text.replace('enabled=true','enabled=false',1))
    before_off=off_file.read_bytes()
    off=json.loads(run(['setup','existing-media-off.toml','--json']).stdout)['media_assessment']
    assert not off['configured']['enabled'] and 'not bound' in off['socket']
    assert off['configured']['media_port']==7100 and off_file.read_bytes()==before_off
    ipv4=json.loads(run(['setup','--new','--listen','127.0.0.1','--json']).stdout)['network_assessment']
    assert ipv4['address_check']=='numeric IPv4 syntax valid'
    run(['setup','--new','--irc-port','7000','--tls-port','7000','--json'],2)
    # A private test-owned listener occupies the port throughout preview;
    # setup must not open or replace a production listener to assess it.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as held:
        held.bind(('127.0.0.1',0)); held.listen(1)
        occupied_port=held.getsockname()[1]
        occupied=json.loads(run(['setup','--new','--irc-port',str(occupied_port),'--json']).stdout)['network_assessment']
        assert 'unknown' in occupied['port_availability'] and held.getsockname()[1]==occupied_port
        with socket.create_connection(('127.0.0.1',occupied_port),timeout=3):
            conn,_=held.accept();conn.close()
    # Existing-network purpose validates the supplied existing config without
    # writing it, contacting a network, or inventing an enrollment result.
    existing_path='node/onyx-server.toml'
    before=(root/existing_path).read_bytes()
    existing_plan=json.loads(run(['setup',existing_path,'--json']).stdout)
    assert existing_plan['purpose']=='existing_network_review'
    assert existing_plan['effective_profile'] is None and not existing_plan['changes_applied']
    expected_existing={'network':'Onyx','server':'irc.example.test','listen_host':'::1','irc_port':7000,'max_clients':256,'media_enabled':True}
    assert existing_plan['existing_summary']==expected_existing
    assert 'not performed' in existing_plan['enrollment']
    existing_text=run(['setup',existing_path]).stdout
    assert b'Enrollment is not performed' in existing_text and b'null' not in existing_text
    assert b'irc.example.test' in existing_text and b'"max_clients":256' in existing_text
    for secret in [snapshot['onyx-server-node.key'].strip(),snapshot['cloak.secret'].strip()]:
        assert secret not in existing_text
    (root/'invalid-existing.toml').write_text('[node]\nid = 0\n')
    for color in (False,True):
        commands=(b'existing\nreview\nset config missing.toml\nreview\n'
                  b'set config invalid-existing.toml\nreview\nset config node/onyx-server.toml\n'
                  b'review\nback\nreview\ndone\n')
        transcript=interact(['--interactive'],commands,color=color)
        assert b'Set an existing configuration path before review' in transcript
        assert b'Cannot read configuration' in transcript and b'Configuration validation failed' in transcript
        assert b'Existing configuration validated for review' in transcript
        assert b'Existing configuration summary:' in transcript and b'"max_clients":256' in transcript.replace(b'\r\n',b'')
        assert b'Enrollment is not performed' in transcript and b'null' not in transcript
        for secret in [snapshot['onyx-server-node.key'].strip(),snapshot['cloak.secret'].strip()]:
            assert secret not in transcript
        assert (root/existing_path).read_bytes()==before
    cancelled=interact(['--interactive'],b'existing\nset config node/onyx-server.toml\ncancel\n')
    assert b'Setup cancelled' in cancelled and (root/existing_path).read_bytes()==before
    eof=interact(['--interactive'],b'existing\nset config node/onyx-server.toml\n\x04')
    assert b'Setup cancelled' in eof and (root/existing_path).read_bytes()==before
    back=interact(['--interactive'],b'existing\nset config node/onyx-server.toml\nback\nreview\ndone\n')
    assert b'Profile: private' in back and (root/existing_path).read_bytes()==before
    for blocked in (['--new'],['--max-clients','512'],['--export','blocked-existing.toml']):
        result=interact(['--interactive',*blocked],b'existing\ncancel\n')
        assert b'cannot discard requested new-install options or edits' in result
        assert not (root/'blocked-existing.toml').exists() and (root/existing_path).read_bytes()==before
    edited=interact(['--interactive'],b'set max-clients 512\nexisting\ncancel\n')
    assert b'cannot discard requested new-install options or edits' in edited
    assert (root/existing_path).read_bytes()==before
    assert snapshot=={x.name:x.read_bytes() for x in node.iterdir()}
    commands=b'3\nset hostname irc.example.test\nset listen ::1\nset irc-port 7000\nset node-id 17\nset tls-port 7001\nset max-clients 256\nset media-port 7100\nreview\nback\nreview\ndone\n'
    transcript=interact(['--new','--interactive','--bundle','interactive-node'],commands)
    interactive=tomllib.loads((root/'interactive-node/onyx-server.toml').read_text())
    for table in ['node','network','listen','limits','media']:
        assert cfg[table]==interactive[table]
    assert interactive['tls']['port']==7001
    for secret in ['cloak.secret','onyx-server-node.key']:
        assert (root/'interactive-node'/secret).read_bytes().strip() not in transcript
    clean_stage()
    interact(['--new','--interactive','--bundle','cancelled'],b'set hostname cancel.example.test\nreview\ncancel\n',color=True)
    assert not (root/'cancelled').exists();clean_stage()
    interact(['--new','--interactive','--bundle','cancelled-after-generation'],b'review\ndone\n',material_reply=b'cancel\n')
    assert not (root/'cancelled-after-generation').exists();clean_stage()
    interact(['--new','--interactive','--bundle','eof-after-generation'],b'review\ndone\n',material_reply=b'\x04')
    assert not (root/'eof-after-generation').exists();clean_stage()
    interact(['--new','--interactive','--draft','interactive-choices'],b'set hostname saved.example.test\nset node-id 23\nset tls-port 7777\nreview\nsave\n')
    saved=json.loads((root/'interactive-choices').read_text())
    assert saved['settings']['hostname']=='saved.example.test' and saved['settings']['node_id']==23
    run(['setup','--resume','interactive-choices','--bundle','resumed-node','--json'])
    resumed=tomllib.loads((root/'resumed-node/onyx-server.toml').read_text())
    assert resumed['network']['server_name']=='saved.example.test' and resumed['node']['id']==23 and resumed['tls']['port']==7777
    clean_stage()
print(f'PASS: {cases} native/headless/PTY cases; custom hostname/IP/ports/id/capacity, private stable canonical bundle/TLS/secret omission, arbitrary-CWD validation, existing file/dir/symlink refusal and cleanup, invalid settings/schema/parent rejection, legacy draft compatibility, interactive edits/back/save/resume parity, actual prepublication material review, explicit publish identity stability, postgeneration cancellation and EOF stage cleanup.')
