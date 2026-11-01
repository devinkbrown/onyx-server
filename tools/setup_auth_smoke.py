#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native private account/setup/TLS acceptance; disposable processes only."""
import argparse,hashlib,os,sys,json,pathlib,tempfile,subprocess,socket,ssl,time,base64,pty,select,errno,resource
from setup_review_client import run_review
from scram_fixture import Client as ScramProof, decode as decode_scram
LIMIT=1<<20

def limit_files():
    resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT))

def run(binary,scratch):
    if sys.platform!='linux' or os.geteuid()==0:raise RuntimeError('requires non-root Linux')
    B=str(binary.resolve(strict=True))
    artifact_digest=hashlib.sha256(pathlib.Path(B).read_bytes()).hexdigest()
    ENV={'PATH':os.defpath,'NO_COLOR':'','TERM':'xterm-256color'}
    PASSWORD=b'Wave4 bootstrap private secret 7zK9'
    cases=0
    scratch.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=scratch) as d:
        root=pathlib.Path(d); ENV['TMPDIR']=d; secret=root/'private-input'; secret.write_bytes(PASSWORD+b'\n');secret.chmod(0o600)
        def no_stage(): assert not list(root.glob('.onyx-setup-*'))
        def run(args,expected=0,pass_fds=()):
            nonlocal cases
            try:
                out_path=root/f'capture-{cases}.out';err_path=root/f'capture-{cases}.err'
                with out_path.open('xb') as out,err_path.open('xb') as err:
                    out_path.chmod(0o600);err_path.chmod(0o600)
                    if '--bundle' in args and '--interactive' not in args:
                        child_result,record,review=run_review([B,'setup',*args],d,ENV,pass_fds=pass_fds,preexec_fn=limit_files)
                        assert PASSWORD not in review
                        out.write(child_result.stdout);err.write(child_result.stderr)
                    else:
                        child_result=subprocess.run([B,'setup',*args],cwd=d,env=ENV,stdout=out,stderr=err,timeout=120,pass_fds=pass_fds,preexec_fn=limit_files)
                assert out_path.stat().st_size<LIMIT and err_path.stat().st_size<LIMIT, 'CLI capture bound reached'
                result=subprocess.CompletedProcess([],child_result.returncode,out_path.read_bytes(),err_path.read_bytes())
            except subprocess.TimeoutExpired:
                raise AssertionError(('setup case timeout',cases)) from None
            assert result.returncode==expected,('setup case failed',result.returncode,len(result.stdout),len(result.stderr))
            assert PASSWORD not in result.stdout+result.stderr
            assert b'\x1b' not in result.stdout+result.stderr
            cases+=1
            return result
        def ports():
            handles=[]
            for _ in range(2):
                sock=socket.socket();sock.bind(('127.0.0.1',0));handles.append(sock)
            result=[sock.getsockname()[1] for sock in handles]
            for sock in handles:sock.close()
            return result
        # Preview/drafts must not touch nonexistent/private/FD sources.
        intent=['--bootstrap-account','Alice','--oper-privileges','server_rehash,audit_read']
        p=run(['--new',*intent,'--password-file','does-not-exist','--json'])
        assert json.loads(p.stdout)['settings']['bootstrap']['account']=='Alice'
        assert json.loads(p.stdout)['bootstrap_account'] is None
        p=run(['--new',*intent,'--password-fd','999999','--draft','choices.json','--json'])
        draft=json.loads((root/'choices.json').read_text());assert draft['version']==3
        assert draft['settings']['bootstrap']==dict(account='Alice',privileges='server_rehash,audit_read')
        assert PASSWORD not in (root/'choices.json').read_bytes()
        assert 'password_file' not in json.dumps(draft) and 'password_fd' not in json.dumps(draft)
        irc,tls=ports()
        flags=['--new',*intent,'--irc-port',str(irc),'--tls-port',str(tls)]
        p=run([*flags,'--password-file',str(secret),'--bundle','operator-node','--json'])
        plan=json.loads(p.stdout);node=root/'operator-node'
        assert plan['bootstrap_account']=='alice' and plan['operator_privileges']=='server_rehash,audit_read'
        assert plan['authentication_mechanisms']==['PLAIN over TLS','SCRAM-SHA-256','SCRAM-SHA-512']
        assert (node/'accounts.wal').stat().st_mode&0o777==0o600
        for file in node.iterdir():assert PASSWORD not in file.read_bytes()
        before={file.name:file.read_bytes() for file in node.iterdir()}
        run([*flags,'--password-file',str(secret),'--bundle','operator-node'],1)
        assert before=={file.name:file.read_bytes() for file in node.iterdir()};no_stage()
        for args,code in [(['--new','--bootstrap-account','Alice','--bundle','missing-source'],1),
                          (['--new',*intent,'--password-fd','999999','--bundle','bad-fd'],1),
                          (['--new','--bootstrap-account','Alice','--oper-privileges','not_real','--bundle','bad-role'],2),
                          (['--new','--password','forbidden-argv-value'],2)]:
            run(args,code);no_stage()
        secret.chmod(0o644)
        run(['--new',*intent,'--password-file',str(secret),'--bundle','broad-source'],1);no_stage();secret.chmod(0o600)
        os.symlink('private-input',root/'input-link')
        run(['--new',*intent,'--password-file','input-link','--bundle','symlink-source'],1);no_stage()
        os.mkfifo(root/'input-fifo',mode=0o600)
        run(['--new',*intent,'--password-file','input-fifo','--bundle','fifo-source'],1);no_stage()
        weak=root/'weak';weak.write_bytes(b'short');weak.chmod(0o600)
        run(['--new',*intent,'--password-file','weak','--bundle','weak-source'],1);no_stage()
        irc_member,tls_member=ports()
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,PASSWORD+b'\n');os.close(write_fd);write_fd=None
            p=run(['--new','--bootstrap-account','Member','--irc-port',str(irc_member),'--tls-port',str(tls_member),'--password-fd',str(read_fd),'--bundle','member-node','--json'],pass_fds=(read_fd,))
            assert json.loads(p.stdout)['operator_privileges']=='none'
        finally:
            os.close(read_fd)
            if write_fd is not None:os.close(write_fd)
        assert '[[opers]]' not in (root/'member-node/onyx-server.toml').read_text()
        # A caller-supplied descriptor must still never read an echoing terminal.
        master,slave=pty.openpty()
        tty_child=subprocess.Popen([B,'setup','--new',*intent,'--password-fd',str(slave),'--bundle','terminal-source','--json','--review-stdin'],cwd=d,env=ENV,stdin=slave,stdout=slave,stderr=slave,pass_fds=(slave,),preexec_fn=limit_files)
        os.close(slave);tty_output=b''
        try:
            tty_child.wait(timeout=10)
            while select.select([master],[],[],0)[0]:
                try:chunk=os.read(master,65536)
                except OSError:break
                if not chunk:break
                tty_output+=chunk
                assert len(tty_output)<LIMIT, "terminal refusal capture bound reached"
            assert tty_child.returncode==1 and b'TerminalPasswordInputRefused' in tty_output
            assert PASSWORD not in tty_output and not (root/'terminal-source').exists();no_stage();cases+=1
        finally:
            if tty_child.poll() is None:tty_child.kill();tty_child.wait()
            os.close(master)
        # Actual post-generation role review, secret omission, cancellation and EOF.
        def interact(destination,reply=b'publish\n'):
            nonlocal cases
            master,slave=pty.openpty()
            child=subprocess.Popen([B,'setup','--new',*intent,'--password-file',str(secret),'--interactive','--bundle',destination],cwd=d,env=ENV,stdin=slave,stdout=slave,stderr=slave,preexec_fn=limit_files)
            os.close(slave);transcript=b'';first=False;reviewed=False
            try:
                deadline=time.monotonic()+120
                while child.poll() is None:
                    if time.monotonic()>deadline:raise AssertionError(('PTY timeout',len(transcript)))
                    if select.select([master],[],[],0.05)[0]:
                        try:chunk=os.read(master,65536)
                        except OSError as exc:
                            if exc.errno==errno.EIO:break
                            raise
                        transcript+=chunk
                        assert len(transcript)<LIMIT, "PTY capture bound reached"
                        if not first and b'choice> ' in transcript:
                            os.write(master,b'review\ndone\n');first=True
                        if not reviewed and b'Material action (publish/cancel)> ' in transcript.replace(b'\r\n',b''):
                            assert not (root/destination).exists()
                            stages=list(root.glob('.onyx-setup-*'));assert len(stages)==1
                            assert (stages[0]/'accounts.wal').exists()
                            assert b'"bootstrap_account": "alice"' in transcript and b'accounts.wal' in transcript
                            assert b'server_rehash,audit_read' in transcript and b'SCRAM-SHA-512' in transcript
                            os.write(master,reply);reviewed=True
                child.wait(timeout=2)
                while select.select([master],[],[],0)[0]:
                    try:chunk=os.read(master,65536)
                    except OSError:break
                    if not chunk:break
                    transcript+=chunk
                    assert len(transcript)<LIMIT, "PTY capture bound reached"
                assert child.returncode==0 and reviewed,('PTY case failed',child.returncode,len(transcript))
                assert PASSWORD not in transcript and b'\x1b' not in transcript
                no_stage();cases+=1
            finally:
                if child.poll() is None:child.kill();child.wait()
                os.close(master)
        interact('pty-account');assert (root/'pty-account/accounts.wal').exists()
        interact('cancelled-account',b'cancel\n');assert not (root/'cancelled-account').exists()
        interact('eof-account',b'\x04');assert not (root/'eof-account').exists()
        # Boot only this new, temporary bundle. No REGISTER is sent on the wire.
        class Client:
            def __init__(self,port):
                expected=((root/'member-node' if port==tls_member else node)/'tls-cert.der').read_bytes()
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(expected))
                self.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=2),server_hostname='localhost')
                assert self.sock.getpeercert(binary_form=True)==expected, 'fixture TLS pin mismatch'
                self.sock.settimeout(0.2);self.seen=b'';self.auth_cursor=0
            def send(self,data):self.sock.sendall(data)
            def until(self,needle,timeout=25):
                end=time.monotonic()+timeout
                while needle not in self.seen:
                    if time.monotonic()>end:raise AssertionError(('client timeout',len(self.seen)))
                    try:chunk=self.sock.recv(65536)
                    except socket.timeout:continue
                    assert chunk,('client closed',len(self.seen));self.seen+=chunk;assert len(self.seen)<LIMIT, 'IRC response bound reached'
                    assert len(self.seen)<=131072,'client response bound exceeded' 
                return self.seen
            def login(self,password,nick,ok=True):
                self.send(b'CAP LS 302\r\n');self.until(b'CAP')
                self.send(b'CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n');self.until(b'AUTHENTICATE +')
                account=b'alice' if nick!=b'member' else b'member'
                self.send(b'AUTHENTICATE '+base64.b64encode(b'\0'+account+b'\0'+password)+b'\r\n')
                self.until(b' 903 ' if ok else b' 904 ')
                if ok:self.send(b'CAP END\r\nNICK '+nick+b'\r\nUSER '+nick+b' 0 * :setup bootstrap test\r\n');self.until(b' 001 ')
            def auth_payload(self,timeout=25):
                end=time.monotonic()+timeout
                while True:
                    start=self.seen.find(b'AUTHENTICATE ',self.auth_cursor)
                    if start!=-1:
                        finish=self.seen.find(b'\r\n',start)
                        if finish!=-1:
                            self.auth_cursor=finish+2
                            return self.seen[start+len(b'AUTHENTICATE '):finish]
                    assert b' 904 ' not in self.seen,'SCRAM challenge rejected'
                    assert time.monotonic()<end,('SCRAM response timeout',len(self.seen))
                    try:chunk=self.sock.recv(65536)
                    except socket.timeout:continue
                    assert chunk,('SCRAM connection closed',len(self.seen));self.seen+=chunk;assert len(self.seen)<LIMIT, 'IRC response bound reached'
                    assert len(self.seen)<=131072,'SCRAM response bound exceeded'
            def scram(self,digest,nick,wrong_proof=False):
                mechanism=b'SCRAM-SHA-256' if digest=='sha256' else b'SCRAM-SHA-512'
                proof=ScramProof(b'alice',b'setup-auth-fixture-'+digest.encode()+b'-nonce-0123456789',digest)
                self.send(b'CAP LS 302\r\n');self.until(b'CAP')
                self.send(b'CAP REQ :sasl\r\nAUTHENTICATE '+mechanism+b'\r\n')
                assert self.auth_payload()==b'+','SCRAM initial prompt malformed'
                self.send(b'AUTHENTICATE '+base64.b64encode(proof.first)+b'\r\n')
                final=proof.respond(decode_scram(self.auth_payload()),PASSWORD)
                if wrong_proof:
                    prefix,_,encoded=final.rpartition(b'p=')
                    raw=decode_scram(encoded)
                    final=prefix+b'p='+base64.b64encode(bytes([raw[0]^1])+raw[1:])
                self.send(b'AUTHENTICATE '+base64.b64encode(final)+b'\r\n')
                if wrong_proof:
                    self.until(b' 904 ')
                    assert b' 903 ' not in self.seen and b' 381 ' not in self.seen,'wrong SCRAM proof accepted'
                    return
                proof.verify(decode_scram(self.auth_payload()))
                self.until(b' 903 ')
                self.send(b'CAP END\r\nNICK '+nick+b'\r\nUSER '+nick+b' 0 * :SCRAM bootstrap fixture\r\n')
                self.until(b' 381 ')
            def close(self):self.sock.close()
        def daemon(bundle,port,action):
            nonlocal cases
            log=root/'runtime.log'
            with log.open('ab') as stream:
                log.chmod(0o600)
                child=subprocess.Popen([B,str(bundle/'onyx-server.toml')],cwd=d,env=ENV,stdout=stream,stderr=stream,preexec_fn=limit_files)
                client=None
                try:
                    deadline=time.monotonic()+120
                    while True:
                        assert child.poll() is None,('daemon exited',child.returncode,log.stat().st_size)
                        try:client=Client(port);break
                        except (OSError,ssl.SSLError):
                            if time.monotonic()>deadline:raise
                            time.sleep(0.05)
                    action(client,child)
                    assert child.poll() is None, "fixture exited after action"
                    assert log.stat().st_size<LIMIT, "runtime log bound reached"
                    cases+=1
                finally:
                    if client:client.close()
                    if child.poll() is None:
                        child.terminate()
                        try:child.wait(timeout=10)
                        except subprocess.TimeoutExpired:child.kill();child.wait()
            assert log.stat().st_size<LIMIT, "runtime log bound reached"
            assert PASSWORD not in log.read_bytes()
            assert base64.b64encode(b'\0alice\0'+PASSWORD) not in log.read_bytes()
        def verify_operator(client,child):
            client.login(PASSWORD,b'bootstrapoper');client.until(b' 381 ')
            assert client.sock.getpeercert(binary_form=True)==(node/'tls-cert.der').read_bytes()
            client.send(b'DIE\r\n');client.until(b' 481 ');assert child.poll() is None
            client.send(b'REHASH\r\n');client.until(b' 382 ');assert child.poll() is None
            wrong=Client(tls)
            try:wrong.login(b'wrong bootstrap secret',b'wrong',False);assert b' 381 ' not in wrong.seen
            finally:wrong.close()
            for digest in ['sha256','sha512']:
                good=Client(tls)
                try:good.scram(digest,('proof'+digest).encode())
                finally:good.close()
                bad=Client(tls)
                try:bad.scram(digest,('bad'+digest).encode(),wrong_proof=True)
                finally:bad.close()
        daemon(node,tls,verify_operator)
        daemon(node,tls,verify_operator)
        for key in ['onyx-server-node.key','cloak.secret','tls-cert.der','tls-key.der']:
            assert (node/key).read_bytes()==before[key]
        # Account-only bundle has its own generated listener settings.
        member=root/'member-node'
        def verify_member(client,child):
            client.login(PASSWORD,b'member');client.send(b'DIE\r\n');client.until(b' 481 ')
            assert b' 381 ' not in client.seen and child.poll() is None
        daemon(member,tls_member,verify_member)
    assert hashlib.sha256(pathlib.Path(B).read_bytes()).hexdigest()==artifact_digest, 'artifact changed during smoke'
    return dict(artifact_sha256=artifact_digest,cases=cases,checks=['TLS-PLAIN','TLS-SCRAM-SHA-256','TLS-SCRAM-SHA-512','server-proofs','bad-proof-denial','exact-operator-permissions','private-file-and-FD','TTY-refusal','private-review','cancel-and-EOF','cold-restart'],limitations=['disposable-fixture','no-live-installation-or-release-acceptance'])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=pathlib.Path,required=True)
    parser.add_argument('--scratch-dir',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'.zig-cache'/'cloak-tmp')
    args=parser.parse_args()
    if not __debug__:parser.error('run acceptance with assertions enabled')
    try:
        print(json.dumps(run(args.binary,args.scratch_dir),indent=2))
    except Exception:
        parser.exit(1,'setup auth smoke: fixture failed; private captures omitted\n')
