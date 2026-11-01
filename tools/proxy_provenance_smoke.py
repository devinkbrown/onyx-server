#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private trusted and untrusted PROXY source-identity acceptance probe."""
import argparse, hashlib, os, pathlib, re, socket, subprocess, sys, tempfile, time
sys.path.insert(0,str(pathlib.Path.cwd()/'tools'))
from setup_review_client import run_review
from privacy_corpus_smoke import command, limits, ports, stop

HOST='127.0.0.1'
CLAIM='198.51.100.177'
phase='arguments'
class Failure(Exception): pass
class Unavailable(Exception): pass
def require(value):
    if not value:raise Failure()
class Client:
    def __init__(self,proc,port,nick,proxy):
        self.buffer=b'';self.wire=b'';deadline=time.monotonic()+30
        while True:
            if proc.poll() is not None:raise Unavailable()
            try:self.socket=socket.create_connection((HOST,port),timeout=.5);break
            except OSError:
                if time.monotonic()>=deadline:raise Failure()
                time.sleep(.05)
        header=f'PROXY TCP4 {CLAIM} {HOST} 40123 {port}\r\n' if proxy else ''
        self.socket.sendall((header+f'NICK {nick}\r\nUSER fixture 0 * :provenance fixture\r\n').encode())
        self.nick=nick
    def until(self,needle,allow_eof=False):
        deadline=time.monotonic()+20
        while True:
            end=self.buffer.find(b'\r\n')
            if end>=0:
                line=self.buffer[:end+2];self.buffer=self.buffer[end+2:];self.wire+=line
                require(len(self.wire)<65536)
                if needle in line:return True
                continue
            left=deadline-time.monotonic()
            if left<=0:raise Failure()
            self.socket.settimeout(left);data=self.socket.recv(4096)
            if not data:
                if allow_eof:return False
                raise Failure()
            self.buffer+=data;require(len(self.buffer)<65536)
    def confirm_address(self,address):
        self.socket.sendall(('WHOIS '+self.nick+'\r\n').encode())
        require(self.until((' 338 '+self.nick+' '+self.nick+' '+address+' ').encode()))
        require(self.until((' 318 '+self.nick+' '+self.nick+' ').encode()))
    def close(self):self.socket.close()
def launch(binary,config,root,name):
    with (root/(name+'.log')).open('xb') as log:
        return subprocess.Popen([str(binary),str(config)],cwd=config.parent,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,preexec_fn=limits)
def main():
    global phase
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=pathlib.Path,required=True);ap.add_argument('--expected-sha256',required=True);ap.add_argument('--scratch-dir',type=pathlib.Path,required=True);args=ap.parse_args()
    binary=args.binary.resolve(strict=True);digest=hashlib.sha256(binary.read_bytes()).hexdigest();require(re.fullmatch('[0-9a-f]{64}',args.expected_sha256) and digest==args.expected_sha256)
    if sys.platform!='linux':raise Unavailable()
    args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as tmp:
        root=pathlib.Path(tmp).resolve();irc,tls,media=ports(3)
        phase='prepare';result,review,_=run_review([str(binary),'setup','--new','--hostname','proxy-proof.example.test','--listen',HOST,'--irc-port',str(irc),'--tls-port',str(tls),'--media-port',str(media),'--bundle','bundle','--json'],root,{'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'},preexec_fn=limits)
        require(result.returncode==0 and review and review['certificate_subject']=='proxy-proof.example.test')
        directory=root/'bundle';base=(directory/'onyx-server.toml').read_text();configs=[]
        for name,allowed in (('trusted',HOST),('untrusted','192.0.2.55')):
            text=base.replace('[listen]\n',f'[listen]\nproxy_protocol = true\ntrusted_proxies = ["{allowed}"]\n',1);require(text!=base)
            config=directory/(name+'.toml');config.write_text(text);config.chmod(0o600);configs.append(config)
            phase='config';require(command(binary,['--check-config',str(config)],directory).returncode==0)
        phase='trusted';trusted=launch(binary,configs[0],root,'trusted')
        try:
            client=Client(trusted,irc,'Trusted',True)
            try:
                require(client.until(b' 001 Trusted '));client.confirm_address(CLAIM);require(trusted.poll() is None)
            finally:client.close()
        finally:stop(trusted)
        phase='untrusted';untrusted=launch(binary,configs[1],root,'untrusted');forged_result=''
        try:
            plain=Client(untrusted,irc,'Plain',False)
            try:
                require(plain.until(b' 001 Plain '));plain.confirm_address("localhost");require(CLAIM.encode() not in plain.wire)
            finally:plain.close()
            forged=Client(untrusted,irc,'Forged',True)
            try:
                if forged.until(b' 001 Forged ',allow_eof=True):
                    forged.confirm_address("localhost");require(CLAIM.encode() not in forged.wire);forged_result='kernel'
                else:
                    require(CLAIM.encode() not in forged.wire);forged_result='explicit_eof'
            finally:forged.close()
            require(untrusted.poll() is None)
            recovery=Client(untrusted,irc,'Recovery',False)
            try:require(recovery.until(b' 001 Recovery '));recovery.confirm_address("localhost")
            finally:recovery.close()
        finally:stop(untrusted)
    print(f'PASS trusted_proxy=1 untrusted_proxy={forged_result} ordinary_kernel=2 artifact_sha256={digest}')
if __name__=='__main__':
    try:main()
    except Unavailable:print(f'UNAVAILABLE phase={phase}',file=sys.stderr);sys.exit(2)
    except Exception as exc:print(f'FAIL phase={phase} error={type(exc).__name__}',file=sys.stderr);sys.exit(1)
