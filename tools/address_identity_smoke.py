#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private direct/PROXY address, clone and reputation behavior fixture."""
import argparse, hashlib, os, pathlib, re, socket, struct, subprocess, sys, tempfile, time
sys.path.insert(0,str(pathlib.Path.cwd()/'tools'))
from setup_review_client import run_review
from privacy_corpus_smoke import Irc, command, limits, ports, stop
HOST='127.0.0.1'
TARGET='198.51.100.153'
MAPPED='::ffff:c633:6499'
PASSWORD='Address-Provenance-Fixture-Only-78-Password'
phase='arguments'
diagnostic='none'
class Failure(Exception):pass
class Unavailable(Exception):pass
def require(value):
    if not value:raise Failure()
def wait_port(proc,port):
    end=time.monotonic()+30
    while time.monotonic()<end:
        if proc.poll() is not None:raise Unavailable()
        try:
            with socket.create_connection((HOST,port),timeout=.5):return
        except OSError:time.sleep(.05)
    raise Failure()
def preamble(kind,address,port):
    if kind=='direct':return b''
    if kind=='v4':return f'PROXY TCP4 {address} {HOST} 40123 {port}\r\n'.encode()
    if kind=='mapped-v1':return f'PROXY TCP6 ::ffff:{address} ::1 40123 {port}\r\n'.encode()
    if kind=='mapped-v2':
        src=socket.inet_pton(socket.AF_INET6,'::ffff:'+address);dst=socket.inet_pton(socket.AF_INET6,'::1')
        return b'\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24'+src+dst+struct.pack('!HH',40123,port)
    raise Failure()
class Client:
    def __init__(self,port,nick,kind,address,source=None):
        self.sock=socket.socket();self.sock.settimeout(10)
        if source:self.sock.bind((source,0))
        self.sock.connect((HOST,port));self.nick=nick;self.buffer=b'';self.data=b''
        self.sock.sendall(preamble(kind,address,port)+f'NICK {nick}\r\nUSER identity 0 * :Identity fixture\r\n'.encode())
    def until(self,marker):
        global diagnostic
        diagnostic='waiting'
        lines=0
        end=time.monotonic()+20
        while True:
            ix=self.buffer.find(b'\r\n')
            if ix>=0:
                line=self.buffer[:ix+2];self.buffer=self.buffer[ix+2:];self.data+=line;lines+=1;require(len(self.data)<65536)
                diagnostic='lines_'+str(lines)+'_reputation_'+str(int(b'ERROR :Connection refused (reputation)' in self.data))+'_clones_'+str(int(b'ERROR :Too many connections from your host' in self.data))+'_welcome_'+str(int(b' 001 ' in self.data))
                if marker.encode() in line:return
                if b' 001 ' in line or line.startswith(b'ERROR '):raise Failure()
                continue
            left=end-time.monotonic()
            if left<=0:raise Failure()
            self.sock.settimeout(left)
            try:chunk=self.sock.recv(4096)
            except TimeoutError:
                diagnostic+='_partial_'+str(len(self.buffer));raise
            require(bool(chunk));self.buffer+=chunk;require(len(self.buffer)<65536)
    def registered(self):self.until(' 001 '+self.nick+' ')
    def whois(self,expected):
        self.sock.sendall(('WHOIS '+self.nick+'\r\n').encode());self.until(' 338 '+self.nick+' '+self.nick+' '+expected+' ');self.until(' 318 '+self.nick+' '+self.nick+' ')
    def ping(self):
        self.sock.sendall(b'PING :identity-alive\r\n');self.until(':identity-alive')
    def quit_and_wait_eof(self):
        # QUIT's close path releases the clone slot before closing its fd.
        require(not self.buffer)
        self.sock.sendall(b'QUIT :identity-fixture-complete\r\n')
        self.sock.settimeout(20)
        require(self.sock.recv(4096)==b'')
        self.sock.close()
    def close(self):self.sock.close()
def main():
    global phase, diagnostic
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True,type=pathlib.Path);ap.add_argument('--expected-sha256',required=True);ap.add_argument('--scratch-dir',required=True,type=pathlib.Path);args=ap.parse_args()
    binary=args.binary.resolve(strict=True);digest=hashlib.sha256(binary.read_bytes()).hexdigest();require(re.fullmatch('[0-9a-f]{64}',args.expected_sha256) and digest==args.expected_sha256)
    if sys.platform!='linux':raise Unavailable()
    args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as tmp:
        root=pathlib.Path(tmp).resolve();irc,tls,media=ports(3)
        phase='prepare';result,review,_=run_review([str(binary),'setup','--new','--hostname','address-policy.example.test','--listen',HOST,'--irc-port',str(irc),'--tls-port',str(tls),'--media-port',str(media),'--bundle','bundle','--json'],root,{'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'},preexec_fn=limits);require(result.returncode==0 and review)
        config=root/'bundle'/'onyx-server.toml';text=config.read_text().replace('[listen]\n',f'[listen]\nproxy_protocol = true\ntrusted_proxies = ["{HOST}"]\n',1).replace('[limits]\n','[limits]\nmax_clones_per_ip = 1\nreputation_refuse_threshold = 1\nreputation_half_life = "1h"\n',1)
        text+='\n[sasl]\nenabled = true\naccount_db = "accounts.wal"\n[accounts]\npbkdf2_rounds = 10000\n[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_admin"]\n[[opers]]\naccount = "addressadmin"\nclass = "netadmin"\n';config.write_text(text);config.chmod(0o600)
        phase='config';require(command(binary,['--check-config',str(config)],config.parent).returncode==0)
        with (root/'daemon.log').open('xb') as log:proc=subprocess.Popen([str(binary),str(config)],cwd=config.parent,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,preexec_fn=limits)
        clients=[]
        def connect(nick,kind,address,source=None):
            c=Client(irc,nick,kind,address,source);clients.append(c);return c
        try:
            phase='start';wait_port(proc,irc)
            phase='operator';admin=Irc(tls,'Admin','198.51.100.180',True);clients.append(admin);admin.send('REGISTER addressadmin * '+PASSWORD);admin.until('REGISTER SUCCESS addressadmin',40);admin.until(' 381 Admin ',40)
            phase='direct';direct=connect('Direct','direct','',source='127.0.0.2');direct.registered();direct.whois('localhost')
            equivalent=connect('DirectProxy','v4','127.0.0.2');equivalent.until('ERROR :Too many connections from your host');direct.ping()
            control=connect('Different','v4','198.51.100.154');control.registered();control.whois('198.51.100.154')
            phase='clone-v4-mapped';original=connect('Original','v4',TARGET);original.registered();original.whois(TARGET)
            mapped=connect('Mapped','mapped-v2',TARGET);mapped.until('ERROR :Too many connections from your host');original.ping();original.quit_and_wait_eof();clients.remove(original)
            # The clone refusal produces a configured penalty above threshold.
            phase='reputation-v4';again=connect('Penalty4','v4',TARGET);again.until('ERROR :Connection refused (reputation)')
            phase='reputation-mapped-v1';again6=connect('Penalty6','mapped-v1',TARGET);again6.until('ERROR :Connection refused (reputation)')
            phase='reputation-control';control.ping()
            phase='reputation-unreject-hex';diagnostic='external_helper';admin.send('UNREJECT :'+MAPPED);admin.until('UNREJECT '+MAPPED+': cleared')
            phase='recovery';restored=connect('Restored','mapped-v2',TARGET);restored.registered();restored.whois(TARGET)
            phase='reverse-clone';reverse=connect('Reverse','v4',TARGET);reverse.until('ERROR :Too many connections from your host');restored.ping();restored.quit_and_wait_eof();clients.remove(restored)
            phase='reputation-again';again=connect('PenaltyAgain','v4',TARGET);again.until('ERROR :Connection refused (reputation)')
            phase='reputation-unreject-dotted';diagnostic='external_helper';admin.send('UNREJECT :::ffff:'+TARGET);admin.until('UNREJECT ::ffff:'+TARGET+': cleared')
            final=connect('Final','v4',TARGET);final.registered();final.whois(TARGET);control.ping();require(proc.poll() is None)
            require(PASSWORD.encode() not in admin.data)
            print(f'PASS direct_proxy_clone=1 v4_mapped_clone=2 reputation_refusals=3 mapped_unreject=2 recovery=2 artifact_sha256={digest}')
        finally:
            for c in clients:c.close()
            stop(proc)
if __name__=='__main__':
    try:main()
    except Unavailable:print(f'UNAVAILABLE phase={phase}',file=sys.stderr);sys.exit(2)
    except Exception as exc:print(f'FAIL phase={phase} error={type(exc).__name__} diagnostic={diagnostic}',file=sys.stderr);sys.exit(1)
