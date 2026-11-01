#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private actual Services account-cloak and channel access regression corpus."""
import argparse, hashlib, os, pathlib, re, socket, subprocess, sys, tempfile, time
sys.path.insert(0,str(pathlib.Path.cwd()/'tools'))
from setup_review_client import run_review
from privacy_corpus_smoke import Irc, command, limits, ports, stop

HOST='127.0.0.1'
PASSWORD='Account-Cloak-Policy-Fixture-Password-Only-77'
phase='arguments'
class Failure(Exception):pass
class Unavailable(Exception):pass
def require(value):
    if not value:raise Failure()
def ready(proc,port):
    end=time.monotonic()+30
    while time.monotonic()<end:
        if proc.poll() is not None:raise Unavailable()
        try:
            with socket.create_connection((HOST,port),timeout=.5):return
        except OSError:time.sleep(.05)
    raise Failure()
def account_digest(account):return hashlib.sha256(b'onyx/cloak/account/v2\x00'+account.lower().encode()).hexdigest()[:32]
def account_host(account):
    folded=account.lower()
    if re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',folded):return folded+'.users.onyx'
    friendly=''.join(c if c.isascii() and (c.isalnum() or c=='-') else '-' for c in folded).lstrip('-')[:30].rstrip('-') or 'account'
    return friendly+'.'+account_digest(account)+'.users.onyx'
def whois(client,address):
    client.send('WHOIS '+client.nick);reply=client.until(' 318 '+client.nick+' '+client.nick+' ')
    lines=[line for line in reply.split(b'\r\n') if b' 311 '+client.nick.encode()+b' '+client.nick.encode()+b' ' in line]
    require(len(lines)==1);fields=lines[0].split(b' ');require(len(fields)>=7 and fields[4]==b'fixture')
    require((' 338 '+client.nick+' '+client.nick+' '+address+' ').encode() in reply)
    return fields[5].decode('ascii')
def register(client,account):
    client.send('REGISTER '+account+' * '+PASSWORD);client.until('REGISTER SUCCESS '+account,40)
    identify(client,account)
def identify(client,account):
    client.send('IDENTIFY '+account+' :'+PASSWORD);client.until('You are now identified as ',40)
def join(client,channel,voiced):
    client.send('JOIN '+channel);reply=client.until(' 366 '+client.nick+' '+channel+' ')
    names=[line for line in reply.split(b'\r\n') if b' 353 ' in line]
    require(names and any((b'+'+client.nick.encode()) in line.split(b' :')[-1].split() for line in names)==voiced)
def speak(owner,subject,channel,marker,allow):
    subject.send('PRIVMSG '+channel+' :'+marker)
    if allow:
        line=owner.until('PRIVMSG '+channel+' :'+marker);require((':'+subject.nick+'!fixture@').encode() in line)
    else:
        subject.until(' 404 '+subject.nick+' '+channel+' ')
        barrier=owner.barrier('policy-proof-barrier');require((' PRIVMSG '+channel+' :'+marker+'\r\n').encode() not in barrier)
def main():
    global phase
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=pathlib.Path,required=True);ap.add_argument('--expected-sha256',required=True);ap.add_argument('--scratch-dir',type=pathlib.Path,required=True);args=ap.parse_args()
    binary=args.binary.resolve(strict=True);digest=hashlib.sha256(binary.read_bytes()).hexdigest();require(re.fullmatch('[0-9a-f]{64}',args.expected_sha256) and digest==args.expected_sha256)
    if sys.platform!='linux':raise Unavailable()
    args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as tmp:
        root=pathlib.Path(tmp).resolve();irc,tls,media=ports(3)
        phase='prepare';result,review,_=run_review([str(binary),'setup','--new','--hostname','account-policy.example.test','--listen',HOST,'--irc-port',str(irc),'--tls-port',str(tls),'--media-port',str(media),'--bundle','bundle','--json'],root,{'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'},preexec_fn=limits)
        require(result.returncode==0 and review)
        config=root/'bundle'/'onyx-server.toml';text=config.read_text().replace('[listen]\n',f'[listen]\nproxy_protocol = true\ntrusted_proxies = ["{HOST}"]\n',1).replace('[cloak]\n','[cloak]\naccount_cloak = true\n',1)
        text+='\n[sasl]\nenabled = true\naccount_db = "accounts.wal"\n[accounts]\npbkdf2_rounds = 10000\n';config.write_text(text);config.chmod(0o600)
        phase='config';require(command(binary,['--check-config',str(config)],config.parent).returncode==0)
        with (root/'daemon.log').open('xb') as log:proc=subprocess.Popen([str(binary),str(config)],cwd=config.parent,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,preexec_fn=limits)
        clients=[]
        try:
            phase='start';ready(proc,tls)
            names=[('Owner',None),('First','_'),('Second','.'),('LongOne','abcdefghijklmnopqrstuvwxyzabcd_1'),('LongTwo','abcdefghijklmnopqrstuvwxyzabcd_2'),('Plain','account'),('Craft',account_digest('_')),('Same',None)]
            entries={}
            for i,(nick,account) in enumerate(names):
                phase='register-clients';address=f'198.51.100.{150+i}';client=Irc(tls,nick,address,True);clients.append(client);entries[nick]=(client,address)
                if account is not None:
                    phase='register-account';register(client,account);phase='account-host';require(whois(client,address)==account_host(account))
            owner=entries['Owner'][0];same=entries['Same'][0]
            phase='casefold';identify(same,'ABCDEFGHIJKLMNOPQRSTUVWXYZABCD_1');require(whois(same,entries['Same'][1])==account_host('abcdefghijklmnopqrstuvwxyzabcd_1'))
            owner.send('IRCX');owner.until(' 800 Owner 1 0 ')
            cases=[('punct','First','Second',False),('long','LongOne','LongTwo',False),('placeholder','First','Plain',False),('lookalike','First','Craft',False),('casefold','LongOne','Same',True)]
            for index,(label,granted,other,also_granted) in enumerate(cases):
                phase='policy-'+label;channel='#policy'+str(index);left=entries[granted][0];right=entries[other][0]
                grant_host=whois(left,entries[granted][1]);other_host=whois(right,entries[other][1]);require((grant_host==other_host)==also_granted)
                owner.send('JOIN '+channel);owner.until(' 366 Owner '+channel+' ')
                owner.send('ACCESS '+channel+' ADD VOICE *!fixture@'+grant_host);owner.until(' 801 Owner '+channel+' VOICE ')
                owner.send('MODE '+channel+' +m');owner.until(' MODE '+channel+' +m')
                join(left,channel,True);join(right,channel,also_granted)
                speak(owner,left,channel,'grant_'+label,True);speak(owner,right,channel,'other_'+label,also_granted)
            require(proc.poll() is None)
            for client in clients:require(PASSWORD.encode() not in client.data)
            print(f'PASS account_hosts=7 policy_pairs=5 allowed_speech=6 denied_speech=4 artifact_sha256={digest}')
        finally:
            for client in clients:client.close()
            stop(proc)
if __name__=='__main__':
    try:main()
    except Unavailable:print(f'UNAVAILABLE phase={phase}',file=sys.stderr);sys.exit(2)
    except Exception as exc:print(f'FAIL phase={phase} error={type(exc).__name__}',file=sys.stderr);sys.exit(1)
