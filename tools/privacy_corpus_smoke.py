#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private, bounded privacy transcript corpus; no installed services are used."""
import argparse, base64, hashlib, json, os, pathlib, re, resource, select, signal, socket, ssl, subprocess, sys, tempfile, time, tomllib, urllib.request
sys.path.insert(0, str(pathlib.Path.cwd() / 'tools'))
from setup_review_client import run_review

HOST='127.0.0.1'
ADDRESS='198.51.100.137'
PASSWORD='PrivacyFixture-Password-72-Only'
MESH_PASSWORD='PrivacyFixture-Mesh-Secret-72-Only'
phase='arguments'
class Failure(Exception): pass
class Unavailable(Exception): pass
def require(value):
    if not value: raise Failure()
def ports(count):
    held=[];chosen=[]
    try:
        for _ in range(count):
            for attempt in range(50):
                tcp=socket.socket();tcp.bind((HOST,0));port=tcp.getsockname()[1]
                udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                try:udp.bind((HOST,port))
                except OSError:tcp.close();udp.close();continue
                held.extend((tcp,udp));chosen.append(port);break
            else:raise Failure()
        require(len(set(chosen))==count)
        return chosen
    finally:
        for sock in held:sock.close()

def limits():
    os.umask(0o077)
    _,hard=resource.getrlimit(resource.RLIMIT_STACK)
    resource.setrlimit(resource.RLIMIT_STACK,(512*1024*1024 if hard==resource.RLIM_INFINITY else min(hard,512*1024*1024),hard))
    resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024*1024,4*1024*1024))
def stop(p):
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:raise Failure()
def command(binary,args,cwd):
    p=subprocess.Popen([str(binary),*args],cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
    streams={p.stdout:bytearray(),p.stderr:bytearray()};active=set(streams);end=time.monotonic()+30
    try:
        while active:
            remaining=end-time.monotonic()
            if remaining<=0:raise Failure()
            ready,_,_=select.select(list(active),[],[],remaining)
            if not ready:raise Failure()
            for stream in ready:
                part=os.read(stream.fileno(),8192)
                if not part:active.remove(stream);continue
                streams[stream].extend(part)
                require(sum(len(value) for value in streams.values())<=1024*1024)
        code=p.wait(timeout=max(.1,end-time.monotonic()))
        return subprocess.CompletedProcess(args,code,bytes(streams[p.stdout]),bytes(streams[p.stderr]))
    finally:stop(p)

def redact_self_address(transcript,nick,address):
    result=[]
    records=transcript.split(b'\r\n')
    for line in records[:-1]:
        fields=line.split(b' ',5)
        if (b'\r' not in line and b'\n' not in line and len(fields)==6 and
            fields[0].startswith(b':') and fields[2]==nick.encode() and fields[3]==nick.encode()):
            if fields[1]==b'338' and fields[4]==address.encode():
                fields[4]=b'X'*len(fields[4]);line=b' '.join(fields)
            elif fields[1]==b'320' and fields[4]==b':actual' and fields[5]==b'address '+address.encode():
                fields[5]=b'address '+b'X'*len(address);line=b' '.join(fields)
        result.append(line)
    result.append(records[-1])  # An incomplete final record is never exempt.
    return b'\r\n'.join(result)

def has_self_320(transcript,nick,address):
    for line in transcript.split(b'\r\n')[:-1]:
        fields=line.split(b' ',5)
        if (b'\r' not in line and b'\n' not in line and len(fields)==6 and
            fields[0].startswith(b':') and fields[1]==b'320' and fields[2]==nick.encode() and
            fields[3]==nick.encode() and fields[4]==b':actual' and fields[5]==b'address '+address.encode()):return True
    return False

def credentials_absent(transcript,secrets):
    return all(secret not in transcript for secret in secrets)

def parser_self_test():
    nick='Target';address='198.51.100.137'
    valid=b':srv 338 Target Target 198.51.100.137 :credential-canary\r\n'
    expected=b':srv 338 Target Target XXXXXXXXXXXXXX :credential-canary\r\n'
    valid320=b':srv 320 Target Target :actual address 198.51.100.137\r\n'
    expected320=b':srv 320 Target Target :actual address XXXXXXXXXXXXXX\r\n'
    require(redact_self_address(valid,nick,address)==expected)
    require(redact_self_address(valid320,nick,address)==expected320 and has_self_320(valid320,nick,address))
    require(not credentials_absent(valid,[b'credential-canary']) and credentials_absent(valid,[b'other-credential']))
    wrong=[b':srv 338 Other Target 198.51.100.137 :x\r\n',b':srv 338 Target Other 198.51.100.137 :x\r\n',
           b':srv 338 Target Target 198.51.100.138 :x\r\n',b'@tag=x :srv 338 Target Target 198.51.100.137 :x\r\n',
           b':srv 311 Target Target 198.51.100.137 :x\r\n',
           b':srv NOTICE Target :foo\n:srv 338 Target Target 198.51.100.137 :x\r\n',
           b':srv NOTICE Target :foo\r:srv 338 Target Target 198.51.100.137 :x\r\n',
           b':srv 338 Target Target 198.51.100.137 :unterminated']
    wrong320=[b':srv 320 Other Target :actual address 198.51.100.137\r\n',
              b':srv 320 Target Other :actual address 198.51.100.137\r\n',
              b':srv 320 Target Target :other address 198.51.100.137\r\n',
              b':srv 320 Target Target extra :actual address 198.51.100.137\r\n',
              b':srv 320 Target Target :actual address 198.51.100.138\r\n',
              b':srv 320 Target Target :actual address 198.51.100.137 credential-canary\r\n',
              b':srv NOTICE Target :x\n:srv 320 Target Target :actual address 198.51.100.137\r\n',
              b':srv NOTICE Target :x\r:srv 320 Target Target :actual address 198.51.100.137\r\n',
              b':srv 320 Target Target :actual address 198.51.100.137']
    for wire in wrong+wrong320:require(redact_self_address(wire,nick,address)==wire)
    for wire in wrong320:require(not has_self_320(wire,nick,address))
    require(not credentials_absent(wrong320[5],[b'credential-canary']))
    combined=wrong[-2]+valid+valid320+wrong[0]
    require(redact_self_address(combined,nick,address)==wrong[-2]+expected+expected320+wrong[0])
    print('PASS parser: exact self 338/320 tokens and malformed record controls')

def check_report(report,online):
    require(isinstance(report,dict) and set(report)=={'schema_version','mode','readiness','report_build_version','failed','checks','observations','service_environment','service_plan'})
    require(report['schema_version']==1 and report['mode']=='preflight' and report['readiness']=='unknown' and isinstance(report['failed'],bool) and isinstance(report['report_build_version'],str))
    require(isinstance(report['checks'],list) and report['checks'])
    for check in report['checks']:
        require(isinstance(check,dict) and set(check)=={'status','id','source','detail'})
        require(check['status'] in ('pass','warn','fail','skipped') and all(isinstance(check[k],str) and len(check[k])<=2048 for k in check))
    environment=report['service_environment'];require(isinstance(environment,dict) and set(environment)=={'openrc_marker','systemd_marker','container_marker','manager_hint'})
    require(all(environment[k] in ('present','absent','unknown') for k in ('openrc_marker','systemd_marker','container_marker')) and environment['manager_hint'] in ('openrc','systemd','unknown'))
    plan=report['service_plan'];plan_fields={'selected','selection_basis','template','container_template','host_paths','runtime_identity_access','manager_status','daemon_readiness','network_reachability','resource_ceilings','validation'}
    require(isinstance(plan,dict) and set(plan)==plan_fields and plan['selected'] in ('openrc','systemd','foreground'))
    for k in plan_fields-{'selected','template','container_template'}:require(isinstance(plan[k],str) and len(plan[k])<=2048)
    for name in ('template','container_template'):
        item=plan[name];fields={'source','executable','config','identity','working_directory','preflight_argv','preflight_policy','start_argv','restart','logging'}
        require(isinstance(item,dict) and set(item)==fields)
        for k in fields-{'preflight_argv','start_argv'}:require(isinstance(item[k],str) and len(item[k])<=2048)
        for k in ('preflight_argv','start_argv'):require(isinstance(item[k],list) and all(isinstance(x,str) and len(x)<=2048 for x in item[k]))
    obs=report['observations']
    if not online:require(obs is None);return
    fields={'tcp_active','secured_links','established_links','peers_up','peers_total','quorum','components','freshness','service_readiness','partitioned','connection_events'}
    require(isinstance(obs,dict) and set(obs)==fields)
    for key in fields-{'freshness','service_readiness','connection_events'}:require(obs[key] is None or (type(obs[key]) is int and 0<=obs[key]<2**64))
    require(isinstance(obs['freshness'],str) and isinstance(obs['service_readiness'],str) and obs['established_links'] is not None and obs['established_links']>=1)
    events={'accepted','adopted','registered','closed','refused','recv_eof','recv_error','send_error','recv_buffer_missing','recv_buffer_bounds','recv_buffer_replenish','ktls_rx_close','tls_established','tls_kernel_handshake_conflict','tls_output_error','tls_error','command_quit','parser_error','recvq_limit','nick_auth_required','nick_denial_output','websocket_peer_close','websocket_close'}
    require(isinstance(obs['connection_events'],list) and len(obs['connection_events'])==len(events))
    for item in obs['connection_events']:
        require(isinstance(item,dict) and set(item)=={'event','count'} and item['event'] in events and (item['count'] is None or (type(item['count']) is int and 0<=item['count']<2**64)))
    require({x['event'] for x in obs['connection_events']}==events)

class Irc:
    def __init__(self,port,nick,address,tls=False):
        raw=socket.create_connection((HOST,port),timeout=10)
        raw.sendall(f'PROXY TCP4 {address} {HOST} 40000 {port}\r\n'.encode())
        if tls:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            raw=ctx.wrap_socket(raw,server_hostname='privacy.example.test')
        self.sock=raw;self.data=b'';self.pending=b'';self.nick=nick
        self.send('CAP REQ :draft/search batch standard-replies');self.send('NICK '+nick);self.send('USER fixture 0 * :Privacy fixture');self.send('CAP END')
        self.until(' 001 '+nick+' ')
    def send(self,text):self.sock.sendall((text+'\r\n').encode())
    def until(self,needle,timeout=20):
        end=time.monotonic()+timeout;start=len(self.data)
        while True:
            index=self.pending.find(b'\r\n')
            if index>=0:
                line=self.pending[:index+2];self.pending=self.pending[index+2:];self.data+=line
                require(len(self.data)<1024*1024)
                if needle.encode() in line:return self.data[start:]
                continue
            remaining=end-time.monotonic()
            if remaining<=0:raise Failure()
            self.sock.settimeout(remaining);part=self.sock.recv(8192);require(bool(part));self.pending+=part
            require(len(self.pending)<65536)
    def barrier(self,token):
        self.send('PING :'+token);return self.until(':'+token)
    def close(self):self.sock.close()
def wait_metrics(port,processes):
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        if any(p.poll() is not None for p in processes):raise Unavailable()
        try:
            with urllib.request.urlopen(f'http://{HOST}:{port}/metrics',timeout=1) as response:body=response.read(2*1024*1024).decode()
            if re.search(r'^onyx_s2s_links_active [1-9]',body,re.M):return
        except (OSError,TimeoutError):pass
        time.sleep(.1)
    raise Failure()
def main():
    global phase
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True,type=pathlib.Path);ap.add_argument('--expected-sha256',required=True);ap.add_argument('--scratch-dir',required=True,type=pathlib.Path);args=ap.parse_args()
    binary=args.binary.resolve(strict=True);digest=hashlib.sha256(binary.read_bytes()).hexdigest();require(re.fullmatch('[0-9a-f]{64}',args.expected_sha256) and digest==args.expected_sha256)
    args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as tmp:
        root=pathlib.Path(tmp).resolve();p=ports(11);irc1,tls1,s2s1,metrics1,irc2,tls2,s2s2,metrics2,native,media1,media2=p
        reviews=[];configs=[];processes=[];clients=[]
        try:
            for i,(irc,tls) in enumerate(((irc1,tls1),(irc2,tls2))):
                phase='provision';directory=root/f'node{i+1}';directory.mkdir(mode=0o700)
                env={'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'}
                result,review,_=run_review([str(binary),'setup','--new','--hostname',f'privacy{i+1}.example.test','--listen',HOST,'--irc-port',str(irc),'--tls-port',str(tls),'--media-port',str(media1 if i==0 else media2),'--node-id',str(i+1),'--bundle','bundle','--json'],directory,env,preexec_fn=limits)
                require(result.returncode==0 and review);reviews.append(review);configs.append(directory/'bundle'/'onyx-server.toml')
            # A single shared cloak key is an explicit mesh configuration invariant.
            shared_cloak=(configs[0].parent/'cloak.secret').read_bytes()
            (configs[1].parent/'cloak.secret').write_bytes(shared_cloak)
            for i,config in enumerate(configs):
                text=config.read_text();text=text.replace('[listen]\n',f'[listen]\ns2s = {s2s1 if i==0 else s2s2}\nproxy_protocol = true\ntrusted_proxies = ["{HOST}"]\n'+(f'native_media = {native}\nmedia_host = "{HOST}"\n' if i==0 else ''),1)
                if i==0:text=text.replace('[media]\nenabled = false','[media]\nenabled = true\nnative_media_require_mac = true',1)
                text+=f'\n[mesh]\nrealm = "privacy-corpus"\nmesh_pass = "{MESH_PASSWORD}"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = ["{reviews[1-i]["node_public_key"]}"]\n'
                if i==0:text+=f'connect = ["{HOST}:{s2s2}"]\n'
                text+=f'\n[stats]\ninterval = "1s"\n[metrics]\nbind = "{HOST}"\nlisten = {metrics1 if i==0 else metrics2}\n'
                if i==0:text+='\n[sasl]\nenabled = true\naccount_db = "accounts.wal"\n[accounts]\npbkdf2_rounds = 10000\n[[oper_groups]]\nname = "netadmin"\nprivileges = ["server_admin", "event_subscribe"]\n[[opers]]\naccount = "privacyadmin"\nclass = "netadmin"\n'
                config.write_text(text);config.chmod(0o600)
                phase='config';require(command(binary,['--check-config',str(config)],config.parent).returncode==0)
            phase='doctor';doc=command(binary,['doctor',str(configs[0]),'--json'],configs[0].parent);report=json.loads(doc.stdout);check_report(report,False)
            secrets=[PASSWORD.encode(),MESH_PASSWORD.encode(),(configs[0].parent/'onyx-server-node.key').read_bytes().strip(),(configs[0].parent/'cloak.secret').read_bytes().strip(),(configs[0].parent/'tls-key.der').read_bytes()]
            require(tomllib.loads(configs[0].read_text())['mesh']['mesh_pass']==MESH_PASSWORD)
            require(all(secret not in doc.stdout+doc.stderr for secret in secrets))
            require(base64.b64encode(secrets[-1]) not in doc.stdout+doc.stderr and secrets[-1].hex().encode() not in doc.stdout+doc.stderr)
            phase='export';export=root/'export.toml'
            result=command(binary,['setup','--new','--hostname','privacy-export.example.test','--listen',HOST,'--irc-port',str(irc1),'--export',str(export),'--json'],root)
            require(result.returncode==0 and export.is_file());exported=export.read_bytes()
            generated=tomllib.loads(exported.decode());require(set(generated)=={'node','network','listen','limits','media','tls'} and set(generated['node'])=={'id'} and set(generated['network'])=={'name','server_name','discoverable'} and set(generated['listen'])=={'host','irc','media'} and set(generated['limits'])=={'max_clients'} and set(generated['media'])=={'enabled'} and set(generated['tls'])=={'enabled','port','dns_name'} and generated['network']['server_name']=='privacy-export.example.test')
            require(all(secret not in exported+result.stdout+result.stderr for secret in secrets))
            for i,config in reversed(list(enumerate(configs))):
                log=(root/f'node{i}.log').open('xb');proc=subprocess.Popen([str(binary),str(config)],cwd=config.parent,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,preexec_fn=limits);log.close();processes.append(proc)
            phase='secured-mesh';wait_metrics(metrics1,processes);wait_metrics(metrics2,processes)
            phase='doctor-online';online=command(binary,['doctor',str(configs[0]),f'http://{HOST}:{metrics1}/metrics','--json'],configs[0].parent);check_report(json.loads(online.stdout),True);require(all(secret not in online.stdout+online.stderr for secret in secrets));require(base64.b64encode(secrets[-1]) not in online.stdout+online.stderr and secrets[-1].hex().encode() not in online.stdout+online.stderr)
            phase='clients'
            for spec in ((irc1,'Target',ADDRESS,False),(irc1,'Observer','198.51.100.138',False),(irc2,'Remote','198.51.100.139',False),(tls1,'Admin','198.51.100.140',True)):
                clients.append(Irc(*spec))
            target,observer,remote,admin=clients
            phase='oper';admin.send('REGISTER privacyadmin * '+PASSWORD);admin.until('REGISTER SUCCESS',40);admin.until(' 381 Admin ',40)
            phase='whois';target.send('WHOIS Target');own=target.until(' 318 Target Target ');require(b' 338 Target Target '+ADDRESS.encode() in own and has_self_320(own,'Target',ADDRESS))
            remote.send('WHOIS Remote');remote_own=remote.until(' 318 Remote Remote ');require(b' 338 Remote Remote 198.51.100.139' in remote_own and has_self_320(remote_own,'Remote','198.51.100.139'))
            for client in (observer,):
                client.send('WHOIS Target');reply=client.until(' 318 '+client.nick+' Target ');require(b' 311 ' in reply and ADDRESS.encode() not in reply and b' 338 ' not in reply)
            admin.send('WHOIS Target');reply=admin.until(' 318 Admin Target ');require(b' 338 Admin Target '+ADDRESS.encode() in reply)
            phase='channel';target.send('JOIN #privacy');target.until(' 366 Target #privacy ');remote.send('JOIN #privacy');remote.until(' 366 Remote #privacy ')
            target.send('PRIVMSG #privacy :privacy_corpus_apple');event=remote.until('PRIVMSG #privacy :privacy_corpus_apple');require(b':Target!' in event and ADDRESS.encode() not in event)
            remote.send('PRIVMSG #privacy :privacy_corpus_reverse');reverse=target.until('PRIVMSG #privacy :privacy_corpus_reverse');require(b':Remote!' in reverse and b'198.51.100.139' not in reverse)
            phase='remote-whois';remote.send('WHOIS Target');reply=remote.until(' 318 Remote Target ');require(b' 311 ' in reply and ADDRESS.encode() not in reply and b' 338 ' not in reply)
            phase='media-denied';observer.send('MEDIA OFFER #privacy cadencevox');denied_media=observer.until(' 442 Observer #privacy ');require(ADDRESS.encode() not in denied_media and b'MEDIA TRANSPORT' not in denied_media)
            phase='search-denied';observer.send('SEARCH #privacy :privacy_corpus_apple');denied=observer.until('FAIL SEARCH INVALID_TARGET');require(ADDRESS.encode() not in denied and b'privacy_corpus_apple' not in denied)
            phase='search';observer.send('JOIN #privacy');observer.until(' 366 Observer #privacy ');target.send('PRIVMSG #privacy :privacy_corpus_search');observer.until('PRIVMSG #privacy :privacy_corpus_search');observer.send('SEARCH #privacy :privacy_corpus_search');result=observer.until('BATCH -search');require(b'BATCH +search chathistory #privacy' in result and b'PRIVMSG #privacy :privacy_corpus_search' in result and ADDRESS.encode() not in result)
            phase='media';admin.send('JOIN #privacy');admin.until(' 366 Admin #privacy ')
            for client in (admin,observer,remote):
                client.send('IRCX');client.until(' 800 '+client.nick+' 1 0 ')
                for event in ('MEDIA','CHANNEL','MEMBER'):
                    client.send('EVENT ADD '+event+' #privacy');client.until(' 806 '+client.nick+' '+event+' #privacy ')
            phase='member-event';witness=Irc(irc1,'Witness','198.51.100.141',False);clients.append(witness)
            witness.send('JOIN #privacy');witness.until(' 366 Witness #privacy ')
            for client in (observer,remote):client.until('EVENT '+client.nick+' MEMBER JOIN #privacy Witness')
            phase='channel-event';target.send('MODE #privacy +m')
            for client in (observer,remote):client.until('EVENT '+client.nick+' CHANNEL MODE #privacy +m')
            phase='media';admin.send('MEDIA JOIN #privacy voice');admin.until('MEDIA JOIN #privacy Admin voice')
            admin.send('MEDIA OFFER #privacy cadencevox')
            offer=admin.until('MEDIA TRANSPORT #privacy')
            offer+=admin.until('MEDIA NATIVE #privacy')
            offer+=admin.until('MEDIA NATIVE-MACKEY #privacy')
            require(b'candidate='+HOST.encode()+b':' in offer)
            media_secrets=[]
            for name in (b'ufrag',b'pwd',b'key',b'srtp'):
                match=re.search(rb'(?:^| )'+name+rb'=([^ \r\n]+)',offer)
                require(match is not None and len(match.group(1))>=4);media_secrets.append(match.group(1))
            for bystander in (observer,remote):
                public=bystander.until('EVENT '+bystander.nick+' MEDIA CAPS #privacy Admin codecs=cadencevox')
                require(ADDRESS.encode() not in public)
                bystander.barrier('privacy-media-'+bystander.nick)
                require(all(secret not in bystander.data for secret in media_secrets))
            observer.send('MEDIA PROFILE #privacy');profile=observer.until('EVENT Observer MEDIA PROFILE #privacy');require(b'codecs=cadencevox' in profile and all(secret not in profile for secret in media_secrets))
            phase='whowas';target.send('NICK FormerTarget');observer.until(' NICK :FormerTarget');observer.send('WHOWAS Target');history=observer.until(' 369 Observer Target ');require(b' 314 Observer Target ' in history and ADDRESS.encode() not in history)
            phase='ordinary-transcripts'
            for client in (target,observer,remote,witness):
                client.barrier('privacy-end-'+client.nick)
                ordinary=client.data
                if client is target:ordinary=redact_self_address(ordinary,'Target',ADDRESS)
                if client is remote:ordinary=redact_self_address(ordinary,'Remote','198.51.100.139')
                for address in ('198.51.100.137','198.51.100.138','198.51.100.139','198.51.100.140','198.51.100.141'):
                    require(address.encode() not in ordinary)
                require(credentials_absent(client.data,[PASSWORD.encode(),MESH_PASSWORD.encode(),*media_secrets]))
            print(f'PASS partial: secured_mesh=1 self_whois=2 oper_whois=1 ordinary_whois=2 history=1 search=2 events=2 media_offer=1 media_profile=1 media_denied=1 channel_events=2 member_events=2 doctor=2 export=1 artifact_sha256={digest}')
        finally:
            for client in clients:client.close()
            for proc in processes:stop(proc)
if __name__=='__main__':
    try:
        if sys.argv[1:]==['--parser-self-test']:parser_self_test()
        else:main()
    except Unavailable:print(f'UNAVAILABLE phase={phase}',file=sys.stderr);sys.exit(2)
    except Exception as exc:print(f'FAIL phase={phase} error={type(exc).__name__}',file=sys.stderr);sys.exit(1)
