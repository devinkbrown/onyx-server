#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private Linux startup fault campaign; never starts an installed service."""
import argparse, hashlib, os, pathlib, re, resource, select, signal, socket, struct, subprocess, sys, tempfile, time

# Resolve the helper from the immutable build context, not a system install.
sys.path.insert(0, str(pathlib.Path.cwd() / 'tools'))
from setup_review_client import run_review

TRACE='/usr/bin/strace'
MAX_LOG=4*1024*1024
HOST='127.0.0.1'
phase='arguments'
class Failure(Exception): pass
class Unavailable(Exception): pass

def demand(condition):
    if not condition: raise Failure()

def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_LOG,MAX_LOG))
    soft,hard=resource.getrlimit(resource.RLIMIT_STACK)
    wanted=64*1024*1024
    resource.setrlimit(resource.RLIMIT_STACK,(min(wanted,hard) if hard>0 else wanted,hard))

def ports():
    held=[]
    try:
        for _ in range(2):
            s=socket.socket();s.bind((HOST,0));held.append(s)
        result=[s.getsockname()[1] for s in held]
        demand(len(set(result))==2 and all(p not in (6667,6680,6697,8080) for p in result))
        return result
    finally:
        for s in held:s.close()

def can_bind(port):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind((HOST,port))

def trace_rows(path,strict=False):
    demand(path.exists() and path.stat().st_size<MAX_LOG)
    text=path.read_text(errors='replace')
    if strict:demand('<unfinished ...>' not in text and not re.search(r'<\.\.\. .* resumed>',text))
    rows=[]
    for line in text.splitlines():
        m=re.match(r'^\s*(?:(\d+)\s+)?(io_uring_register|io_uring_setup|io_uring_enter|close|accept|accept4|socket|bind|listen)\((.*)$',line)
        if m:rows.append((m.group(1) or 'main',m.group(2),m.group(3),line))
    return rows

def review_config(binary,root,irc,tls):
    result,review,_=run_review([str(binary),'setup','--new','--hostname','kernel-proof.example.test',
                               '--listen',HOST,'--irc-port',str(irc),'--tls-port',str(tls),
                               '--bundle','fixture','--json'],root,{'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'})
    demand(result.returncode==0 and review and review['certificate_subject']=='kernel-proof.example.test')
    config=root/'fixture'/'onyx-server.toml'
    text=config.read_text();demand(text.count('[limits]\n')==1 and '[io]\n' not in text)
    return config,text

def configure(root,base,name,shards=1,sqpoll=False):
    config=root/(name+'.toml')
    text=base.replace('[limits]\n',f'[limits]\nnum_shards = {shards}\n',1)
    if sqpoll:text+='\n[io]\nsqpoll = true\nsqpoll_idle_ms = 10\n'
    config.write_text(text);config.chmod(0o600)
    return config

def probe_table(kind):
    # Linux io_uring_probe: 16-byte header then 8-byte opcode records.
    # x86_64 little-endian only; strace poke_exit writes the actual tracee buffer.
    data=bytearray(16+28*8)
    data[0]=27;data[1]=28
    for i in range(28):
        data[16+i*8]=i
        struct.pack_into('<H',data,16+i*8+2,1)
    if kind=='malformed':data[1]=0
    elif kind=='incomplete':data[1]=27
    elif kind=='missing-send':struct.pack_into('<H',data,16+26*8+2,0)
    else:raise ValueError('invalid fixture')
    return data.hex()

def spawn(binary,config,root,label,injection=None):
    trace=root/(label+'.trace');out=root/(label+'.out');err=root/(label+'.err')
    argv=[TRACE,'-f','-qq','--kill-on-exit','-s','24','-o',str(trace),'-e',
          'trace=io_uring_setup,io_uring_register,io_uring_enter,close,accept,accept4,socket,bind,listen']
    if injection:argv+=['-e','inject='+injection]
    argv += [str(binary),str(config)]
    with out.open('xb') as stdout,err.open('xb') as stderr:
        os.chmod(out,0o600);os.chmod(err,0o600)
        child=subprocess.Popen(argv,cwd=root,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                               env={'PATH':os.defpath,'NO_COLOR':'','TERM':'dumb'},
                               start_new_session=True,preexec_fn=limits)
    return child,trace,out,err

def stop(child):
    try: os.killpg(child.pid,signal.SIGTERM)
    except ProcessLookupError: pass
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait(timeout=5)
    # Kill any traced descendant left in the private process group.
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass

def register_and_ping(child,port):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if child.poll() is not None: raise Unavailable()
        try:
            s=socket.create_connection((HOST,port),timeout=.3);break
        except OSError:time.sleep(.05)
    else:raise Failure()
    with s:
        s.settimeout(5);s.sendall(b'NICK kernelproof\r\nUSER kernelproof 0 * :proof\r\n')
        data=b''
        while b' 001 kernelproof ' not in data:
            chunk=s.recv(8192);demand(bool(chunk));data+=chunk;demand(len(data)<65536)
        s.sendall(b'PING :kernel-proof\r\n')
        while b' PONG ' not in data or b':kernel-proof' not in data:
            chunk=s.recv(8192);demand(bool(chunk));data+=chunk;demand(len(data)<65536)

def baseline(binary,config,root,label,port):
    child,trace,out,err=spawn(binary,config,root,label)
    try:register_and_ping(child,port)
    finally:stop(child)
    demand(out.stat().st_size<MAX_LOG and err.stat().st_size<MAX_LOG)
    return trace_rows(trace)

def probe_positions(rows):
    # Per-process injection ordinal: match every register, not only PROBE.
    by_pid={}
    for pid,op,args,line in rows:
        if op!='io_uring_register':continue
        prior=by_pid.setdefault(pid,[]);prior.append((args,line))
    candidates=[]
    for pid,entries in by_pid.items():
        matches=[i+1 for i,(args,_) in enumerate(entries) if 'IORING_REGISTER_PROBE' in args]
        if matches:candidates.append((pid,matches))
    demand(len(candidates)==1)
    return candidates[0][1]

def prove_cleanup_and_no_submission(rows, expected_ports, minimum_rings):
    # Generations begin at successful setup/socket and end only at successful
    # close, so fd reuse cannot make a later unrelated close prove cleanup.
    rings={};sockets={};listener_ports=set();probe_count=0
    for pid,op,args,line in rows:
        returned=re.search(r'=\s*(\d+)\s*$',line)
        first=re.match(r'(\d+)',args)
        if op=='io_uring_setup' and returned:
            key=(pid,returned.group(1));demand(key not in rings)
            rings[key]=False
        elif op=='socket' and returned:
            key=(pid,returned.group(1));demand(key not in sockets)
            sockets[key]=None
        elif first:
            key=(pid,first.group(1))
            if op=='io_uring_register' and 'IORING_REGISTER_PROBE' in args:
                demand(key in rings and not rings[key]);rings[key]=True;probe_count+=1
            elif op=='io_uring_enter' and key in rings and rings[key]:raise Failure()
            elif op in ('accept','accept4'):raise Failure()
            elif op=='bind' and key in sockets and re.search(r'=\s*0\s*$',line):
                match=re.search(r'sin6?_port=htons\((\d+)\)',args)
                if match and int(match.group(1)) in expected_ports:
                    port=int(match.group(1));sockets[key]=port;listener_ports.add(port)
            elif op=='close' and re.search(r'=\s*0\s*$',line):
                rings.pop(key,None);sockets.pop(key,None)
    demand(probe_count>=minimum_rings and not rings)
    demand(listener_ports==set(expected_ports) and not any(v is not None for v in sockets.values()))

def fault(binary,config,root,label,injection,expected,ordinal,ports_to_check):
    child,trace,out,err=spawn(binary,config,root,label,injection)
    try:
        child.wait(timeout=30)
        demand(child.returncode!=0)
        demand(out.stat().st_size<MAX_LOG and err.stat().st_size<MAX_LOG)
        diagnostic=err.read_bytes();demand(expected.encode() in diagnostic)
        rows=trace_rows(trace,strict=True)
        regs=[row for row in rows if row[1]=='io_uring_register']
        injected=[row for row in regs if 'INJECTED' in row[3]]
        demand(len(injected)==1 and 'IORING_REGISTER_PROBE' in injected[0][2])
        same_pid=[row for row in regs if row[0]==injected[0][0]]
        demand(same_pid.index(injected[0])+1==ordinal)
        prove_cleanup_and_no_submission(rows,ports_to_check,2 if label=='later-shard' else 1)
        for port in ports_to_check:can_bind(port)
    finally:
        stop(child)


def main():
    global phase
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=pathlib.Path,required=True);parser.add_argument('--scratch-dir',type=pathlib.Path,required=True);parser.add_argument('--expected-sha256',required=True)
    args=parser.parse_args();binary=args.binary.resolve(strict=True)
    if sys.platform!='linux' or os.uname().machine!='x86_64' or not os.access(TRACE,os.X_OK):raise Unavailable()
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    demand(re.fullmatch(r'[0-9a-f]{64}',args.expected_sha256) is not None and digest==args.expected_sha256)
    args.scratch_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as temporary:
        root=pathlib.Path(temporary).resolve();irc,tls=ports()
        phase='prepare';config,base=review_config(binary,root,irc,tls)
        one=configure(root,base,'single');two=configure(root,base,'multi',shards=2)
        for item in (one,two):
            check=subprocess.run([str(binary),'--check-config',str(item)],cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,preexec_fn=limits)
            demand(check.returncode==0)
        phase='control-single';single=baseline(binary,one,root,'control-single',irc)
        first=probe_positions(single);demand(first and first[0]==1)
        for port in (irc,tls):can_bind(port)
        phase='control-multi';multi=baseline(binary,two,root,'control-multi',irc)
        multi_probes=probe_positions(multi);demand(len(multi_probes)>=2 and multi_probes[0]==1)
        second=multi_probes[1]
        for port in (irc,tls):can_bind(port)
        cases=[('denied','error=EPERM','KernelOpcodeProbeDenied'),('resources','error=ENOMEM','KernelOpcodeProbeResources'),
               ('unavailable','error=EINVAL','KernelOpcodeProbeUnavailable')]
        for label,mode,expected in cases:
            phase=label;fault(binary,one,root,label,'io_uring_register:'+mode+':when=1',expected,1,(irc,tls))
        for label,expected in [('malformed','KernelOpcodeProbeMalformed'),('incomplete','KernelOpcodeProbeIncomplete'),('missing-send','KernelMissingSend')]:
            phase=label;fault(binary,one,root,label,'io_uring_register:retval=0:poke_exit=@arg3='+probe_table(label)+':when=1',expected,1,(irc,tls))
        phase='later-shard';fault(binary,two,root,'later-shard',f'io_uring_register:error=EPERM:when={second}','KernelOpcodeProbeDenied',second,(irc,tls))
        phase='sqpoll';sq=configure(root,base,'sqpoll',sqpoll=True)
        child,trace,out,err=spawn(binary,sq,root,'sqpoll','io_uring_setup:error=EPERM:when=1')
        try:
            child.wait(timeout=30);demand(child.returncode!=0)
            rows=trace_rows(trace,strict=True);setups=[row for row in rows if row[1]=='io_uring_setup']
            demand(len(setups)==1 and 'IORING_SETUP_SQPOLL' in setups[0][2] and 'INJECTED' in setups[0][3])
            demand(b'cannot start server: Unsupported' in err.read_bytes());prove_cleanup_and_no_submission(rows,(irc,tls),0)
            for port in (irc,tls):can_bind(port)
        finally:
            stop(child)
        phase='recovery';baseline(binary,one,root,'recovery',irc)
        for port in (irc,tls):can_bind(port)
    print(f'PASS: control=2 errno=3 malformed=2 missing=1 later_shard=1 sqpoll=1 recovery=1 artifact_sha256={digest}')

if __name__=='__main__':
    try:main()
    except Unavailable:
        print(f'UNAVAILABLE: phase={phase} (kernel/ptrace capability not established)',file=sys.stderr);sys.exit(2)
    except Exception as exc:
        print(f'FAIL: phase={phase} error={type(exc).__name__}',file=sys.stderr);sys.exit(1)
