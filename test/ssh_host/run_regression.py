#!/usr/bin/env python3
"""Portable offline SSH/crypto/transport checks; sockets bind only to loopback.

Requires GCC, Clang with ASan/UBSan, Python cryptography, OpenSSH and make.
Optional --fuzz-runs N enables a separate libFuzzer campaign (default: no rerun).
Generated binaries/logs stay under output/, never in source or device flash.
"""
import argparse,hashlib,random,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--fuzz-runs',type=int,default=0);args=p.parse_args()
O=R/'output/ssh-regression';O.mkdir(parents=True,exist_ok=True)
def run(name,cmd,**kw):
 result=subprocess.run(cmd,cwd=R,capture_output=True,**kw)
 (O/(name+'.log')).write_bytes(result.stdout+result.stderr)
 if result.returncode:sys.stderr.write((result.stdout+result.stderr).decode(errors='replace'));raise SystemExit(result.returncode)
 print(name+': PASS',flush=True);return result.stdout
common=['clang','-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unknown-pragmas','-include','test/ssh_host/compat.h']
crypto=['test/ssh_host/fe_host.c']+['crypto/'+x+'.c' for x in ['x25519','ed25519','sha256','sha512','poly1305']]
for name in ['test_parser','test_output_hardened']:
 run(name+'-build',common+['test/ssh_host/'+name+'.c',*crypto,'-o',str(O/name)])
 run(name,[str(O/name)])
run('transport-build',['clang','-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unknown-pragmas','-Wno-pointer-sign','-DRTLP_HOST_TEST','-DSSH','-include','test/sdcc_shim.h','-Itest/stub','-Itest','-I.','-Ihttpd','-Iuip','test/ssh_host/test_transport_ownership.c','httpd/httpd.c','uip/uip.c','sessions.c','ssh/ssh_port.c',*crypto,'-o',str(O/'transport')])
run('transport',[str(O/'transport')])
run('crypto',['bash','test/ssh_host/run_crypto.sh',str(O/'crypto')])
run('rfc8032',[sys.executable,'test/ssh_host/test_rfc8032.py'])
run('sha-stream-build',common+['test/ssh_host/test_sha256_stream.c','crypto/sha256.c','-o',str(O/'sha-stream')])
rng=random.Random(0x5b256);cases=[b'',b'abc',b'a'*1000000]+[rng.randbytes(n) for n in [1,55,56,63,64,65,127,128,129,4096,10000]];count=0
for msg in cases:
 for chunk in [1,7,63,64,65,4096]:
  result=subprocess.run([str(O/'sha-stream'),str(chunk)],input=msg,capture_output=True,check=True)
  assert result.stdout.decode().strip()==hashlib.sha256(msg).hexdigest() and not result.stderr
  count+=1
(O/'sha-stream.log').write_text('PASS '+str(count)+' differential streaming cases including million-a\n');print('SHA streaming: PASS',count,flush=True)
run('openssh',[sys.executable,'test/ssh_host/integration_crypto.py',str(O/'openssh')])
run('subsystems',['make','-C','test','CC=clang'])
if args.fuzz_runs:
 run('fuzz-build',common+['-DFUZZ','-fsanitize=fuzzer','test/ssh_host/test_parser.c',*crypto,'-o',str(O/'fuzzer')])
 corpus=O/'corpus';corpus.mkdir(exist_ok=True)
 for i,data in enumerate([bytes([0,1])+b'SSH-2.0-fixture\r\n',bytes([1,1,0,0,0,12,4,20]),bytes([2,1,2,0,0,0,0]),bytes([3,1,98,0,0,0,0])]):(corpus/str(i)).write_bytes(data)
 run('fuzz',[str(O/'fuzzer'),'-runs='+str(args.fuzz_runs),'-seed=1512046','-max_len=4096',str(corpus)])
print('All selected offline checks passed. No target firmware build or device access performed.')
