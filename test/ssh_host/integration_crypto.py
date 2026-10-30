#!/usr/bin/env python3
"""Four sequential loopback SSH exchanges using the installed OpenSSH client."""
import os, socket, subprocess, sys, tempfile, time
from pathlib import Path
root=Path(os.environ.get('CRYPTO_SOURCE_ROOT', Path(__file__).resolve().parents[2])).resolve()
out=root/(sys.argv[1] if len(sys.argv)>1 else 'output/crypto-integration'); out.mkdir(parents=True,exist_ok=True)
cc=['clang','-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unknown-pragmas','-include','test/ssh_host/compat.h']
sources=['test/ssh_host/ssh_host.c','test/ssh_host/fe_host.c']+['crypto/'+x+'.c' for x in ['x25519','ed25519','sha256','sha512','poly1305']]+['ssh/ssh.c']
subprocess.run(cc+sources+['-o',str(out/'server')],cwd=root,check=True)
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
with open(out/'server.log','w') as log:
    server=subprocess.Popen([str(out/'server'),str(port),'536','37'],stdout=log,stderr=log,cwd=root)
    try:
        for _ in range(100):
            if 'listening' in (out/'server.log').read_text(): break
            if server.poll() is not None: raise RuntimeError('server startup failed')
            time.sleep(.02)
        with tempfile.TemporaryDirectory(dir=out) as td:
            for i in range(4):
                args=['ssh','-F','/dev/null','-vv','-p',str(port),'-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(Path(td)/'known_hosts'),'-o','ConnectTimeout=15','-o','BatchMode=yes','-o','PreferredAuthentications=none','-o','KexAlgorithms=curve25519-sha256','-o','HostKeyAlgorithms=ssh-ed25519','-o','Ciphers=chacha20-poly1305@openssh.com','test@127.0.0.1','true']
                r=subprocess.run(args,capture_output=True,text=True,timeout=30)
                (out/f'client-{i}.log').write_text(r.stderr)
                assert 'SSH2_MSG_NEWKEYS received' in r.stderr,r.stderr
                assert 'Permission denied' in r.stderr,r.stderr
                assert server.poll() is None,(out/'server.log').read_text()
    finally:
        server.terminate(); server.wait(timeout=5)
text=(out/'server.log').read_text()
assert 'runtime error' not in text and 'ERROR: AddressSanitizer' not in text,text
print('PASS: 4 sequential loopback OpenSSH exchanges, mss=536, receive chunks=37; signature and encrypted auth failure verified; ASan/UBSan clean. No device accessed.')
