#!/usr/bin/env python3
"""RFC 8032 fixtures on a temporary length/key adapter; firmware API stays m32.

The actual SSH API supports only its compiled expanded key and a 32-byte message.
RFC messages here have lengths 0, 1, 2. Only the two message-length constants and
key constants are substituted in a temporary copy; arithmetic is unchanged.
"""
import hashlib, os, re, subprocess, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
ROOT=Path(os.environ.get('CRYPTO_SOURCE_ROOT', Path(__file__).resolve().parents[2])).resolve()
vectors=[
('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60','',
 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb','72',
 '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7','af82',
 '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a')]
out=ROOT/'output/rfc8032'; out.mkdir(parents=True,exist_ok=True)
for seed,m,sig in vectors:
    seed=bytes.fromhex(seed); m=bytes.fromhex(m)
    priv=Ed25519PrivateKey.from_private_bytes(seed); assert priv.sign(m).hex()==sig
    expanded=bytearray(hashlib.sha512(seed).digest()); expanded[0]&=248; expanded[31]&=63; expanded[31]|=64
    values={'ed_key_a':expanded[:32],'ed_key_prefix':expanded[32:],'ed_key_pub':priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    with tempfile.TemporaryDirectory(dir=out) as td:
        td=Path(td)
        text=(ROOT/'crypto/ed25519_consts.h').read_text()
        for name,data in values.items():
            text=re.sub(r'(\b'+name+r'\[32\]\s*=\s*\{)[^}]+',lambda match:match[1]+','.join(hex(v) for v in data),text)
        (td/'ed25519_consts.h').write_text(text)
        text=(ROOT/'crypto/ed25519.c').read_text().replace('sha512_update(msg, 32)',f'sha512_update(msg, {len(m)})')
        assert text.count(f'sha512_update(msg, {len(m)})')==2
        (td/'ed25519.c').write_text(text)
        (td/'fixture.c').write_text('#include <stdio.h>\n#include "ed25519.h"\nstatic unsigned char m[32]={'+','.join(str(v) for v in m or b'\0')+'};\nint main(void){ ed_init(); ed_sign_start(m); unsigned n=0; while(!ed_sign_step()) if(++n>1024) return 2; for(int i=0;i<64;i++) printf("%02x",ed_sig[i]);return 0;}\n')
        args=['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unknown-pragmas','-include','test/ssh_host/compat.h','-Icrypto',str(td/'ed25519.c'),str(td/'fixture.c'),'crypto/x25519.c','crypto/sha512.c','test/ssh_host/fe_host.c','-o',str(td/'fixture')]
        subprocess.run(args,cwd=ROOT,check=True)
        r=subprocess.run([str(td/'fixture')],capture_output=True,text=True,check=True)
        assert r.stdout==sig,(m.hex(),r.stdout,sig)
print('PASS: RFC 8032 Ed25519 vectors 1, 2, 3 with temporary key/message-length adapter; arithmetic unmodified; ASan/UBSan clean. Production m32 API is separately differential-tested.')
