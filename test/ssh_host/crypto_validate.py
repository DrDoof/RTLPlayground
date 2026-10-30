#!/usr/bin/env python3
"""Deterministic differential tests; host backend does not validate 8051 ASM."""
import argparse, hashlib, json, random, re, subprocess, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

ROOT = Path(__file__).resolve().parents[2]
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

def constants(name):
    text = (ROOT / 'crypto/ed25519_consts.h').read_text()
    body = re.search(r'\b'+name+r'\[32\]\s*=\s*\{([^}]+)', text).group(1)
    return bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]+)', body))

# Independent affine Edwards reference using Python integers. Signing uses the
# baseline's expanded key; that API has no arbitrary seed or message length.
D = -121665 * pow(121666, -1, P) % P
Y = 4 * pow(5, -1, P) % P
X = pow((Y*Y-1)*pow(D*Y*Y+1,-1,P)%P, (P+3)//8, P)
if (X*X*(D*Y*Y+1)-(Y*Y-1)) % P: X = X*pow(2,(P-1)//4,P)%P
if X & 1: X = P-X
B = (X,Y)
def add(a,b):
    x,y=a; u,v=b; z=D*x*u*y*v%P
    return ((x*v+y*u)*pow(1+z,-1,P)%P, (y*v+x*u)*pow(1-z,-1,P)%P)
def mul(s):
    r=(0,1); b=B
    while s:
        if s&1: r=add(r,b)
        b=add(b,b); s>>=1
    return r
def encode(q):
    x,y=q
    return (y | ((x&1)<<255)).to_bytes(32,'little')
def sign(m):
    a=int.from_bytes(constants('ed_key_a'),'little'); pub=constants('ed_key_pub')
    r=int.from_bytes(hashlib.sha512(constants('ed_key_prefix')+m).digest(),'little')%L
    rr=encode(mul(r)); h=int.from_bytes(hashlib.sha512(rr+pub+m).digest(),'little')%L
    return rr+((r+h*a)%L).to_bytes(32,'little')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('runner'); ap.add_argument('--random',type=int,default=64)
    args=ap.parse_args(); rng=random.Random(77488032); cases=[]
    def case(op,m,expected,extra=''): cases.append((op+' '+(m.hex() or '-')+extra,expected.hex()))
    # RFC 7748 section 5.2 direct vector and section 6.1 Alice/Bob exchange.
    k=bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
    u=bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
    case('x',k,bytes.fromhex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'),' '+u.hex())
    k=bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    case('x',k,bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'),' '+(b'\x09'+bytes(31)).hex())
    bob=bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
    case('x',k,bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'),' '+bob.hex())
    # RFC 7748 iterative chain, with every intermediate checked independently.
    k=u=b'\x09'+bytes(31)
    for _ in range(1000):
        e=x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
        case('x',k,e,' '+u.hex()); k,u=e,k
    assert k.hex()=='684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51'
    for i in range(args.random):
        k=rng.randbytes(32); u=rng.randbytes(32)
        expected=x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
        case('x',k,expected,' '+u.hex())
    for v in [0,1,2,P-1,P,P+1,2**255-1,2**256-1]:
        u=v.to_bytes(32,'little'); k=bytes([255])*32
        try: e=x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
        except ValueError: e=bytes(32) # raw X25519 emits zero; SSH rejection is separate.
        case('x',k,e,' '+u.hex())
    for n in [0,1,3,31,32,55,56,63,64,65,111,112,127,128,129,255,300,4096]:
        m=rng.randbytes(n)
        case('h',m,hashlib.sha512(m).digest()); case('g',m,hashlib.sha256(m).digest())
    pub=ed25519.Ed25519PublicKey.from_public_bytes(constants('ed_key_pub'))
    for m in [bytes(32),bytes([255])*32,bytes(range(32))]+[rng.randbytes(32) for _ in range(args.random)]:
        e=sign(m); pub.verify(e,m); case('s',m,e)
    # Repeating the entire mixed workload detects stale state and resume errors.
    cases=cases*2
    start=time.process_time(); wall=time.perf_counter()
    result=subprocess.run([args.runner],input='\n'.join(c[0] for c in cases)+'\n',text=True,capture_output=True,check=True)
    wall=time.perf_counter()-wall
    outputs=result.stdout.splitlines()
    assert len(outputs)==len(cases),(len(outputs),len(cases),result.stderr)
    for i,(got,(_,expected)) in enumerate(zip(outputs,cases)):
        assert got==expected,(i,cases[i][0],got,expected)
    print(json.dumps({'cases':len(cases),'random_seed':77488032,'runner_wall_seconds':wall,'result':'PASS','backend':'existing portable C field replacement; not target assembly'},indent=2))

if __name__=='__main__': main()
