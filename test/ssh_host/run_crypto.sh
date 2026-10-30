#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:-output/crypto-host}
mkdir -p "$out"
sources=(test/ssh_host/crypto_runner.c test/ssh_host/fe_host.c crypto/x25519.c crypto/ed25519.c crypto/sha512.c crypto/sha256.c)
flags=(-std=c11 -Wno-unknown-pragmas -include test/ssh_host/compat.h)
gcc "${flags[@]}" -O2 "${sources[@]}" -o "$out/runner"
python3 test/ssh_host/crypto_validate.py "$out/runner"
clang "${flags[@]}" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer "${sources[@]}" -o "$out/runner-sanitize"
python3 test/ssh_host/crypto_validate.py "$out/runner-sanitize"
