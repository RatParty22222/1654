#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
BUILD_DIR="$ROOT/build"
DEMO="$BUILD_DIR/demo"
KAT="$BUILD_DIR/kat"

# Known-answer vectors
K1="d6e7f871713e19cca9191b2816a421843d86fc8393bcd2cc946015d58677787e89c24f260e0a85737e85e44729565160a9fc7c6c53775cd28cde69446a00cd5d5dfe859f97d82455f7ac8fb04e918112efc3cd96cdebb9c71c91aa84d97548d9293ea020dc2a44e4c2b55b515db74dac51586568e62896ba507ab95b367ff251"
K2="d6e7f871713e19cca9191b2816a421843d86fc8393bcd2cc946015d58677787e89c24f260e0a85737e85e44729565160a9fc7c6c53775cd28cde69446a00cd5d"
K3="1f0c07e60bbb7c512b65a4aaa248b007eb32963fa7392b3ba0e7c1df5d758414716852364d0222cd1f6e5e45f8b9fcc48552c9832950f4a46f9c86c6ca2001cc0f1a211d9448be0ca1f7d084688f937d741615bca35d51b221535288cc4b1dcd9637175a99b6ac26bb2b5cc6bc6abb7f07561bb6a89204b9032625c90b12ab33a6c0a3b8a37ae0a08815c07c0bee27e4c16725ebb6e54d222d1ee60b47261c87721fcdb1a1b27f6e4344ea5fa8b0f0cd60ff8532ad737c59a4f184a8a5189dbd6a9387040fea39fcaa8902472f22b61daa5f67b2f078563fbbec46945d0089fe61feab462fa5fe666c0514a0d75ad3b9dc085e91271448d6e6d145c309eaefd9"

echo "== Build =="
rm -rf "$BUILD_DIR"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD_DIR" -j >/dev/null
[[ -x "$DEMO" && -x "$KAT" ]]

echo "== KAT =="
"$KAT" >/dev/null

run_demo() { "$DEMO" "$@" | tr -d ' \t\r\n'; }

echo "== KAT (demo) =="
o1=$(run_demo --msg "hello" --ctx "CTX" --out-bits 1024)
[[ "$o1" == "$K1" ]] || { echo "KAT1 mismatch"; exit 3; }
o2=$(run_demo --msg "hello" --ctx "CTX" --out-bits 512)
[[ "$o2" == "$K2" ]] || { echo "KAT2 mismatch"; exit 4; }
o3=$(run_demo --msg "hello" --ctx "CTX" --salt "SALT-123" --out-bits 2048)
[[ "$o3" == "$K3" ]] || { echo "KAT3 mismatch"; exit 5; }

echo "== Determinism =="
a1=$(run_demo --msg "repeat-test" --ctx "CTX")
a2=$(run_demo --msg "repeat-test" --ctx "CTX")
[[ "$a1" == "$a2" ]] || { echo "Determinism (inline) failed"; exit 6; }
TMPF="$BUILD_DIR/tmp.bin"
if [[ -r /dev/urandom ]]; then head -c 64 /dev/urandom > "$TMPF"; else printf 'seed-%s' "$(date +%s%N)" | head -c 64 > "$TMPF"; fi
b1=$(run_demo --in "$TMPF" --ctx "RND" --out-bits 1024)
b2=$(run_demo --in "$TMPF" --ctx "RND" --out-bits 1024)
rm -f "$TMPF"
[[ "$b1" == "$b2" ]] || { echo "Determinism (file) failed"; exit 7; }

echo "== Context/Salt variability =="
x1=$(run_demo --msg "hello" --ctx "CTX1")
x2=$(run_demo --msg "hello" --ctx "CTX2")
[[ "$x1" != "$x2" ]] || { echo "Context variability failed"; exit 8; }
s1=$(run_demo --msg "hello" --ctx "CTX" --salt "A")
s2=$(run_demo --msg "hello" --ctx "CTX" --salt "B")
[[ "$s1" != "$s2" ]] || { echo "Salt variability failed"; exit 9; }

echo "== Linkage check =="
if command -v otool >/dev/null 2>&1; then
  ! otool -L "$DEMO" | grep -qiE 'libcrypto|libssl'
elif command -v ldd >/dev/null 2>&1; then
  ! ldd "$DEMO" | grep -qiE 'crypto|ssl'
fi

echo "== Perf (10 MiB) =="
RANDF="$BUILD_DIR/perf_rand.bin"
if [[ -r /dev/urandom ]]; then head -c 10485760 /dev/urandom > "$RANDF"; else dd if=/dev/zero of="$RANDF" bs=1 count=10485760 2>/dev/null; fi
( time "$DEMO" --in "$RANDF" --ctx "PERF" --out-bits 1024 >/dev/null ) 2>&1 | sed -n '1,5p'
rm -f "$RANDF"

echo "OK"

