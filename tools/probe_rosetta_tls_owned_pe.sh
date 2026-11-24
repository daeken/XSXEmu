#!/bin/sh
# Build and run only the embedded PE fixture in a disposable Rosetta child.
set -eu
if [ "$#" -ne 0 ]; then
    echo 'usage: tools/probe_rosetta_tls_owned_pe.sh (no arguments)' >&2
    exit 2
fi
cd "$(dirname "$0")/tls-owned-pe"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-tls-owned-pe.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target x86_64-apple-darwin -D warnings -O -C panic=abort \
    fixture.rs -o "$tmp/fixture"
ulimit -c 0
python3 - "$tmp/fixture" <<'PY'
import subprocess
import sys

try:
    child = subprocess.run(['/usr/bin/arch', '-x86_64', sys.argv[1]],
                           timeout=10, stdout=subprocess.PIPE, text=True)
except subprocess.TimeoutExpired:
    sys.exit('owned PE: timed out (child killed)')
print(child.stdout, end='', flush=True)
print(f'owned PE: subprocess status {child.returncode}', flush=True)
passed = child.returncode == 0 and (
    'owned PE PASS: bounded import and nested callback; GS and mask restored' in child.stdout.splitlines()
)
sys.exit(0 if passed else 1)
PY
