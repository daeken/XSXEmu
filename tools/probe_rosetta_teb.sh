#!/bin/sh
# Standalone owned observer; no Wine, PE files, special privileges, or security changes.
set -eu
cd "$(dirname "$0")/teb-probe"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-teb.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target x86_64-apple-darwin -D warnings -O -C panic=abort \
    probe.rs -o "$tmp/probe"
python3 - "$tmp/probe" "$@" <<'PY'
import subprocess
import sys

available = ('private', 'mach-baseline', 'mach-change')
modes = sys.argv[2:] or available
if any(mode not in available for mode in modes):
    sys.exit('usage: tools/probe_rosetta_teb.sh [private|mach-baseline|mach-change] ...')
failed = False
for mode in modes:
    try:
        code = subprocess.run(['/usr/bin/arch', '-x86_64', sys.argv[1], mode], timeout=10).returncode
    except subprocess.TimeoutExpired:
        print(f'{mode}: timed out (child killed)', file=sys.stderr, flush=True)
        failed = True
    else:
        print(f'{mode}: subprocess status {code}', flush=True)
        failed |= code != 0
sys.exit(int(failed))
PY
