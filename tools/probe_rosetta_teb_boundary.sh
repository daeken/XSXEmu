#!/bin/sh
# Each mode runs in a fresh, bounded Rosetta child; no production hooks.
set -eu
cd "$(dirname "$0")/teb-boundary"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-teb-boundary.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target x86_64-apple-darwin -D warnings -O -C panic=abort \
    fixture.rs -o "$tmp/fixture"
python3 - "$tmp/fixture" "$@" <<'PY'
import subprocess
import sys

available = ('sync', 'signal-host', 'signal-guest')
modes = sys.argv[2:] or ('sync',)
if any(mode not in available for mode in modes):
    sys.exit('usage: tools/probe_rosetta_teb_boundary.sh [sync|signal-host|signal-guest] ...')
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
