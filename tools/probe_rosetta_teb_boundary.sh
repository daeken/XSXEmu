#!/bin/sh
# Each mode runs in a fresh, bounded Rosetta child; no production hooks.
set -eu
cd "$(dirname "$0")/teb-boundary"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-teb-boundary.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target x86_64-apple-darwin -D warnings -O -C panic=abort \
    fixture.rs -o "$tmp/fixture"
# Do not leave core files from intentional child faults.
ulimit -c 0
python3 - "$tmp/fixture" "$@" <<'PY'
from pathlib import Path
import signal
import subprocess
import sys

faults = {
    'fault-ill': (1, signal.SIGILL),
    'fault-access': (2, signal.SIGBUS),
    'fault-trap': (3, signal.SIGTRAP),
    'fault-div': (4, signal.SIGFPE),
    'fault-unmapped': (5, signal.SIGSEGV),
}
available = ('sync', 'signal-host', 'signal-guest', 'masked', *faults)
modes = sys.argv[2:] or ('sync',)
if any(mode not in available for mode in modes):
    sys.exit(f'usage: tools/probe_rosetta_teb_boundary.sh [{"|".join(available)}] ...')
failed = False
marker = Path(sys.argv[1]).with_name('fault-marker')
for mode in modes:
    args = ['/usr/bin/arch', '-x86_64', sys.argv[1], mode]
    if mode in faults:
        marker.write_bytes(b'\0')
        args.append(str(marker))
    try:
        code = subprocess.run(args, timeout=10).returncode
    except subprocess.TimeoutExpired:
        print(f'{mode}: timed out (child killed)', file=sys.stderr, flush=True)
        failed = True
        continue
    if mode in faults:
        index, sig = faults[mode]
        reached = marker.read_bytes() == bytes([index])
        passed = reached and code == -sig
        print(f'{mode}: subprocess status {code} (expected {-sig}, {sig.name}); '
              f'guest fault site reached={reached}; pass={passed}', flush=True)
        failed |= not passed
    else:
        print(f'{mode}: subprocess status {code}', flush=True)
        failed |= code != 0
sys.exit(int(failed))
PY
