#!/bin/sh
# Build the standalone owned-data fixture, then bound the Metal probe subprocess.
set -eu
cd "$(dirname "$0")/xmem-metal-buffer"
case $# in 0|1) ;; *) exit 2 ;; esac
arch=${1:-$(uname -m)}
case "$(uname -s):$arch" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    *) echo 'usage (on macOS): tools/probe_xmem_metal_buffer.sh [arm64|x86_64]' >&2; exit 2 ;;
esac
cargo build --locked --target "$target" --target-dir target
python3 - "$arch" "target/$target/debug/xmem-metal-buffer" <<'PY'
import subprocess
import sys

arch, probe = sys.argv[1:]
try:
    status = subprocess.run(['/usr/bin/arch', '-' + arch, probe], timeout=30).returncode
except subprocess.TimeoutExpired:
    sys.exit(f'{arch}: timed out (child killed)')
if status:
    sys.exit(f'{arch}: Metal backing probe failed (status {status})')
PY
