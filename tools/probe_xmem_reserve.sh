#!/bin/sh
# Build and run only the owned Darwin reservation probe.
set -eu
cd "$(dirname "$0")"
case $# in 0|1) ;; *) exit 2 ;; esac
arch=${1:-$(uname -m)}
case "$(uname -s):$arch" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    *) echo 'usage (on macOS): tools/probe_xmem_reserve.sh [arm64|x86_64]' >&2; exit 2 ;;
esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-xmem-reserve.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target "$target" -D warnings -O -C panic=abort \
    xmem-reserve.rs -o "$tmp/probe"
python3 - "$tmp/probe" "$arch" <<'PY'
import subprocess
import sys

probe, arch = sys.argv[1:]
try:
    status = subprocess.run(['/usr/bin/arch', '-' + arch, probe], timeout=10).returncode
except subprocess.TimeoutExpired:
    sys.exit(f'{arch}: reservation probe timed out (child killed)')
if status:
    sys.exit(f'{arch}: reservation probe failed (status {status})')
PY
