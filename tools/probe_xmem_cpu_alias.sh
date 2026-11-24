#!/bin/sh
# Build only the standalone proof; never run the launcher or a guest.
set -eu
cd "$(dirname "$0")"
case $# in 0|1) ;; *) exit 2 ;; esac
arch=${1:-$(uname -m)}
case "$(uname -s):$arch" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    *) echo 'usage (on macOS): tools/probe_xmem_cpu_alias.sh [arm64|x86_64]' >&2; exit 2 ;;
esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-xmem.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rustc --edition 2024 --target "$target" -D warnings -O -C panic=abort \
    xmem-cpu-alias.rs -o "$tmp/probe"
python3 - "$tmp/probe" "$arch" <<'PY'
import subprocess
import sys

probe, arch = sys.argv[1:]
for order in ('a-first', 'b-first'):
    try:
        status = subprocess.run(['/usr/bin/arch', '-' + arch, probe, order], timeout=10).returncode
    except subprocess.TimeoutExpired:
        sys.exit(f'{arch} {order}: timed out (child killed)')
    if status:
        sys.exit(f'{arch} {order}: child failed (status {status})')
PY
