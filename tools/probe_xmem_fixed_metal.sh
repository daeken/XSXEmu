#!/bin/sh
# Run each owned fixed-placement Metal case in a separate bounded child.
set -eu
cd "$(dirname "$0")/xmem-metal-buffer"
case $# in 0|1) ;; *) exit 2 ;; esac
arch=${1:-$(uname -m)}
case "$(uname -s):$arch" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    *) echo 'usage (on macOS): tools/probe_xmem_fixed_metal.sh [arm64|x86_64]' >&2; exit 2 ;;
esac
python3 - "$arch" "$target" <<'PY'
import json
import subprocess
import sys

arch, target = sys.argv[1:]
run = subprocess.run(['cargo', 'test', '--locked', '--no-run', '--target', target,
                      '--target-dir', 'target', '--message-format=json-render-diagnostics'],
                     stdout=subprocess.PIPE, text=True, check=True)
artifacts = (json.loads(line) for line in run.stdout.splitlines())
probes = [a['executable'] for a in artifacts if a['reason'] == 'compiler-artifact'
          and a['target']['name'] == 'xmem-metal-buffer' and a['profile']['test']
          and a['executable']]
if len(probes) != 1:
    sys.exit('expected exactly one fixed Metal probe executable')
for case in ('fixed_one_page', 'fixed_consecutive_control', 'fixed_nonconsecutive_composition',
             'fixed_full_descriptor_suffix'):
    try:
        status = subprocess.run(['/usr/bin/arch', '-' + arch, probes[0], '--exact',
                                 'fixed::' + case, '--nocapture'], timeout=30).returncode
    except subprocess.TimeoutExpired:
        sys.exit(f'{arch} {case}: timed out (child killed)')
    if status:
        sys.exit(f'{arch} {case}: fixed Metal probe failed (status {status})')
PY
