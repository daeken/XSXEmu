#!/bin/sh
# Owned fixture only. Use command-scoped DEVELOPER_DIR to select Xcode.
set -eu
if [ "$(uname -s)" != Darwin ]; then
    echo 'Metal smoke requires macOS' >&2
    exit 1
fi
if ! xcrun -sdk macosx metal --version || ! xcrun -sdk macosx --find metallib; then
    echo 'MetalToolchain unavailable; check xcodebuild -showComponent MetalToolchain -json' >&2
    exit 1
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
trap 'exit 1' HUP INT TERM
cargo build --locked --manifest-path "$root/Cargo.toml" --target-dir "$d/target" \
    --features metal-probe --bin shader-metal-probe
p=$d/target/debug/shader-metal-probe
compile() {
    xcrun -sdk macosx metal -c "$d/$1.metal" -o "$d/$1.air"
    xcrun -sdk macosx metallib "$d/$1.air" -o "$d/$1.metallib"
}
"$p" --emit-exec-store-msl > "$d/store.metal"
compile store
MTL_DEBUG_LAYER=1 MTL_SHADER_VALIDATION=1 "$p" --load-exec-store-metallib "$d/store.metallib"
export MTL_DEBUG_LAYER=1
unset MTL_SHADER_VALIDATION
"$p" --bake-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"
"$p" --replay-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"

# Same exported name, different observable behavior. Prove the negative is an
# archive miss, not a lookup failure or an invalid library.
sed 's/= uint(empty);/= uint(!empty);/' "$d/store.metal" > "$d/modified.metal"
if cmp -s "$d/store.metal" "$d/modified.metal"; then
    echo 'owned mutation did not apply' >&2
    exit 1
fi
compile modified
if "$p" --replay-exec-store-metallib-archive "$d/modified.metallib" "$d/store.metalar" > "$d/miss.log" 2>&1; then
    echo 'changed kernel unexpectedly hit original archive' >&2
    exit 1
fi
if ! grep -Fq 'in binary archives' "$d/miss.log"; then
    cat "$d/miss.log" >&2
    echo 'changed kernel failed for a reason other than the observed strict archive miss' >&2
    exit 1
fi
printf '%s\n' 'strict archive refused the independently compiled same-name changed kernel'
