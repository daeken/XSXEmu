#!/bin/sh
# Owned fixture only. Select Xcode with command-scoped DEVELOPER_DIR.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
trap 'exit 1' HUP INT TERM
export MTL_DEBUG_LAYER=1
unset MTL_SHADER_VALIDATION
cargo build --locked --manifest-path "$root/Cargo.toml" --target-dir "$d/target" \
    --features metal-probe --bin shader-metal-graphics-lift
p=$d/target/debug/shader-metal-graphics-lift
compile() {
    xcrun -sdk macosx metal -std=metal3.1 -fno-fast-math -c "$d/$1.metal" -o "$d/$1.air"
    xcrun -sdk macosx metallib "$d/$1.air" -o "$d/$1.metallib"
}
"$p" --emit-msl > "$d/owned.metal"
compile owned
"$p" --load-metallib "$d/owned.metallib"
"$p" --bake-archive "$d/owned.metallib" "$d/owned.metalar"
"$p" --replay-archive "$d/owned.metallib" "$d/owned.metalar"
"$p" --emit-mutated-msl > "$d/mutated.metal"
compile mutated
"$p" --load-mutated-metallib "$d/mutated.metallib"
if "$p" --replay-archive "$d/mutated.metallib" "$d/owned.metalar" > "$d/miss.log" 2>&1; then
    echo 'unexpected strict replay hit after changing the native pixel literal' >&2
    exit 1
fi
grep -F 'Unable to find function "translated_ps"' "$d/miss.log" | grep -F 'in binary archives'
