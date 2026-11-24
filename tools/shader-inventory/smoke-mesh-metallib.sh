#!/bin/sh
# Owned fixture only. Select Xcode with command-scoped DEVELOPER_DIR.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
trap 'exit 1' HUP INT TERM
unset MTL_SHADER_VALIDATION
export MTL_DEBUG_LAYER=1
cargo build --locked --manifest-path "$root/Cargo.toml" --target-dir "$d/target" \
    --features metal-probe --bin shader-metal-mesh-probe
p=$d/target/debug/shader-metal-mesh-probe
compile() {
    xcrun -sdk macosx metal -std=metal3.1 -c "$d/$1.metal" -o "$d/$1.air"
    xcrun -sdk macosx metallib "$d/$1.air" -o "$d/$1.metallib"
}
"$p" --emit-msl > "$d/owned.metal"
compile owned
"$p" --load-metallib "$d/owned.metallib"
"$p" --bake-archive "$d/owned.metallib" "$d/owned.metalar"
"$p" --replay-archive "$d/owned.metallib" "$d/owned.metalar"
sed 's/set_primitive(0, Primitive{1})/set_primitive(0, Primitive{0})/' \
    "$d/owned.metal" > "$d/modified.metal"
compile modified
"$p" --load-mutated-metallib "$d/modified.metallib"
if "$p" --replay-archive "$d/modified.metallib" "$d/owned.metalar" > "$d/miss.log" 2>&1; then
    echo 'unexpected strict mesh hit with mutated mesh stage' >&2
    exit 1
fi
grep -F 'Unable to find function "owned_mesh" (mesh pipeline) in binary archives' "$d/miss.log"
