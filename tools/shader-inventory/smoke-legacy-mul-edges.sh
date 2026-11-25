#!/bin/sh
# Owned arithmetic fixture only; use command-scoped DEVELOPER_DIR.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
trap 'exit 1' HUP INT TERM
export MTL_DEBUG_LAYER=1
unset MTL_SHADER_VALIDATION
cargo build --locked --manifest-path "$root/Cargo.toml" --target-dir "$d/target" \
    --features metal-probe --bin shader-legacy-mul-edges
p=$d/target/debug/shader-legacy-mul-edges
"$p" --source
"$p" --emit-msl > "$d/edges.metal"
xcrun -sdk macosx metal -std=metal3.1 -fno-fast-math -c "$d/edges.metal" -o "$d/edges.air"
xcrun -sdk macosx metallib "$d/edges.air" -o "$d/edges.metallib"
"$p" --bake "$d/edges.metallib" "$d/edges.metalar"
"$p" --replay "$d/edges.metallib" "$d/edges.metalar"

"$p" --vertex-xyz --source
"$p" --vertex-xyz --emit-msl > "$d/xyz.metal"
xcrun -sdk macosx metal -std=metal3.1 -fno-fast-math -c "$d/xyz.metal" -o "$d/xyz.air"
xcrun -sdk macosx metallib "$d/xyz.air" -o "$d/xyz.metallib"
"$p" --vertex-xyz --bake "$d/xyz.metallib" "$d/xyz.metalar"
"$p" --vertex-xyz --replay "$d/xyz.metallib" "$d/xyz.metalar"
