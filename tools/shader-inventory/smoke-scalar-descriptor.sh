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
    --features metal-probe --bin shader-metal-scalar-descriptor-probe
p=$d/target/debug/shader-metal-scalar-descriptor-probe
"$p"
"$p" --emit-msl > "$d/owned.metal"
xcrun -sdk macosx metal -std=metal3.1 -c "$d/owned.metal" -o "$d/owned.air"
xcrun -sdk macosx metallib "$d/owned.air" -o "$d/owned.metallib"
"$p" --load-metallib "$d/owned.metallib"
