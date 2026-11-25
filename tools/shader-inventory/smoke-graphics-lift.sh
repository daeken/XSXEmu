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
# Fingerprint the trusted tools, SDK version and exact offline flags.
{
    xcrun -sdk macosx metal --version
    xcrun -sdk macosx --show-sdk-version
    xcrun -sdk macosx --show-sdk-build-version
    for tool in metal metallib; do
        path=$(xcrun -sdk macosx --find "$tool")
        printf '%s\n' "$tool"
        shasum -a 256 < "$path"
    done
    printf '%s\n' 'metal -std=metal3.1 -fno-fast-math -c; metallib'
} > "$d/compiler-profile"
compiler=$(shasum -a 256 "$d/compiler-profile" | cut -d ' ' -f 1)
compile() {
    xcrun -sdk macosx metal -std=metal3.1 -fno-fast-math -c "$d/$1.metal" -o "$d/$1.air"
    xcrun -sdk macosx metallib "$d/$1.air" -o "$d/$1.metallib"
}
"$p" --emit-msl > "$d/owned.metal"
compile owned
"$p" --load-metallib "$d/owned.metallib"
"$p" --bake-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler"
"$p" --replay-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler"
"$p" --emit-mutated-msl > "$d/mutated.metal"
compile mutated
"$p" --load-mutated-metallib "$d/mutated.metallib"
expect_mismatch() {
    if "$p" "$@" > "$d/miss.log" 2>&1; then
        echo 'unexpected replay for changed owned identity' >&2
        exit 1
    fi
    grep -F 'owned graphics artifact identity mismatch' "$d/miss.log"
}
expect_mismatch --replay-mutated-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler"
expect_mismatch --replay-archive "$d/mutated.metallib" "$d/owned.metalar" "$compiler"
changed_compiler=$(printf '%s\n' "$compiler changed options" | shasum -a 256 | cut -d ' ' -f 1)
expect_mismatch --replay-archive "$d/owned.metallib" "$d/owned.metalar" "$changed_compiler"
MTL_DEBUG_LAYER=0 expect_mismatch --replay-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler"
cp "$d/owned.metalar.identity" "$d/original.identity"
printf x >> "$d/owned.metalar.identity"
if "$p" --replay-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler" > "$d/miss.log" 2>&1; then
    echo 'unexpected replay for an oversized identity record' >&2
    exit 1
fi
grep -F 'expected a bounded regular owned artifact' "$d/miss.log"
mv "$d/original.identity" "$d/owned.metalar.identity"
# Independent Metal negative control: the copied archive has no sidecar.
cp "$d/owned.metalar" "$d/diagnostic.metalar"
"$p" --expect-owned-metal-miss "$d/mutated.metallib" "$d/diagnostic.metalar"
printf x >> "$d/owned.metalar"
expect_mismatch --replay-archive "$d/owned.metallib" "$d/owned.metalar" "$compiler"

# The packed FP16_ABGR variant has its own ABI and is not an archive job.
"$p" --packed-source
"$p" --emit-packed-msl > "$d/packed.metal"
compile packed
"$p" --load-packed-metallib "$d/packed.metallib"

# Partial export preserves nonzero B/A in the explicit RG-write descriptor.
"$p" --packed-rg-source
"$p" --emit-packed-rg-msl > "$d/packed-rg.metal"
compile packed-rg
"$p" --load-packed-rg-metallib "$d/packed-rg.metallib"

# Locally proven packed RTZ constants, including above-midpoint and signed zero.
for variant in constant-rtz constant-rtz-rg; do
    "$p" "--$variant-source"
    "$p" "--emit-$variant-msl" > "$d/$variant.metal"
    compile "$variant"
    "$p" "--load-$variant-metallib" "$d/$variant.metallib"
done

# Scalar depth with explicit Depth32Float and overlapping draws.
"$p" --depth-source
"$p" --emit-depth-msl > "$d/depth.metal"
compile depth
"$p" --load-depth-metallib "$d/depth.metallib"

# Nonfinal depth must still control the overlap and allow a later color write.
"$p" --early-depth-source
"$p" --emit-early-depth-msl > "$d/early-depth.metal"
compile early-depth
"$p" --load-early-depth-metallib "$d/early-depth.metallib"

# EXPCNT(0) protects the old MRTZ value from reuse as packed MRT0 RG.
"$p" --wait-depth-source
"$p" --emit-wait-depth-msl > "$d/wait-depth.metal"
compile wait-depth
"$p" --load-wait-depth-metallib "$d/wait-depth.metallib"
"$p" --expect-late-depth-read

# POS0 must retain clip position while the replaced X feeds PARAM0.
"$p" --wait-pos-source
"$p" --emit-wait-pos-msl > "$d/wait-pos.metal"
compile wait-pos
"$p" --load-wait-pos-metallib "$d/wait-pos.metallib"
"$p" --expect-late-pos-read

# POS0 DONE is not an instruction terminator; a distinct ADD feeds PARAM0.
"$p" --pos-first-source
"$p" --emit-pos-first-msl > "$d/pos-first.metal"
compile pos-first
"$p" --load-pos-first-metallib "$d/pos-first.metallib"

# Seven explicit native PARAM outputs linked by name with a synthetic consumer.
"$p" --multi-source
"$p" --emit-multi-msl > "$d/multi.metal"
compile multi
"$p" --load-multi-metallib "$d/multi.metallib"

# Native vertex byte extraction and full unsigned conversion, with fused FMA.
for kind in byte uint; do
    "$p" "--unpack-$kind-source"
    "$p" "--emit-unpack-$kind-msl" > "$d/unpack-$kind.metal"
    compile "unpack-$kind"
    "$p" "--load-unpack-$kind-metallib" "$d/unpack-$kind.metallib"
done

# Owned native VS→native PS PARAM0 and exact interpolation pairs.
for channel in x z; do
    "$p" "--interp-$channel-source"
    "$p" "--emit-interp-$channel-msl" > "$d/interp-$channel.metal"
    compile "interp-$channel"
    "$p" "--load-interp-$channel-metallib" "$d/interp-$channel.metallib"
done
"$p" --expect-interp-wrong-mode
"$p" --expect-interp-wrong-channel

# Two explicitly mapped FP16_ABGR exports, each with independent readback.
"$p" --dual-source
"$p" --emit-dual-msl > "$d/dual.metal"
compile dual
"$p" --load-dual-metallib "$d/dual.metallib"

# Three distinct full-mask FP16_ABGR outputs, including nonfinal MRT1.
"$p" --triple-source
"$p" --emit-triple-msl > "$d/triple.metal"
compile triple
"$p" --load-triple-metallib "$d/triple.metallib"

# A binding permutation must change both slots, not merely fail to render.
"$p" --expect-swapped-triple

# Only MRT1 masks off B/A; MRT2 still commits all four components.
"$p" --triple-rg-source
"$p" --emit-triple-rg-msl > "$d/triple-rg.metal"
compile triple-rg
"$p" --load-triple-rg-metallib "$d/triple-rg.metallib"
