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
    --features metal-probe --bin shader-metal-probe --bin shader-metal-render-probe
p=$d/target/debug/shader-metal-probe
r=$d/target/debug/shader-metal-render-probe
language=metal3.1
{
    printf 'SDK=macosx\ncompile-flags=-std=%s -c\nlink-flags=(defaults)\n' "$language"
    xcodebuild -version
    xcrun -sdk macosx --show-sdk-build-version
    version=$(xcrun -sdk macosx metal --version)
    printf '%s\n' "$version" | sed '/^InstalledDir: /d'
} > "$d/compiler.profile"
compile() {
    xcrun -sdk macosx metal -std="$language" -c "$d/$1.metal" -o "$d/$1.air"
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

"$p" --bake-keyed-exec-store-archive "$d/store.metallib" "$d/keyed.metalar" \
    "$d/compiler.profile" "$d/keyed.manifest"
"$p" --replay-keyed-exec-store-archive "$d/store.metallib" "$d/keyed.metalar" \
    "$d/compiler.profile" "$d/keyed.manifest"

reject_stale() {
    label=$1
    shift
    if "$p" --replay-keyed-exec-store-archive "$@" "$d/keyed.manifest" > "$d/stale.log" 2>&1 ||
        ! grep -Fq 'owned cache identity mismatch (rejected before pipeline creation)' "$d/stale.log"; then
        cat "$d/stale.log" >&2
        echo "expected the application cache guard to reject $label" >&2
        exit 1
    fi
    printf 'owned cache guard rejected %s before pipeline creation\n' "$label"
}
cp "$d/compiler.profile" "$d/stale.profile"
printf 'different compiler profile\n' >> "$d/stale.profile"
cp "$d/keyed.metalar" "$d/changed.metalar"
printf 'changed archive\n' >> "$d/changed.metalar"
reject_stale 'changed same-name metallib' "$d/modified.metallib" "$d/keyed.metalar" "$d/compiler.profile"
reject_stale 'stale compiler profile' "$d/store.metallib" "$d/keyed.metalar" "$d/stale.profile"
reject_stale 'modified archive bytes' "$d/store.metallib" "$d/changed.metalar" "$d/compiler.profile"
MTL_DEBUG_LAYER=0 reject_stale 'different API validation setting' "$d/store.metallib" "$d/keyed.metalar" "$d/compiler.profile"

"$r" --emit-msl > "$d/render.metal"
compile render
"$r" --load-metallib "$d/render.metallib"
"$r" --bake-archive "$d/render.metallib" "$d/render.metalar"
"$r" --replay-archive "$d/render.metallib" "$d/render.metalar"
sed 's/return color;/return color.bgra;/' "$d/render.metal" > "$d/modified-render.metal"
if cmp -s "$d/render.metal" "$d/modified-render.metal"; then
    echo 'owned fragment mutation did not apply' >&2
    exit 1
fi
compile modified-render
# The mutated metallib is valid and observably different without the archive.
if "$r" --load-metallib "$d/modified-render.metallib" > "$d/render-modified.log" 2>&1 ||
    ! grep -Fq 'pixel (0,0): expected [255, 0, 0, 255], got [0, 0, 255, 255]' "$d/render-modified.log"; then
    cat "$d/render-modified.log" >&2
    echo 'owned fragment mutation did not produce its expected pixel change' >&2
    exit 1
fi
if "$r" --replay-archive "$d/modified-render.metallib" "$d/render.metalar" > "$d/render-miss.log" 2>&1; then
    echo 'changed fragment unexpectedly hit original archive' >&2
    exit 1
fi
if ! grep -Fq 'in binary archives' "$d/render-miss.log"; then
    cat "$d/render-miss.log" >&2
    echo 'changed fragment failed for a reason other than the observed strict archive miss' >&2
    exit 1
fi
printf '%s\n' 'strict render archive refused the independently compiled same-name changed fragment'
