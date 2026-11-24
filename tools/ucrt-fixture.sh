#!/bin/sh
# Build the original Win64 fixture and audit the local, exact UCRT without executing it.
set -eu

usage() {
    echo 'Usage: sh tools/ucrt-fixture.sh [--run]'
    echo 'Default: build and audit only. --run: also run the trusted fixture (not sandboxed),'
    echo 'requiring an x86-64 macOS XSXEmu build with --trace-missing-imports support.'
}

mode=audit
case "$#:${1-}" in
    0:) ;;
    1:--run) mode=run ;;
    1:--help|1:-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

fail() { echo "ucrt-fixture: $*" >&2; exit 1; }
sha256() { shasum -a 256 < "$1" | cut -d ' ' -f 1; }

cd "$(dirname "$0")/.."
ucrt=/Volumes/External2/windlls/ucrtbase.dll
schema=${UCRT_API_SET:-/Volumes/External2/gta6/win11-arm64-reference/apisetschema.dll}
expected=7ee229626b22799faa28cd7c22d4ff2ad0603c17e5f5ee9086fa7cf6483331fb
[ -r "$ucrt" ] || fail "missing local UCRT: $ucrt"
[ "$(sha256 "$ucrt")" = "$expected" ] || fail "unexpected SHA-256 for $ucrt (expected $expected)"
[ -r "$schema" ] || fail "missing API-set schema: $schema (set UCRT_API_SET to its path)"

host=$(rustc -vV | sed -n 's/^host: //p')
lld=$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld
[ -x "$lld" ] || fail "Rust toolchain has no rust-lld at $lld"
tmp_root=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmp_root%/}/xsxemu-ucrt.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/providers"
# Isolate the resolver from sibling Windows DLLs. Never copy the supplied DLL.
ln -s "$ucrt" "$tmp/providers/ucrtbase.dll"
cat > "$tmp/ucrt.def" <<'EOF'
LIBRARY ucrtbase.dll
EXPORTS
    malloc
    free
EOF
"$lld" -flavor link /lib /machine:x64 "/def:$tmp/ucrt.def" "/out:$tmp/ucrt.lib"
rustc --edition 2024 --target x86_64-pc-windows-gnullvm \
    -C panic=abort -C opt-level=2 -C force-unwind-tables=yes \
    --emit=obj tools/ucrt-fixture.rs -o "$tmp/fixture.obj"
fixture=$tmp/ucrt-fixture.exe
# GNU PE link mode preserves the gnullvm target's Win64 unwind tables.
"$lld" -flavor gnu -m i386pep --entry fixture_entry --subsystem console \
    --no-insert-timestamp --strip-all -o "$fixture" "$tmp/fixture.obj" "$tmp/ucrt.lib"
printf 'Original fixture SHA-256: %s\nLocal UCRT SHA-256: %s\n' "$(sha256 "$fixture")" "$expected"

# Native host builds suffice for audit; only execution requires x86-64 macOS.
target=$host
if [ "$mode" = run ]; then
    [ "$(uname -s)" = Darwin ] || fail '--run requires macOS (Rosetta on Apple Silicon)'
    target=x86_64-apple-darwin
fi
cargo build --offline --target "$target" --target-dir "$tmp/target"
emu=$tmp/target/$target/debug/xsxemu

"$emu" inspect "$fixture" --symbols
# Require an audit that actually reached both images. Missing imports in the UCRT
# are expected for now; unrelated failures (schema errors, missing EXE imports,
# etc.) must not count as a successful diagnostic.
status=0
"$emu" audit "$fixture" --dll-dir "$tmp/providers" --api-set "$schema" \
    --rust-providers --symbols > "$tmp/audit.log" 2>&1 || status=$?
cat "$tmp/audit.log"
grep -Fq "$tmp/providers/ucrtbase.dll (134 IAT slots)" "$tmp/audit.log" ||
    fail 'audit did not reach the exact UCRT and its 134 IAT slots'
if grep -Eq '^  ucrt-fixture\.exe:.*ucrtbase\.dll!(malloc|free) → ' "$tmp/audit.log"; then
    fail 'fixture imports did not bind to the UCRT'
fi
case "$status" in
    0) echo 'Static UCRT audit is fully resolved; no guest code ran.' ;;
    1)
        grep -Fq 'incomplete dependency graph; no guest code ran' "$tmp/audit.log" &&
            grep -Eq '^  ucrtbase\.dll:0x[[:xdigit:]]+: .* → ' "$tmp/audit.log" ||
            fail 'audit failed for a reason other than unresolved UCRT imports'
        echo 'Static UCRT audit confirmed unresolved imports; no guest code ran.' ;;
    *) fail "unexpected audit exit status $status" ;;
esac

[ "$mode" = run ] || exit 0
status=0
"$emu" run "$fixture" --dll-dir "$tmp/providers" --api-set "$schema" \
    --rust-providers --trace-missing-imports > "$tmp/run.log" 2>&1 || status=$?
cat "$tmp/run.log"
[ "$status" -eq 42 ] && grep -Fxq 'Guest entry returned 42' "$tmp/run.log" ||
    fail "expected guest return 42 after UCRT process attach; got exit status $status"
echo 'Guest returned 42 after UCRT process attach and a malloc/free round trip.'
