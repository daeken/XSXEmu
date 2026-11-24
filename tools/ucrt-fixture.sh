#!/bin/sh
# Build the original Win64 fixture and audit the local, exact UCRT without executing it.
set -eu

usage() {
    echo 'Usage: sh tools/ucrt-fixture.sh [--static-tls] [--run]'
    echo 'Default: build and audit only. --static-tls: build the PE static TLS variant.'
    echo '--run: also run the trusted fixture (not sandboxed), requiring an x86-64 macOS'
    echo 'XSXEmu build. Running the static TLS variant requires Rosetta.'
}

mode=audit
variant=original
case "$#:${1-}" in
    1:--help|1:-h) usage; exit 0 ;;
esac
for arg do
    case "$arg:$mode:$variant" in
        --run:audit:*) mode=run ;;
        --static-tls:*:original) variant=static-tls ;;
        *) usage >&2; exit 2 ;;
    esac
done

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
set --
name=ucrt-fixture.exe
label='Original fixture'
if [ "$variant" = static-tls ]; then
    set -- --cfg fixture_static_tls
    name=ucrt-static-tls-fixture.exe
    label='Static TLS fixture'
fi
rustc --edition 2024 --target x86_64-pc-windows-gnullvm \
    -C panic=abort -C opt-level=2 -C force-unwind-tables=yes \
    "$@" --emit=obj tools/ucrt-fixture.rs -o "$tmp/fixture.obj"
fixture=$tmp/$name
# GNU PE link mode preserves the gnullvm target's Win64 unwind tables.
"$lld" -flavor gnu -m i386pep --entry fixture_entry --subsystem console \
    --no-insert-timestamp --strip-all -o "$fixture" "$tmp/fixture.obj" "$tmp/ucrt.lib"
printf '%s SHA-256: %s\nLocal UCRT SHA-256: %s\n' "$label" "$(sha256 "$fixture")" "$expected"

# Native host builds suffice for audit; only execution requires x86-64 macOS.
target=$host
if [ "$mode" = run ]; then
    [ "$(uname -s)" = Darwin ] || fail '--run requires macOS (Rosetta on Apple Silicon)'
    target=x86_64-apple-darwin
fi
cargo build --offline --target "$target" --target-dir "$tmp/target"
emu=$tmp/target/$target/debug/xsxemu

if [ "$variant" = static-tls ]; then
    "$emu" inspect "$fixture" --symbols > "$tmp/inspect.log"
    cat "$tmp/inspect.log"
    grep -Eq '^  static TLS: template=Some\(.+\) zero-fill=8 alignment=Some\(8\) index=Some\([[:xdigit:]]+\) callbacks=\[\]$' "$tmp/inspect.log" ||
        fail 'expected a static TLS directory with a template, zero-fill and index'
    # At least the heap function pointer, template self-pointer and three TLS
    # directory VAs. The compiler can emit additional reference pointers.
    awk '/^  [0-9]+ DIR64 relocations$/ && $1 >= 5 { found = 1 } END { exit !found }' \
        "$tmp/inspect.log" || fail 'expected at least five DIR64 fixups in the static TLS fixture'
    "$emu" map "$fixture" --base 0x180000000
else
    "$emu" inspect "$fixture" --symbols
fi
# Require an audit that actually reached both images. Missing imports in the UCRT
# are expected for now; unrelated failures (schema errors, missing EXE imports,
# etc.) must not count as a successful diagnostic.
status=0
"$emu" audit "$fixture" --dll-dir "$tmp/providers" --api-set "$schema" \
    --rust-providers --symbols > "$tmp/audit.log" 2>&1 || status=$?
cat "$tmp/audit.log"
grep -Fq "$tmp/providers/ucrtbase.dll (134 IAT slots)" "$tmp/audit.log" ||
    fail 'audit did not reach the exact UCRT and its 134 IAT slots'
if grep -Eq '^  (ucrt-fixture|ucrt-static-tls-fixture)\.exe:.*ucrtbase\.dll!(malloc|free) → ' "$tmp/audit.log"; then
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
set --
if [ "$variant" = static-tls ]; then
    set -- --experimental-static-tls
fi
status=0
"$emu" run "$fixture" --dll-dir "$tmp/providers" --api-set "$schema" \
    --rust-providers --trace-missing-imports "$@" > "$tmp/run.log" 2>&1 || status=$?
cat "$tmp/run.log"
[ "$status" -eq 42 ] && grep -Fxq 'Guest entry returned 42' "$tmp/run.log" ||
    fail "expected guest return 42 after UCRT process attach; got exit status $status"
if [ "$variant" = static-tls ]; then
    echo 'Guest verified the static TLS index, GS vector, relocated template and zero-fill state across malloc/free; returned 42.'
else
    echo 'Guest returned 42 after UCRT process attach and a malloc/free round trip.'
fi
