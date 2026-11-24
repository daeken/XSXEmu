#!/bin/sh
# Build original, freestanding PE fixtures; no Microsoft SDK or Wine required.
set -eu
cd "$(dirname "$0")/.."
cc=${PE_CC:-x86_64-w64-mingw32-clang}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-smoke.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/providers"
cat > "$tmp/library.c" <<'EOF'
static int state;
static int *volatile state_ptr = &state; /* actual DIR64 relocation */
int dll_entry(void *base, unsigned reason, void *reserved) {
    if (base && reason == 1 && !reserved) *state_ptr = 19;
    return 1;
}
__declspec(dllexport) int named_value(void) { return state; }
int ordinal_value(void) { return state + 4; }
EOF
cat > "$tmp/library.def" <<'EOF'
LIBRARY smoke.dll
EXPORTS
ordinal_value @7 NONAME
EOF
cat > "$tmp/app.c" <<'EOF'
__declspec(dllimport) int named_value(void);
__declspec(dllimport) int ordinal_value(void);
int app_entry(void) { return named_value() + ordinal_value(); }
EOF
"$cc" -O2 -nostdlib -shared -Wl,--image-base,0x140000000,--entry,dll_entry,--out-implib,"$tmp/libsmoke.a" \
    "$tmp/library.c" "$tmp/library.def" -o "$tmp/providers/SMOKE.dll"
"$cc" -O2 -nostdlib -Wl,--image-base,0x140000000,--entry,app_entry "$tmp/app.c" "$tmp/libsmoke.a" -o "$tmp/app.exe"

cargo build --offline --target x86_64-apple-darwin
emu=${CARGO_TARGET_DIR:-target}/x86_64-apple-darwin/debug/xsxemu
"$emu" inspect "$tmp/app.exe" --symbols
if "$emu" audit "$tmp/app.exe"; then
    echo 'expected unresolved dependency to fail audit' >&2
    exit 1
fi
"$emu" audit "$tmp/app.exe" --dll-dir "$tmp/providers"
set +e
"$emu" run "$tmp/app.exe" --dll-dir "$tmp/providers"
status=$?
set -e
if [ "$status" -ne 42 ]; then
    echo "guest should return 42 after DLL process attach; got exit status $status" >&2
    exit 1
fi
echo 'Win64 guest returned 42 via named and ordinal DLL imports.'

cat > "$tmp/tls.c" <<'EOF'
typedef void (*callback)(void *, unsigned, void *);
static unsigned tls_index;
static const char seed[] = {1, 2, 3, 4};
static callback const callbacks[] = {0};
const struct {
    const char *start, *end;
    unsigned *index;
    callback const *callbacks;
    unsigned zero_fill, characteristics;
} _tls_used = {seed, seed + sizeof(seed), &tls_index, callbacks, 0, 0};
int app_entry(void) { return 0; }
EOF
"$cc" -O2 -nostdlib -Wl,--entry,app_entry,--undefined,_tls_used "$tmp/tls.c" -o "$tmp/tls.exe"
"$emu" inspect "$tmp/tls.exe" | grep -F 'static TLS:'
if "$emu" run "$tmp/tls.exe" > "$tmp/tls.out" 2>&1; then
    echo 'expected unsupported TLS profile to refuse execution' >&2
    exit 1
fi
grep -F 'static TLS requires a Windows TEB' "$tmp/tls.out"
