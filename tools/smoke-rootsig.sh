#!/bin/sh
# Run only an original, freestanding PE; no console DLL, Windows SDK or Wine.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d "${TMPDIR:-/tmp}/xsxemu-rootsig.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
host=$(rustc -vV | sed -n 's/^host: //p')
lld="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
dlltool=${PE_DLLTOOL:-llvm-dlltool}
cat > "$tmp/import.def" <<'EOF'
LIBRARY d3d12_xs.dll
EXPORTS
D3D12SerializeVersionedRootSignature
EOF
"$dlltool" -m i386:x86-64 -d "$tmp/import.def" -l "$tmp/import.lib"
rustc --edition 2024 --target x86_64-pc-windows-gnu --emit=obj -O -C panic=abort \
    tests/fixtures/root_signature/guest.rs -o "$tmp/guest.obj"
"$lld" -flavor link /nodefaultlib /subsystem:console /entry:app_entry \
    "/out:$tmp/guest.exe" "$tmp/guest.obj" "$tmp/import.lib"

# Prove that neither opt-in alone wires the exact import.
cargo build --offline --target x86_64-apple-darwin --no-default-features
emu=${CARGO_TARGET_DIR:-target}/x86_64-apple-darwin/debug/xsxemu
if "$emu" audit "$tmp/guest.exe" --symbols --rust-providers > "$tmp/audit.log" 2>&1; then
    echo 'default build unexpectedly resolved the Xbox serializer' >&2
    exit 1
fi
grep -F 'D3D12SerializeVersionedRootSignature' "$tmp/audit.log"
cargo build --offline --target x86_64-apple-darwin --features experimental-xbox-rootsig
if "$emu" audit "$tmp/guest.exe" --symbols > "$tmp/audit.log" 2>&1; then
    echo 'experimental build unexpectedly resolved the serializer without --rust-providers' >&2
    exit 1
fi
grep -F 'D3D12SerializeVersionedRootSignature' "$tmp/audit.log"
"$emu" audit "$tmp/guest.exe" --rust-providers | grep -F '1/1 IAT slots resolved (1 Rust)'

status=0
"$emu" run "$tmp/guest.exe" --rust-providers 2> "$tmp/run.log" || status=$?
cat "$tmp/run.log"
if [ "$status" != 44 ]; then
    echo "root signature fixture returned $status, expected 44" >&2
    exit 1
fi
[ "$(grep -c 'WARNING: experimental d3d12_xs.dll!D3D12SerializeVersionedRootSignature' "$tmp/run.log")" = 6 ]
grep -F 'version=2 (1.1), original flags=0x03000000, ignored=0x03000000, unsupported=0x00000000' "$tmp/run.log"
for flags in 0x01000000 0x02000000 0x03100000 0x03001000 0x00000000; do
    grep -F "original flags=$flags, ignored=0x00000000" "$tmp/run.log"
done
[ "$(grep -c 'no Xbox semantic compatibility claimed' "$tmp/run.log")" = 6 ]
echo 'Win64 guest verified real DXBC, ID3DBlob, flag rejection and diagnostics via the opt-in IAT binding.'
