# Owned Metal binary archive bake/replay probe

The optional `shader-metal-probe` flags exercise a **local, owned** compute pipeline end to end across two processes. Bake compiles the owned EXEC MSL fixture, confirms a strict miss with an empty archive, adds the compute descriptor and serializes the archive. Replay regenerates the matching function from the owned MSL, loads the archive from disk and creates the pipeline with `MTLPipelineOptionFailOnBinaryArchiveMiss`. It does not compile a replacement PSO on a cache miss. It dispatches the resulting pipeline and compares all five cases to the CPU oracle.

Run on a Metal device with binary archive support. Use a private scratch directory; the probe refuses to overwrite an existing file and refuses to load a symlink. Do not put the archive in Git.

```sh
M=tools/shader-inventory/Cargo.toml
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
unset MTL_SHADER_VALIDATION
export MTL_DEBUG_LAYER=1
cargo run --locked --release --manifest-path "$M" --features metal-probe \
  --bin shader-metal-probe -- --bake-exec-archive "$d/owned.metalar"
cargo run --locked --release --manifest-path "$M" --features metal-probe \
  --bin shader-metal-probe -- --replay-exec-archive "$d/owned.metalar"
```

On Apple M4, API-validation bake and strict replay passed in separate processes, with **165/165** CPU/Metal words matching and the empty archive rejected. The same experiment with Metal GPU shader validation instrumentation enabled missed even after a successful serialization; the archive mode now refuses that configuration explicitly. Running the regular probe with GPU instrumentation still checks the same owned EXEC semantics. This is an observed backend constraint, not a claim that instrumented binaries are universally unsupported.

The source-based archive replay above still compiles the owned MSL in memory. The separate workflow below persists the library as well as the PSO archive.

## Owned mesh-stage render probe

```sh
MTL_DEBUG_LAYER=1 cargo run --locked --manifest-path tools/shader-inventory/Cargo.toml \
  --features metal-probe --bin shader-metal-mesh-probe
```

On Apple M4 (macOS 27.0.1), the source-compiled, no-object-stage mesh/fragment pipeline matched all 64 `RGBA8Unorm` pixels with primitive count zero (only the red clear color survives) and all 64 with count one (cyan from separate vertex green and flat per-primitive blue inputs). The same mesh threadgroup, triangle vertices, indices and primitive payload are supplied in both draws; only the explicit primitive count changes. This checks a local Metal lowering target for distinct vertex and primitive outputs and for suppressing rasterization by emitting zero primitives. It does not map the title's `PRIM` word, infer an Xbox message effect, or bake a mesh PSO archive.

## Offline library and strict PSO replay

Requires `xcrun -sdk macosx metal --version` and `xcrun -sdk macosx --find metallib` to succeed. Xcode may ship a `metal` stub before its optional component is installed; check `xcodebuild -showComponent MetalToolchain -json`. If needed, check scratch free space first and install with `DEVELOPER_DIR="$XCODE/Contents/Developer" xcodebuild -downloadComponent MetalToolchain`, where `XCODE` is the chosen app bundle. No global `xcode-select` change is needed.

Run the repeatable positive and negative smoke checks in scratch:

```sh
DEVELOPER_DIR="$XCODE/Contents/Developer" sh tools/shader-inventory/smoke-metallib.sh
```

Equivalent manual steps for the positive path (using the same command-scoped Xcode selection):

```sh
set -e
M=tools/shader-inventory/Cargo.toml
cargo build --locked --manifest-path "$M" --features metal-probe --bin shader-metal-probe
p=tools/shader-inventory/target/debug/shader-metal-probe
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
"$p" --emit-exec-store-msl > "$d/store.metal"
xcrun -sdk macosx metal -std=metal3.1 -c "$d/store.metal" -o "$d/store.air"
xcrun -sdk macosx metallib "$d/store.air" -o "$d/store.metallib"
MTL_DEBUG_LAYER=1 MTL_SHADER_VALIDATION=1 "$p" --load-exec-store-metallib "$d/store.metallib"
unset MTL_SHADER_VALIDATION
export MTL_DEBUG_LAYER=1
"$p" --bake-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"
"$p" --replay-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"
```

The first load creates a pipeline without an archive. The archive replay instead loads the compiled library, requires a strict archive hit and does not use the in-memory MSL compile path. All file inputs must be trusted, locally baked artifacts from the owned fixture. On Apple M4/macOS 27.0.1, Xcode 27A266a and `metalfe-32023.921.6`, both runs matched **1,088/1,088** words with the independent validation settings above. Missing, invalid and symlinked libraries were refused, a differently named function failed lookup, and changing the kernel’s empty-mask result **without changing its function name** caused a strict archive miss. No game assets were used; this is not a title cache key, proof of cross-device portability, or a retail pipeline bake.

## Owned archive identity guard

The smoke also exercises `--bake-keyed-exec-store-archive` and `--replay-keyed-exec-store-archive`. Each takes four paths: the offline metallib, archive, compiler profile, and manifest. The script records the Xcode and SDK builds, Metal compiler version and target, and compile/link flags; it omits the compiler installation path. The probe treats that profile as an opaque, trusted bake input, not as an attestation of how a metallib was produced.

The v1 key hashes length-delimited fields with SHA-256: the emitted MSL and metallib digest; the compiler profile digest; the local Metal device name and registry ID, macOS build, host architecture and API validation setting; and the single modeled compute pipeline contract (entry, default descriptor with no specialization, resource slots and inline constants ABI, one-wave dispatch). The sidecar stores the schema magic, key, and a separate archive SHA-256. Replay compares it before loading either artifact into Metal and still uses `FailOnBinaryArchiveMiss`. A missing or malformed sidecar does not permit fallback. The smoke checks successful separate-process keyed replay (**1,088/1,088** Apple M4 readback words) and rejects a changed same-name metallib, stale compiler profile, modified archive bytes, and changed API validation setting before pipeline creation. The separate unkeyed negative still proves that Metal itself refuses the changed same-name function.

This is deliberately a conservative same-host, trusted scratch cache; the registry ID is not a portability identifier. The digest is for cache identity and accidental replacement detection, not authentication or protection against concurrent writers. It does not define a general PSO canonicalization or cover optional compute descriptor settings, specialized functions, graphics state, or retail pipelines.

## Owned render archive

The same smoke script also compiles an owned VS/fragment pair to a standalone metallib and runs `shader-metal-render-probe --load-metallib LIB`, `--bake-archive LIB ARCHIVE`, and `--replay-archive LIB ARCHIVE` in separate processes. It adds four render descriptors to one archive: all-channel replacement, green-only replacement, all-channel blending, and a separate fragment entry that writes depth. All four are refused by the empty archive and created from the persisted archive with `FailOnBinaryArchiveMiss`, with no source compilation path in replay. The `Depth32Float` compare/write states and per-draw scissor are set separately at runtime; this does not prove that the render archive keys or encodes those settings.

The blended draw overlaps an opaque red pixel with green at source alpha `102/255`. RGB uses `src * srcAlpha + dst * (1 - srcAlpha)`; alpha uses `dstAlpha - srcAlpha` with unit factors. An integer UNORM8 oracle expects `[153, 102, 0, 153]`, distinguishing replacement, RGB blend factors, and the independent alpha operation. One column is blended in each depth-write mode; the other columns still exercise scissor, depth rejection, and the green-only write mask.

The depth-output fragment returns a color and `[[depth(any)]]`. It replaces the depth in one column with `1/8` even though its rasterized `7/8` would fail `Less`. The subsequent white draw at `2/8` must fail against the newly written depth and leave that column magenta. This distinguishes shader-depth testing and writing from using the interpolated depth or ignoring the depth output. The fixture does not model conservative depth qualifiers, stencil, or title export semantics.

On the same Apple M4/macOS 27.0.1 profile, both standalone load and strict replay matched **64/64 RGBA pixels** against the CPU oracle. An independently compiled fragment with the same entry name and swapped red/blue channels changes the expected pixel without the archive and fails strict replay from the original archive. A separate mutation changes only the depth fragment's result from `1/8` to `7/8`: standalone rendering leaves the follow-up white pixel, and the original archive strictly accepts the three unchanged descriptors before refusing the changed depth descriptor. This checks that the rejection is descriptor-specific on this profile. The render probe does not use the compute-only identity guard, and these fixtures do not translate or bake title pipelines.
