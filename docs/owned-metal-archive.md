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

## Offline library and strict PSO replay

Requires `xcrun -sdk macosx metal --version` and `xcrun -sdk macosx --find metallib` to succeed. Xcode may ship a `metal` stub before its optional component is installed; check `xcodebuild -showComponent MetalToolchain -json`. Install via `xcodebuild -downloadComponent MetalToolchain` if needed.

```sh
set -e
M=tools/shader-inventory/Cargo.toml
cargo build --locked --manifest-path "$M" --features metal-probe --bin shader-metal-probe
p=tools/shader-inventory/target/debug/shader-metal-probe
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
"$p" --emit-exec-store-msl > "$d/store.metal"
xcrun -sdk macosx metal -c "$d/store.metal" -o "$d/store.air"
xcrun -sdk macosx metallib "$d/store.air" -o "$d/store.metallib"
MTL_DEBUG_LAYER=1 MTL_SHADER_VALIDATION=1 "$p" --load-exec-store-metallib "$d/store.metallib"
unset MTL_SHADER_VALIDATION
export MTL_DEBUG_LAYER=1
"$p" --bake-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"
"$p" --replay-exec-store-metallib-archive "$d/store.metallib" "$d/store.metalar"
```

The first load creates a pipeline without an archive. The archive replay instead loads the compiled library, requires a strict archive hit and does not use the in-memory MSL compile path. All file inputs must be trusted, locally baked artifacts from the owned fixture. On Apple M4/macOS 27.0.1, Xcode 27A266a and `metalfe-32023.921.6`, both runs matched **1,088/1,088** words with the independent validation settings above. Missing, invalid and symlinked libraries were refused, a differently named function failed lookup, and changing the kernel’s empty-mask result **without changing its function name** caused a strict archive miss. No game assets were used; this is not a title cache key, proof of cross-device portability, or a retail pipeline bake.
