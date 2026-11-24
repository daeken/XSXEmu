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

Only the owned compute PSO was archived. Replay still compiles the MSL function in memory to identify the expected pipeline key. This probe does not persist a `.metallib`, identify pinned-build title cache entries, implement cache keys or PSO enumeration, claim cross-device/OS portability, or execute retail shaders. Next: share the descriptor between owned EXEC and bounded-buffer lowering, then verify stable library and PSO artifacts independently.
