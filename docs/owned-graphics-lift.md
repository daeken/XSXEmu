# Owned native VS+PS lift to Metal

The owned fixture begins with two bounded streams of GFX10 instruction words, independently checked against LLVM MC 21 for `gfx1013` and `gfx1030`. Rust decodes typed VGPR operands, `v_mov_b32_e32`, `v_add_f32_e32` with one normal literal dword, uncompressed full-enable `EXP`, and exact `s_endpgm`. The validator checks defined registers, exact stage export sequence (`PARAM0`, `POS0 done` for VS; `MRT0 done` for PS), and that the genuine exit consumes the span. Unknown encodings, other export targets/configurations, missing or trailing instructions, and uninitialized inputs fail rather than generating a substitute. This profile does not model branches, wave operations, SGPRs, exceptional floating point or guest FP modes.

The only handwritten MSL is the entry/interface glue: vertex buffer 0 supplies a position in `v0..v3` and a varying in `v4..v7`; the exported `PARAM0` travels through one center-sampled no-perspective `float4`, feeding PS `v0..v3`; `MRT0` is RGBA8Unorm slot 0. The emitter generates register moves, arithmetic, export operands, and returns from the validated native instructions. This explicit synthetic link is not an Xbox calling convention. The fixture is not derived from a title payload and proves no title launch state or translation coverage.

A CPU oracle uses the analytic gradient of the full-screen fixture at pixel centers. Red is `(x+0.5)/16 + 1/4` for the original native literal; green and blue are distinct fixed values swapped by the native export. It computes expected UNORM bytes with integer rounding; it does not call the decoder or emitter.

```sh
M=tools/shader-inventory/Cargo.toml
MTL_DEBUG_LAYER=1 cargo run --locked --manifest-path "$M" --features metal-probe \
  --bin shader-metal-graphics-lift
# With the Xcode MetalToolchain installed:
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  sh tools/shader-inventory/smoke-graphics-lift.sh
```

On Apple M4/macOS 27.0.1, generated-source execution, standalone offline metallib, and strict archive replay in a fresh process each match 64/64 pixels. The empty archive misses. An independent offline rebuild changes only the pixel shader's native literal from `1/4` to `1/2`: the translated standalone pipeline matches the modified oracle at all 64 pixels, while strict replay against the original archive misses specifically at `translated_ps`. All artifacts are trusted-local scratch; the probe is not a general cache or a title bake.

## Measured instruction gaps

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --graphics-lift-gaps "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$NATIVE_FSSM_DIRECTORY"
# Repeat with gfx1030.
```

The command compares the same Rust decoder against each instruction start in a complete strict reference CFG from the stored `+40` hypothesis. Matching requires width and LLVM mnemonic agreement; it does not apply the synthetic stage ABI or validate register provenance, control lowering, exports as a sequence, or pipeline linkage. It lists every unmodeled mnemonic with separate distinct-payload and static-site counts; repeated sites and already supported forms of the same mnemonic are not counted as new payloads. Both wave settings reproduce the aggregate counts below.

| Reference | Stage | Framed inputs | Complete reference graphs | Graphs with no encoding gap | Matching / checked sites |
|---|---|---:|---:|---:|---:|
| `gfx1013` | VS | 2,236 | 1,448 | 0 | 27,902 / 950,624 |
| `gfx1013` | PS | 12,101 | 12,091 | 0 | 640,029 / 18,916,461 |
| `gfx1030` | VS | 2,236 | 1,242 | 0 | 18,580 / 636,957 |
| `gfx1030` | PS | 12,101 | 6,188 | 0 | 71,690 / 2,027,022 |

In the initial `gfx1013` pass, unsupported MOV forms occur in all complete VS graphs (21,368 sites), and unmodeled `v_fma_f32` appears in 1,359 (32,515 sites). Every complete PS graph contains unsupported EXP forms; `v_mul_legacy_f32_e32` occurs in 11,197 (2,474,543 sites). Scalar loads and waits also occur in most graphs. These are independent co-occurring blockers, not disjoint categories. Standalone opcode matches cannot be counted as title conversion or extrapolated to the rejected graphs, absent stages, library programs or runtime variants.
