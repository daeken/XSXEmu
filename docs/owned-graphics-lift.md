# Owned native VS+PS lift to Metal

The owned fixture begins with two bounded streams of GFX10 instruction words, independently checked against LLVM MC 21 for `gfx1013` and `gfx1030`. Rust decodes typed VGPR operands, `v_mov_b32_e32`, `v_add_f32_e32` with one normal literal dword, unmodified three-VGPR `v_fma_f32`, VOP2 `v_mul_legacy_f32_e32` (VGPR pair, or inline 0/0.5 with a VGPR), uncompressed full-enable `EXP`, and exact `s_endpgm`. The validator checks defined registers, exact stage export sequence (`PARAM0`, `POS0 done` for VS; `MRT0 done` for PS), and that the genuine exit consumes the span. Unknown encodings, other export targets/configurations, missing or trailing instructions, and uninitialized inputs fail rather than generating a substitute. This profile does not model branches, wave operations, SGPRs, exceptional floating point or guest FP modes.

The only handwritten MSL is the entry/interface glue: vertex buffer 0 supplies a position in `v0..v3` and a varying in `v4..v7`; the exported `PARAM0` travels through one center-sampled no-perspective `float4`, feeding PS `v0..v3`; `MRT0` is RGBA8Unorm slot 0. The emitter generates register moves, arithmetic, export operands, and returns from the validated native instructions. This explicit synthetic link is not an Xbox calling convention. The fixture is not derived from a title payload and proves no title launch state or translation coverage.

A CPU oracle uses the analytic gradient of the full-screen fixture at pixel centers. Red is `(x+0.5)/16 + 1/4` for the original native literal. Green checks the single-rounding result `4097 × 4097 − 16785408 = 1`; rounding the intermediate product would give zero. Blue exercises legacy multiplication by that fused result, then by one half. Alpha checks zero times a negative finite operand; UNORM readback cannot distinguish signed zeros. The lowering checks exact zero magnitude by bits and returns positive zero before doing the multiply, consistent with LLVM 21 `opt -passes=instcombine` folding `llvm.amdgcn.fmul.legacy(-0.0, +inf)` and `llvm.amdgcn.fmul.legacy(NaN, -0.0)` to positive zero. No denormal-mode or NaN-payload equivalence is claimed. It computes expected UNORM bytes with integer rounding; it does not call the decoder or emitter.

```sh
M=tools/shader-inventory/Cargo.toml
MTL_DEBUG_LAYER=1 cargo run --locked --manifest-path "$M" --features metal-probe \
  --bin shader-metal-graphics-lift
# With the Xcode MetalToolchain installed:
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  sh tools/shader-inventory/smoke-graphics-lift.sh
```

On Apple M4/macOS 27.0.1, generated-source execution, standalone offline metallib, and strict archive replay in a fresh process each match 64/64 pixels. The empty archive misses. An independent offline rebuild changes only the pixel shader's native literal from `1/4` to `1/2`; the translated standalone pipeline matches the modified oracle at all 64 pixels. The independent Metal negative control pairs that altered library with a copy of the original archive without a sidecar and requires `FailOnBinaryArchiveMiss` to report a miss specifically at `translated_ps`. This control does not replay successfully, publish artifacts, or fall back to compilation.

### Owned bake admission and artifact identity

The archive path now admits the checked fixture as a [ready bake job](shader-bake-plan.md). It hashes each exact little-endian native program, the shared emitted MSL module and named entries, and the explicit owned stage ABI and normalized render descriptor. The smoke script hashes the local `metal`/`metallib` executables, tool/SDK version information and the offline compile flags for the compiler profile. The probe separately binds to the device registry ID, OS build and API validation setting; it requires shader validation unset. Changing the fixture's pixel literal changes the native PS identity and emitted module, even with unchanged function names, layout and render state.

After a strict pipeline hit and successful 64-pixel oracle, bake creates `ARCHIVE.identity` without overwriting. It reuses the 72-byte local Metal manifest (`XSXMCA1\0`, cache identity, archive SHA-256); a graphics-specific domain binds the admitted job key and metallib SHA-256 into the cache identity. Replay checks exact length and byte equality before loading either Metal artifact, then still requires a strict hit and the pixel oracle. The smoke tests reject independent changes to selected native variant, metallib, compiler profile, and archive bytes. This is trusted-local, private scratch: the profile argument is a trusted caller assertion, not compiler attestation, and the sidecar does not authenticate a directory under concurrent or hostile modification. The script builds both artifacts from the exact emitted fixture source. Neither the owned ABI nor its keys are usable as evidence for shipped rows.

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

Adding unmodified three-VGPR `v_fma_f32` increased matched VS/PS sites by 3,642/189,598 under `gfx1013` and 3,002/8,775 under `gfx1030`, identically for both wave checks. This leaves 28,873/967,349 unsupported `v_fma_f32` sites under `gfx1013` and 21,956/79,139 under `gfx1030`. The whole-graph no-gap count is unchanged at zero.

The bounded legacy-multiply forms add a further 65,746 VS / 1,774,743 PS matched sites under `gfx1013` and 51,066 VS / 153,329 PS under `gfx1030`, in each wave check. Residual legacy-multiply sites are 31,519 / 699,800 and 25,720 / 69,629, respectively. No whole graph becomes encoding-complete.

The shape census separates the first source field from its instruction mnemonic. In complete `gfx1013` PS graphs, the largest shape is the VGPR selector (1,759,129 sites in 10,320 payloads). Of the 699,800 then-unsupported sites, 379,524 used a literal dword, 309,493 an ordinary SGPR selector, and 10,783 another inline float selector. The next increment admits only normal or signed-zero literal dwords: 379,522 PS sites and 4,626 VS sites under `gfx1013`, and 39,785 PS sites and 3,590 VS sites under `gfx1030`. Two and one PS literal sites respectively still reject. The whole-graph gate remains zero, and the notable remaining gfx1013 PS gaps include 1,531,043 `v_fmac_f32_e32` sites and 36,936 unsupported EXP sites across all 12,091 complete PS graphs.

`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer sh tools/shader-inventory/smoke-legacy-mul-edges.sh` uses the same instruction decoder and arithmetic emitter in a separate, owned raw-bit compute probe. It exercises two native instruction operands: a VGPR pair and a literal quarter with a VGPR. Fresh-process strict Metal archive replay matches all 16 expected result words on Apple M4, including either-signed zero with infinity or NaN, negative finite inputs, and preservation of a nonzero infinity product. This checks positive zero bit-for-bit rather than relying on UNORM colors; it does not establish behavior for nonzero NaN operands or guest denormal modes.
