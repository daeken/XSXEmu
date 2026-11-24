# Conditional native graphics CFG census

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --reachable-graphics "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$NATIVE_FSSM_DIRECTORY"
# Repeat with gfx1030.
```

The census classifies extracted `.fssm` payloads by the raw stage byte at `+0x100`. Stage labels below come from the separate [same-wrapper stage audit](wrapped-signatures.md), not from opcode inference. No library program, fixed-function state, or embedded PE payload is joined here. The pinned directory has 26,698 valid headers, of which 2,689 are compute (excluded). All 24,009 graphics spans pass the shared FSSM framing check (`+0xc0/+0xc8`, aligned range, `+0xe8` agreement or unset marker, raw trailing fill and end marker). Post-span tails are not interpreted as code.

The walk starts at stored-span offset `+40` as an explicit hypothesis. It follows the same strict basic control subset as the [compute census](compute-reachability.md), with no indirect-PC closure, assumed message behavior, or decoder fallback. Completion requires all modeled reachable edges to decode within the span without overlapping instruction starts and at least one checked `s_endpgm`. It does not require every path to terminate. The wave64 and wave32 tests under LLVM 21.1.6 give the same **result class for every payload** within each CPU, not necessarily the same graph or actual launch width.

| Raw stage byte | Payloads | `gfx1013` complete | `gfx1013` first rejection | `gfx1030` complete | `gfx1030` first rejection |
|---|---:|---:|---|---:|---|
| 2 (VS wrapper companion) | 195 | 0 | 37 `s_setpc_b64`, 158 `s_swappc_b64` | 0 | same |
| 3 (GS) | 195 | 0 | 195 `s_sendmsg` (`MSG_GS`, `GS_OP_EMIT`) | 0 | same |
| 4 (VS) | 2,236 | 1,448 | 788 `s_swappc_b64` | 1,242 | 788 `s_swappc_b64`, 206 decode |
| 5 (PS) | 12,101 | 12,091 | 10 unclassified `s_sendmsg` | 6,188 | 5,913 decode |
| 7 (MS) | 9,282 | 0 | 9,282 `s_sendmsg` (`MSG_GS_ALLOC_REQ`) | 0 | 8,258 `MSG_GS_ALLOC_REQ`, 1,024 decode |

The message classification requires the public four-byte SOPP opcode and recognized immediate fields to agree with LLVM's symbolic operands. Unrecognized cases stay grouped, with no operands printed. Only the first rejection is counted; neither the operation names nor the reported stream encoding establish how the Xbox schedules or couples stages. No message is treated as fallthrough or exit. The owned fixture also rejects noncanonical bits and a numeric-only operand presentation.

Every complete graph has at least one reachable eight-byte `exp` checked against LLVM and the public GFX10 encoding prefix. No export result is attributed to an incomplete graph. An owned fixture distinguishes reachable, branch-skipped, and seen-before-rejection exports under all four decoder configurations. The census does not establish export targets or masks, payload coupling, message semantics, native linkage, authenticated entry, or executable Metal coverage. No title shader was executed or modified.

## Same-wrapper PS target comparison

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-ps-exports "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$WRAPPED_DXBC_DIRECTORY"
# Repeat with gfx1030.
```

All 12,101 PS wrappers have one checked native stage-5 payload and a supported `OSG1` color-target projection. The source set is the `SV_Target` semantic ordinals with public enum 64. The native set is the union of reachable `exp mrt0`–`exp mrt7` ordinals whose raw four-bit enable field is nonzero, in a complete strict graph. The public six-bit target field and LLVM's symbolic target must agree. `MRTZ`, `NULL`, and zero-enable color exports are counted separately. A payload with an unclassified EXP is not compared. These are wrapper counts, not pipeline or attachment counts.

| CPU (either wave test) | Complete | Exact ordinal sets | Mismatched | Has MRTZ | Has NULL |
|---|---:|---:|---:|---:|---:|
| `gfx1013` | 12,091 | 11,870 | 221 | 1,171 | 6,180 |
| `gfx1030` | 6,188 | 5,967 | 221 | 1,166 | 2,497 |

No complete payload has a zero-enable color EXP or an unclassified EXP in either comparison. Every mismatch in each pass has both source-only and native-only ordinals, with equal cardinality; the native set is always dense from `mrt0` through ordinal `count - 1`. This supports a compact set hypothesis for those cases but does not establish the order of any mapping, component writes, whether a path actually reaches a given export, or the PSO attachment binding. The two wave settings give identical projected results per wrapper, not a measured native wave width.

A separate same-wrapper test compares the [PSV0 `DepthOutput` flag](wrapped-signatures.md) against reachable `MRTZ` presence. In complete `gfx1013` graphs all 1,171 positive flags have an `MRTZ` and all 10,920 clear flags do not. The `gfx1030` counts are 1,166 and 5,022, also with zero disagreement. Every observed `MRTZ` in those complete graphs has raw `EN=1`; no other four-bit enable value is observed. This says which encoding correlates with the depth declaration, not what value is computed, which source components feed it, whether it executes for a specific fragment, or whether the depth attachment receives a write. Rejected graphs do not contribute to this comparison.

## PSO candidate projection

With its optional LLVM reference, [the wrapped/library audit](shader-pipeline-library.md) joins each PSO row to PS wrapper candidates by the exact PS metadata footer digest and stage. Each candidate must have one stage-5 FSSM payload with a complete, classifiable PS export projection under both wave settings of the selected CPU, and both settings must agree on the color set. Multi-wrapper families are compared only when both source and native sets are invariant across every candidate. This is **not** an exact match to the library's native program bytes.

| CPU | Slots | Unique candidate compared | Invariant multi compared | Missing family | Unsupported | Source/native sets differ |
|---|---|---:|---:|---:|---:|---:|
| `gfx1013` | PS+VS | 13,340 | 24 | 19 | 0 | 11 |
| `gfx1013` | PS+MS | 10,656 | 70 | 0 | 0 | 250 |
| `gfx1030` | PS+VS | 10,029 | 18 | 19 | 3,317 | 11 |
| `gfx1030` | PS+MS | 4,250 | 24 | 0 | 6,452 | 250 |

Two extra-slot rows lack a PS family under either CPU; neither pass has a divergent family in the checked projection. All 261 differing rows per pass have native sets packed from `mrt0` and bounded eight-byte residuals at the empirical state baselines. In **none** does the position set of nonzero residual chunks match either the declared set or the candidate's compacted native set. The result does not support interpreting those residuals as target-indexed arrays, even after compaction, and does not determine bound attachments. Counts are per PSO row, not distinct shaders.
