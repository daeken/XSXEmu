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

The message classification requires the public four-byte SOPP opcode and recognized immediate fields to agree with LLVM's symbolic operands. Unrecognized cases stay grouped, with no operands printed. Only the first rejection is counted; neither the operation names nor the reported stream encoding establish how the Xbox schedules or couples stages. Strict graphs reject messages without assuming fallthrough or exit. The owned fixture also rejects noncanonical bits and a numeric-only operand presentation.

None of the 158 stage-2 or 788 stage-4 first `s_swappc_b64` blockers matches the tested adjacent local `GETPC` + literal `ADD`/carry or `SUB`/borrow window with distinct ordinary source/destination register pairs, under either CPU or wave test. The same narrow literal-PC hypothesis also matches none of the 37 stage-2 first `s_setpc_b64` blockers under any decoder configuration. The classifier inspects only the immediately preceding checked fallthrough decode sequence; it does not rule out nonadjacent setup or other control-flow paths. It adds no successor and does not model a call, return, or link register.

Every complete strict graph has at least one reachable eight-byte `exp` checked against LLVM and the public GFX10 encoding prefix. No export result is attributed to an incomplete graph. An owned fixture distinguishes reachable, branch-skipped, and seen-before-rejection exports under all four decoder configurations. This census does not establish payload coupling, message semantics, native linkage, authenticated entry, or executable Metal coverage. No title shader was executed or modified.

## Separate GS/MS message projection

For GS/MS only, a second pass is run on strict first rejections at a recognized message. This pass assumes a single local fallthrough edge after each checked `s_sendmsg` in the public GS emit/cut/emit-cut, GS done/NOP, or GS allocation-request set. Other messages and control, graph extents, decoder errors, and the checked `s_endpgm` requirement are unchanged. No actual message effect, external state, invocation coupling, or guarantee of resumption is modeled.

Under this hypothesis all 195 GS payloads complete in both CPU passes with no checked reachable `EXP`. All 9,282 eligible MS payloads complete with checked reachable `EXP` on `gfx1013`; all 8,258 eligible complete with `EXP` on `gfx1030`, and 1,024 rejected earlier by the strict decoder do not enter the projection. Both wave settings give the same aggregate counts. This is not part of the strict census or a substitute for checking message behavior on the title hardware.

In the complete mesh projections, every payload has both raw `EN=0` and `EN=15` at checked `POS0` exports, and only `EN=1` at checked `PRIM` exports (public target 20 and LLVM symbolic `prim`). `POS1` occurs in 1,906 (`gfx1013`) and 1,644 (`gfx1030`) payloads; no higher `POS` occurs. Nonempty enabled `PARAM` sets are present in 7,543 and 6,785 payloads, respectively, all dense from ordinal zero. No zero-enable `PARAM`, color, `MRTZ`, `NULL`, or unclassified export is seen in these complete projections. The masks describe reachable instruction encodings across a graph, not which sites execute or how primitive payloads or null vertices are interpreted.

Counting reachable instruction starts, every complete mesh projection contains exactly two checked `PRIM` sites: 18,564 sites for `gfx1013` or 16,516 for `gfx1030`, independently under either wave setting. Every first dword has raw bit 11 set and bits 10 and 12 clear. In the validated local graph, the immediate fallthrough successor of each is a non-export linear instruction, not `POS0`, another `EXP`, a direct jump or fork, or `s_endpgm`. The raw bit does not terminate the projected graph. Two static sites do not imply two primitive exports execute or identify the primitive count, indices, or payload semantics.

### Same-wrapper mesh output comparison

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-ms-exports "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$WRAPPED_DXBC_DIRECTORY"
# Repeat with gfx1030.
```

All 9,282 DXIL stage-13 wrappers have a single checked raw stage-7 payload. The source projection requires an empty PSV0 input group and primitive signature group, zero primitive signature vectors, and an OSG1 row count equal to the PSV0 vertex output count. It does not require a zero primitive limit. The checked stream-zero OSG1 projection separates public position and clip/cull declarations from ordinary registers. No other system outputs occur in the compared cases.

Both wave settings agree on each wrapper's result. The strict walk stops at a checked allocation message for all 9,282 `gfx1013` wrappers and 8,258 `gfx1030` wrappers; the remaining 1,024 `gfx1030` wrappers stop earlier at decode and are not compared. Every eligible separate message projection is complete. Position presence agrees with `POS0` in every comparison; clip-or-cull presence agrees with `POS1` in both directions (1,906 or 1,644 positives, respectively). Every complete payload still has a checked `PRIM`, although every checked source primitive signature is empty. `PRIM` presence cannot be used to infer a declared per-primitive varying.

| CPU (either wave test) | Projected complete | Native PARAM ordinal count lower / equal / higher than ordinary source register count | Exact unshifted set | Native EN-union bits lower / equal / higher than source primary-mask-union bits |
|---|---:|---:|---:|---:|
| `gfx1013` | 9,282 | 3,724 / 5,024 / 534 | 1,811 | 4,558 / 4,233 / 491 |
| `gfx1030` | 8,258 | 3,458 / 4,452 / 348 | 1,541 | 4,258 / 3,695 / 305 |

Counts use active `PARAM` ordinals and unions grouped separately by native ordinal and source register, as in the VS comparison below. They rule out a uniform one-to-one mapping of these projections. Neither the same-wrapper join nor the presence comparisons identify packing, native linkage, a primitive payload format, an executed wave width, or a launch contract.

## Native VS export projection

The stage-4 check cross-validates the six-bit public target field for `POS0`–`POS4` and `PARAM0`–`PARAM31` against the LLVM mnemonic and symbolic operand. Under both wave tests every complete `gfx1013` stage-4 graph (1,448) and every complete `gfx1030` stage-4 graph (1,242) contains `POS0` with raw `EN=15` and a nonempty dense set of enabled `PARAM` ordinals starting at zero. Neither pass observes a zero-enable `PARAM` or an export outside `POS`/`PARAM` in a complete stage-4 graph. In each pass 20 payloads also have `POS1`, none has `POS2`–`POS4`. Both wave settings agree on the per-payload projection. These are reachable target and enable-field observations only; they do not correlate parameter ordinals with source declarations, physical interpolation slots, or an individual executed path.

## Same-wrapper VS output comparison

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-vs-exports "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$WRAPPED_DXBC_DIRECTORY"
# Repeat with gfx1030.
```

All 2,236 VS wrappers join their checked `OSG1` to the unique raw stage-4 FSSM payload in the same wrapper. The 195 additional raw stage-2 companion payloads are not included in the comparison. Source rows with public `SV_Position`, `SV_ClipDistance`, or `SV_CullDistance` name/enum pairs are counted separately from ordinary output registers. There are no other system outputs in the complete cases. In both decoder passes, `SV_Position` presence agrees with `POS0` in every complete graph and all 20 cases with `POS1` have a clip-or-cull declaration, with neither direction of disagreement. This is a presence correlation, not a packing or lane assignment.

| CPU (either wave test) | Complete | Native PARAM count lower than ordinary source registers | Equal count | Higher count | Exact unshifted ordinal set |
|---|---:|---:|---:|---:|---:|
| `gfx1013` | 1,448 | 434 | 878 | 136 | 5 |
| `gfx1030` | 1,242 | 394 | 712 | 136 | 5 |

The ordinary projection counts distinct source register numbers, including shared registers once. The native projection counts distinct reachable nonzero-enable `PARAM` ordinals. Neither direct ordinal equality nor a uniform one-to-one compaction explains the corpus. Counting mask bits also fails to establish uniform correspondence: union the `OSG1` ordinary primary masks per source register, union reachable raw `EN` masks per native `PARAM` ordinal, then compare the total set bits. The native total is lower/equal/higher in 93/121/1,234 `gfx1013` cases and 65/118/1,059 `gfx1030` cases. These are comparisons of stored and encoded mask bits, not live channels, lane values, compression semantics, native linkage, or stage-pair placement.

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
