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

The probe also checks `v_fmac_f32_e32` with two unmodified VGPR operands. The typed operation reads the old destination as its third input; an undefined destination or scalar source is rejected. Strict replay matches two exact finite FMAC results, including the cancellation case that would give zero after a rounded multiply. This form adds 75,989 VS / 1,211,682 PS matched sites under `gfx1013` and 61,421 VS / 102,414 PS under `gfx1030`, with zero whole graphs free of encoding gaps. The keyed VS/PS fixture is unchanged.

The census also splits unsupported EXP sites by checked numeric and LLVM-symbol target class, raw EN mask, and the raw value of bits 10–12. It retains an unclassified bucket for any rejected EXP whose fields and symbol cannot be reconciled. Before adding the packed MRT0 decoder, both independent wave checks reproduced the same 11 PS shapes per reference. Each table cell counts distinct payloads / static sites; the payload counts are not additive.

| Target | EN | Bits 10–12 | `gfx1013` | `gfx1030` |
|---|---:|---:|---:|---:|
| MRT0 | 15 | 1 | 6,353 / 6,353 | 2,155 / 2,155 |
| MRT0 | 15 | 7 | 2,589 / 2,589 | 1,953 / 1,953 |
| MRT0 | 3 | 1 | 812 / 812 | 10 / 10 |
| MRT0 | 3 | 7 | 736 / 736 | 602 / 602 |
| MRT1–7 | 15 | 1 | 4,013 / 10,645 | 1,048 / 2,716 |
| MRT1–7 | 15 | 7 | 5,017 / 5,017 | 1,211 / 1,211 |
| MRT1–7 | 3 | 1 | 970 / 970 | 87 / 87 |
| MRT1–7 | 3 | 7 | 2,148 / 2,148 | 954 / 954 |
| MRTZ | 1 | 0 | 31 / 31 | 27 / 27 |
| MRTZ | 1 | 6 | 1,140 / 1,140 | 1,139 / 1,139 |
| NULL | 0 | 6 | 6,180 / 6,495 | 2,497 / 2,810 |
| **Total sites** | | | **36,936** | **13,664** |

VS has two classified gaps on each reference: PARAM1–31 EN15 value 0 (1,172 / 6,364 and 966 / 5,328), and POS1–4 EN15 value 2 (20 / 20 each). This is an encoding census, not an attachment map, output format inference, or export-sequence validator. Owned LLVM MC checks on both references identify bits 10, 11, and 12 as `compr`, `done`, and `vm`. The broadest single PS candidate is compressed full-mask MRT0 without `done` or `vm`. It needs independently verified source packing and an explicit owned target format; partial EN also needs an explicit disabled-component policy. Attachment ordinals, `vm`, and NULL must not be inferred from these counts or treated as unconditional no-ops.

### Owned full-mask packed color

AMD's [RDNA 2 Shader ISA](https://gpuopen.com/download/rdna2-shader-instruction-set-architecture.pdf), §§11.1–11.2 and §13.9, gives R/G in VSRC0 and B/A in VSRC1, low half first. `compr` alone does not select float vs integer interpretation. LLVM MC on both CPUs gives words `0xf8001c0f 0x00000001` for `exp mrt0 v1, v1, v0, v0 done compr vm`; without `done vm` it gives `0xf800040f 0x00000001`. The decoder admits only these full-mask flag combinations, with zero unused source bytes. The separate packed pixel ABI explicitly selects binary16 RGBA (`FP16_ABGR`), slot zero, and one final DONE+VM export followed by a real `s_endpgm`. It does not modify EXEC or run side effects, so ordinary Metal raster coverage supplies the valid mask in this fixture. Neither a no-VM shader nor partial masks, arbitrary EXEC updates, NULL, or other MRT slots are admitted by this profile.

`smoke-graphics-lift.sh` also runs this ABI from generated MSL and from an offline metallib. On Apple M4, both match all 64 RGBA32Float pixels bit-for-bit: 20 scissored pixels receive `(-2, 0.25, 1.5, -0.5)` from two raw ABI words in reversed VGPR order, and 44 outside retain the clear value. The original keyed fixture still passes strict archive replay and its independent miss control. The packed probe does not bake or replay an archive.

With both bounded encodings recognized, PS matched sites rise by 8,942 under `gfx1013` (to 4,204,516 / 18,916,461) and 4,108 under `gfx1030` (to 380,101 / 2,027,022); VS counts are unchanged. Remaining unsupported PS EXP sites are 27,994 and 9,556. Wave checks agree and zero whole graphs become encoding-complete. Static encoding matches do not prove any retail pixel format, attachment binding, lane behavior, or shader conversion.

The live census output splits the earlier table's target classes by exact six-bit ordinal and prints `compr`, `done`, and `vm` separately. For example, the largest remaining PS shape is target 9 (NULL), EN0, uncompressed, DONE+VM: 6,495 / 2,810 sites under `gfx1013` / `gfx1030`. The largest remaining full-mask compressed color shape is target 1, EN15, neither DONE nor VM: 4,007 / 1,047 sites. Neither count implies an attachment binding. The next observable depth-only shape is target 8, EN1, uncompressed, 31 / 27 nonfinal sites and 1,140 / 1,139 DONE+VM sites; an owned depth compare/write oracle can distinguish the actual depth export from raster depth independently of a title color-slot map.

After packed MRT0, the export encoding gate alone is clear in 1,983 / 12,091 complete PS graphs under `gfx1013` and 1,580 / 6,188 under `gfx1030`; the corresponding VS values are 276 / 1,448 and 276 / 1,242. Counts include only complete reference graphs, agree across wave checks and do not validate export sequencing. No graph has EXP as its only remaining encoding gap, so expanding just EXP further cannot yet make an entire graph encoding-complete.

### Owned final scalar depth

Selected target 8 (`MRTZ`), EN1, uncompressed, DONE+VM because it introduces a distinct depth output and test/write behavior without needing to recover any additional color attachment. AMD's RDNA 2 ISA §§11.1–11.2 identifies the depth target and uncompressed source enables. LLVM MC independently gives `0xf8001881 0x00000002` for `exp mrtz v2, off, off, off done vm` on both reference CPUs; the [same-wrapper `DepthOutput` comparison](graphics-reachability.md) corroborates the depth classification but does not prove a bound depth attachment. The owned profile requires a full-mask nonfinal packed MRT0 export, followed by final scalar MRTZ and then `s_endpgm`, with no EXEC changes. Multi-component depth exports, nonfinal MRTZ, and noncanonical unused operand bytes still reject.

The lift writes the scalar operand as `[[depth(any)]]`. The owned Metal descriptor uses Depth32Float and RGBA32Float, a depth clear of 1/2, a strict-less comparison, and depth writes. The first draw has raster Z=7/8 but exports 1/8, so its color survives the clear-depth test only if shader depth is used. The overlapping draw has raster Z=1/8 but exports 2/8, so its color wins only outside the first draw if depth was written. The independent integer CPU oracle distinguishes both no-export and no-write behavior. Apple M4 source compilation and standalone offline metallib each match all 64 pixels bit-for-bit (20 first color, 10 second color, 34 clear); the original strict archive and its negative controls still pass. This depth variant is not an archive job.

This exact depth encoding adds 1,140 / 1,139 PS matching sites for `gfx1013` / `gfx1030`, to 4,205,656 / 18,916,461 and 381,240 / 2,027,022. Remaining PS EXP sites are 26,854 / 8,417, including 31 / 27 nonfinal scalar MRTZ sites. The EXP encoding gate alone clears for 720 more complete PS graphs on each reference, to 2,703 / 12,091 and 2,300 / 6,188. Both wave checks agree; VS counts are unchanged, there are still zero whole encoding-complete graphs, and no retail descriptor or translation is inferred.

### Nearest complete reference graphs

The census reports the three smallest positive unsupported-site distances per stage/CPU/wave, grouped by the multiset of missing forms (six most frequent patterns and a remainder count). The current projection splits MOV and packed RTZ by source selector class and width, NOP and prefetch by immediate, and EXP by raw target/mask/flags; remaining opcodes are explicitly labeled operands-unclassified. Counts rank complete strict graphs by static instruction sites only; a mnemonic can still hide distinct operand forms. Under both references and wave checks, 10 VS graphs are closest at nine missing sites each: six EXPs, two MOVs and one instruction prefetch. The next 95 VS graphs each have ten gaps; the 93-graph dominant pattern has no EXP gap, but includes byte conversion, logical, shift, FMA, MOV and prefetch gaps. The closest 18 PS graphs have six missing sites each: one prefetch, two NOPs, two packed round-toward-zero F32-to-F16 conversions and one MOV. Another 298 PS graphs each have seven missing sites: 296 have one each of EXP, prefetch, packed conversion and MOV plus three NOPs; the other two have one prefetch, two NOPs, two packed conversions and two MOVs. Thus the nearest two ranks total 18 + 296 + 2 = 316 graphs, with 36 + 296 + 4 = 336 packed conversion sites. This makes packed RTZ a functional target for the nearest PS cohorts, rather than prioritizing solely by global frequency. These ranks exclude rejected reference graphs and do not establish liftable whole programs, instruction-cache or scheduling semantics, or title ABI.

AMD's RDNA 2 ISA, §12.2 (VOP2 opcode 47), specifies RTZ regardless of the active rounding mode, with source zero in the low half and source one in the high half. LLVM MC confirms `0x5e0a0300` for `v_cvt_pkrtz_f16_f32_e32 v5, v0, v1` under both reference CPUs. The separate raw-bit arithmetic probe verifies three packed results in offline strict archive replay on Apple M4, including an above-tie case where nearest-even would change both halves and cases checking signed zero and source order. The existing legacy and FMAC checks still pass. This establishes the tested finite normal-result and signed-zero behavior; graphics ABI admission remains withheld pending provenance and unvalidated floating-point modes or exceptional values.

The two-VGPR encoding adds 53,874 / 17,723 checked PS site matches under `gfx1013` / `gfx1030` and no VS sites. Both wave checks agree: the 18 closest PS graphs go from six unsupported encoding sites to four (prefetch, two NOPs, MOV); the next distances are five sites in two graphs and six sites in 299 graphs. No whole graph becomes encoding-complete and no title shader is translated. The exact remaining shape split of the closest 18 PS graphs agrees across both CPUs and waves: all have prefetch immediate 3 and two NOPs with immediate 0. Their one remaining MOV has selector 128 in nine graphs, 242 in four, 240 in three, and literal selector 255 in two. This output does not disclose register indices, literal values, or program identities.

### Raw MOV and bounded scheduling hints

Both LLVM MC references independently identify MOV selectors 128, 240 and 242 as raw `0x00000000`, `0x3f000000` and `0x3f800000`, and selector 255 consumes one raw literal dword. The lift writes an unsigned 32-bit value, not a host float. The standalone arithmetic fixture reads back 52/52 words on Apple M4 in offline strict archive bake and replay, including a literal with a noncanonical NaN payload treated as raw bits. AMD RDNA 2 ISA §§2.5 and 12.5 documents `s_inst_prefetch 3` as a three-cacheline fetch-mode change (with native shader padding requirements) and `s_nop 0` as one cycle with no register effect. These exact words are omitted only in the synthetic straight-line profile without guest instruction fetch, memory synchronization or observable timing; no native padding rule is waived. Other immediates, waits and unknown forms still reject. The original keyed graphics fixture and guard cases pass unchanged.

Both wave checks agree: the decoder now matches 193,768 / 950,624 VS and 4,770,056 / 18,916,461 PS sites under `gfx1013`, and 149,173 / 636,957 VS and 469,297 / 2,027,022 PS sites under `gfx1030`. The 18 closest PS graphs clear their last four encoding gaps; there are 21 encoding-complete PS graphs per reference in total (out of 12,091 and 6,188); no VS graph is encoding-complete. Exactly 299 PS graphs are now one site away: 296 are missing packed MRT0 EN3 DONE+VM, and three are missing packed MRT1 EN15 DONE+VM. The ten nearest VS graphs each lack exactly six full-mask PARAM exports (targets 33–38). These are encoding counts, not conditional control-flow validation, register/attachment ABI admission, or retail translation.

### Owned partial packed RG export

AMD RDNA 2 ISA §11.1 defines compressed EN3 as enabling VSRC0 (R and G), not VSRC1 (B and A). Both LLVM MC references encode the owned final `exp mrt0 v1, v1, off, off done compr vm` as `0xf8001c03 0x00000001`. This profile reads only the live packed RG VGPR, requires canonical zero unused selectors, and requires one final export followed by `s_endpgm`. It uses the same synthetic FP16_ABGR format and fixed raster valid-mask assumption as the full-mask fixture, but only with a separate RG-only write mask and blending disabled. No general relationship between guest export enables and retail color-attachment write masks is assumed.

Apple M4 matched all 64 RGBA32Float pixels from generated source and offline metallib. The independent CPU oracle requires 20 covered pixels to get R/G = (-2, 0.25) while preserving nonzero B/A = (1, 0.75); 44 outside pixels retain clear. This would fail if disabled channels were zeroed or sourced from the second packed ABI word. Full-mask, depth, and strict keyed-archive regressions pass.

This exact form adds 736 / 602 PS matches under `gfx1013` / `gfx1030`, and clears the last encoding gap in 296 graphs on each reference. Both wave checks now find 317 encoding-complete PS graphs (of 12,091 / 6,188), three PS graphs one exact packed MRT1 site short, and no encoding-complete VS graphs. Other masks, nonfinal compressed RG, and alternate targets remain outside this profile. These are reference decoder totals, not actual retail translation or bake coverage.

### Owned multi-PARAM linkage

The decoder now accepts uncompressed full-mask PARAM1–6 (raw targets 33–38), with DONE, VM and reserved bits clear. LLVM MC verifies all seven PARAM exports, POS0 and `s_endpgm` in the owned producer on both reference CPUs. The explicit fixture profile assigns one contiguous float4 input and one `center_no_perspective` varying per ordinal, requires exactly PARAM0–6 in its chosen order followed by final POS0 and `s_endpgm`, and rejects duplicate slots, uninitialized operands, unsupported targets and flags. This fixture order is not a claim about every native producer.

An authored fragment consumer declares the seven Metal `user(paramN)` links in reverse order and weights slots 1 through 7, so positional swaps change the result. The independent CPU oracle uses integer-derived channel sums and a dyadic horizontal ramp over the eight pixel centers. Apple M4 matched 64/64 RGBA32Float pixels both from generated MSL and from an offline metallib. The existing strict keyed fixture still passes. This verifies an owned native vertex producer and explicit linkage, not a translated native pixel consumer or a retail varying map.

Both wave checks agree: 4,763 / 4,033 new VS sites match under `gfx1013` / `gfx1030`, to 198,531 / 950,624 and 153,206 / 636,957. Ten complete VS reference graphs per CPU clear all encoding gaps (of 1,448 / 1,242); another 740 / 610 graphs clear the EXP encoding gate only. PS counts remain 317 encoding-complete per CPU. No title ABI, title pipeline, or bake coverage is established.

### Owned two-attachment packed export

Both LLVM MC references verify the final full-mask packed MRT1 `DONE+VM` word `0xf8001c1f` and its packed RG/BA source order. The owned profile requires nonfinal packed MRT0, final packed MRT1, and an actual `s_endpgm`, with no EXEC changes. Metal binds native ordinals 0 and 1 explicitly to `[[color(0)]]` and `[[color(1)]]` with separate RGBA32Float attachments, full write masks, and blending disabled. This is not a rule for compacting or recovering title attachment ordinals. The two-attachment profile rejects nonfinal MRT1, partial masks on MRT1, and higher targets.

Reversed source VGPRs produce distinct RGBA colors in the two attachments. Independent CPU expectations check 20 written and 44 untouched pixels per slot, with distinct clears. Apple M4 matched all 128 attachment pixels bit-for-bit from generated MSL and from the offline metallib. This probe does not bake an archive; the original keyed strict regression is unchanged.

The decoder gains 2,310 / 602 matching PS sites under `gfx1013` / `gfx1030`. Both wave checks now count 320 / 12,091 and 320 / 6,188 PS reference graphs without an encoding gap (three additional per reference), and unchanged VS totals. The nearest remaining incomplete PS cohort has seven graphs with two gaps each. No title attachment mapping, translation, or bake coverage is inferred.

### Owned lane-local compare and select

The nearest-site audit isolated two PS graphs missing `v_cmp_ne_u32_e32` with inline integer zero (selector 128) and a VGPR, followed in their missing-form signatures by `v_cndmask_b32_e32` with literal S0 (selector 255) and VGPR S1. The exact forms match LLVM MC on both references. AMD's RDNA 2 ISA defines the comparison as unsigned integer inequality and VOP2 select as choosing S1 when the current VCC bit is set, S0 otherwise. The owned straight-line pixel profile maintains only the active lane's locally defined predicate; a second compare overwrites it. It rejects uninitialized operands or predicate and does not implement compare-and-write-EXEC, wave-wide VCC observation, subgroup communication, or an EXEC transition. Wave32/64 below are independent reference decoder settings, not runtime lane-layout validation.

The Apple M4 strict offline arithmetic probe matches 8/8 select words in bake and replay. Mixed lanes exercise both operand choices and both predicate transitions, including `+0` vs the nonzero integer bit pattern of `-0`, an infinity word passed through unchanged and a NaN payload returned as raw bits. No floating-point comparison or NaN policy is assumed. The keyed graphics replay is unchanged.

Both wave checks agree: the decoder gains 590 / 404 VS sites and 26,215 / 2,690 PS sites under `gfx1013` / `gfx1030`. Encoding-complete PS reference graphs rise from 320 to 322 (of 12,091 / 6,188); VS stays at ten per reference. Five PS graphs now share the closest incomplete distance of two sites. No title ABI, execution, or translation follows from these counts.

### Owned three-attachment packed export

LLVM MC confirms full-mask compressed MRT1 without DONE or VM (`0xf800041f`) and full-mask compressed MRT2 with DONE+VM (`0xf8001c2f`) on both reference CPUs. The owned three-attachment profile requires nonfinal MRT0, nonfinal MRT1, final MRT2, and an actual `s_endpgm`. It admits only initialized packed RG/BA operands with canonical unused selector bytes and does not change EXEC. The full-mask profile rejects partial MRT1; nonfinal MRT2 and higher targets remain unsupported.

The Metal descriptor explicitly maps ordinals 0–2 to three RGBA32Float textures with full write masks, no blending, and separate clears. Each slot has a distinct output color and clear sentinel. Apple M4 matched all 192 attachment pixels from generated MSL and again from the offline metallib (20 drawn and 44 untouched per slot). The original keyed archive and strict miss controls still pass; the three-slot probe does not bake an archive.

Both wave checks agree. The two exact encodings add 4,901 / 1,223 PS matching sites under `gfx1013` / `gfx1030`, to 4,804,218 / 18,916,461 and 474,414 / 2,027,022. The EXP encoding gate clears for 176 / 163 more complete PS graphs; whole encoding-complete PS counts rise from 322 to 324 on both references (out of 12,091 / 6,188), with VS unchanged at ten per reference. One remaining PS graph is one site short (nonfinal packed MRT1 EN3). The next two are each two short (nonfinal scalar MRTZ and `s_waitcnt`); a wait is not treated as a scheduling hint. These are decoder counts, not validation of retail export order, attachment bindings, translation or bake.

### Owned partial nonfinal MRT1

The separate three-slot RG profile accepts nonfinal compressed MRT1 EN3 (`0xf8000413`), confirmed by LLVM MC on both references (`exp mrt1 v0, v0, off, off compr`). It reads one initialized RG source with all other selector bytes zero. The ordered profile still requires nonfinal full MRT0, then exactly RG-only MRT1, then full MRT2 with DONE+VM, then `s_endpgm`; exchanging the MRT1/MRT2 instructions or mixing the full and partial profiles rejects.

Only attachment 1 has the RG-only Metal write mask. Its covered pixels get R/G = (1.5, −0.5) and retain nonzero B/A = (0.75, 1) from the clear, while MRT2 still writes all four channels. Generated MSL and offline metallib each match 192/192 pixels against the independent CPU oracle on Apple M4. A separate negative control binds the full-mask shader's MRT1 and MRT2 textures in reverse, keeping readback order unchanged: all 128 pixels in those two slots differ from the normal mapping and match the predicted swap, while MRT0 is unchanged. This demonstrates sensitivity to actual attachment permutation without making assumptions about title ordinals.

The exact EN3 form adds 15 / 7 matching PS sites under `gfx1013` / `gfx1030`; both wave checks now count 325/12,091 and 325/6,188 encoding-complete PS graphs, one more on each reference. VS counts are unchanged. The nearest two incomplete PS graphs still have nonfinal scalar MRTZ and `s_waitcnt`; no wait is admitted or removed.

### Owned nonfinal scalar depth and the remaining export wait

Both LLVM MC references confirm `0xf8000081` for scalar EN1 MRTZ with DONE, VM and COMPR clear. The separate owned profile requires one initialized depth source with canonical zero unused selectors, followed by full packed MRT0 with DONE+VM and actual `s_endpgm`. It rejects the reverse profile, a nonfinal color tail, and an inserted wait. The Metal pipeline uses explicit Depth32Float with less testing and writes and an RGBA32Float color target. The independent overlap oracle requires shader Z=1/8 to win the first draw, Z=2/8 to lose in the overlap but write a different full color where its draw is alone, and the clear elsewhere. Apple M4 matched 64/64 pixels both from generated MSL and from the offline metallib (20 first color, 10 second color, 34 clear). This probe does not bake an archive.

The public `s_waitcnt expcnt(0)` form independently assembles to `0xbf8cff0f` on both CPUs (VMCNT and LGKMCNT set to their GFX10 maxima of 63). AMD RDNA 2 ISA §§11.4 and 12.5 explain that EXPCNT tracks pending exports and that the hardware may read the export VGPR and EXEC after issue; waiting until zero protects them against overwrite before transfer. In both complete reference graphs where this is the sole gap, the wait directly follows nonfinal scalar MRTZ on a linear path and a later packed RTZ conversion overwrites that export's source VGPR. The audit reports the aggregate relationship, not register numbers or program identities. An owned wait-free fixture does not prove that ordering: any future lowering needs to preserve the pre-overwrite export value and account for the outstanding-export dependencies in its admitted profile. The wait is neither admitted nor omitted here.

Both wave checks agree: nonfinal scalar MRTZ adds 31 / 27 matching PS sites under `gfx1013` / `gfx1030`, to 4,804,264 / 18,916,461 and 474,448 / 2,027,022, and clears the EXP encoding gate in six additional PS graphs per CPU. Whole encoding-complete PS counts remain 325/12,091 and 325/6,188; VS is unchanged at ten per CPU. No retail depth state, translation or bake is inferred.

### Owned export completion before register reuse

The separate snapshot fixture accepts only nonfinal scalar MRTZ → exact `s_waitcnt expcnt(0)` → two-VGPR packed RTZ → final packed MRT0 → `s_endpgm`. It requires one outstanding export, fixed EXEC, an RTZ overwrite of the depth source register, and use of that overwritten register as the final color's packed RG. Other counter values, missing or reordered waits, and unrelated destination registers reject. LLVM MC verifies the full owned stream on both CPU references. The lowerer snapshots the raw depth operand and completes that export from the snapshot before reusing its register; it does not emit a Metal barrier or treat the wait as a scheduling hint. This model is confined to the single-export, straight-line, memory-free fixture and its owned finite RTZ inputs.

Two overlapping draws use 1/8 and 1/4 as the captured depth and distinguishable packed colors. The RTZ inputs lie above the midpoint to the next half, so round-to-nearest would also fail the color oracle. Apple M4 matched 64/64 pixels from generated MSL and from an offline metallib. An independent late-read control sources depth from the overwritten packed RG word, where the bit pattern now represents 3/4 or 1 as float32. Both fail the strict-less test against the 1/2 clear, and readback verified all 64 pixels remained clear instead of the 30 expected color writes.

The general stage lift and reference gap census still reject a standalone wait. The census reruns are unchanged, including both wait-bearing PS graphs; the owned dependency proof does not admit those whole graphs or validate retail bindings, floating-point modes or bake.

### Contextual wait eligibility and next gates

The separate static audit runs only on complete reference paths where exact `expcnt(0)` is the sole encoding gap. It requires contiguous fallthrough, one scalar nonfinal MRTZ directly before the wait, no other pending work or EXEC changes in the checked instruction set, local definitions of depth and both packed conversion inputs, an overwrite of the original depth VGPR, final full packed MRT0 consuming that overwritten value, and true termination. It assumes no incoming VGPR values. The proof accepts normalized depth in [0,1] and packed conversion sources that are signed zero or within the finite half-normal range. It does not use source metadata to supply values or ABI.

Both eligible reference PS graphs pass these checks on both CPU and wave settings. They are **static snapshot-eligible**, not encoding-complete or translated: this covers the dependency under the checked entry and decoder hypotheses, not actual Xbox entry/EXEC/raster state, color binding, floating-point modes or attachment state. The context-free census is unchanged at 325/12,091 and 325/6,188 complete PS graphs without an encoding gap. No other wait is accepted.

Remaining nearest cohorts, ranked by number of whole graphs affected on each reference (not predicted translation gains):

| Gate | Whole-graph cohort | Remaining work |
| --- | ---: | --- |
| VS byte unpack and FMA | 104 at seven sites each | 102 share two ANDs, two byte-0-to-float conversions, two FMA and one shift; two substitute one U32 conversion. Another 18 have similar arithmetic plus a true wait and are separate. Exact operand fields still need checking. |
| PS interpolation and linkage | 6 at three sites each; 2 more at four | Scalar MOV plus interpolation phase 1/2, and one subtraction in the latter two. Check exact scalar destination/immediate, paired attribute/channel/temporary selectors, and their actual dependency. |
| PS export completion | 2 at one site each | Both meet the bounded static snapshot proof above; actual bindings and title execution are still unvalidated. |
| PS higher color ordinals | 1 at three sites | Two nonfinal full-mask exports and one final partial export; an owned mapping would not establish a title attachment map. |

The VS arithmetic cohort has the largest potential encoding gain. The next owned validation should target the PS interpolation pair because it tests a missing end-to-end native VS→native PS linkage path, not another export variant. Use one explicitly mapped PARAM/channel and an explicit interpolation qualifier; choose asymmetric vertex data and a CPU pixel-center oracle that detects an attribute/channel swap or wrong interpolation mode. Verify the phase pair and scalar setup on both references before admitting any exact forms. No retail ordinal or interpolation mode follows from that owned interface.

### Owned native interpolation pair

LLVM MC on both references verifies `s_mov_b32 m0, s9` and `s_mov_b32 m0, s14`, VINTRP P1/P2 for attribute 0 channels X and Z, and the complete native vertex and pixel fixture streams. The separate profile requires an explicitly bound M0 source (owned zero state), full-precision PARAM0, I=v0 and J=v1, matching phase destination and attribute/channel, and a final color export of that result. AMD RDNA 2 ISA §10.4.2 describes the combined value `P0 + P10*I + P20*J`. The Metal rasterizer supplies the combined interpolation for this owned named PARAM0 link at pixel center without perspective correction. This is not a general M0 or LDS implementation; an individual VINTRP phase cannot be translated in isolation.

The independent CPU oracle computes pixel-center barycentric weights and, for the wrong-mode control, applies reciprocal W before normalization. Unequal clip W and independent X/Z gradients distinguish both errors. Apple M4 matched all 64 RGBA32Float pixels per channel from generated source and again from offline metallib (absolute error below 1e-6 per component). Both deliberate controls matched all 64 separately predicted pixels and differed from the correct X result at every pixel. The existing keyed strict archive is unchanged.

The shared exact encoding decoder adds 24,529 / 13,626 checked PS sites under gfx1013 / gfx1030, respectively. Both wave checks count 331/12,091 and 331/6,188 complete PS reference graphs without an encoding gap, six more per reference. Two additional PS graphs now have only the subtraction gap. VS remains at ten per reference and the separate contextual wait audit is unchanged. These measurements do not validate retail scalar inputs, barycentric VGPRs, attribute mapping, interpolation mode, translation or bake.

### Owned vertex byte unpack and FMA

LLVM MC checks both owned native vertex streams on `gfx1013` and `gfx1030`. The exact forms are shift-left-reverse with integer selector 129 (+1), AND selector 130 (+2) or 194 (−2), VGPR-source byte-0 or full unsigned conversion, and modifier-free VOP3 FMA of a VGPR with inline selectors (244,243) or (245,242), respectively `2*x−1` and `1−2*x`. The 104 formerly seven-gap VS graphs share this projected register pattern: one AND masks a raw input, the other masks the shifted input; each feeds its own conversion, then one FMA. 102 have two byte-0 conversions, and two use the full U32 conversion on the first path. This describes matching operand edges among the seven audited sites, not a whole-path dominance or input-binding proof.

The owned vertex shader takes raw U32 inputs, emits the two transformed values and both unsigned conversions on one explicit flat PARAM0 link, and uses an authored passthrough fragment shader. Four stripes per variant distinguish shift truncation, masking, signed FMA offsets and unsigned conversion. The integer-derived CPU table checks nearest-even ties in both directions at 2^25 and unsigned carry to 2^32, including the resulting FMA rounding. Apple M4 matched 64/64 RGBA32Float pixels bit-for-bit per variant in both source and offline metallib runs. The power-of-two coefficients do not distinguish split vs fused evaluation; the earlier dedicated FMA fixture tests that separately.

Both reference wave settings agree. Encoding-complete VS graphs rise from 10 to 114 per CPU (114/1,448 `gfx1013`, 114/1,242 `gfx1030`). Added site matches are 14,531 / 11,762 VS and 241,440 / 19,569 PS; whole PS counts remain 331 per CPU. Fifteen neighboring VS graphs have only the exact export wait remaining, and another three have that wait plus an unsupported unsigned conversion form. These waits are neither admitted nor omitted. Counts do not establish title pipeline bindings, translation, execution, or bake.

### Vertex export wait audit and next validation

The fifteen sole-gap VS graphs on both CPU and wave settings share an exact contiguous suffix: full POS0 with DONE, `s_waitcnt expcnt(0)`, one VGPR MOV overwriting a POS0 source, full PARAM0 consuming the overwritten register, and `s_endpgm`. A bounded prefix walk checks that there is no earlier export, wait, memory operation, EXEC change or branch. This proves a local operand-reuse hazard on the checked reference path. It does not prove input values, position conventions, or the POS0-DONE-before-PARAM0 protocol on Metal. The three VS with an additional conversion gap remain outside the audit. A future owned test should overwrite a position component with a distinct PARAM0 sentinel and independently verify both raster coverage and varying color, including a late-position-read control. Do not reuse the scalar depth proof to admit these waits.

The next independently verifiable encoding gain is smaller but simpler: the two one-gap PS graphs per CPU/wave both use exact `v_sub_f32_e32` with inline positive zero (selector 128) minus one VGPR. LLVM MC confirms the form on both CPU references. Validate it with raw-word readback, including signed zero (positive zero minus positive zero is positive zero under nearest rounding, not the result of a sign-bit XOR), plus finite values; keep denorm and NaN behavior scoped to separately proven modes. This audit does not change any encoding-complete counts or admit a wait or subtraction lowering.

### Owned vertex POS0 snapshot

The separate owned fixture admits the exact POS0 DONE → `expcnt(0)` → VGPR MOV → PARAM0 → `s_endpgm` stream, with one pending export and initialized position/parameter inputs. LLVM MC confirms the entire sequence on both reference CPUs. It rejects wrong counters or order, an undefined operand, or a MOV not linking the two exports. The Metal lowerer assigns the complete position output from the pre-MOV values and uses the post-MOV value only for the named PARAM0 link; it does not implement a general wait or barrier.

Apple M4 matched 64/64 pixels from source and again from offline metallib: 20 covered pixels carry the replacement X as PARAM0 red (with the other three checked channels) and 44 retain clear. In a deliberate late-position read, every clip X becomes the same constant and the triangle degenerates; all 64 remain clear and exactly 20 expected writes disappear. The fixture makes no change to the reference decoder, general lift, keyed archive or retail admission.

### Exact positive-zero subtraction

LLVM MC confirms `v_sub_f32_e32` with inline positive zero (selector 128) and an ordinary VGPR on both references. The lowerer emits an actual floating-point subtraction, not sign-bit inversion. Apple M4 strict arithmetic archive bake and replay each match 8/8 raw result words against literal goldens for both signed zeros, finite normals and both infinities under the owned compiler mode. The test does not establish denormal, NaN-payload or retail floating-point behavior.

Both wave checks agree: the exact form adds 6,117 / 167 matched PS sites and 14 / 3 VS sites for `gfx1013` / `gfx1030`. Whole encoding-complete PS rises by two each to 333/12,091 and 333/6,188. Whole VS stays at 114 per reference; no wait or title admission changes.

### Full-path owned-profile audit and packed constant RTZ

`--graphics-lift-gaps` keeps the original owned-profile histogram separate from the no-default static census below. The owned-profile audit passes only the contiguous reached prefix through the real `s_endpgm` to the same Rust validator used for the owned fixtures, without decoding trailing storage. Nonlinear graphs are counted separately. It tries the generic straight-line stage profiles with synthetic inputs and exports, not the dedicated interpolation, export-wait, or POS0-first fixtures. If no profile passes, the reported blocker is the rejection at the furthest instruction offset among applicable profiles (ties follow the fixed profile order); this is not a census of every missing semantic in a program.

Before admitting local constant RTZ, none of the encoding-complete graphs fit: the `gfx1013` blocker breakdown was 114 VS export profile mismatches and 333 PS rejections (325 packed RTZ, 8 interpolation). With the new RTZ profiles, both CPU references and both wave checks report the same result:

| Stage | Encoding-complete (`gfx1013` / `gfx1030`) | Fits owned shape | Remaining profile blockers |
|---|---:|---:|---|
| VS | 114/1,448 / 114/1,242 | 0 | 114 export profile mismatches |
| PS | 333/12,091 / 333/6,188 | 315 | 4 packed RTZ value/provenance, 8 interpolation, 6 export profile mismatches |

None of these encoding-complete graphs is nonlinear; encoding counts are unchanged. A fit means the full path passes a synthetic stage contract. It is not a title input, output, or interpolation binding, an actual floating-point mode check, a translated title shader, or a pipeline bake.

The two RTZ pixel profiles assume no live-in VGPRs. Each pack needs two values proven by local raw moves to be signed zeros or to have magnitudes from the minimum normal half through the maximum finite half, inclusive. A pack invalidates its destination's constant fact. The validator rejects unknown values, subnormal-domain inputs, overflow-domain inputs, infinities, NaNs, and wrong export shapes. It uses the existing integer RTZ helper and explicit packed MRT0 format and write-mask contracts, with no new decoder encodings.

LLVM MC matches both complete owned pixel streams on both references. Apple M4 readback matched 64/64 bit-exact `RGBA32Float` pixels for each full and RG-only shader, both from generated source and offline metallib. The positive and negative normal inputs above the half midpoint distinguish truncation from nearest rounding. The full output also checks negative zero and minimum positive normal half; the RG-only descriptor preserves nonzero clear B/A. The owned keyed archive and live admission are unchanged.

### No-default static full-path census

`--graphics-lift-gaps` now audits only encoding-complete, contiguous reference paths through the reached `s_endpgm`. It walks every operation on each initially active lane, with no seeded register values or pipeline state. An ordinary VGPR read before local write records an entry dependency. Exact FMAC and interpolation P2 read their old destination, CNDMASK depends on local CMP or entry VCC, and interpolation checks local M0 and an adjacent matching phase pair without guessing barycentric inputs or M0 contents. Raw MOV/shift/AND propagate known bits; unknown float computations invalidate their destination facts. Byte conversion is exact, full unsigned conversion can require rounding evidence, and F32 arithmetic remains conditional on the required FP mode. Packed RTZ is proven only within the previously verified value domain.

The export check uses RDNA 2 ISA §§11.1–11.4: POS0 DONE does not terminate PARAM exports; PARAM must not set DONE. PS needs a final DONE and at least one VM. An export source overwritten after issue would need a separate completion proof and is not silently accepted. Vertex output linkage and pixel attachment format/mask remain external even when the instruction order is locally valid. This is a bounded reference check, not a proof of the launch state, native ABI, Metal equivalence or Xbox execution.

Both CPU references and both wave checks agree:

| Stage | No local pair/order/overwrite gap | No entry register reads | No additional FP mode or RTZ domain predicate | Fully resolved without bindings |
|---|---:|---:|---:|---:|
| VS | 114/114 | 10 | 10 | 0 |
| PS | 333/333 | 321 | 321 | 0 |

The same 10 VS and 321 PS in the two middle columns still require their output contracts. The other 104 VS need VGPR inputs and F32 arithmetic mode evidence; two of those also require full unsigned conversion rounding evidence. Of the other 12 PS, four need entry VGPRs and RTZ operand proof, while eight also need SGPR state, interpolation linkage and F32 mode. There are no nonlinear paths in this cohort. In particular, the six previously rejected PS export profiles are not six violations of the checked native DONE/VM protocol.

All 114 VS have a single full uncompressed POS0 first (EN=15, DONE=1, VM=0), followed by dense full uncompressed PARAM exports (EN=15, DONE=0, VM=0): 95 with only PARAM0, six with PARAM0–1, three with PARAM0–2 and ten with PARAM0–6. This is the largest independently testable **owned profile** mismatch, not a native ordering defect. The owned fixture selects the 95-graph single-PARAM shape, not the title's input values or arithmetic.

### Owned POS0-first export without overlap

LLVM MC matches the whole fixture on both references: POS0 DONE, a literal `v_add_f32` that writes a distinct VGPR, PARAM0 with DONE clear using the new value, then actual `s_endpgm`. The Rust lift rejects a missing POS0 DONE, an ADD that overwrites a pending position operand, uninitialized inputs, PARAM DONE or disconnected output, and a missing real END. This shape has no export wait to omit or emulate.

Apple M4 source and offline metallib both match 64/64 RGBA32Float pixels against an independent CPU oracle. Coverage remains the explicit 20-pixel scissor; those pixels carry red 0.5 (not the live-in red 0.25) and the other expected PARAM0 channels; the other 44 stay clear. The fixture proves this owned sequence is not truncated at POS0 DONE. It neither changes the static census nor assigns native linkage, title FP mode, or live admission.

### Explicit coverage-only VS/PS bindings

`graphics_lift::bound::translate` accepts separate bounded native VS/PS word slices and an explicit contract rather than selecting a fixture or assuming an entry register layout. Each live-in VS VGPR is mapped to a raw `uint4` vertex-buffer slot and component. POS0 must be explicitly declared to carry Metal clip-space coordinates. In the coverage-only variant the caller constructs `NoPsLink` and names every native PARAM export by exact ordinal as unconsumed. This is an assertion for the closed owned profile, not inferred title liveness; the PS validator starts with no inputs and refuses interpolation. The only color path is one supported native packed FP16_ABGR export bound to Metal color 0 in RGBA32Float, with the required RG or RGBA write mask. The caller must apply that descriptor and the specified buffer layout. The contract requires single-sample coverage EXEC, a triangle list, and no blending, depth/stencil or alpha-to-coverage.

The validator walks both stages through actual END before returning MSL. It refuses absent or duplicate mappings, wrong native outputs or mask, invalid export order/flags, reads without definitions, writes over pending export operands, unsupported instructions or state, and unproven packed value domains. The first slice admits raw moves and verified hints, full POS0/PARAM exports, and locally proven normal-or-zero packed color and RTZ. It does not infer title inputs, FP behavior, inactive lanes, varying semantics, attachments or PSO state.

LLVM MC matches both CPU references for the owned words. Two distinct native pairs run through the same API. The first uses a permuted slot-5 raw record, POS0 before explicitly unconsumed PARAM2, and full native MRT1. The second uses different VGPRs and a different permutation at slot 6, explicitly unconsumed PARAM0 before POS0, and final RG native MRT0. Both native color targets map to Metal color 0. An independent integer pixel-center coverage oracle and a bit-exact color oracle cover 48 drawn and 16 clear pixels on Apple M4. Each pair matches 64/64 pixels from generated source and offline metallib, including RG B/A preservation. A missing input component rejects. Swapping X and Z in the first contract leaves the native words and the vertex records unchanged but makes every clip-space X zero; the source control matches all 64 clear pixels, losing exactly the predicted 48 writes. This does not enroll the new translator in the historical histogram, alter the static eligibility census or establish retail admission.

### Explicit affine VS→PS binding

The same `bound::translate` API accepts one `AffineLink` naming the producing native VS PARAM ordinal, PS attribute and channel, M0 source SGPR and value, and I/J VGPRs. Only full-precision, center no-perspective interpolation, M0 value zero, attribute 0, and v0/v1 I/J are admitted. The translator checks one matching full VS export and an adjacent exact PS M0/P1/P2 prefix with matching destination and channel. It maps that pair to one named Metal varying lookup, not LDS or a general M0 implementation. Other declared PARAM opt-outs must be disjoint from the link. The PS starts with only the verified pair's result available; there are no raw barycentric values to read in subsequent instructions. The linked path supports the previously tested uncompressed MRT0 DONE encoding (VM clear) under the explicit owned raster-coverage contract; this is not admission of native VM-clear behavior for an arbitrary console launch. It rejects other interpolation modes, unsupported state, and missing or conflicting link declarations.

LLVM MC verifies the owned streams for both reference CPUs. Two owned pairs bind PARAM0/X with s9 and PARAM2/Z with s14, both into attribute 0. The independent CPU oracle uses unequal clip W and distinct channel values to discriminate perspective and channel selection. Apple M4 matches 64/64 pixels per pair from generated source and offline metallib within the established `1e-6` interpolation tolerance. The binding tests reject a missing or duplicate producer, a missing link, a wrong channel or mode, and a mismatched P2. The GPU harness separately mutates source produced by the accepted bound API; a perspective qualifier or a substituted Z lookup each matches its own CPU prediction and changes all 64 pixels relative to affine X. Neither mutation is an admitted translator mode. Existing keyed archive regressions and the static eligibility projection are unchanged.

### Strict archive replay of the bound affine pair

The owned archive adapter keys the same PARAM0/X pair used for source and standalone offline-metallib readback. It takes the exact native word slices and validated bindings passed to `bound::translate`, not a fixture name as a substitute for linkage. The ready job hashes the little-endian native words for each stage, the generated module and entry names (`translated_vs`, `bound_ps`), the raw vertex-slot/component layout, and the verified full-precision center no-perspective link (producer PARAM, PS attribute/channel, M0 source/value, and I/J VGPRs). The planner uses a distinct fixed profile for the single-sample triangle pipeline with one RGBA32Float color attachment, all channels enabled, and no blend or depth/stencil. The existing trusted-local manifest binds that job key to the offline metallib and serialized archive digests. Its target identity includes the offline compiler/SDK/options fingerprint and the local Metal device/OS/debug profile.

On Apple M4, an empty archive missed `bound_ps`. Adding and serializing the pipeline produced a strict hit and a 64/64 pixel match against the unequal-W CPU oracle before the bake published its manifest. A fresh process matched the manifest, loaded the offline metallib and serialized archive, created the pipeline with `FailOnBinaryArchiveMiss` (no fallback or archive additions), and again matched 64/64 pixels at `1e-6` tolerance.

The negative variant changes only PARAM0's consumed channel from X to Z and the matching P1 and P2 channel bits. The VS words, attribute, s9/zero M0 setup, v0/v1 I/J, resources, and render descriptor remain fixed. LLVM MC matches the changed PS stream on both reference CPUs. The variant's independently compiled metallib matches the affine Z oracle at 64/64 pixels, all distinct from X. A replay that selects the changed job but receives the original metallib and archive is rejected by the application manifest. Substituting only the metallib or only the compiler profile also rejects. Separately, the changed metallib with an exact copy of the original archive on a path without a sidecar reaches Metal and fails strict creation specifically because `bound_ps` is not in the archive.

This verifies strict replay for one owned, locally trusted pipeline and does not establish cache portability, shipped PSO bake coverage, or title shader admission.

### Two independently bound affine varyings

`bound::translate` now takes a slice of zero, one, or two affine links. Each link names a distinct VS PARAM producer and a distinct PS attribute (0 or 1). Both retain the same full-precision center no-perspective restrictions, X/Z channels, zero M0 contract, and v0/v1 I/J. Each PS link must appear in its own adjacent M0/P1/P2 group at entry, with a matching attribute, channel, M0 source and distinct result VGPR. The validator matches groups by the encoded attribute, not by contract order or VS export order, and refuses missing or repeated groups and mismatched phases. The context-free decoder still recognizes only the prior attribute-0 forms, so the static census is unchanged.

LLVM MC matches both complete native streams on `gfx1013` and `gfx1030`. The owned PS consumes `attr1.z` from PARAM2 using s14, then `attr0.x` from PARAM0 using s9, and exports `(X,Z,Z,X)` to RGBA32Float. On Apple M4, source compilation and offline metallib each matched 64/64 pixels to the independent unequal-W CPU oracle at `1e-6` tolerance. The harness also swaps just the lookup producers while retaining the two channels; this control matches its own prediction at 64/64 pixels and changes both link values at every pixel. The two-link fixture does not enter the single-link archive profile or title admission.

### Direct PS gap ranking: packed RTZ with NEG0

`--direct-library-graphics-gaps` now reports refined operand patterns for windows with a single missing bucket. Before the decoder change, both LLVM CPU references (`gfx1013`/`gfx1030`) and both wave checks gave the same ranking at the tested +36 and +40 starts. These are stage-export-qualified windows, not recovered entry points.

| Sole missing bucket | Contiguous windows at each start | Sites at +36 / +40 |
| --- | ---: | ---: |
| `v_interp_mov_f32_e32`, attr0, P0 selector | 3 | 8 / 7 |
| `v_cvt_pkrtz_f16_f32_e64`, two VGPRs, NEG0 only | 2 | 2 / 2 |
| Packed MRT0 EN12, COMPR+DONE+VM | 1 | 1 / 1 |
| Packed MRT1 EN3, COMPR+DONE+VM | 1 | 1 / 1 |
| `v_cmp_lt_f32_e32` (operands unclassified) | 1 | 1 / 1 |

The raw P0 probe does not establish native M0/LDS coefficient provenance for the first bucket. The next-ranked bucket has one exact form: `VGPR-VGPR/ctrl00-0800/8B` (second word bit 29 is NEG0). LLVM MC independently checks the owned `v_cvt_pkrtz_f16_f32_e64 v22, -v0, v1` as `0xd52f0016 0x20020300` on both CPUs. The decoder varies only the destination and the two VGPR indices; SGPR sources, nonzero SRC2, absent NEG0 and other modifiers reject. The owned constant-RTZ profiles require the same locally proven signed-zero or finite half-normal input range as before. Lowering flips only source zero's sign bit before the integer RTZ conversion, then packs source zero low and source one high. It does not claim subnormal, NaN, overflow, FP exception, or timing behavior. The explicit bound translator and depth-wait profile remain e32-only for this pack.

Apple M4 matched 5/5 raw packed words for each e32 and e64 form in Metal source compilation, strict offline arithmetic archive bake, and fresh-process strict replay. The oracle includes above-tie inputs, both zero signs, and asymmetric halves that distinguish negating the wrong source or swapping the halves. The existing graphics smoke passed separately; it did not draw the new form.

With the exact e64 form, encoding-complete PS counts rise from 225 to 227 at each of +36 and +40 on both references (6,161 qualified at wave64; 6,191 at wave32). The other sole-gap buckets above remain, and +0, +24 and all VS encoding-complete counts are unchanged. A local aggregate cross-check found the same two distinct spans across the tested hypotheses, each with one newly recognized site. Neither has a local dataflow or export-order gap in the no-default audit, but both still require entry VGPR and SGPR state, interpolation linkage, F32 arithmetic mode, RTZ operand-domain evidence, and attachment format/mask. This adds two observations to that requirement set in each profile, with no addition to the attachment-only or fully resolved cohorts. The new counts measure encoding coverage, not attachment reconstruction, bound translation, PSO bake, or title admission.

### Final packed MRT0 EN12: B/A only

The exact compressed MRT0 header `0xf8001c0c` (EN12, DONE+VM) reads only VSRC1. As specified in AMD RDNA 2 ISA §13.9, B comes from its low half and A from its high half. LLVM MC on `gfx1013` and `gfx1030` assembles `exp mrt0 off, off, v0, v0 done compr vm` with canonical zero disabled bytes and disassembles the owned noncanonical variant the same way. The decoder does not read or assign values to VSRC0/2/3. Neighboring target, mask, flags, and reserved-bit forms are not added. The owned validator rejects an undefined VSRC1, a wrong export profile, or a missing END.

The isolated Metal fixture supplies only one finite packed B/A dword (`0xb8003e00`), with an explicit RGBA32Float attachment, B/A-only PSO write mask, no blending, and 8×8 render extent with a 4×5 scissor. Apple M4 matched 64/64 bit-exact pixels both from source and from the offline metallib: all 20 covered pixels wrote B=1.5 and A=−0.5 while preserving R=1 and G=0.5, and the other 44 matched the clear. Running the same offline metallib with an intentionally wrong all-channel mask matched its own 64/64 oracle and differed from the correct oracle on all 20 covered pixels: both R/G clears were lost while B/A remained correct. The generated R/G return components are placeholders under the owned mask, not guessed native selector data.

At each +36/+40 hypothesis and on both CPU/wave references, 10 sites in the same 10 distinct PS spans gain exact coverage; one span becomes encoding-complete (227→228, out of 6,161 wave64 or 6,191 wave32). `--direct-library-graphics-gaps` reports one additional contiguous span whose no-default audit has no local gaps and requires only `AttachmentFormatAndMask`. It adds no fully resolved span; +0/+24 and VS closure remain unchanged. The sample's attachment state, code extent and entry are not inferred, and the bound translator and title admission do not acquire a B/A profile.

### Final packed MRT1 EN3: R/G only

The exact compressed MRT1 header `0xf8001c13` (EN3, DONE+VM) reads only VSRC0, with R in its low half and G in its high half (AMD RDNA 2 ISA §13.9). LLVM MC on `gfx1013` and `gfx1030` matches `exp mrt1 v0, v0, off, off done compr vm` with canonical disabled bytes, and disassembles the owned variant with nonzero disabled bytes identically. VSRC1/2/3 are not read. The existing nonfinal MRT1 EN3 form retains its canonical-zero rule. The owned profile requires full nonfinal packed MRT0, then this final packed MRT1 and real END, and checks all active sources. The bound translator does not gain this profile.

The owned dual RGBA32Float pipeline disables blending, writes all channels at slot 0 and only R/G at slot 1. Apple M4 matched 128/128 attachment pixels bit-exactly in each of the source and offline runs. In the 20 covered pixels, slot 0 wrote its distinct full color, while slot 1 wrote R=1.5 and G=−0.5, preserving B=0.75 and A=1. Both attachments preserved all 44 out-of-scissor clears. Changing only the slot-1 write mask to all channels on the same metallib matched an independent control oracle and lost both B/A sentinels in exactly those 20 pixels; slot 0 and the active R/G results were unchanged. The slot-1 B/A return placeholders are not native selector values.

The direct-library census recognizes 366 sites in the same 366 distinct PS spans at each +36/+40 CPU/wave hypothesis; only one contiguous span becomes encoding-complete, from 228 to 229 of 6,161 (wave64) or 6,191 (wave32). The no-default audit for that span detects no local gap and only `AttachmentFormatAndMask`, adding one attachment-only span and no fully resolved spans. +0/+24 and VS closure are unchanged. No title entry, extent, attachment binding, or admission is inferred.

### Ordered CMP LT F32: inline zero, VGPR

The sole compare gap refines to VOPC e32 `0 < VGPR`: the four-byte word varies only in VSRC1, with SRC0 selector 128. LLVM MC on both `gfx1013` and `gfx1030` recognizes owned word `0x7c020280` as `v_cmp_lt_f32_e32 vcc_lo, 0, v1` under wave32 and `v_cmp_lt_f32_e32 vcc, 0, v1` under wave64. The immediate owned CNDMASK uses the same implicit predicate destination in each wave setting. Per AMD RDNA 2 ISA §12.9 this is one bit per lane in VCC, not a CMPX/EXEC update. Other compare opcodes and other SRC0 forms are not added.

The owned arithmetic probe observes only its lane's bit as a raw CNDMASK result. Integer bit classification implements ordered `<` with an explicit preserve-subnormal result policy: positive finite values and positive infinity pass; equal zeros (either sign), negative values and either NaN class do not. This is not a native FP-mode or exception/status model. Apple M4 matched 10/10 literal result words from source, strict offline bake and fresh-process strict replay, including zeros, quiet/signaling NaNs, infinities and signed subnormals. The ordinary graphics and bound profiles still reject this compare; no wave-wide predicate, EXEC, entry, or PSO admission behavior changed.

For each reference CPU, at both +36 and +40 the form covers 4,634 sites in 1,816 qualified PS windows in wave64 and 4,791 in 1,844 in wave32 (1,844 distinct spans across hypotheses). The same one contiguous span becomes encoding-complete, **229→230** in every profile. Its no-default audit finds no local gaps or entry VCC requirement, but still requires `EntryVgpr`, `F32ArithmeticMode`, and `AttachmentFormatAndMask`. Neither the attachment-only nor the fully resolved cohort grows. +0/+24 and VS closure remain unchanged.

### Next exact PS blocker after CMP LT

At `8ce2628`, `--direct-library-graphics-gaps` has 230 encoding-complete PS windows at each +36/+40 hypothesis on both LLVM CPU/wave references (6,161 qualified wave64, 6,191 wave32). Rank by contiguous whole windows, not by dynamic importance or instruction frequency:

| Remaining blocker set | Contiguous windows per +36/+40 profile | Why not admit it yet? |
| --- | ---: | --- |
| VINTRP attr0 P1/P2, Y and W | 6 | Five need all four forms; only one needs just the exact Y pair. Native interpolation coefficients, I/J, M0 and linkage are not bound. |
| VINTRP attr0 P0 MOV | 3 | Only sole mnemonic bucket left (8 sites at +36, 7 at +40). Y/Z/W and X are distinct exact forms. The owned raw-P0 probe does not supply the native LDS coefficient contract. |
| Nonfinal packed MRT1 EN3 and final packed MRT2 EN15, nonzero disabled bytes | 1 | **Selected:** both headers and the ordered triple-target profile already have a canonical owned source/offline oracle. The cohort has a different active-source alias pattern, so recognition is held pending an owned alias-matched test. |
| Nonfinal packed MRT0 EN12 and final packed MRT1 EN12, nonzero disabled bytes | 1 | Same closure leverage, but requires a separate dual B/A-only owned profile and per-slot preservation controls. |

For the selected pair, the exact headers are `0xf8000413` (COMPR only) and `0xf8001c2f` (COMPR+DONE+VM). AMD RDNA 2 ISA §13.9 assigns VSRC0 to R/G and VSRC1 to B/A; only VSRC0 is enabled in EN3, while both are enabled in EN15. LLVM MC on both CPUs and waves disassembles purpose-built nonzero inactive selector variants exactly as their canonical equivalents. The existing canonical triple-RG Metal probe matched 192/192 attachment pixels from source and offline, but has not tested those variants. A follow-up should test them with nonzero disabled bytes, preserve MRT1 B/A, and use a wrong MRT1 mask to distinguish placeholders from required preservation without touching MRT0/MRT2.

The actual cohort agrees across both CPU references, both wave settings, and both starts on the exact header order (`0xf800040f`, `0xf8000413`, `0xf8001c2f`) and nonzero inactive bytes at all three exports. The active positions match the owned profile, but the active selector assignments do not: every enabled half-pair reads the same locally defined VGPR, while the canonical owned test uses two distinct VGPR inputs and gives the attachments different colors. Therefore the actual comparison is not solely a mutation of inactive bytes. Keep the independent-color control for detecting slot swaps; an additional alias-matched fixture is needed before claiming direct cohort equivalence.

An isolated scratch decoder that drops just these two disabled-byte checks projects **230→231** at every +36/+40 CPU/wave hypothesis, not a strict gain in this revision. Its aggregate attachment audit finds one distinct span and row with ordered full MRT0 → R/G MRT1 → full MRT2, no depth export, no local gaps, and only `AttachmentFormatAndMask`. No other slot or flag variant was projected; +0/+24 and VS totals are unchanged. Neither entry, attachment state nor PSO admission is inferred.
