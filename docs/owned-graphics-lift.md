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

Both LLVM MC references verify the final full-mask packed MRT1 `DONE+VM` word `0xf8001c1f` and its packed RG/BA source order. The owned profile requires nonfinal packed MRT0, final packed MRT1, and an actual `s_endpgm`, with no EXEC changes. Metal binds native ordinals 0 and 1 explicitly to `[[color(0)]]` and `[[color(1)]]` with separate RGBA32Float attachments, full write masks, and blending disabled. This is not a rule for compacting or recovering title attachment ordinals. Nonfinal MRT1, partial masks on MRT1, and higher targets still reject.

Reversed source VGPRs produce distinct RGBA colors in the two attachments. Independent CPU expectations check 20 written and 44 untouched pixels per slot, with distinct clears. Apple M4 matched all 128 attachment pixels bit-for-bit from generated MSL and from the offline metallib. This probe does not bake an archive; the original keyed strict regression is unchanged.

The decoder gains 2,310 / 602 matching PS sites under `gfx1013` / `gfx1030`. Both wave checks now count 320 / 12,091 and 320 / 6,188 PS reference graphs without an encoding gap (three additional per reference), and unchanged VS totals. The nearest remaining incomplete PS cohort has seven graphs with two gaps each. No title attachment mapping, translation, or bake coverage is inferred.

### Owned lane-local compare and select

The nearest-site audit isolated two PS graphs missing `v_cmp_ne_u32_e32` with inline integer zero (selector 128) and a VGPR, followed in their missing-form signatures by `v_cndmask_b32_e32` with literal S0 (selector 255) and VGPR S1. The exact forms match LLVM MC on both references. AMD's RDNA 2 ISA defines the comparison as unsigned integer inequality and VOP2 select as choosing S1 when the current VCC bit is set, S0 otherwise. The owned straight-line pixel profile maintains only the active lane's locally defined predicate; a second compare overwrites it. It rejects uninitialized operands or predicate and does not implement compare-and-write-EXEC, wave-wide VCC observation, subgroup communication, or an EXEC transition. Wave32/64 below are independent reference decoder settings, not runtime lane-layout validation.

The Apple M4 strict offline arithmetic probe matches 8/8 select words in bake and replay. Mixed lanes exercise both operand choices and both predicate transitions, including `+0` vs the nonzero integer bit pattern of `-0`, an infinity word passed through unchanged and a NaN payload returned as raw bits. No floating-point comparison or NaN policy is assumed. The keyed graphics replay is unchanged.

Both wave checks agree: the decoder gains 590 / 404 VS sites and 26,215 / 2,690 PS sites under `gfx1013` / `gfx1030`. Encoding-complete PS reference graphs rise from 320 to 322 (of 12,091 / 6,188); VS stays at ten per reference. Five PS graphs now share the closest incomplete distance of two sites. No title ABI, execution, or translation follows from these counts.
