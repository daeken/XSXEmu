# VS+PS binding-minimal semantic cohorts

With an explicit LLVM reference, `--wrapped-library` intersects the checked semantic audit with the actual VS+PS rows (slots 0 and 1 only). It preserves stage, program and metadata identity; a same-stage digest nominates wrappers, not bodies. `BindingMinimal` means no local path gaps, no entry VGPR/VCC/SGPR/M0 prerequisites, and no unresolved FP mode, uint rounding or packed-RTZ input domain, under equal wave32/wave64 reference projections. The underlying audit requires a complete straight-line path and exact opcode/width agreement. Vertex output linkage and attachment format/mask remain necessary even for this cohort. No state or binding defaults are filled in.

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-library "$WRAPPED" "$INFLATED_LIBRARY" "$TRUSTED_LLVM_21_DYLIB" gfx1013
# Repeat with gfx1030.
```

Two independent evidence levels are reported. The **exact-window** projection requires an exact match of the checked wrapped executable candidate (stored FSSM extent with the +40 hypothesis and checked trailing fill) to the length-derived library suffix (aligned start within 512 bytes; bounded final end-marker hypothesis). Distinct matching starts are retained; multiple starts or non-agreeing wave projections cannot qualify. This is still a conditional window match, not runtime entry provenance. The **wrapped-family-only** projection asks separately whether there exists a qualifying wrapped payload under the corresponding stage/digest, and counts wrapper and payload multiplicity. It never chooses a library program body.

On the pinned local extraction, gfx1013 and gfx1030 agreed:

| VS+PS PSO occurrences | Count |
|---|---:|
| All exact two-slot rows | 13,383 |
| Distinct `(VS program/metadata, PS program/metadata)` pairs | 3,128 |
| Rows with a checked exact suffix witness for either stage | 0 |
| Rows with a wrapped digest-family binding-minimal candidate, PS only | 20 |
| Rows with a wrapped digest-family binding-minimal VS candidate | 0 |
| Rows with binding-minimal evidence on both stages, at either evidence level | 0 |
| Rows with empty stage metadata item list, VS / PS / both | 15 / 34 / 4 |

An empty item list is not evidence that a shader has no resource inputs. A missing exact-window witness only rules out this comparison, not other library entry hypotheses. No shipped pipeline was translated, admitted, baked, or run.

## Independent native-corpus join

`--native-vs-ps` starts from standalone native FSSM files rather than wrapped source digests. It validates the FSSM version, stage byte and code extent. The semantic audit takes only the contiguous reached prefix through the first decoded `s_endpgm`; bytes after that instruction cannot supply semantic evidence. LLVM and the owned decoder must agree on opcode and width. The shared cohort additionally requires wave64 and wave32 to agree on the decoded instruction text and semantic outcome. The primary cohort admits only no-gap outcomes with **exactly** `VertexOutputLink` for VS or `AttachmentFormatAndMask` for PS. The secondary cohort needs encoding completeness, not viable semantics or bindings. Single-wave encoding-complete joins are also counted independently.

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --native-vs-ps "$NATIVE" "$INFLATED_LIBRARY" "$TRUSTED_LLVM_21_DYLIB" gfx1013
# Repeat with gfx1030.
```

For each exact two-slot PSO occurrence (PS at slot 0, VS at slot 1), the probe compares each checked whole library program span against the eligible native windows for that **same stage**, without source-digest nomination. It tests three types of byte equality:

1. **Full stored:** whole library span versus the whole checked native extent (`+0xc0/+0xc8`). Neither side is trimmed.
2. **Full +40:** whole library span versus the native extent after removing its first 40 bytes; no end trimming. This is a displacement hypothesis, not an authenticated graphics entry.
3. **Cut suffix:** native reached code through `s_endpgm` versus a library suffix ending at its last aligned `0xbf810000` in the final 512 bytes. The suffix starts at a dword-aligned offset from 0 through 512 inclusive. The marker is a library boundary hypothesis, not a decoded library exit.

The row matrix separates full stored, full +40, suffix-only and no witness for each stage, with the strongest evidence shown first. Independent nonexclusive counts and candidate multiplicity retain weaker evidence and duplicate native files; even one witness does not authenticate entry, select a variant, or resolve a binding.

Both CPU profiles with LLVM 21.1.6 admitted 10 VS and 321 PS native file occurrences into the primary cohort, out of 2,236 VS and 12,101 PS files with checked extents. The single-wave encoding-complete counts were 114 VS and 333 PS for each wave; two PS files had differing wave disassembly text despite agreeing semantic projections. The shared encoding-complete cohort was 114 VS and 331 PS. Those two disputed files are still measured in the corresponding single-wave joins, not promoted to the shared cohort.

| VS+PS PSO occurrences | Output-binding-only | Wave-agreeing encoding-complete | Encoding-complete, either single-wave report |
|---|---:|---:|---:|
| Exact two-slot denominator (3,128 distinct program/metadata pairs) | 13,383 | 13,383 | 13,383 |
| Any full stored witness, VS / PS / both | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| Any full +40 witness, VS / PS / both | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| Any cut-suffix witness, VS / PS / both | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| No witness for either stage | 13,383 | 13,383 | 13,383 |

No native file in any tested cohort had a witness. This rules out the compared windows as a way to establish even one stage of these pairs; it does not rule out different program framing or a different native variant. No lift, bake admission, readiness, artifacts, or title execution changed.

## Direct stored graphics program census

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --direct-library-graphics "$INFLATED_LIBRARY" "$TRUSTED_LLVM_21_DYLIB" gfx1013
# Repeat with gfx1030.
```

This probe uses the checked library arena spans without requiring wrappers, native files, or source digests. It uses known PS/VS/MS slot roles and excludes the two unknown slot occurrences. Each of `+0`, `+24`, `+36`, and `+40` is tested independently to both the stored end and the hypothesized last aligned `0xbf810000` in the last 512 bytes. A closed reference graph must reach a decoded exact `s_endpgm` and must not hit an unmodeled transfer, overlap, or out-of-span edge. Closure neither requires the last raw marker to be that instruction nor proves termination on all inputs. The stricter stage-export tier additionally needs active PS color/depth/stencil export, active VS POS0, or MS PRIM. For VS and PS, encoding completeness additionally needs a contiguous reached path with exact agreement between LLVM and the owned opcode/width decoder. Output-binding-only adds the same no-default static semantic check as above. The MS survey stops at the stage-export tier; `s_sendmsg` does not get a synthetic fallthrough. Counts labeled same-window require that both wave references pass on the same start/end hypothesis, not that their decoded operands are identical.

The complete aggregate histograms were identical between gfx1013 and gfx1030 with LLVM 21.1.6. At `+0` all 18,837 distinct stage/program references stopped at decode. For the stored end, `+24` gave stage-export closure on 5 PS and 2 VS programs in either wave; `+36` and `+40` each reached the counts below. Cutting at the last marker removed one of the PS closures at each of `+36` and `+40` in both waves. At those two starts the strict MS walk stopped at `s_sendmsg` for 6,775 programs, and at decode for the other 723.

| Stage | Slot occurrences | Distinct stage/programs | Any closed window, wave64 / wave32 | Stage-export closures, wave64 / wave32 / same window |
|---|---:|---:|---:|---:|
| PS | 24,111 | 9,996 | 6,755 / 6,785 | 6,161 / 6,191 / 6,161 |
| VS | 13,409 | 1,343 | 1,304 / 1,304 | 1,304 / 1,304 / 1,304 |
| MS | 12,062 | 7,498 | 0 / 0 | 0 / 0 / 0 |

Every program with stage-export closure had multiple passing starts; none established a unique entry. Of 13,383 exact VS+PS occurrences, both stages had stage-export closure on 12,794 (wave64), 12,798 (wave32), and 12,794 (same window in both waves for each stage). For the same-window projection, 550 had only VS closure, 39 only PS, and none had neither. In the original census no stage-export-qualified VS or PS window was encoding-complete; see the follow-up below for the newly cleared PS cohort. This is conditional static evidence about the tested library spans, not a runtime entry, binding, native variant selection, bake admission, or translation.

## Direct stored-window translator gap ranking

Run `--direct-library-graphics-gaps "$INFLATED_LIBRARY" "$TRUSTED_LLVM_21_DYLIB" gfx1013` (and repeat with `gfx1030`). The report ranks checked unsupported sites and counts affected windows per form. It deduplicates stage/program references, keeps starts and waves separate, and uses the stored end only. It counts reached instruction starts in reference graphs that close at a decoded END and contain a qualifying stage export. It excludes MS and rejected graphs. Counts are static, not execution frequencies; operand-unclassified buckets may contain several forms.

Before the change, `v_mul_f32_e32` at four bytes ranked first by site count at +36 and +40 for both stages and waves. Both CPU references gave the same aggregates. The exact two-VGPR form now matches the following subset (the +36 and +40 counts agree; do not add them):

| Stage / wave | Qualified windows | Prior 4-byte multiply gaps | Newly matched two-VGPR sites | Windows with those sites |
|---|---:|---:|---:|---:|
| PS / 64 | 6,161 | 594,614 | 460,619 | 5,510 |
| PS / 32 | 6,191 | 619,337 | 481,658 | 5,540 |
| VS / both, each | 1,304 | 105,923 | 82,623 | 908 |

At +36 the largest remaining PS buckets are 4-byte `s_waitcnt` (270,008 / 275,768) and 8-byte `v_fma_f32` (249,700 / 260,190), in wave64 / wave32 order. The leading VS bucket is 4-byte `v_add_f32_e32` (52,623 in either wave). The multiply alone did not make any window encoding-complete. At that point, +36 had 218 PS windows with one gap and 25 VS windows with five each. No runtime entry or binding is selected.

The owned lowering emits ordinary F32 multiplication, not the legacy zero shortcut. LLVM MC confirms the exact two-VGPR VOP2 word on both references; SGPR, inline, literal and other forms remain outside this addition. Apple M4 strict arithmetic archive bake and replay each passed 11/11 ordinary multiply checks: finite and rounding-sensitive values, signed zeros, and NaN classification for zero with infinity or NaN inputs. The static semantic check still requires both operands to be defined and the applicable F32 mode to be proven. No claim about title FP mode, NaN payloads, denormals, or pipeline admission follows.

### Prioritize by whole-window leverage

The census also ranks sole gap buckets by number of windows, reporting the contiguous subset separately. Under both LLVM 21.1.6 reference CPUs (`gfx1013` and `gfx1030`), at each start the prior top PS cohort was uncompressed MRT0 EN=1, DONE+VM: the one remaining site in each of 212 contiguous windows. The next cohorts were compressed MRT0 EN=3 (5 windows), compressed MRT0 EN=15 (1), and an unclassified `v_interp_mov_f32_e32` bucket (1 window, with 3 sites at +36 and 2 at +40). No VS window had just one gap bucket (1,304 closed stage-export windows per start and wave).

| Stored start | PS wave64 closed stage-export windows | PS wave32 closed stage-export windows | Newly encoding-complete per wave and CPU |
|---|---:|---:|---:|
| +36 | 6,161 | 6,191 | 212 |
| +40 | 6,161 | 6,191 | 212 |

The bounded owned red-only lowering reads only VSRC0 and requires the exact MRT0/DONE/VM/EN header. LLVM MC assembles the canonical word on both CPUs; disassembly still reports GBA `off` when those disabled selector bytes are nonzero. With a single-sample no-blend RGBA32Float target and red-only write mask, Apple M4 readback matched 64/64 pixels bit-for-bit from source and from an offline metallib: 20 pixels wrote red only, and all retained nonzero GBA clears. Existing keyed graphics replay is unchanged. The owned straight-line profile leaves coverage to the rasterizer and scissor and has no EXEC updates or kills. It does not emulate a general VM validity mask.

Across starts, 212 distinct PS become encoding-complete (do not add the two rows). Of those, 210 have only the attachment format/mask predicate outstanding in the static audit. No VS becomes encoding-complete, and no complete VS+PS pair passes both stages. Neither the closure nor this owned test selects a runtime entry, establishes a title attachment contract, or demonstrates bake readiness.

### Dominant ordinary vertex add form

At each stored start (+36 and +40), both LLVM CPUs and both wave settings see 42,370 exact two-VGPR `v_add_f32_e32` sites in 966 of 1,304 qualified VS windows. For PS, the same form matches 81,268 sites in 3,459 of 6,161 wave64 windows and 82,788 in 3,489 of 6,191 wave32 windows. No additional windows become encoding-complete: VS stays at zero and PS at 212 per hypothesis. The 7,450 ordinary SGPR-source add sites at each VS start still lack a proved scalar source contract; this change supports neither them nor new inline forms. The existing literal form and unsupported waits are unchanged.

LLVM MC verifies the exact two-VGPR VOP2 word on both CPUs. On Apple M4, the owned offline strict arithmetic bake and separate-process replay each match 8/8 raw sum words, covering ties in both rounding directions, an above-tie input, signed zero and cancellation. The static audit still requires both operands and the applicable native FP mode; these tests establish neither a title FP profile nor denormal or NaN-payload behavior.

### Final compressed MRT0 selector blockers

The next five RG windows each have one compressed MRT0 EN=3 DONE+VM export; the next full-mask window has one compressed MRT0 EN=15 DONE+VM export. Their headers and enabled source positions already fit the owned packed export profiles. The former decoder rejected nonzero disabled selector bytes. LLVM disassembly on both reference CPUs confirms EN=3 uses only VSRC0 (RG), and EN=15 uses VSRC0 (RG) and VSRC1 (BA); higher unused bytes do not change those operands. The relaxation is restricted to those two final MRT0 headers, not other targets or export forms.

The audit finds five distinct RG and one distinct RGBA PS spans across hypotheses. Each of +36 and +40 contains those same six candidate windows per CPU and wave, raising encoding completeness from 212 to 218 out of 6,161 (wave64) or 6,191 (wave32). Four RG spans add only the attachment format/mask predicate; the other RG span and the full-mask span additionally need entry VGPRs and SGPRs, interpolation linkage, F32 mode and the packed RTZ domain. The static output-binding-only total is now 214 PS; no VS or full pair clears both stages. No wait, runtime entry or PSO admission change follows.

On Apple M4, the owned packed RG and RGBA paths with nonzero disabled selectors each match 64/64 RGBA32Float pixels from generated source and from an offline metallib. The RG write mask preserves nonzero B/A clears. As a control, the same RG metallib with all-channel writes overrides both clears on exactly the 20 covered pixels, matching a separate CPU prediction. The fixture uses raster/scissor coverage without lane kills or EXEC updates and does not model general VM behavior.

### Raw interpolation coefficient move

The direct gap audit separates windows with exactly one missing instruction from windows with only one missing instruction form. For `gfx1013` and `gfx1030` and both wave settings, the same single span has exactly one gap at each stored start (+36 and +40): `v_interp_mov_f32_e32` with selector 2 (P0), attr0.x. Three distinct spans including that one have only that instruction form missing: 8 sites at +36 (1/3/4 by window), and 7 at +40 (1/2/4). All select P0 from attr0, across X/Y/Z/W. The PS denominators remain 6,161 wave64 and 6,191 wave32 at either start.

RDNA 2 ISA §10.4.2 describes a raw LDS coefficient read selected using M0, not the evaluated affine varying. It does not establish the title's LDS offset, primitive association, or provoking vertex. The owned probe requires exactly `s_mov_b32 m0, s9` with declared zero M0, selector 2 attr0.x, and a matching red export followed by END. Its caller supplies the raw P0 word explicitly; it neither reads native LDS nor reconstructs P0 from vertex outputs. LLVM MC matches the complete owned PS on both reference CPUs. On Apple M4, source and offline metallib each match 64/64 pixels bit-for-bit, with 20 covered pixels writing 0.625 to red. Substituting only the bound P0 word in the same metallib changes those 20 writes to −0.125 and leaves the other channels and uncovered pixels intact. The context-free decoder and the 218 encoding-complete PS candidates are unchanged. No runtime entry, title binding, or PSO admission follows.

### Two remaining forms in a stage-export-closed window

`--direct-library-graphics-gaps` ranks pairs of gap buckets and separately ranks pairs after refining observed operands (interpolation attribute/channel and MOV selector, BFREV source class, EXP mask/flags and disabled-selector use). Forms not resolved by these checks remain unclassified; no literal data or register indices are printed. A pair can have more than two sites. Start/wave rows show site multiplicities; the summary deduplicates program spans within each stage and across start/wave hypotheses. The two LLVM 21.1.6 CPU references (`gfx1013`, `gfx1030`) agree. At each of +36/+40 the base is 6,161 PS wave64, 6,191 PS wave32, and 1,304 VS per wave. No VS qualifies for either two-form cut. All observed pair windows are contiguous.

| Refined gap pair | Unique PS spans | Windows per wave, +36 / +40 |
|---|---:|---:|
| Nonfinal packed MRT0 EN15 + final scalar MRT1 EN1 DONE+VM | 2 | 2 / 2 |
| Nonfinal depth-only MRTZ EN1 + e32 BFREV of selector 188 | 2 | 2 / 2 |
| Final packed MRT0 EN12 DONE+VM + e32 BFREV of selector 188 | 1 | 1 / 1 |
| Nonfinal packed MRT0 EN15 + final packed MRT1 EN3 DONE+VM | 1 | 1 / 1 |
| VINTRP e32 P1 + P2, both attr0.y | 1 | 1 / 1 |
| VINTRP e32 MOV P0 attr0.w + P0 attr0.z | 1 | 0 / 1 |

All eight refined spans have two sites. Every export listed above has nonzero disabled source selectors. RDNA 2's source table identifies BFREV selector 188 as inline integer 60, whose 32-bit reversal is `0x3c000000`; this does not establish the title's depth/stencil or packed BA contract. There are **13** distinct PS spans with two broader buckets: twelve at +36 and the same twelve at +40, plus two observations at +24 (five stage-qualified PS per wave), one of which overlaps the +36/+40 union. One +24 observation is a distinct scalar-to-M0 plus four P0 MOV sites and is not a refined two-form pair. No pair at +0. The MOV Z/W row above belongs to a single MOV opcode bucket.

The broad P1/P2 bucket leads with six unique spans, not six exact pairs. At +36, one has just attr0.y P1/P2; five have four missing sites (P1 and P2 for each of attr0.y/w). At +40 one of those five loses the Y P1 from the checked window. A closed export path with P2 does not prove the incoming accumulator or that the omitted P1 was executed. Native producer/attribute linkage, interpolation coordinates and FP contract, and M0/LDS primitive/addressing remain unresolved. No affine or P0 substitution, entry selection, or wait elision was made.

The selected owned probe covers the tied leading **exact** export pair: MRT0 consumes two words each containing two packed halves, MRT1 consumes a raw F32 red word from VSRC0 only. It enforces the exact order, flags, bound two-word input, and real END. LLVM MC matches the canonical instruction encodings on both references; owned tests vary only the inactive selector bytes and reject undefined enabled sources, changed encodings, and extra or missing dwords. With explicit RGBA32Float attachments, an all-channel MRT0 and a red-only MRT1, Apple M4 matches 128/128 attachment pixels for both source and offline metallib. Using the same metallib and an incorrect all-channel MRT1 mask matches a separate oracle that loses the nonzero G/B/A clears at exactly 20 covered pixels; MRT0 and uncovered pixels remain unchanged. This is an owned export profile, not generic VM/EXEC support or a recovered title attachment binding. The follow-up shares decoding for exactly nonfinal MRT0 EN15 COMPR and final MRT1 EN1 DONE+VM; other headers keep their previous gates. This raises actual encoding closure from 218 to 220 at each +36/+40 for both CPUs and waves (the same two spans, not four); +0/+24 and VS are unchanged. The all-channel control explicitly checks 20 mismatches against the normal oracle. No shipped translation, admission, or bake follows.

### Inline BFREV and nonfinal scalar depth

In both two-gap spans and all +36/+40 CPU/wave hypotheses, BFREV precedes scalar MRTZ, but its destination is not the enabled depth source. It instead matches the final packed MRT0 VSRC1 (B/A); this register match alone is not a full definition-chain proof. Only exact VOP1 e32 selector 188 (inline integer 60) folds to the raw word `0x3c000000`; only exact nonfinal, uncompressed MRTZ EN1 with VM and DONE clear accepts nonzero disabled bytes. Still read VSRC0, and leave final MRTZ and other headers/selectors unchanged.

The owned stream assembles canonically on both LLVM references and uses distinct MRTZ and BFREV destinations. It binds two independent depths for overlapping draws under Depth32Float Less/write, with BFREV supplying packed B/A=(0,1). On Apple M4, source and offline metallib each match all 64 color pixels bit-for-bit. In the same metallib, supplying the BFREV word as both bound depths ties the draws, changing ten overlap winners relative to the normal oracle. No stencil or coverage export, wait removal, or title state inference.

Actual encoding closure grows from 220 to 225 PS at each +36/+40 and both waves and CPU references: the same two BFREV+MRTZ spans and three formerly BFREV-only spans. +0/+24 and VS are unchanged. A further pairing with final packed MRT0 EN12 still lacks that export form. These results do not select a title entry or admit any shipped pipeline.

### Nearest direct VS cohorts and signed conversion

The direct gap audit ranks the smallest VS missing-form sets first, then by distinct span count, with separate start/wave projections and minimum missing site counts. A bucket marked unclassified is a lower bound on distinct exact forms. At +36/+40 (1,304 stage-export-qualified VS each), both LLVM CPUs and waves agree: no span was within three buckets before the change. The nearest group is 59 distinct spans, four buckets and six sites minimum: exact SETPRIO imm3, nonfinal uncompressed PARAM0 EN3 with nonzero disabled selector bytes, exact signed e32 VGPR conversion, and an unclassified VOP3 FMA family. Next are 25 distinct spans, four buckets and five sites minimum: SETPRIO imm3, VOP2 ADD selector 243, and unresolved e64 signed CVT and e32 SUB operands. The 59 and 25 are the same respective spans at +36 and +40. High-volume separate blockers include WAITCNT (1,216 windows), SMEM dwordx4 loads (1,214 at +36, 1,213 at +40), and SGPR-source F32 MUL (1,050 at either start); their frequency does not establish memory, dependency, or entry contracts.

Only `v_cvt_f32_i32_e32` with ordinary VGPR input was added. Both LLVM MC references verify the complete owned stream. The owned VS supplies two explicitly bound raw words, interprets them as signed, converts with round-to-nearest-even and forwards the results through a flat PARAM0. The CPU oracle covers zero, negative one, both directions of ties for both signs, and both signed extrema. Apple M4 source and offline metallib each match 64/64 RGBA32Float pixels bit-for-bit. The lift checks source liveness and rejects SGPR and e64 encodings. Unknown inexact signed conversions in static analysis require an FP mode rather than inheriting the owned mode.

This covers 434 exact VS sites in 219 windows at each +36/+40 CPU/wave profile. The 59-span group falls to three missing buckets (four sites minimum), but **whole-window encoding closure stays 0 → 0 VS** and 225 → 225 PS at +36/+40. Neither +0 nor +24 gains closure. PARAM linkage, priority, waits, launch state, and entry remain outside the owned contract.

### Partial PARAM0 X/Y export

The shared decoder accepts only header `0xf8000203` for this form: PARAM0, EN=3, nonfinal, uncompressed, VM/DONE clear and reserved bits zero. Only VSRC0/1 are read; no architectural Z/W fill is modeled. LLVM MC confirms the canonical form on both reference CPUs. Owned tests vary the inactive selector bytes, reject undefined enabled sources and changed target/mask/flags, and require final full POS0 and real END. The separate Metal contract declares a `float2` varying; the fragment supplies independently known Z/W sentinels, not values from the VS. On Apple M4, source and offline metallib each match 64/64 pixels bit-for-bit. Swapping only X/Y inputs using the same metallib differs from the normal oracle at all 64 pixels and preserves both consumer sentinels.

At +36 and +40, each CPU/wave profile contains one site in each of the same 119 distinct VS spans (of 1,304 qualified), all with nonzero disabled selector bytes. None at +0/+24. The 59 nearest VS now have two remaining buckets and at least three sites: SETPRIO imm3 and unclassified VOP3 FMA. Whole-window closure remains 0 VS and 225 PS per applicable profile. Native PARAM linkage, interpolant state, priority, waits and entry are not inferred.

### Inline-first VOP3 single-precision FMA

Each of the same 59 nearest VS spans has one each of `v_fma_f32(+2, VGPR, -1)` and `v_fma_f32(-2, VGPR, +1)`. They are the operand-commuted versions of the two previously validated unpack operations, not three-VGPR VOP3 FMA or VOP2 FMAC (which reads its old destination). The inline selectors are 244/243 and 245/242 in SRC0/SRC2, respectively. Negative constants come from the selectors, not NEG bits. Only the modifier-free 8-byte encodings were added: ABS, NEG, OP_SEL, CLAMP and OMOD must be zero, and SRC1 must be an ordinary VGPR. Other forms, including SGPR sources, remain out of scope. RDNA 2's VOP3 opcode 331 specifies fused single-precision `S0 * S1 + S2`; a modifier-free encoding does not establish the title's rounding or denormal mode.

Both LLVM MC references verify the owned unsigned unpack stream with inline-first encodings and the byte stream with the original operand order. Under the finite owned round-to-nearest-even contract, the lift still emits explicit `fma` and rejects undefined sources. An independent literal table for the unsigned unpack stream checks RGBA32Float raw bits, including conversion ties in both directions at 2^25 and carry to 2^32. Apple M4 source and offline metallib each match 64/64 pixels for each order. The fixed `±2` multiply is exact for finite binary32 inputs except overflow, and `±1` cannot distinguish the two evaluation paths at the overflow boundary under round-to-nearest-even. The separate three-VGPR VOP3 graphics control provides the fusion discriminator: exact integer `4097 * 4097 - 16785408` yields fused `0x3f800000` vs split `0x00000000` with an explicitly rounded product. Its GPU green-channel oracle (including strict archive replay) distinguishes the outcomes. The VOP2 FMAC bit-readback remains a separate regression. No guest FP mode or NaN payload propagation is inferred.

Both LLVM 21.1.6 CPUs agree on the site and window counts below, separately at +36 and +40. Entries are sites / windows, not additive across start or wave hypotheses. Neither form occurs in qualifying +0/+24 windows.

| Stage / wave | `(+2, VGPR, -1)` | `(-2, VGPR, +1)` |
|---|---:|---:|
| VS, either wave | 739 / 270 | 105 / 89 |
| PS, wave64 | 17,364 / 2,471 | 114 / 67 |
| PS, wave32 | 17,587 / 2,501 | 114 / 67 |

Across starts and waves, 280 distinct VS spans and 2,502 distinct PS spans have either form. The 59 nearest VS lose 118 unsupported sites per profile and now have exactly one gap each, `s_setprio` imm3, which remains unsupported. **Whole-window encoding closure gains zero**: still 0/1,304 VS and 225/6,161 or 225/6,191 PS at +36/+40. No priority, wait, entry, binding, or title-runtime admission change.

## Independent evidence for distinguishing starts

`--graphics-entry-evidence "$INFLATED_LIBRARY" "$TRUSTED_LLVM_21_DYLIB"` uses the exact 13,383 two-slot rows (2,921 distinct checked PS spans, 1,322 VS). It does not repeat the closure census or use wrapper joins. It checks the stage metadata footer fingerprint, then tests the third-group marker at `+26` as in [compute layout sites](compute-layout-sites.md). The marker supports interpreting the group at `+24` as part of the stored prefix, not a global execution rule. The comparisons beginning at `+24` are withheld for marked groups. Nonzero `0x42` sites are tested independently as aligned in-span scalar loads, without assuming they are reachable from any entry.

For unmarked groups, the register check starts a straight-line decode at the earlier candidate. It rejects an instruction split at the later candidate and conservatively stops at unknown operations. For its small explicit operand whitelist it records ordinary S/V and M0 definitions in the skipped bytes, then looks up to 32 bytes past the later candidate for a read before a locally modeled overwrite. It reports the first witnessed register class, not every live input. The projection does not establish initial register contents, lane activity, EXEC equivalence, or behavior beyond that bound. For marked groups, the exact `s_inst_prefetch 3` encodings at `+36` are counted separately: they do not write a tracked register, but the comparison does not establish that it is safe to elide them or that either offset was used.

The four LLVM 21.1.6 configurations (gfx1013 and gfx1030, each wave64 and wave32) agreed. Counts below are `[distinct stage/program/metadata tuples, stage occurrences]`, with one checked metadata tuple per stage/span in this baseline.

| Independent comparison | PS | VS |
|---|---|---|
| Marked third group; `+36` → `+40` skips only exact prefetch | 2,917 / 13,364 | 1,320 / 13,364 |
| Unmarked; `+24` → `+36` | M0 2 / 15; no read in bound 1 / 2; unresolved 1 / 2 | descriptor SGPR 2 / 19 |
| Unmarked; `+24` → `+40` | M0 3 / 17; VGPR 1 / 2 | descriptor SGPR 2 / 19 |
| Unmarked; `+36` → `+40` | M0 1 / 2; VGPR 3 / 17 | descriptor SGPR 2 / 19 |

The two VS paths read omitted scalar definitions in a buffer descriptor; the PS reads include interpolation M0 and values consumed by arithmetic/packing. Every unmarked span has local evidence against treating `+36` and `+40` as interchangeable **given the same incoming state**. This still cannot choose between entries with different launch state. Four nonzero PS scalar-load metadata items (eight item occurrences across repeated PS slots) are all at `+40` or later, so their geometry does not discriminate these starts; none occurred on the exact-two-slot VS side. The common marked case remains ambiguous between including and excluding the prefetch, and the library does not supply authenticated entry or launch-state evidence. No runtime, translation, or bake gate changes.
