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

Every program with stage-export closure had multiple passing starts; none established a unique entry. Of 13,383 exact VS+PS occurrences, both stages had stage-export closure on 12,794 (wave64), 12,798 (wave32), and 12,794 (same window in both waves for each stage). For the same-window projection, 550 had only VS closure, 39 only PS, and none had neither. No stage-export-qualified VS or PS window was encoding-complete under the owned decoder, so none of the pairs reached the output-binding-only tier. This is conditional static evidence about the tested library spans, not a runtime entry, binding, native variant selection, bake admission, or translation.
