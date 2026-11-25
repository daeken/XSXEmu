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
