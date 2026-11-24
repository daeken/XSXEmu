# Compiled shader pipeline library: PS/0/9 joins

Scope: one read-only local extraction, the inflated `pipeline/library.bin` discussed in [shader-archive.md](shader-archive.md). This is not a native FSSM, general FSPX, or runtime PSO specification. The archive scanner documents the 4,205 zlib streams; offsets here address their concatenated, inflated bytes. Layout observations below come from walking the binary tables independently, comparing all PSO rows and stage IDs with the local extraction's JSON as a secondary check. Leonida's `docs/shader_library.md` is a factual reference only, not an implementation dependency.

## Envelope and tables

All integers are little-endian. Offsets below are in bytes. Header size is `0x80`; `+0x00` is the four-byte magic `50 53 00 09`; `+0x04` and `+0x24` are NUL-padded 32-byte and 36-byte labels; `+0x48` is an opaque u64; `+0x50..+0x60` are four u32 row counts (graphics, compute, blobs, programs); `+0x60` and `+0x64` are u32 sizes of the blob and program arenas. No semantics assigned to `+0x68..+0x80`.

| Section | Inflated start | Row count | Row stride / arena bytes |
|---|---:|---:|---:|
| Graphics PSOs | 128 | 25,471 | 112 |
| Compute PSOs | 2,852,880 | 2,693 | 24 |
| Blob table | 2,917,512 | 54,576 | 8 |
| Program table | 3,354,120 | 21,522 | 8 |
| Blob arena | 3,526,296 | — | 31,120,020 |
| Program arena | 34,646,316 | — | 240,894,464 |
| End (exclusive) | 275,540,780 | — | — |

Derive boundaries by checked count × stride and cumulative additions, requiring exact file length. Blob/program IDs are **zero-based table row indices**, not offsets. Each table entry is `(u32 offset, u32 size)` relative to its own arena. The observed blob spans are nonempty and tile their arena in ID order. Program spans are nonempty and increasing without overlap, with starts aligned to 256 bytes *relative to their arena*, not the file. Their stored sizes are 52–239,464 bytes. All inter-program gaps (2,064,676 bytes) and the final 24-byte tail were zero, outside the table-declared spans. A table span is not a verified executable range; prologues, internal termination and reachability are separate concerns.

## PSO references

| Record | Byte offset | Width | Interpretation |
|---|---|---:|---|
| Both | `0x00` | u64 | Opaque PSO key (extraction labels it `hash`); algorithm and runtime correspondence unproven |
| Graphics | `0x08` | u32 | State blob ID |
| Graphics | `0x0c` | u32 | Pipeline/input-layout blob ID; not a complete portable input layout spec |
| Graphics | `0x10,18,20,28,30` | 5 × u64 | Opaque words; no reconstruction semantics inferred |
| Graphics | `0x38 + 8s` | u32 | Program ID for slot `s`, 0–6 |
| Graphics | `0x3c + 8s` | u32 | Stage metadata blob ID for slot `s`, 0–6 |
| Compute | `0x08` | u32 | Dispatch-state blob ID (all observed sizes 28 bytes) |
| Compute | `0x0c` | u32 | Additional opaque blob ID (all observed sizes 20 bytes) |
| Compute | `0x10` | u32 | Program ID (CS) |
| Compute | `0x14` | u32 | Layout blob ID |

All four compute IDs and both graphics state/layout IDs are mandatory. In a graphics slot, `0xffffffff` means absent in **each** ID field. All observed present slots 0–2 have metadata; slot 6 has a real program and absent metadata. An absent metadata slot is not an absent program. Never substitute program ID for blob ID or select the last stage blob seen by key.

| Stage / slot | PSO references | Distinct programs | Distinct associated stage/layout blobs |
|---|---:|---:|---:|
| CS (compute) | 2,693 | 2,684 | 2,684 |
| PS (slot 0) | 24,111 | 9,996 | 9,333 |
| VS (slot 1) | 13,409 | 1,343 | 1,241 |
| MS (slot 2) | 12,062 | 7,498 | 7,060 |
| Unknown (slot 6) | 2 | 1 | 0 |

Slots 3–5 are absent everywhere; slot 6's shader stage is unidentified. Graphics combinations: 13,383 PS+VS, 10,726 MS+PS, 1,336 MS-only, 24 VS-only, two PS+VS+slot-6. All 21,522 program IDs are referenced, each by only one stage and with a consistent optional stage/layout blob in this sample. The inverse is not unique: e.g. 9,996 PS programs map to 9,333 blob IDs. All 54,576 blob IDs are referenced; the eight nonempty blob roles (graphics state and input layout, PS/VS/MS metadata, compute state/opaque/layout) are pairwise disjoint. Graphics state/input-layout use 5,680/25,229 distinct IDs; compute dispatch/opaque use 665/2,684. Each of the 2,693 compute keys is different despite nine excess rows over unique full reference tuples (2,676 tuples once, seven twice, one three times). Graphics keys are all distinct and do not intersect compute keys; only 25,229 graphics tuples of state/layout and stage pairs are distinct (excluding the opaque words and key). Neither tuple nor PSO key is a verified Metal cache key.

The secondary sidecar check matched every PSO key, graphics top-level reference and named program slot, and compute dispatch reference and program. The sidecar summaries omit some references; range validation of those fields was done against the binary, not inferred from JSON. The binary gives a useful provenance graph, not a pipeline that can yet be baked: root/descriptor binding, complete fixed-function state, input/output linkage, the opaque fields, unidentified stage, source variants, and runtime-key correspondence remain open.

## Graphics state/layout extent checks

`--wrapped-library` counts state blobs by distinct ID within each stage combination, independently of wrapper availability. VS-only state is always 380 bytes; PS+VS state is 380 through 420 in eight-byte steps (including the two extra-slot rows at 388). MS-only state is always 464 bytes; PS+MS state is 464 through 520 in eight-byte steps. These are size profiles, not evidence that the increments are repeated records or attachments.

Within an exact stage-slot combination, the PS program ID predicts the observed state blob size: none of the 2,921 PS programs in PS+VS, 7,132 in PS+MS, or one in PS+VS+slot 6 references two sizes in its cohort. The same programs can reference multiple state IDs (1,117, 2,434, and one respectively). Grouping instead by PS metadata ID finds one PS+VS and eight PS+MS families with multiple sizes. Pooling across slot combinations finds 58 of 9,996 PS programs with multiple sizes. PS metadata ID alone therefore does not uniquely predict state size. Subtracting the respective 380/464-byte cohort baselines leaves an equal residual length in all 58 cross-cohort programs with varying raw lengths. This does not establish a section boundary. As a separate byte comparison, every multi-state-ID program in an exact slot cohort has disagreement before the tentative split at its baseline, so different state IDs are not merely byte-identical duplicates here. Disagreements also occur after that split in 762 PS+VS and 336 PS+MS programs, and in neither of the two PS+VS+slot-6 rows for their shared PS program. The suffix bytes cannot be recovered from PS program ID and slot presence alone even when their lengths agree.

For the 58 PS programs present in both exact PS+VS and PS+MS cohorts, 39 have nonempty suffixes at both baseline offsets. Every one of those 39 has at least one byte-identical cross-cohort suffix pair; all referenced states share the same suffix in 37 of the 39. Moving both starts eight bytes earlier gives the same totals for the nonempty subset. Including all 58 programs, at offsets 336/420 (44 bytes before the baselines) every program has at least one byte-identical cross-cohort pair, and 50 have invariant suffix bytes across all references. The two totals are unchanged one byte earlier, at 335/419. At 334/418 and 332/416 there are no equal pairs. This localizes the earliest aligned suffix match to the byte rather than the dword, without establishing a serialized section boundary.

Across all graphics rows (including pixel-less rows), `--wrapped-library` also walks distinct `(state ID, observed baseline)` pairs; references with unknown baselines are counted separately. The pinned corpus has 5,680 IDs and 5,680 pairs, with no multi-baseline ID, unknown baseline, short span, or residual length outside eight-byte multiples. The 32 bytes at `[336,368)` in the VS cohort and `[420,452)` in the MS cohort are identical across all pairs. Only the first and third dwords in that window are nonzero. The next 12 bytes, ending at the respective baseline, are all zero in 825 pairs but not in the others. The preceding byte at baseline −45 is zero in both cohorts, extending the invariant window to 33 bytes. At baseline −46, the VS byte is always zero and the MS byte is always the same nonzero value; their value sets are disjoint across all state IDs, not only the 58 shared PS programs. This is an invariant byte window, not a decoded field layout, boundary, or safe default for other inputs.

The audit also tests whether the residual directly mirrors declared PS color targets. For each exact PS stage/digest family it projects `OSG1` rows with folded name `sv_target` and public system-value code 64 to semantic indices 0–7. It compares that set with the positions of nonzero eight-byte chunks after the 380/464-byte baseline, leaving zero chunks in place. All candidates agree on this projection in the 24,090 rows with PS source. The chunk count equals the number of declared targets in only 5,281/13,364 PS+VS rows and 1,848/10,726 PS+MS rows. Nonzero chunk positions equal the declared target set in only 5,304 and 3,128 rows, respectively. The other 21 PS rows have no source candidate. Neither test supports reconstructing attachments from the PS declaration or interpreting the residual as a direct array indexed by `SV_Target`; these comparisons do not check actual bound targets or hardware writes.

All 25,229 distinct graphics layout blobs fit an 80-byte prefix with a little-endian u32 record count at `+76`, then densely packed variable-length records starting at `+80`. Each record is a little-endian u32 byte length, a nonempty ASCII string with a single final NUL included in the length, and six little-endian u32 words. There is no alignment between records or before the word fields. The blob ends with just enough zero bytes to align the overall length to four: 16,313 blobs have zero padding bytes, 5,526 have one, 337 have two, and 3,053 have three. The 20,638 observed records must not be walked with a fixed 36-byte stride: the earlier size formula was a corpus-level correlation, not framing. All 15,935 zero-count blobs are 80 bytes; positive counts are 1–5 or 7. Every MS row references an 80-byte layout. The parser checks extents and padding without emitting any string or record payload.

For each PSO row with a VS slot, the scanner compares `(ASCII-folded name, first word after the name)` in the layout with `(ASCII-folded name, semantic index)` in ordinary VS `ISG1` rows. It uses that slot's exact stage/digest candidate family and requires all wrappers to agree on the ordered input keys, component type codes, and primary-mask component counts. A row is ordinary only if its system-value enum is zero and its folded name does not start with `sv_`. The complete key multisets agree in all 13,388 rows with source candidates, preserving multiplicity. They agree in order in 13,327 (13,303 PS+VS and 24 VS-only) and agree only after sorting in 61 PS+VS rows. The other 21 (19 PS+VS and two with extra slot 6) have no VS source candidate. No matched family disagrees on its source key sequence. This supports the name and semantic index fields; it rules out matching by array ordinal as a general rule and does not establish the remaining five words, vertex format or fetch ABI.

The remaining five words are consistent with the public [`D3D12_INPUT_ELEMENT_DESC`](https://learn.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_input_element_desc) field order: candidate format, input slot, aligned byte offset, input class, and instance step rate. All 20,638 records use one of the nine tested public DXGI format codes and a slot below 32; both class and step words are zero. With the candidate DXGI widths, each slot's first element starts at zero and subsequent intervals in record order do not overlap. Counting the first element as contiguous with offset zero gives 20,520 contiguous intervals and 118 gaps. This strongly supports the field interpretation, but does not validate runtime vertex-buffer strides, conversion rules, instance-rate behavior, or actual Metal vertex fetch.

The candidate format's logical conversion type also agrees with the VS declaration for all 20,634 uniquely paired element references, including normalized formats compared to floating declarations. These counts repeat elements across PSO rows. The format's logical component count equals the declared primary-mask population in 17,631 references and exceeds it in 3,003; it is never smaller. Thus equal component counts are not a suitable invariant. The check does not establish which components the native vertex fetch supplies or verify numeric conversion on a device.

## Metadata and source-digest joins

Of the eight referenced blob roles, four share an observed layout: 17,634 distinct graphics stage metadata blobs and 2,684 compute layout blobs. The graphics header is 16 bytes and its first u32 is `2`; the compute header is 24 bytes and its first u32 is `0x403` (low byte `3`). The final u32 of either header has low byte `0x40`; its upper bits vary and are **not** a plain record count. After the header are zero or more 32-byte records beginning with u32 `0x41` or `0x42`, then a 32-byte footer: u32 `0x43`, 16 digest bytes in stored order, and 12 zero bytes. Checked each applicable program's blob against this framing. The table-declared size, not a scan for marker bytes, fixes the footer address (`size - 32`). Records' binding semantics, the remaining header bits and the contents of the 20-byte compute blob are unverified. The separate 28-byte dispatch blob's u32 at +16 has bit 20 set for 1,529 distinct CS programs (wave32 field); the u32 at +24 has bit 10 set for 91 distinct CS programs in this extraction (`TG_SIZE_EN` per AMD register definitions). These are bit counts, not verification of dispatch behavior.

Comparing against every local `fspx` pair: **21,522/21,522** `.code` files exactly match their program span (including in-span non-executable bytes). Every `.json` sidecar and index entry agrees on program and stage label; the sidecars also agree on the code arena offset and size, and on the available metadata digest or its absence. This verifies the extraction correspondence, not that the `fspx` directory contains standalone FSPX containers or that the sidecar's executable subrange is correct.

For source provenance, independently walked all 26,503 extracted wrapped DXBC chunk directories. Each had one `HASH` chunk (20-byte payload: 4-byte flags then 16 digest bytes) and a stage in the `DXIL` program header (u16 at payload +2; structural header, not a claim that the bitcode is genuine DXIL). On equality of digest bytes and stage, retaining **all** candidate wrapped files:

| Stage | Matched programs | Of those, multiple source-file candidates | No match |
|---|---:|---:|---:|
| CS | 2,680 | 8 | 4 |
| PS | 9,991 | 27 | 5 |
| VS | 1,340 | 45 | 3 |
| MS | 7,498 | 733 | 0 |
| Unknown slot 6 | 0 | 0 | 1 (no metadata digest) |
| Total | 21,509 | 813 | 13 |

19,595 extracted wrapped files occur in at least one candidate set; no candidate joined by digest had a conflicting stage. A candidate file count is not a unique shader count. This join establishes source-family provenance only. No first-candidate rule, native FSSM variant selection, signature equivalence, or machine-code equality to wrapped-source payloads was validated.

### Candidate stored-byte comparison

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-library "$WRAPPED_DXBC_DIR" "$EXPANDED_PIPELINE_LIBRARY"
```

The scanner repeats the stage/digest join directly against the expanded binary library and checked wrappers, with no sidecars. It compares each FSSM payload in each candidate wrapper to the corresponding entire library program span. It tests two length-sensitive equality hypotheses: the bounded FSSM window addressed by little-endian u64 start and length at `+0xc0/+0xc8`, and that same window minus its first 40 bytes. The second comparison tests the known compute prefix displacement as a byte-window hypothesis; it is **not** an executable-start rule for graphics. Neither comparison strips suffix bytes, reinterprets fields, or assumes that the two formats use the same padding.

| Stage | Bounded payload/program comparisons | Equal entire stored windows | Equal after FSSM +40 |
|---|---:|---:|---:|
| PS | 10,020 | 0 | 0 |
| VS | 1,419 | 0 | 0 |
| CS | 2,689 | 0 | 0 |
| MS | 8,666 | 0 | 0 |
| Total | 22,794 | 0 | 0 |

There were no unbounded candidate windows. The extra VS payloads are retained, not reduced to one per wrapper. The unlabelled slot-6 program is outside the join. These negative results reject direct stored-span aliasing for the two tested views, not related instruction bodies after other framing, layout fixup, or variant selection. No IDs, digests, shader bytes, or instruction listings are printed.

### Per-row graphics source candidate coverage

The scanner also joins each **present, stage-labelled slot in each PSO row** to wrapped sources by `(stage, digest)`, using the footer on that slot's exact metadata reference. It does not substitute candidates attached to another reference to the same program. Counts are by PSO row, not by unique tuple or program; a slot with more than one wrapper is ambiguous even if the wrappers may be equivalent. Unknown slots remain in the row grouping but have no stage/digest classification.

| Present slot roles | All known slots unique | All known slots found, some ambiguous | Missing known slot, no ambiguity | Missing and ambiguous known slots |
|---|---:|---:|---:|---:|
| PS + VS | 13,284 | 80 | 19 | 0 |
| PS + VS + slot 6 | 0 | 0 | 2 | 0 |
| PS + MS | 8,775 | 1,951 | 0 | 0 |
| VS only | 24 | 0 | 0 | 0 |
| MS only | 1,241 | 95 | 0 | 0 |

The unique two-stage cohorts are the starting point for source interface comparisons. The counts do not prove that a wrapper contains the native variant used by a PSO, that two source interfaces are compatible, or that any PSO is reconstructible. In particular, the two rows with slot 6 have both an unidentified stage reference and a missing wrapped source among the known slots.

### Ordinary source interfaces in complete two-stage graphics rows

For exactly PS+VS or PS+MS rows with one wrapper in each slot's candidate family, the scanner compares the producer's `OSG1` to the pixel shader's `ISG1`. A source key is the ASCII-folded semantic name plus semantic index. It excludes rows with a nonzero system-value enum or a folded `sv_` prefix; these need separate pipeline rules. For each remaining input key, it requires one input and one output row, then compares the raw source component type and the number of bits in their primary masks. Register ordinal and raw primary mask are compared separately, not used to select the match. Counts of keys and excluded system inputs are accumulated per PSO row, not deduplicated across PSOs.

| Producer | Rows compared | Rows with no ordinary PS inputs | Excluded system PS input rows | Unique ordinary key pairs |
|---|---:|---:|---:|---:|
| VS | 13,284 | 596 | 8,226 | 49,477 |
| MS | 8,775 | 742 | 11,963 | 72,222 |

There are no missing or duplicate ordinary keys in these cohorts. All 121,699 unique ordinary pairs agree on raw component type, register ordinal, and primary mask, so none needs more components than the paired producer declares. The 20,721 rows with ordinary PS inputs pass the source-side check; the 1,338 without ordinary PS inputs are kept separate. An owned fixture checks case folding, key indices, duplicates, system-name exclusion, and comparisons with different type, width, register, or lane positions. This is a declaration-level result: no system or per-primitive linkage, interpolation behavior, native parameter indices, runtime stage variants, or verified execution is implied.

Multi-candidate rows are checked separately. Each slot's entire wrapper family must agree on the unordered multiset of ordinary `(key, type, register, primary mask, secondary mask)` rows and the **count** of excluded system rows. A disagreement makes that family ineligible; the scanner never selects a wrapper by its interface. All 80 ambiguous PS+VS and 1,951 ambiguous PS+MS rows meet this projection-invariance check. They add 868 and 16,207 unique ordinary key pairs respectively, all matching type/register/mask. All 80 VS rows and 1,859 MS rows have ordinary PS inputs; the other 92 MS rows do not. This extends the same declaration-level result without resolving the wrapper or native variant ambiguity. System-value contents and incomplete or extra-stage rows are still outside this ordinary-interface comparison.

For ordinary pairs with agreeing registers and primary masks, the [public DXBC convention](https://learn.microsoft.com/en-us/windows/win32/api/d3d12shader/ns-d3d12shader-d3d12_signature_parameter_desc) treats a set secondary bit differently by direction: read for input and never written for output. The scanner intersects `(PS secondary & PS primary)` with the producer's secondary mask, rather than comparing the two secondary bytes for equality. All 138,774 ordinary pairs qualify for this check; 117,986 have a nonempty PS read mask. None intersects a producer never-write mask. Including the secondary bytes in each candidate projection leaves all 2,031 complete multi-wrapper rows invariant. This checks the serialized masks rather than proving that every producer path writes each consumed lane.

### System-value declaration keys in complete two-stage rows

The same PSO rows are checked independently for public system-value declaration keys `(validated name/enum class, semantic index)`. All candidate families agree on this second projection (class/index multiplicity and count of other/mismatched rows), including the multi-wrapper families. A matching producer declaration is counted for PS Position, ClipDistance, and CullDistance; PS IsFrontFace is a rasterizer-generated declaration and is not looked up in the producer outputs.

| Producer / candidate cohort | PSO rows | Position keys paired | ClipDistance keys paired | CullDistance keys paired | IsFrontFace input rows |
|---|---:|---:|---:|---:|---:|
| VS / unique | 13,284 | 6,819 | 1,319 | 1 | 87 |
| VS / multi | 80 | 80 | 0 | 0 | 26 |
| MS / unique | 8,775 | 8,775 | 1,134 | 0 | 2,054 |
| MS / multi | 1,951 | 1,951 | 422 | 0 | 431 |

No compared key is missing or duplicated, and no PS input falls into the other/mismatched system class. Counts are repeated per PSO row. This is a declaration presence test, not a comparison of type, mask, transformed position, interpolation, clip/cull configuration, fixed-function state, or native export locations.

### Conditional marker-bounded equality

The same scanner separately tests a narrower byte window. On the FSSM side it begins at `start + 40`, removes only trailing `0xbf9f0000` words, and requires the resulting aligned bytes to end in `0xbf810000`. On the library side it looks for the last aligned `0xbf810000` in the final 512 stored bytes and compares through that word from each explicit hypothesis (`+0`, `+24`, `+36`). A raw marker can be a literal or data; it is not a verified instruction or proof of entry/exit.

| Stage | Candidate programs with a bounded library marker | Exact at +0 | Exact at +24 | Exact at +36 |
|---|---:|---:|---:|---:|
| PS | 9,990 | 0 | 0 | 0 |
| VS | 1,340 | 0 | 0 | 0 |
| CS | 2,593 | 0 | 46 | 5 |
| MS | 7,498 | 0 | 0 | 0 |

The 51 compute positives are distinct programs. These are exact byte-window correspondences within the digest families under the stated cut hypotheses; they do not establish the actual executable extents, a global skip rule, register bindings, or an identity for the remaining candidates. The owned fixture exercises alignment, the backward search bound and last-marker selection.

All 46 `+24` byte matches are in the 50-program subset with nonzero `0x42` word 1, and none of the five `+36` matches is in that subset. Within the subset, no other tested window even has the same length as its candidate FSSM window, so allowing operand-only differences would not add matches under these cut hypotheses. This distinguishes the observed families without claiming entry offsets or interpreting `0x42` as a relocation.

For compute, the scanner also compares the FSSM XYZ and wave-width bit to every distinct dispatch XYZ/wave-bit pair referencing the digest-joined library program. No program has multiple such library pairs in this corpus. All 2,689 candidate payload/program comparisons have readable compute metadata. All 2,680 joined compute programs agree, including the 51 conditional byte-window positives, with no disagreeing profile. This is launch metadata agreement, not an observed dispatch or a descriptor ABI. The checker retains disagreement even when another candidate or library reference agrees.

Append a trusted LLVM 21 library path and `gfx1013` or `gfx1030` to `--wrapped-library` to walk the matching compute windows under one explicit reference profile. The walker requires profile agreement and independently checks that the FSSM window matches the existing FSSM compute-span parser. It starts at byte zero of the equal window and follows supported direct control, requiring a reachable decoded end instruction. LLVM 21.1.6 completed 43 of 51 on `gfx1013` and 14 of 51 on `gfx1030`; `gfx1013` reports eight first blockers at indirect PC transfers; `gfx1030` reports eight indirect PC blockers and 29 decode blockers. All 51 passed the FSSM span prerequisite. These are conditional static CFG results, not evidence that either reference CPU is the console ISA or that the library actually enters at that offset.

The [indirect closure check](compute-reachability.md) runs separately on these matched windows when the strict reference walker first stops at an indirect transfer. All eight such `gfx1013` library programs have a closed reference hypothesis with a reachable end instruction; none of the eight `gfx1030` programs does. The counts remain separate from the 43 and 14 strict walks and provide no additional evidence of an observed library entry or dispatch.

## Reproduce the structural census

```sh
cargo test --lib pipeline_library
cargo run --release --example shader-pipeline-census -- /path/to/local/pipeline/library.bin
```

The Rust parser is read-only and zero-copy over the supplied inflated bytes, with a 512 MiB input cap. The example reads one file and prints aggregate counts only. It checks structural framing, span placement and ID ranges with explicit absent-slot handling; it does not read the extraction's JSON, open wrapped DXBC, verify blob internals, or decode programs. The sidecar/source comparisons above were separate local experiments. The parser preserves duplicate keys and non-unique joins if encountered; the observed key and tuple cardinalities are evidence, not parse preconditions. No local artifacts or per-record lists are included.
