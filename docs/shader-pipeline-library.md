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

## Reproduce the structural census

```sh
cargo test --lib pipeline_library
cargo run --release --example shader-pipeline-census -- /path/to/local/pipeline/library.bin
```

The Rust parser is read-only and zero-copy over the supplied inflated bytes, with a 512 MiB input cap. The example reads one file and prints aggregate counts only. It checks structural framing, span placement and ID ranges with explicit absent-slot handling; it does not read the extraction's JSON, open wrapped DXBC, verify blob internals, or decode programs. The sidecar/source comparisons above were separate local experiments. The parser preserves duplicate keys and non-unique joins if encountered; the observed key and tuple cardinalities are evidence, not parse preconditions. No local artifacts or per-record lists are included.
