# Compute layout word 1 selects scalar-load sites in PS/0/9

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --compute-layout-sites "$TRUSTED_LLVM_21_DYLIB" "$EXPANDED_LIBRARY"
```

This read-only census validates the [library envelope and joins](shader-pipeline-library.md) and [compute leaves](shader-compute-blobs.md). It counts each distinct `(program ID, layout blob ID)` once after checking the dispatch wave bit for agreement on repeated pairs. No program IDs, site addresses, operands, bytes or disassembly are exported. The survey is over stored program spans, not inferred ISA start/end boundaries.

On the pinned input (2,684 pairs, 2,684 distinct programs), item word 1 (`u32` at item `+4`) shows different evidence for each tag:

- **Tag `0x42`: 92,551 items.** 89,977 have zero word 1; zero is counted separately and not dereferenced. The **2,574 nonzero** values cover 50 programs and 2,574 distinct program/offset pairs. Every value is dword-aligned and selects eight bytes within the matching program, measured as a *byte offset from the program-table span start*. The first dword shifted right by 18 is `0x3d02` (1,702) or `0x3d03` (872). With the associated dispatch wave bit, LLVM 21.1.6 independently decodes all of those as 8-byte `s_load_dwordx4` and `s_load_dwordx8`, respectively, under **both** `gfx1013` and `gfx1030`.
- **Tag `0x41`: 98,351 items.** 88,103 have word 1 in the four-value set observed in the [DLL-embedded FSPX profile](embedded-shaders.md); 10,248 do not. Even where the value is shared, the FSPX same-container root declaration test is not available for these pairs. Do not treat shared numeric codes as confirmed cross-profile class semantics.

At those 2,574 confirmed patterns, word 2's low byte distinguishes two populations. Comparing raw layout fields to the paired instruction's second dword gives:

| Word 2 low byte | Sites | Second dword low 21 bits are zero | Word 3 is zero | Nonzero word 3 × 4 equals low 21 bits |
|---|---:|---:|---:|---:|
| 1 | 1,043 | 24 | 6 | 1 |
| 2 | 1,531 | 1,530 | 1,531 | 0 |

Word 4 is 0 or 1 in all 2,574 items, and every item has a nonzero byte somewhere in words 5–7. The low-byte-2 group has one counterexample to zero instruction bits. Nor does word 3 generally specify those bits in dwords: excluding the six zero cases, that equality succeeds only once in the low-byte-1 group. These are falsifiable raw-field comparisons, not a decoder for offsets, relocations, or bindings. The zero-word-1 population is excluded from this comparison.

The first two 12-byte groups carry the same partial footer-digest fingerprint checked in DLL FSPX for **2,684/2,684** pairs. Only **2,634** have the third `0xd580` group marker: those are exactly the pairs without a nonzero `0x42` site. All **50** with a nonzero site lack that marker, and one checked scalar-load pattern starts before byte 36. Thus a blanket 36-byte prefix skip for this library would omit a checked site. Neither the 24-byte fingerprint nor the third marker establishes the first executable instruction.

For the 50 pairs with nonzero sites, the same command also tests **conditional** CFG walks starting at byte 24 or 36. Each run excludes the preceding bytes, treats edges before the assumed entry or after the stored span as out of bounds, and requires at least one modeled exit. It does not require every path to terminate. A site counts only at a decoded eight-byte scalar load start in a complete modeled graph; a failed walk does not classify its sites.

| LLVM CPU | Assumed entry | Complete / rejected pairs | Site starts / other sites in complete graphs |
|---|---:|---:|---:|
| `gfx1013` | 24 | 41 / 9 | 1,855 / 0 |
| `gfx1013` | 36 | 41 / 9 | 1,853 / 2 |
| `gfx1030` | 24 | 12 / 38 | 62 / 0 |
| `gfx1030` | 36 | 12 / 38 | 60 / 2 |

For both entry assumptions, the first blockers under `gfx1013` were 8 indirect PC transfers and 1 other unmodeled control instruction, with no decode rejects. Under `gfx1030` there were 29 decode rejects, 8 indirect PC transfers and 1 other unmodeled control instruction. Neither profile reported an out-of-bounds edge or overlap. This comparison disfavors assuming byte 36 for these layouts but does not authenticate byte 24 as the hardware entry. The fixture checks a site at entry, a word inside its extension, and a rejected edge back into the omitted prefix.

In each of the four CPU/entry cells, the one other-control rejection is a four-byte `s_sethalt` confirmed by both LLVM and the public GFX10 opcode bits. It starts strictly before the last aligned raw `0xbf810000` marker in the bounded end-of-span search used by the [wrapped/library comparison](shader-pipeline-library.md). That is a positional check, not a decode of the marker or the trailing bytes, and not an exact FSSM join for this rejected walk. The walker still rejects the instruction; neither skipping it nor treating it as an exit has been validated.

The separate [indirect closure check](compute-reachability.md) closes all eight indirect-first `gfx1013` hypotheses at each assumed entry and none under `gfx1030`. It uses exactly the same entry-relative span bounds as the strict walk. These are counts per entry hypothesis, not sixteen unique programs. In the eight closed projections, all 718 checked layout-site references per entry land on decoded eight-byte scalar-load starts (`s_load_dwordx4` or `s_load_dwordx8`). No sites are classified from incomplete projections. The strict completion and site-start totals above are unchanged.

This supplies strong offset-base and unit evidence for **nonzero** `0x42` word 1 in PS/0/9 compute. It does not establish why the loads are named, what role zero plays, whether any load is reached from an authenticated entry PC, whether the loader patches it, or how the loaded data is bound. The two tested decoder profiles are independent encoding references with no fallback; neither decode proves Xbox execution semantics. An owned unit fixture checks alignment, truncation, overflow, and the accepted words. No title shader was executed or modified.

## Graphics cross-check

The command also validates the 16-byte graphics stage metadata header, item tags and footer for **18,837** distinct `(slot, program, metadata)` tuples in graphics slots 0–2. For each nonzero `0x42` word 1 it checks the same span-relative byte offset and 8-byte scalar-load encoding under both CPUs and both wave settings independently. The wave settings are decoder checks, not recovered launch profiles. The unidentified slot 6 is not part of this comparison.

| Stage | Zero | `s_load_dwordx4` | `s_load_dwordx8` | Other nonzero |
|---|---:|---:|---:|---:|
| PS | 185,092 | 2 | 2 | 0 |
| VS | 10,180 | 2 | 0 | 0 |
| MS | 101,762 | 0 | 0 | 0 |

All six nonzero values agree under all four decoder configurations. This supports the offset interpretation in the checked PS and VS examples; the MS rows supply no nonzero example. The graphics check does not assume an entry, reachability, or a patch operation.

The same two-group partial fingerprint matches the exact metadata footer in all **18,837** graphics tuples. The third `0xd580` marker is present in 9,991/9,996 PS, 1,340/1,343 VS, and 7,498/7,498 MS tuples. All three tuples with nonzero sites lack that marker. Unlike the compute set, a missing third marker does not imply nonzero sites: five graphics tuples (three PS, two VS) lack it and have no nonzero sites. This extends evidence for a shared stored-span fingerprint, not a global entry skip or native byte identity with an FSSM payload.
