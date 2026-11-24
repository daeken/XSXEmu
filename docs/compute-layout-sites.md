# Compute layout word 1 selects scalar-load sites in PS/0/9

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --compute-layout-sites "$TRUSTED_LLVM_21_DYLIB" "$EXPANDED_LIBRARY"
```

This read-only census validates the [library envelope and joins](shader-pipeline-library.md) and [compute leaves](shader-compute-blobs.md). It counts each distinct `(program ID, layout blob ID)` once after checking the dispatch wave bit for agreement on repeated pairs. No program IDs, site addresses, operands, bytes or disassembly are exported. The survey is over stored program spans, not inferred ISA start/end boundaries.

On the pinned input (2,684 pairs, 2,684 distinct programs), item word 1 (`u32` at item `+4`) shows different evidence for each tag:

- **Tag `0x42`: 92,551 items.** 89,977 have zero word 1; zero is counted separately and not dereferenced. The **2,574 nonzero** values cover 50 programs and 2,574 distinct program/offset pairs. Every value is dword-aligned and selects eight bytes within the matching program, measured as a *byte offset from the program-table span start*. The first dword shifted right by 18 is `0x3d02` (1,702) or `0x3d03` (872). With the associated dispatch wave bit, LLVM 21.1.6 independently decodes all of those as 8-byte `s_load_dwordx4` and `s_load_dwordx8`, respectively, under **both** `gfx1013` and `gfx1030`.
- **Tag `0x41`: 98,351 items.** 88,103 have word 1 in the four-value set observed in the [DLL-embedded FSPX profile](embedded-shaders.md); 10,248 do not. Even where the value is shared, the FSPX same-container root declaration test is not available for these pairs. Do not treat shared numeric codes as confirmed cross-profile class semantics.

The first two 12-byte groups carry the same partial footer-digest fingerprint checked in DLL FSPX for **2,684/2,684** pairs. Only **2,634** have the third `0xd580` group marker: those are exactly the pairs without a nonzero `0x42` site. All **50** with a nonzero site lack that marker, and one checked scalar-load pattern starts before byte 36. Thus a blanket 36-byte prefix skip for this library would omit a checked site. Neither the 24-byte fingerprint nor the third marker establishes the first executable instruction.

For the 50 pairs with nonzero sites, the same command also tests **conditional** CFG walks starting at byte 24 or 36. Each run excludes the preceding bytes, treats edges before the assumed entry or after the stored span as out of bounds, and requires at least one modeled exit. It does not require every path to terminate. A site counts only at a decoded eight-byte scalar load start in a complete modeled graph; a failed walk does not classify its sites.

| LLVM CPU | Assumed entry | Complete / rejected pairs | Site starts / other sites in complete graphs |
|---|---:|---:|---:|
| `gfx1013` | 24 | 41 / 9 | 1,855 / 0 |
| `gfx1013` | 36 | 41 / 9 | 1,853 / 2 |
| `gfx1030` | 24 | 12 / 38 | 62 / 0 |
| `gfx1030` | 36 | 12 / 38 | 60 / 2 |

For both entry assumptions, the first blockers under `gfx1013` were 8 indirect PC transfers and 1 other unmodeled control instruction, with no decode rejects. Under `gfx1030` there were 29 decode rejects, 8 indirect PC transfers and 1 other unmodeled control instruction. Neither profile reported an out-of-bounds edge or overlap. This comparison disfavors assuming byte 36 for these layouts but does not authenticate byte 24 as the hardware entry. The fixture checks a site at entry, a word inside its extension, and a rejected edge back into the omitted prefix.

This supplies strong offset-base and unit evidence for **nonzero** `0x42` word 1 in PS/0/9 compute. It does not establish why the loads are named, what role zero plays, whether any load is reached from an authenticated entry PC, whether the loader patches it, or how the loaded data is bound. The two tested decoder profiles are independent encoding references with no fallback; neither decode proves Xbox execution semantics. An owned unit fixture checks alignment, truncation, overflow, and the accepted words. No title shader was executed or modified.
