# Compute layout word 1 selects scalar-load sites in PS/0/9

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --compute-layout-sites "$TRUSTED_LLVM_21_DYLIB" "$EXPANDED_LIBRARY"
```

This read-only census validates the [library envelope and joins](shader-pipeline-library.md) and [compute leaves](shader-compute-blobs.md). It counts each distinct `(program ID, layout blob ID)` once after checking the dispatch wave bit for agreement on repeated pairs. No program IDs, site addresses, operands, bytes or disassembly are exported. The survey is over stored program spans, not inferred ISA start/end boundaries.

On the pinned input (2,684 pairs, 2,684 distinct programs), item word 1 (`u32` at item `+4`) shows different evidence for each tag:

- **Tag `0x42`: 92,551 items.** 89,977 have zero word 1; zero is counted separately and not dereferenced. The **2,574 nonzero** values cover 50 programs and 2,574 distinct program/offset pairs. Every value is dword-aligned and selects eight bytes within the matching program, measured as a *byte offset from the program-table span start*. The first dword shifted right by 18 is `0x3d02` (1,702) or `0x3d03` (872). With the associated dispatch wave bit, LLVM 21.1.6 independently decodes all of those as 8-byte `s_load_dwordx4` and `s_load_dwordx8`, respectively, under **both** `gfx1013` and `gfx1030`.
- **Tag `0x41`: 98,351 items.** 88,103 have word 1 in the four-value set observed in the [DLL-embedded FSPX profile](embedded-shaders.md); 10,248 do not. Even where the value is shared, the FSPX same-container root declaration test is not available for these pairs. Do not treat shared numeric codes as confirmed cross-profile class semantics.

This supplies strong offset-base and unit evidence for **nonzero** `0x42` word 1 in PS/0/9 compute. It does not establish why the loads are named, what role zero plays, whether any load is reached from an authenticated entry PC, whether the loader patches it, or how the loaded data is bound. The two tested decoder profiles are independent encoding references with no fallback; neither decode proves Xbox execution semantics. An owned unit fixture checks alignment, truncation, overflow, and the accepted words. No title shader was executed or modified.
