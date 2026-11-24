# Static source joins for the small raw-store compute slice

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --compute-source-join /path/to/libLLVM.dylib gfx1013 \
  /path/to/native /path/to/wrapped /path/to/pipeline/library.bin
```

The reachable census selects the small single-raw-store candidates with proven zero-extended user-data descriptor-base provenance. The join compares the **complete FSSM bytes** against payloads inflated from structurally validated wrapped compute DXBC entries. It takes a digest only from a unique, 20-byte `HASH` chunk, compares the 16 digest bytes to the footer of each validated compute layout and retains all distinct matching library program IDs. Output contains aggregate counts only. No filenames, hashes, contents, or bindings are written. Input is read-only; native retention and file lengths/counts are bounded.

On the local extraction (`gfx1013`, LLVM 21.1.6), both distinct shortlist bodies matched exactly one wrapped compute entry each, each with one source digest and one distinct compiled-library program candidate. **None of the 2,689 compute wrappers in 26,503 wrapped records has a standard `RTS0` chunk.** The absence is specific to the checked top-level DXBC directory; it is not a claim about opaque/private data, externally serialized root signatures, or runtime state. A unique digest association is evidence of genealogy, not proof of program byte identity or which PSO the title selects.

There is now a reproducible static route from the shader body to a candidate layout, but no evidence yet maps its descriptor-base live-in to an exact root parameter or heap binding. Do not assign a Metal resource until the runtime producer (bound compute PSO and root/heap state) or independently validated equivalent metadata corroborates the binding, resource range, and address-space mapping.
