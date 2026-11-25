# Static source joins for the small raw-store compute slice

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --compute-source-join /path/to/libLLVM.dylib gfx1013 \
  /path/to/native /path/to/wrapped /path/to/pipeline/library.bin
```

The reachable census selects the small single-raw-store candidates with proven zero-extended user-data descriptor-base provenance. The join compares the **complete FSSM bytes** against payloads inflated from structurally validated wrapped compute DXBC entries. It takes a digest only from a unique, 20-byte `HASH` chunk, compares the 16 digest bytes to the footer of each validated compute layout and retains all distinct matching library program IDs. Output contains aggregate counts only. No filenames, hashes, contents, or bindings are written. Input is read-only; native retention and file lengths/counts are bounded.

On the local extraction (`gfx1013`, LLVM 21.1.6), both distinct shortlist bodies matched exactly one wrapped compute entry each, each with one source digest and one distinct compiled-library program candidate. **None of the 2,689 compute wrappers in 26,503 wrapped records has a standard `RTS0` chunk.** The absence is specific to the checked top-level DXBC directory; it is not a claim about opaque/private data, externally serialized root signatures, or runtime state. A unique digest association is evidence of genealogy, not proof of program byte identity or which PSO the title selects.

## First bound-dispatch witness: ingestion checklist

For **2/2 wrapped candidates**, the [static def-use check](fssm-launch-inventory.md#descriptor-base-provenance) proves that one user-data SGPR is zero-extended to form the base of the four-dword scalar load, whose result reaches the raw store after `lgkmcnt(0)`. This is proof about the checked **wrapped bodies** under the reference profile. The unique source-digest joins do not prove the same def-use in the compiled-library candidates, select a resident program, or identify its programmed entry. The owned store/replay probe uses a synthetic descriptor ABI and cannot fill that gap.

Start with one direct dispatch of the smallest candidate: a straight-line, 10-node path with a `1×1×1` thread group and one raw store. The [existing capture correlation](compute-capture.md) can resolve an exact table slot but does not prove the shader read from it. No resident dispatch has been authenticated for either candidate. Require all of the following observations for the same executable/library build, session, and dispatch occurrence:

| Join | Required observation | Reject rather than infer |
|---|---|---|
| Successful creation → execution | Live PSO generation, actual resident code extent and bytes, programmed entry, wave mode and launch state (including group size and the observed direct group counts). To call it a library match, verify the exact library occurrence and the mapping from stored bytes to resident bytes, including any fixups. Check the reached load-to-store path in that resident program. | Wrong build, retired or reused PSO, ambiguous match, missing launch state, source digest or stored-window hypothesis in place of resident identity. |
| Binding → scalar load | Ordered list/pipeline/root/heap events for the path actually used; verified root parameter, full table handle and live heap geometry if table-backed; provenance of the actual user-SGPR word, effective scalar-load address and the four consumed dwords. | Recording gap/reset, stale or conflicting bindings, truncated handle, unauthenticated indirect path, or a resolved slot with no evidence it produced the scalar read. |
| Descriptor → store | Independently verified descriptor interpretation, live GPU mapping and writable backing generation/range, plus the active invocation's effective store byte address and access width. Check the full access span within the backing. | Unknown descriptor format or address space, stale/aliased mapping without disambiguation, missing store operands, overflow or out-of-range write. |

A complete join would establish provenance for that dispatch, not general descriptor or wait semantics, validated lowering, or permission to replay. Missing evidence leaves the record incomplete; do not bind a Metal resource from a static candidate alone. Keep raw captures local.
