# Owned GFX10.3 descriptor/store probe

`buffer_fixture.s` is an original, straight-line `gfx1030` compute analogue of a descriptor load followed by a raw write. It loads four scalar dwords, waits for that load, computes one payload word with a vector XOR, issues `buffer_store_dwordx4` (`offen` with scalar and immediate offsets), then terminates. The restricted decoder accepts only this instruction order, register assignments, and modifiers, allowing the low 12 bits of each byte immediate to vary. Both backends use the decoded immediates. The scalar load is synchronous in the lowering: the matched `lgkmcnt(0)` is required, but the probe does not implement general `s_waitcnt` semantics.

## Synthetic dispatch ABI

* One active invocation, with separate read-only descriptor-table and writable backing buffers. The host supplies `s[4:5]` as a zero-extended 32-bit **byte offset into the table**, not a guest or Metal address. It supplies `v4` as an unsigned byte offset and `v0`, `v9`, `v10`, `v11` as payload inputs. The XOR supplies `v8`.
* At `table_base + load_imm`, read `[binding, base_bytes, extent_bytes, mode]` into the role of `s[8:11]`. The entire 16-byte descriptor must fit in the table and its starting address must be dword aligned. Only logical writable binding `0` (Metal `buffer(1)`) and mode `1` (raw write) are accepted. The base and extent must both be dword aligned and the whole view must fit in the bound backing buffer. The host derives both buffer lengths from the actual allocations, independently of the descriptor.
* `relative = v4 + 4 + store_imm` is measured in bytes relative to the view. The address arithmetic widens before addition; 32-bit wraparound never makes an address valid. The entire range `[relative, relative + 16)` must fit in the view, with a dword-aligned start; exact end is valid. If any check fails, no output word changes. Otherwise write `v8` through `v11` in order at `base_bytes + relative`, as four consecutive dwords. The lowering does not promise an atomic 16-byte store or model inter-lane aliasing or ordering.

The instruction **encoding** is standard AMD GFX10.3, checked with LLVM. The descriptor words, table addressing, preloaded registers, active invocation, and bounds behavior are **only the probe ABI**, not verified Xbox ABI or native AMD descriptor semantics. This does not infer Xbox user data, root-table layout, resource addresses, or out-of-range behavior. It does not consume retail shaders or archives; no retail bytes, disassembly, or GPL implementation code were used to build the fixture.

## Checks

From the repo root:

```sh
M=tools/shader-inventory/Cargo.toml
# Use an AMDGPU-enabled LLVM. If LLVM_MC is unset and llvm-mc is not on PATH,
# the suite skips only the external encoding check.
LLVM_MC=/path/to/llvm-mc cargo test --locked --manifest-path "$M" --all-features
MTL_DEBUG_LAYER=1 MTL_SHADER_VALIDATION=1 cargo run --locked --release \
  --manifest-path "$M" --features metal-probe --bin shader-metal-probe
```

LLVM 21.1.6 assembled the owned fixture to the seven checked-in words and disassembled those words back to the five instructions. LLVM validates encoding, not descriptor or execution semantics. The Metal binary runs the existing 32-lane ALU test and then this single-invocation test. On Apple M4 with Metal API and GPU validation, all 16 buffer cases matched the CPU reference across all 316 backing words, including unchanged canaries. The CPU reference was also checked against literal expected outputs. The cases cover exact table, view and allocation endpoints; a dword-aligned but non-16-byte-aligned store; truncated/out-of-bounds descriptors; invalid bindings and modes; alignment failures; a view extending past its backing even when the store would fit; a store crossing the view by one dword; and addresses that would wrap if evaluated in 32 bits.
