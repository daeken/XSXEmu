# Compute descriptor bindings: producer-side evidence

This traces one compute recorder in the retail **companion**, not the main EXE's pipeline compiler or the two archive-backed [raw-store candidates](fssm-launch-inventory.md). No retail code was executed. The static input is the local AMD64 `amd_fidelityfx_upscaler_xbox.dll`, SHA-256 `faff02f294a7e9149ce079dffe3dedbcabe99b1f180ab14222aa8689e00a75fa`. Use `xcrun llvm-objdump -d --x86-asm-syntax=intel --start-address=0x1800059a0 --stop-address=0x180006834 "$dll"` on a local copy to check the following (table addresses are RVAs, image base `0x180000000`). Method names are role labels based on observed call shapes, not a full interface. Leonida's `docs/d3d12_command_objects.md` §3.5a provided the starting locations; no GPL code was used.

| Boundary | Static caller observation |
| --- | --- |
| List #33, `0x5a21` | `RCX=list`, `RDX=loaded root-signature identity`. Compute root-signature-shaped. |
| List #32, `0x5a37` | Same list, `EDX=1`, `R8=&stack_heap_pointer`. The same heap pointer supplies the receiver for the heap call at `0x5a75`. |
| Heap #10, device #15, `0x5a75`–`0x5a9e` | Saves full heap return `RAX`, calls device #15 with `EDX=0`, multiplies its `EAX` by a dword index, zero-extends the low 32-bit product, adds it to the saved heap return and keeps the result in `RSI` and on the stack. This is address provenance, not a numeric stride measurement or a proposed overflow policy. |
| List #35, `0x5e7a` | With the vtable fallback, `RCX=list`, `EDX=0`, `R8=RSI` carrying all 64 bits of that result. The alternative inline path at `0x5e60` writes a header dword, then the **low** dword of `RSI` at `+4`, advancing the cursor by 8 bytes. Other table calls occur later in the routine (e.g. `0x6226`). |
| List #25, `0x6679` | Pipeline-shaped vtable fallback: `RCX=list`, `RDX=identity`. |
| List #14, `0x682e` | Direct dispatch fallback: `RCX=list` and three dwords in `EDX/R8D/R9D`. An alternative direct path at `0x6808` writes these three dwords after an inline header and advances the cursor by 16. A separate branch can use list #61 at `0x67ac` (indirect-dispatch-shaped). |

This links one producer root-table call to a bound **GPU-side heap start plus offset**. It does **not** establish a relationship to the guest CPU address from [heap #9](title-descriptor-heaps.md), how high address bits are constrained on the inline path, what the inline header fields mean, which shader consumes which hardware user SGPR, or whether either archived raw-store candidate uses this route. A 32-bit inline payload and a 32-bit shader live-in do not, by themselves, identify the same value.

## Owned capture seam

`cargo test --offline --target x86_64-apple-darwin --test shader_binding_capture` checks the vtable-fallback argument shapes under Rosetta. The original assembly caller supplies a private list with only slots #33/#32/#35/#25/#14 populated, calls through the Win64 home-area convention, and records raw events in typed Rust callbacks. The test checks call order, synchronous heap-array snapshot (independent of later caller writes), repeated writes to one root parameter, 64-bit table-value preservation, and three dispatch dimensions. A second test verifies that an oversize heap array or a full event ledger is refused explicitly without modifying prior events. The accepted array pointer is fixture-owned; this does not validate arbitrary guest addresses. The slot calls are void recorders, not simulated GPU work or D3D12 results.

To use this seam on real calls, first pin the interface revision and checked guest reads, and account for inline recording, which bypasses these vtable callbacks. Join a dispatch to an independently identified pipeline/shader and root-signature parameter, backed by a live GPU-address-to-guest-memory mapping with range and lifetime checks. Neither this fixture nor the [archive analysis](fssm-launch-inventory.md) performs that join or authorizes replay.
