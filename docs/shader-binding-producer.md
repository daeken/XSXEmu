# Compute descriptor bindings: producer-side evidence

These are static caller observations from the retail EXE and its FSR companion, not a join to the two archive-backed [raw-store candidates](fssm-launch-inventory.md). No retail code was executed.

## FSR companion

The static input is the local AMD64 `amd_fidelityfx_upscaler_xbox.dll`, SHA-256 `faff02f294a7e9149ce079dffe3dedbcabe99b1f180ab14222aa8689e00a75fa`. Use `xcrun llvm-objdump -d --x86-asm-syntax=intel --start-address=0x1800059a0 --stop-address=0x180006834 "$dll"` on a local copy to check the following (table addresses are RVAs, image base `0x180000000`). Method names are role labels based on observed call shapes, not a full interface. Leonida's `docs/d3d12_command_objects.md` §3.5a provided the starting locations; no GPL code was used.

| Boundary | Static caller observation |
| --- | --- |
| Device #67, `0x56d9`; #62, `0x5825` | PSO-construction-shaped calls. #67 takes `RCX=device`, `RDX=&stack_record`, `R8=&pipeline_IID`, `R9=out`; its negative-result branch can fall back to #62. #62 takes `RCX=device`, `RDX=&stack_record`, `R8=0`, `R9=0`, pre-call stack `+0x20=&pipeline_IID`, `+0x28=out`. These are calling shapes, not validation of either descriptor layout. |
| List #33, `0x5a21` | `RCX=list`, `RDX=loaded root-signature identity`. Compute root-signature-shaped. |
| List #32, `0x5a37` | Same list, `EDX=1`, `R8=&stack_heap_pointer`. The same heap pointer supplies the receiver for the heap call at `0x5a75`. |
| Heap #10, device #15, `0x5a75`–`0x5a9e` | Saves full heap return `RAX`, calls device #15 with `EDX=0`, multiplies its `EAX` by a dword index, zero-extends the low 32-bit product, adds it to the saved heap return and keeps the result in `RSI` and on the stack. This is address provenance, not a numeric stride measurement or a proposed overflow policy. |
| List #35, `0x5e7a` | With the vtable fallback, `RCX=list`, `EDX=0`, `R8=RSI` carrying all 64 bits of that result. The alternative inline path at `0x5e60` writes a header dword, then the **low** dword of `RSI` at `+4`, advancing the cursor by 8 bytes. Other table calls occur later in the routine (e.g. `0x6226`). |
| List #25, `0x6679` | Pipeline-shaped vtable fallback: `RCX=list`, `RDX=identity`. |
| List #14, `0x682e` | Direct dispatch fallback: `RCX=list` and three dwords in `EDX/R8D/R9D`. An alternative direct path at `0x6808` writes these three dwords after an inline header and advances the cursor by 16. A separate branch can use list #61 at `0x67ac` (indirect-dispatch-shaped). |

This links one producer root-table call to a bound **GPU-side heap start plus offset**. It does **not** establish a relationship to the guest CPU address from [heap #9](title-descriptor-heaps.md), how high address bits are constrained on the inline path, what the inline header fields mean, which shader consumes which hardware user SGPR, or whether either archived raw-store candidate uses this route. A 32-bit inline payload and a 32-bit shader live-in do not, by themselves, identify the same value.

## Main retail executable

Input and preferred base as pinned in the [startup ABI map](xbox-d3d12-abi.md) (SHA-256 `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993`, base `0x140000000`). Offsets below are RVAs. To recheck, use `xcrun llvm-objdump -d --x86-asm-syntax=intel` with start/stop addresses equal to the image base plus the listed RVAs; start on an instruction boundary. `S20` and `S28` denote offsets from the caller's pre-call RSP.

| Boundary | Static caller observation and limit |
| --- | --- |
| Device #62 at `0x247fe66` | `RCX=device`, `RDX=&stack_record`, `R8=R9=0`, `S20=&IID` (`0x61e06b8`, `ID3D12PipelineState` UUID), `S28=&object[+0x120]`; caller tests EAX sign. Stack record starts with the pointer from object `+0x118` (`0x247fe00`–`0x247fe14`). This has the companion's compute PSO creation shape; fields of the record and identity of the code supplied are not verified. |
| Device #67 at `0x24800d5` | Reached from the alternative lookup helper called at `0x247fe25`. `RCX=device`, `RDX=record` after a write of the caller-supplied pointer to the record's first qword, `R8=&IID` (same), `R9=&stack_out`; sign test and out-pointer return on success. The wrapper stores that return at `+0x120` and attempts #62 if it is null. No format or fallback policy inferred for other callers. |
| List #25 at `0x248c33b`; #33 at `0x248c373` | Same list receiver in RCX; RDX is loaded from `+0x120` for the PSO-shaped call and `+0x118` for the compute-root-signature-shaped call. These offsets are consistent with the creation wrapper; static offsets don't identify any one live pipeline instance. The PSO code also has an inline alternative. |
| List #35 at `0x248c465` | `RCX=list`, `EDX=zero_extended_parameter_byte`, `R8=full_value`. The value in R15 is loaded from a helper's stack output and adjusted by qword global `0x75e73b0` at `0x248c418`; inline alternative at `0x248c44c` writes header and low dword only. The global's origin as a heap-start return and its live identity are not established for this EXE path. The companion path above independently supplies a concrete #32/#10 heap-binding chain. |
| List #14 at `0x056b2b` / tail jump `0x056b3f` | Calls the helper beginning at `0x248c2a0` (above) at `0x056b02` on one branch, then dispatches with list in RCX and three dimensions in EDX/R8D/R9D. Inline alternative writes a header and the same three dwords at `0x056b69`–`0x056b78`. |
| List #61 at `0x248cbba` | Same binding helper at `0x248cb73` on one branch; indirect-shaped call: `RCX=list`, `RDX` loaded from a global, `R8D=1`, `R9` loaded from a record, `S20=computed offset`, then two zero qwords at `S28/S30`. No argument buffer or command-signature layout inferred. This is not intercepted by the direct-dispatch fixture. |

The static trace gives capture points, not live evidence of a particular PSO, bound heap, root parameter or group count. Until boot gets past VM configuration and device creation, we cannot observe which creation path succeeds, whether the game takes the vtable or inline paths, which concrete shader/PSO and heap lifetime are in use, or how the driver materializes root tables and shader inputs. A later capture must keep pipeline creation identity, binding events, and inline records distinguishable, not reconstruct one from truncated handle words.

## Owned capture seam

`cargo test --offline --target x86_64-apple-darwin --test shader_binding_capture` checks the vtable-fallback argument shapes under Rosetta. The original assembly caller supplies a private list with only slots #33/#32/#35/#25/#14 populated, calls through the Win64 home-area convention, and records raw events in typed Rust callbacks. The test checks call order, synchronous heap-array snapshot (independent of later caller writes), repeated writes to one root parameter, 64-bit table-value preservation, and three dispatch dimensions. A second test verifies that an oversize heap array or a full event ledger is refused explicitly without modifying prior events. The accepted array pointer is fixture-owned; this does not validate arbitrary guest addresses. The slot calls are void recorders, not simulated GPU work or D3D12 results.

To use this seam on real calls, first pin the interface revision and checked guest reads, and account for inline recording, which bypasses these vtable callbacks. Join a dispatch to an independently identified pipeline/shader and root-signature parameter, backed by a live GPU-address-to-guest-memory mapping with range and lifetime checks. Neither this fixture nor the [archive analysis](fssm-launch-inventory.md) performs that join or authorizes replay.
