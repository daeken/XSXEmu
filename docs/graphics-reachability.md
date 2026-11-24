# Conditional native graphics CFG census

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --reachable-graphics "$TRUSTED_LLVM_21_DYLIB" gfx1013 "$NATIVE_FSSM_DIRECTORY"
# Repeat with gfx1030.
```

The census classifies extracted `.fssm` payloads by the raw stage byte at `+0x100`. Stage labels below come from the separate [same-wrapper stage audit](wrapped-signatures.md), not from opcode inference. No library program, fixed-function state, or embedded PE payload is joined here. The pinned directory has 26,698 valid headers, of which 2,689 are compute (excluded). All 24,009 graphics spans pass the shared FSSM framing check (`+0xc0/+0xc8`, aligned range, `+0xe8` agreement or unset marker, raw trailing fill and end marker). Post-span tails are not interpreted as code.

The walk starts at stored-span offset `+40` as an explicit hypothesis. It follows the same strict basic control subset as the [compute census](compute-reachability.md), with no indirect-PC closure, assumed message behavior, or decoder fallback. Completion requires all modeled reachable edges to decode within the span without overlapping instruction starts and at least one checked `s_endpgm`. It does not require every path to terminate. The wave64 and wave32 tests under LLVM 21.1.6 give the same **result class for every payload** within each CPU, not necessarily the same graph or actual launch width.

| Raw stage byte | Payloads | `gfx1013` complete | `gfx1013` first rejection | `gfx1030` complete | `gfx1030` first rejection |
|---|---:|---:|---|---:|---|
| 2 (VS wrapper companion) | 195 | 0 | 37 `s_setpc_b64`, 158 `s_swappc_b64` | 0 | same |
| 3 (GS) | 195 | 0 | 195 `s_sendmsg` (`MSG_GS`, `GS_OP_EMIT`) | 0 | same |
| 4 (VS) | 2,236 | 1,448 | 788 `s_swappc_b64` | 1,242 | 788 `s_swappc_b64`, 206 decode |
| 5 (PS) | 12,101 | 12,091 | 10 unclassified `s_sendmsg` | 6,188 | 5,913 decode |
| 7 (MS) | 9,282 | 0 | 9,282 `s_sendmsg` (`MSG_GS_ALLOC_REQ`) | 0 | 8,258 `MSG_GS_ALLOC_REQ`, 1,024 decode |

The message classification requires the public four-byte SOPP opcode and recognized immediate fields to agree with LLVM's symbolic operands. Unrecognized cases stay grouped, with no operands printed. Only the first rejection is counted; neither the operation names nor the reported stream encoding establish how the Xbox schedules or couples stages. No message is treated as fallthrough or exit. The owned fixture also rejects noncanonical bits and a numeric-only operand presentation.

Every complete graph has at least one reachable eight-byte `exp` checked against LLVM and the public GFX10 encoding prefix. No export result is attributed to an incomplete graph. An owned fixture distinguishes reachable, branch-skipped, and seen-before-rejection exports under all four decoder configurations. The census does not establish export targets or masks, payload coupling, message semantics, native linkage, authenticated entry, or executable Metal coverage. No title shader was executed or modified.
