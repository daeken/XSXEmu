# Owned Metal scalar descriptor ordering

The direct mesh message projection finds 236 adjacent `s_load_dwordx4` → `s_waitcnt lgkmcnt(0)` → `s_buffer_load_dword` read witnesses. A witness needs unique incoming fallthrough edges at the wait and consumer, and detects a raw operand overlap with the buffer resource or scalar offset. It does not identify which earlier instruction supplies the descriptor-table pointer or its contents, prove that the projected path executes, or resolve nonadjacent and alternative branch paths. Independently, LLVM MC (`gfx1013` and `gfx1030`) verifies an owned sequence in which `s_load_dwordx4 s[8:11], s[2:3], 16` produces the consumer's resource quad and `s_buffer_load_dword s12, s[8:11], s4` takes its independent scalar offset from `s4`. The probe does not execute or translate those instructions.

The authored Metal descriptor is a 16-byte `uint4`: bank index, byte base within the bank, byte length, and a fixed fixture tag. The host checks 16-byte alignment and extent of the descriptor-table address before dispatch. The consumer validates the bank and tag, four-byte alignment of base/length/offset, the range within its 24-byte bank without overflow, and the complete aligned dword within that range. Invalid descriptors and offsets return explicit failure status and zero rather than issuing the read. Both six-dword banks are slices of one fixed, owned bound Metal buffer; the descriptor never encodes host or guest pointers, nor selects a Metal resource binding.

A producer compute pass copies the four descriptor words into a private, hazard-untracked buffer and updates an `MTLFence`. The consumer compute pass in the same command buffer waits on the fence before validating and reading. After command buffer completion, a literal CPU oracle checks the four observed descriptor words, validity and result for all ten cases:

| Input | Result |
| --- | ---: |
| Completed descriptor, original offset | `0x0202` |
| Prior valid descriptor selected, same offset | `0x0101` |
| Same completed descriptor, offset at its last dword | `0x0204` |
| Seven invalid descriptor or offset cases | rejected |

Both controls keep the fence. The stale case deterministically selects a pre-existing descriptor record; it is not a deleted-fence race or evidence about hardware stale-read timing. Apple M4 API validation matched **60/60 words each** for source and offline metallib runs.

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  sh tools/shader-inventory/smoke-scalar-descriptor.sh
```

This validates only the explicit Metal completion and descriptor-use contract, not console descriptor encoding/binding, LGKM pending sets, concurrent descriptor writes, wave/EXEC behavior or allocation completion. Strict decoding, reachability and retail admission are unchanged.
