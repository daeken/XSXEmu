# Owned Metal raw dword → completion → bitfield probe

In the direct mesh audit, 247 sites have a checked adjacent `buffer_load_dword` → `s_waitcnt vmcnt(0)` → `v_bfe_u32` load-to-read witness. LLVM MC (`gfx1013` and `gfx1030`) independently verifies an owned example of those forms; the probe does not execute or translate the native words. The unsigned bitfield operation uses the low five bits of offset and width, as documented in RDNA2 ISA §12.12. A width whose low five bits are zero returns zero; a field reaching past bit 31 is zero-extended.

The Metal fixture accepts only authored, aligned, in-bounds byte offsets into an owned `uint` buffer. A compute encoder issues the raw load and writes its result to a private, hazard-untracked intermediate buffer. It updates an `MTLFence` after dispatch. A second compute encoder in the same command buffer waits on that fence before dispatching the bitfield consumer. Both the raw dword seen by the consumer and the extracted value are read back only after command buffer completion. A CPU bit-by-bit oracle checks every output word, including width zero, width 31, masked high selector bits, the top bit, and fields past the top bit.

On Apple M4, API-validation source compilation and offline metallib runs each matched **60/60 words**: 20 normal, 20 with the load redirected to a different in-bounds address, and 20 with the consumer bound to a separately initialized prior snapshot. The latter two controls changed seven and eight of ten extracted fields respectively. The prior-snapshot control is deterministic and keeps the fence; it is not a race obtained by deleting the fence.

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  sh tools/shader-inventory/smoke-vm-bfe.sh
```

This is a Metal pass-ordering and value-dependency test, not a model of an AMD vector memory counter or a proposal to use separate encoders for every guest load. It does not establish native buffer descriptors, out-of-bounds behavior, EXEC effects, the set of outstanding operations, wait elision, or allocation/PRIM behavior. Strict reachability, entry selection, and title admission are unchanged.
