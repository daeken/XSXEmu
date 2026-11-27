# Owned Metal texture heap sizing and placement

Run on macOS with a Metal device (from the repository root):

```sh
MTL_DEBUG_LAYER=1 cargo test --locked --manifest-path tools/xmem-metal-buffer/Cargo.toml \
  --test owned_texture_heap -- --nocapture
```

The test is separate from the guest runtime. It uses a synthetic public
`D3D12_RESOURCE_DESC`-shaped input with dimensions and format matching the
3840×2160, `0x1c` observation, not a decoder of the live descriptor. It accepts
only 2D RGBA8_UNORM, one layer, one mip, one sample, zero sample quality,
default alignment, unknown layout and no resource flags. It chooses an owned
Metal private shader-read texture with default CPU cache mode. The 4096 per-axis
cap is a probe budget, not a guest or device limit. Row-major, both desktop
64 KiB swizzle modes, explicit alignment, other formats or flags, arrays,
additional mips and multisampling are rejected before passing anything to Metal.

`heapTextureSizeAndAlignWithDescriptor:` reports the host allocation
requirements of that exact Metal descriptor. The test uses checked arithmetic
to place two simultaneous textures into one `MTLHeapTypePlacement` heap at
`align` and `align + round_up(size, align)`, then checks their heap identity,
offsets and descriptor properties. The first offset tests the queried alignment
without relying on offset zero or on accidental page alignment. Invalid sizes,
alignments, dimensions, width truncation and arithmetic overflow have negative
coverage. Misaligned and out-of-range offsets are never passed to Metal; the
SDK does not define behavior for invalid placement offsets.

Measured on Apple M4 with Metal API Validation, both native arm64 and x86_64
under Rosetta (height 2160 throughout):

| Width | Tight texel bytes | Linear row pitch (bytes) | Metal placement size (bytes) | Metal placement alignment (bytes) |
|---:|---:|---:|---:|---:|
| 3839 | 33,168,960 | 15,360 | 33,947,648 | 128 |
| 3840 | 33,177,600 | 15,360 | 33,947,648 | 128 |
| 3841 | 33,186,240 | 15,376 | 34,504,704 | 128 |
| 4096 | 35,389,440 | 16,384 | 36,175,872 | 128 |

For 3840×2160, both textures reported `allocatedSize` of 33,947,648 and
`heapOffset` of 128 and 33,947,776 respectively. Total heap capacity can be
rounded separately. The linear column is computed by aligning `width × 4` to
the device's `minimumLinearTextureAlignmentForPixelFormat` (16 bytes here);
it is a buffer-view pitch calculation, not a heap texture's pitch or a buffer
allocation experiment. The neighboring widths show that texel-byte arithmetic,
linear row pitch and private placement footprint are different quantities.

This proves that the reported size and alignment suffice for these Metal
placements, not that they are minimal, describe a native texture layout, or
are Xbox-visible allocation requirements. No GPU commands or title code are
run. Slot 25's guest size/alignment remain unproved: do not return these host
values (or texel bytes or linear pitch) to a guest caller without a verified
consumer contract. See [the Xbox ABI notes](xbox-d3d12-abi.md).
