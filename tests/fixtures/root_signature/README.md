# Original root-signature oracles

`mixed.dxbc` and `padding.dxbc` are compiled from the adjacent XSXEmu-authored HLSL definitions. No proprietary program, shader, or capture was used. The first exercises every 1.1 parameter kind, range order and flags, offset append, visibility, and static sampler floats. The second exercises the retail digest's two-final-block padding case (`(140 - 20) % 64 == 56`).

From this directory, using native Microsoft [DirectXShaderCompiler at `c7357f0e1349ba857d2af167d38cb3407a44dfbd`](https://github.com/microsoft/DirectXShaderCompiler/tree/c7357f0e1349ba857d2af167d38cb3407a44dfbd) (built from source on macOS):

```sh
for f in mixed padding; do
  dxc -T rootsig_1_1 -E ROOT_SIG "$f.hlsl" -Fo "$f.dxbc"
done
shasum -a 256 *.dxbc
```

```
ac15fe53da4692659491446b7bb725dd44d8d5abccd0fe0cb5cc067115c15734  mixed.dxbc
f7ff0205c80fefabe864787c5d77aa21b0a5f7ed5241f566040f2a0c7571164a  padding.dxbc
```

The native DXC output was also verified separately by calling the same upstream revision's `ComputeHashRetail(blob + 20, size - 20, digest)` from `libLLVMDxilHash.a`; inserting that digest at byte 4 left both files byte-identical. `cargo test --test root_signature` compares the **entire** encoded containers, not self-generated expectations. Windows `d3d12.dll` was not executed.

Wire-layout references: Microsoft DXC's `lib/DxilRootSignature/DxilRootSignatureSerializer.cpp` and `include/dxc/DxilRootSignature/DxilRootSignature.h` (UIUC/NCSA); `libs/vkd3d-shader/dxbc.c` and `checksum.c` in [vkd3d-proton `30b0eb9bc12dc9f40e1a33a2be8c87cf0846447b`](https://github.com/HansKristian-Work/vkd3d-proton/tree/30b0eb9bc12dc9f40e1a33a2be8c87cf0846447b) were corroborating references (checksum: Hans-Kristian Arntzen for Valve, based on RenderDoc by Baldur Karlsson and Crytek, MIT). The Rust writer/compression loop is independently written from the layout and RFC 1321; no native code is shipped. ABI definitions follow Microsoft DirectX-Headers' Win64 `d3d12.h`/`d3dcommon.h` declarations.
