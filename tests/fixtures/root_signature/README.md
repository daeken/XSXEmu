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

## Experimental Xbox import adapter

Build with `cargo build --offline --target x86_64-apple-darwin --features experimental-xbox-rootsig`, then pass `--rust-providers` to `xsxemu audit` or `xsxemu run`. Both opt-ins are required. This registers only the named `d3d12_xs.dll!D3D12SerializeVersionedRootSignature`; neither `d3d12.dll` nor other Xbox graphics exports are supplied.

The adapter accepts the same bounded 1.1 desktop subset as the strict entry point, except that it ignores the **complete** top-level `0x03000000` combination when those are the only non-desktop flag bits. It preserves desktop flags, does not modify caller data, rejects partial masks or additional unknown flags, and emits a stderr warning for every call. The warning includes version, original flags, ignored bits and, where readable, unsupported bits. No Xbox semantic compatibility is claimed. Other root-signature versions, console-specific parameter behavior, device creation, and downstream Xbox blob consumption remain unverified. The ABI assumes valid storage from trusted guests; it is not a guest memory sandbox.

The flag combination is documented in xcl (`91f9a5e9f03156ea82dc55a18f7704862da7a5db`, GPL-2.0-only, `HANDOFF.md` and `crates/xcl/src/hle/d3d12x/mod.rs`) and Leonida (local GPLv3 snapshot, `docs/d3d12_vulkan.md` and `runtime/test/root_signature_oracle_test.cpp`). Those compatibility paths use desktop forwarding. Only the observed flag value and independent descriptions of the layout were used here; no xcl/Leonida code, game bytes, or captured output was copied.

`PE_DLLTOOL=/path/to/llvm-dlltool tools/smoke-rootsig.sh` builds a freestanding Rust Win64 PE from `guest.rs` and runs only that original fixture under Rosetta. It checks both opt-ins, the exact IAT binding, whole-blob DXC equality, HRESULT and success/error out slots, ID3DBlob lifetime, input preservation, rejection of incomplete or extended masks, and the per-call warning. This requires the `x86_64-pc-windows-gnu` and `x86_64-apple-darwin` Rust targets, not any Windows or Xbox DLL.
