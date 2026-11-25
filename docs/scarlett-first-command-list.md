# First Scarlett command-list calls

Read-only static audit of the pinned AMD64 executable in the [startup ABI map](xbox-d3d12-abi.md). All locations are RVAs. No title, console DLL or reference provider was run.

## Creation and immediate dispatch

The first device #9 call (`02478b2d`) uses selector `0` and the allocator IID at `061e0658`, with output at `[rsp+0x78]`. Device #73 at `02478b71` passes the device in `RCX`, stack description pointer in `RDX`, allocator in `R8`, and zero in `R9`. The caller sets its pre-call `[rsp+0x20]` to the IID pointer at `061e0668` (`c3827890-4024-474c-98cf-645b51dc4874`) and `[rsp+0x28]` to `&[rsp+0x60]` (list output). The description's initialized dwords are `(0,2,1,0)` from RVA `0615c190`. The later loop (`02478c3b`/`02478c70`) uses allocator selector `2` and sign-extends four bytes `(2,2,1,0)` from `0615c1c0` to four dwords. This proves an initialized 16-byte prefix for each site, not complete native layout or meanings of words 1–3. Negative allocator or list creation status reaches `INT3`; the nonnegative edge dereferences the returned list without a null test.

Both paths load `RCX=[rsp+0x60]` independently for every returned-list dispatch:

| List slot | First call | Loop call | Win64 caller evidence |
| --- | --- | --- | --- |
| **132** (`+0x420`) | `02478b9e` | `02478c93` | `EDX=0x700000` / `0x100000`; `R8D=0`, `R9D=0`; caller `[rsp+0x20]=0x0000ffffffffff00` as a **qword**. Constant originates in `R12` at `02478b81`. Return not consumed. |
| **131** (`+0x418`) | `02478bbf` | `02478cb4` | `EDX=0xc3c0` / `0xc380`; `R8D=0x80020000` / `0x20000`; `R9D=0`; same stack qword. Return not consumed. |
| **9** (`+0x48`) | `02478bcd` | `02478cc2` | Receiver in `RCX`; no other argument set up. Negative `EAX` reaches `INT3`. `Close` is the public analogue; the preceding two calls are on the returned list, not the device. |

Not consuming a result at #131/#132 does not prove a void signature or that either operation can be skipped. Static evidence does not classify the flags, address/range roles, hardware ordering, caches, or the meaning of the wide constant. Do not treat the constant as a host pointer or allocation length.

## Ownership and next observed consumer

After the #9 check, `02478c0e`/`02478c15` store list/allocator into separate globals (`075e7300` / `075e72a0`); the loop stores four more pairs (`02478cd4`/`02478cd9`). Cleanup checks the first list pointer then invokes list slot 2 (`0248bc9a`), clears it, invokes allocator slot 2 (`0248bcb0`), and clears the allocator global. This supports independent caller-held references; it does not prove whether a native list retains its allocator. A later wrapper at `02482660` indexes the list-global array by an incoming byte. At `02482689` it calls slot `+0x118` of the incoming receiver, passing `EDX=1`, `R8=&selected_list_pointer`, `R9=*075e0e88`, and caller stack dword zero. That is submission-shaped, not proof of execution, ordering, or frame-token semantics.

## Comparators and bounded next step

VIctory (`940d32f`, `crates/victory-gpu/src/list.rs`) maps `+0x418/+0x420` to its newer-layout pipeline-sync analogue, with a no-op body justified by its own host submission model. This corroborates a possible name, not native effect or safe omission in XSXEmu. XCL (`91f9a5e`, `crates/xcl/src/hle/d3d12x/device_x.rs`) treats #73 description words 0 and 2 as type/node for its adapter; that is not native layout proof. Leonida `docs/retail_boot_chain.md` §3.3 reports proxy creation and closing of 581 lists, without a native proof of either preceding sync-shaped call. Pinned desktop DirectX-Headers map graphics command list #9 to `Close`, but the public `ID3D12GraphicsCommandList6` has no #131/#132 and uses a different IID. The common low slot does not make it a desktop alias.

A bounded owned oracle can use separate synthetic device, allocator and list objects: check the fifth/sixth arguments at #73, then invoke #132/#131 with distinct scalar guards and a fifth **64-bit** argument, verify ordering, and close/release the synthetic objects. It should record scalars only, not interpret the wide argument or model GPU barriers. In a separately admitted experimental run, #132 is the first terminal diagnostic after successful #73; record the receiver/arguments before attempting any effects. Neither the oracle nor this audit admits a provider or justifies advancing through unknown synchronization calls.
