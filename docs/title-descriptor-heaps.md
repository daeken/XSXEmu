# Title-addressed descriptor heaps: test-only model

This model asks a bookkeeping question: **if the caller already has a guest virtual address for a descriptor heap, can the model preserve that address and reject invalid or stale slot references?** It does not implement any Xbox D3D12 method.

## Evidence and limits

- Leonida's `docs/retail_boot_chain.md`, step 13, reports that a retail caller reads the slot-9 return value from RAX and compares it to an address it already holds after its first `CreateDescriptorHeap` call. The report treats the provenance of the expected address as a hypothesis. Its `docs/d3d12_command_objects.md` §4.2 attributes the slot-9/10 RAX return convention to the earlier `americas-recomp` probe. The return convention does not establish any relationship between the CPU and GPU handle values.
- XCL's [`HANDOFF.md` retail bring-up notes](https://github.com/ivall/xcl/blob/91f9a5e/HANDOFF.md#retail-game-bring-up-2026-11-23) report using title `__XMemAllocationHooks__` to obtain descriptor heap memory. That is evidence for studying title-supplied memory, not verification of the callback ABI, allocation rules, or placement behavior across console versions.
- Leonida's `docs/d3d12_vulkan.md` §3.4 (D3D-329) reports 32-bit bases and static T#/S# offsets in a shader census. This is evidence about those shaders' GPU-side inputs, not a CPU guest VA limit or a universal API stride. Leonida's `docs/d3d12_xs_surface.md` §9 does not report a measured API increment; XCL's `HANDOFF.md` describes the view and sampler increments used by its compatibility layer. This model takes the guest VA window, base alignment and stride explicitly and does not assign implied values by heap kind.

Only factual observations were taken from the GPL-licensed reports. The Rust implementation and numeric fixtures are original.

### Static retail cross-check

Coordinated with the D3D12 ABI investigation and checked the local retail PE (SHA-256 `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993`) by static disassembly only. The locations below are RVAs:

| Location | Caller observation |
| --- | --- |
| `0x5a54712`, `0x5cabb3c` | Two callers of wrapper `0x1cf3280`: the former passes zero in R8; the latter forwards its own first argument in R8 and divides its second argument by the device slot-15 return to compute R9. |
| `0x2478eab`–`0x2478eb5` | The upstream call into the latter caller takes the expected base from title global `0x75df188`. This does not establish how the global was allocated or populated. |
| `0x1cf32a7`, `0x1cf32be`–`0x1cf32dd` | The wrapper saves incoming R8 in RBX, calls device slot 15 (`+0x78`) using the first dword of the descriptor as the type argument, and records the supplied base alongside the product of the return value and incoming R9. The caller arithmetic is consistent with a descriptor increment; no numeric increment is recovered. |
| `0x1cf3332`, `0x1cf32fa` | For a nonzero supplied base, a helper links a record containing a pointer to that base/size pair before device slot 14 (`+0x70`, `CreateDescriptorHeap`-shaped call with the heap IID at `0x61e0628`). The base is not an extra direct argument to slot 14. |
| `0x1cf3358`–`0x1cf336c` | The success path consumes the slot-9 (`+0x48`) return in RAX and traps on mismatch with the supplied base, but only if the supplied base is nonzero. |
| `0x1cf3392`–`0x1cf3398` | A flag-gated slot-10 (`+0x50`) call returns in RAX; the caller stores its difference from the slot-9 value, rather than requiring the two to match. |

This corroborates a title-supplied expected base on one path. It does not prove the consumer of the linked record, a callback signature, page ownership, a universal heap-placement rule, or how a GPU address relates to the CPU VA.

## Model contract

- A registry tracks one caller-specified, nonempty, non-null guest VA window. A registration claims the exact half-open interval `[base, base + count * stride)` in that window. These are model policies, not documented console restrictions.
- Count, stride and alignment must be nonzero; the base must meet the supplied alignment. The product and exclusive end are checked in `u64`. The whole stride is reserved, including any padding. Live registrations must not intersect; adjacency is allowed. Validation failures do not change the registry.
- Slot `i` is the `i`th stride-wide range starting at `base + i * stride`. Address lookup accepts a slot start, not an interior byte. It queries only the current registrations: a bare numeric VA has no lifetime information.
- Model heap and slot tokens carry an opaque registration identity. Explicit unregister makes them stale even if the exact VA and geometry are later reused. Tokens from another registry are rejected, and dropping tokens does not unregister a heap. These rules do not model COM reference counting.
- The registry checks its own intervals only. It neither consults the launcher VM nor verifies page ownership, commitment or accessibility. The model has no descriptor bytes, host pointers, GPU handles, memory backing, provider registration, title execution or D3D12/HRESULT results.

Run `cargo test --test title_descriptor_heaps`; both the model and its original fixtures live under `tests/`.

## Owned backing fixture for the startup sizing inputs

The bounded terminal probe at device slot 15 (saved return `0x5c5ff32`, outer return `0x2478e27`, full raw heap type zero) captured three dwords: `0x20000`, `0x30000`, and `0x8000`. It did not return an increment. The pinned caller adds the first pair as dwords, multiplies the resulting count and the third dword separately by the zero-extended increment, then rounds each span up to 64 KiB. A later caller divides its backing span by a fresh slot-15 result; its placed-heap wrapper multiplies the count by another slot-15 result. That later span need not be either of the individual startup sizing regions.

`cargo test --test owned_descriptor_backing` reuses the interval registry in a separate fixture with one contiguous host allocation of 64 KiB-aligned pages and two adjacent logical regions. The exact placed CPU start of each region is the address of its actual first byte; placement rejects a mismatched supplied base, even another aligned one. The fixture treats the addresses as integers for lookup and resolves them to checked slice indices, never casts a handle back to a pointer. An **owned policy** of 32 opaque bytes per slot produces `0xa00000` and `0x100000` bytes (320 Ki slots and 32 Ki slots), totaling 11 MiB. Both aligned spans divide exactly and multiply back to the original bytes. A policy of 16 also fits the measured inputs, so the arithmetic does not establish a unique increment. The fixture rejects dword carry rather than reproducing the caller's wrap and checks exact division, combined size, placement, and allocation bounds. Placement, lookup, and byte access check the full raw heap kind against type zero. Byte access also requires a live token from this backing's registry. A full-allocation comparison verifies that writes preserve adjacent bytes across page and region boundaries. Foreign owner tokens and stale tokens from a previous registration at the same CPU base are refused.

This fixture does not map guest pages or expose host addresses to the title. The two logical region registrations are test policy, not a recreation of title placement. The static wrapper audit establishes use of address values, not direct guest access to descriptor bytes; the bounded terminal capture never reaches a heap writer or consumer. The live placement/allocation chain, writes and record byte ranges, direct-load layout/lifetime, and relation of CPU addresses to GPU handles remain unverified. The opaque fixture records are neither native shader descriptor bytes nor a Metal argument-buffer layout. No runtime slot-15 return is implemented.
