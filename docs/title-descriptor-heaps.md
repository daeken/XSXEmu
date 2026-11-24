# Title-addressed descriptor heaps: test-only model

This model asks a bookkeeping question: **if the caller already has a guest virtual address for a descriptor heap, can the model preserve that address and reject invalid or stale slot references?** It does not implement any Xbox D3D12 method.

## Evidence and limits

- Leonida's `docs/retail_boot_chain.md`, step 13, reports that a retail caller reads the slot-9 return value from RAX and compares it to an address it already holds after its first `CreateDescriptorHeap` call. The report treats the provenance of the expected address as a hypothesis. Its `docs/d3d12_command_objects.md` §4.2 attributes the slot-9/10 RAX return convention to the earlier `americas-recomp` probe. The return convention does not establish any relationship between the CPU and GPU handle values.
- XCL's [`HANDOFF.md` retail bring-up notes](https://github.com/ivall/xcl/blob/91f9a5e/HANDOFF.md#retail-game-bring-up-2026-11-23) report using title `__XMemAllocationHooks__` to obtain descriptor heap memory. That is evidence for studying title-supplied memory, not verification of the callback ABI, allocation rules, or placement behavior across console versions.
- Leonida's `docs/d3d12_vulkan.md` §3.4 (D3D-329) reports 32-bit bases and static T#/S# offsets in a shader census. This is evidence about those shaders' GPU-side inputs, not a CPU guest VA limit or a universal API stride. Leonida's `docs/d3d12_xs_surface.md` §9 does not report a measured API increment; XCL's `HANDOFF.md` describes the view and sampler increments used by its compatibility layer. This model takes the guest VA window, base alignment and stride explicitly and does not assign implied values by heap kind.

Only factual observations from the GPL-licensed reports informed this work. The Rust implementation and numeric fixtures are original.

## Model contract

- A registry tracks one caller-specified, nonempty, non-null guest VA window. A registration claims the exact half-open interval `[base, base + count * stride)` in that window. These are model policies, not documented console restrictions.
- Count, stride and alignment must be nonzero; the base must meet the supplied alignment. The product and exclusive end are checked in `u64`. The whole stride is reserved, including any padding. Live registrations must not intersect; adjacency is allowed. Validation failures do not change the registry.
- Slot `i` is the `i`th stride-wide range starting at `base + i * stride`. Address lookup accepts a slot start, not an interior byte. It queries only the current registrations: a bare numeric VA has no lifetime information.
- Model heap and slot tokens carry an opaque registration identity. Explicit unregister makes them stale even if the exact VA and geometry are later reused. Tokens from another registry are rejected, and dropping tokens does not unregister a heap. These rules do not model COM reference counting.
- The registry checks its own intervals only. It neither consults the launcher VM nor verifies page ownership, commitment or accessibility. The model has no descriptor bytes, host pointers, GPU handles, memory backing, provider registration, title execution or D3D12/HRESULT results.

Run `cargo test --test title_descriptor_heaps`; both the model and its original fixtures live under `tests/`.
