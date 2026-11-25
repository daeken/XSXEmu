# Owned Mach view as a Metal shared buffer

[Slot 133](xbox-d3d12-abi.md#device-and-returned-heap-calls) receives an address just passed to `XMemMapPhysicalPages`, a description with a buffer-like prefix, a `0xffffffff` state word, a null stack argument, and the resource IID/output. This motivates trying an import of already mapped bytes, not a new committed buffer. It does not establish the full description, meaning of the sentinel or null argument, placement granularity, or resource visibility rules. The [CPU alias proof](xmem-cpu-alias.md) establishes aliasing for owned Mach mappings only, not the behavior of `XMemMapPhysicalPages`.

## Import and ownership

The standalone [Metal import](../src/xbox_vm/metal_backing.rs) takes ownership of a `View` from the [Mach backing module](../src/xbox_vm/host_backing.rs). It does not take a guest address, remap a view, round a range up, or allocate a substitute buffer. Before calling Metal it rejects empty, unaligned, out-of-bounds and overflowing ranges. Both offset and length must be multiples of 64 KiB, the backing module's conservative logical alignment. Length must also fit the device's `maxBufferLength`.

The call is `newBufferWithBytesNoCopy:length:options:deallocator:` with `MTLStorageModeShared` and the selected virtual address. A nil result is an error, not a retry; this selector has no `NSError` out parameter. A non-nil result must report the exact input pointer, length and shared storage mode. The Metal deallocator block holds an unmap-only ownership token for the **whole** view; final block disposal unmaps it. The block can be released on any thread. It captures neither the thread-bound CPU access handle nor a reference to the mapped bytes. The import consumes the view on failure too. Other CPU aliases own separate mappings and are unaffected.

The caller must serialize conflicting CPU and GPU accesses through **all** aliases and retained buffer references. The probe writes CPU bytes before submission and reads back only after successful command completion. No volatile access, ownership transfer, or buffer retain is a GPU synchronization operation.

## Reproduce

On macOS with Metal, Cargo, the requested Rust target and linker, and Python 3:

```sh
tools/probe_xmem_metal_buffer.sh arm64
tools/probe_xmem_metal_buffer.sh x86_64  # requires Rosetta on Apple Silicon
```

Use `CARGO_NET_OFFLINE=true` if the locked dependencies are already cached. The runner bounds the child to 30 seconds. Both commands passed on Apple M4, macOS 27.0.1 (26A434), with process page sizes of 16,384 and 4,096 bytes respectively:

- An anonymous 192 KiB backing provides two non-overlapping 128 KiB virtual views spanning object pages `[0, 2)` and `[1, 3)`. Metal imports **only** the second 64 KiB of the first view. The Mach entry owner is already dropped; the same bytes remain reachable through the second CPU view. Metal's `contents` equals the import address, and host writes through either path are visible through the other.
- After import, two rounds feed distinct CPU values into the first and last words of the shared range. A Metal kernel XORs each word in place with a distinct constant. All four expected words are observed through the CPU alias after waiting; neighboring sentinel words outside the import are untouched. No staging resource, blit, explicit cache flush or substitute allocation is used.
- Invalid zero, misaligned, out-of-view and overflowing requests reject and unmap the consumed view. A retained `MTLBuffer` remains usable after dropping the initial handle. After final release and autorelease-pool drain, a kernel copy check (not a stale dereference) verifies invalid addresses in the former import view. The independent CPU alias still retains data and remains writable until separately dropped and checked.

## Fixed-VA import and retirement

The fixed probe reuses the [owned exact-address arena](../src/xbox_vm/fixed_proof.rs) from the CPU proof, including its one kernel mapper, token checks, and no-access restoration. It does not claim ownership of an externally supplied address. Its range pin checks every slot for live coverage; a range containing a parked slot is rejected. The pin keeps the arena's unmap owner alive and any overlap with a live pin rejects unmap or a new map request. The batch cannot be freed with live views. Metal's deallocator holds the pin, not the CPU arena handle.

```sh
tools/probe_xmem_fixed_metal.sh arm64
tools/probe_xmem_fixed_metal.sh x86_64
```

The runner starts one bounded child per case. On the same M4/macOS host, both native and Rosetta accepted the exact VA and length as `MTLStorageModeShared` in all three cases:

| Fixed view | Construction | GPU words checked through separate CPU aliases |
| --- | --- | --- |
| 64 KiB | One fixed call for object page 1 | First and last words (2/2) |
| 128 KiB control | One fixed call for consecutive object pages `[0, 1]` | Both outer endpoints and the two words straddling the 64 KiB boundary (4/4) |
| 128 KiB nonconsecutive | Two one-page fixed calls for object pages `[2, 0]`, in that order at adjacent VAs | Same four offsets (4/4) |

Each command waits on an unsignaled Metal shared event. The fixture commits it and drops its own `MTLBuffer` reference while the command is pending. With the buffer retained by Metal, attempts to unmap, map over the pinned VA, or free the live batch fail. The CPU then signals the event, waits for successful completion, and checks in-place GPU results through the CPU aliases. After Metal release and autorelease-pool drain, the arena can restore the exact no-access slots and reuse them without accepting stale batch tokens. There is no copy fallback: nil for the nonconsecutive case is logged as a capability result, with unchanged input and working teardown required; nil for a control is a test failure.

This is a host result for one tested device and explicitly ordered command pattern. It does not establish simultaneous CPU/GPU access, visibility without a wait, cross-queue ordering, arbitrary guest-address imports, support on other Metal drivers, or Xbox cache, residency, descriptor or placed-resource semantics. No guest ABI/provider or existing XMem behavior is changed. Only original owned fixture bytes and shader code are used; no title or console DLL runs.
