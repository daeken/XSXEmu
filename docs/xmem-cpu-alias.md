# macOS CPU alias proof for 64 KiB logical pages

The [test-only XMem model](../src/xbox_vm/backing.rs) translates numeric guest addresses. The independent [macOS host backing module](../src/xbox_vm/host_backing.rs) uses **real mappings at disjoint CPU virtual addresses**. Darwin `mach_vm_map` can request 64 KiB alignment and let the kernel pick free addresses, without a fixed-address replacement or an address-hint retry loop. Only the standalone CPU and [Metal](xmem-metal-buffer.md) probes use this module; the runtime does not link it.

`Backing` owns an anonymous Mach memory-entry send right, and each `View` owns one virtual mapping. `Drop` releases each resource; the kernel retains the underlying object as long as any mapping survives, even after `Backing` is dropped. Creation and mapping require nonempty, 64 KiB-aligned extents and check for overflow and out-of-bounds ranges. Mappings are writable, shared (`copy = false`), non-executable, and without inheritance.

Reads and writes copy bytes between caller buffers and the view after checking the entire byte range; they never borrow a slice of mapped bytes. Both handle types are `!Send` and `!Sync`, so aliases stay on the creating thread. Operations are neither atomic nor synchronization primitives. The numeric view address is diagnostic only; don't access or remap a live view through external APIs.

The probe creates one 192 KiB backing and maps object pages `[0, 2)` into view A and `[1, 3)` into view B. It checks alignment, virtual non-overlap, rejection of invalid ranges, sampled zero-fill, visibility at both ends of the shared page, and isolation of neighboring pages. No flush or copy between views is needed. It drops `Backing` and checks both aliases again, then drops one view and checks that both of its former endpoints return `KERN_INVALID_ADDRESS` via a kernel copy call (no stale pointer dereference). The surviving view must retain its data and remain writable before it is also dropped and checked. The shell runner tests both drop orders in fresh subprocesses, with a 10-second timeout per child. Only a temporary build directory is used; the backing has no file.

## Reproduce

Requires macOS, Rust with the requested target's standard library, a macOS linker, and Python 3. From the repository root:

```sh
tools/probe_xmem_cpu_alias.sh arm64
tools/probe_xmem_cpu_alias.sh x86_64  # Rosetta on Apple Silicon; requires Rosetta already installed
```

Both orders passed on Apple Silicon (macOS 27.0.1, build 26A434) natively and under Rosetta. `getpagesize()` reported 16,384 bytes in the arm64 process and 4,096 in the x86-64 process. The 65,536-byte unit is the proof's alignment and offset granularity, not a claim about hardware page size.

## Scope

This demonstrates single-threaded CPU visibility and independent view lifetime for these host mappings only. It does not establish Xbox `XMem*` ABI or placeholder/replacement semantics, console physical memory or residency, cross-thread ordering, GPU visibility or coherency, resource placement, or descriptor compatibility. No production provider is registered; no title, game file, or OS setting is used or changed by the proof.
