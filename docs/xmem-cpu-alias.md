# macOS CPU alias proof for 64 KiB logical pages

The [test-only XMem model](../src/xbox_vm/backing.rs) translates numeric guest addresses. This separate Rust proof uses **two real mappings at disjoint CPU virtual addresses** in one macOS child. It uses Darwin Mach VM rather than POSIX `mmap`: `mach_vm_map` can request 64 KiB alignment and let the kernel pick free addresses, without a fixed-address replacement or an address-hint retry loop.

Each child creates one anonymous 192 KiB Mach memory entry. It maps object pages `[0, 2)` into view A and `[1, 3)` into view B, writable, shared (`copy = false`), non-executable, and without inheritance. It checks the returned backing length, mapping status, logical offset and bounds, virtual address alignment, and non-overlap. Volatile byte accesses check zero-fill at sampled boundaries, visibility in both directions at the first and last bytes of the shared page, and isolation of the adjacent pages. No flush or copy is involved.

The child drops its memory-entry send right while both maps are live and verifies existing data through both aliases. It then deallocates one view, checks that its former endpoints return `KERN_INVALID_ADDRESS` via a kernel copy call (no stale pointer dereference), and verifies that the survivor retains its data and is still writable. The survivor is deallocated and checked the same way. The shell runner tests both unmap orders in fresh subprocesses, with a 10-second timeout per child. Only a temporary build directory is used; the backing has no file.

## Reproduce

Requires macOS, Rust with the requested target's standard library, a macOS linker, and Python 3. From the repository root:

```sh
tools/probe_xmem_cpu_alias.sh arm64
tools/probe_xmem_cpu_alias.sh x86_64  # Rosetta on Apple Silicon; requires Rosetta already installed
```

Both orders passed on Apple Silicon (macOS 27.0.1, build 26A434) natively and under Rosetta. `getpagesize()` reported 16,384 bytes in the arm64 process and 4,096 in the x86-64 process. The 65,536-byte unit is the proof's alignment and offset granularity, not a claim about hardware page size.

## Scope

This demonstrates single-threaded CPU visibility and independent view lifetime for these host mappings only. It does not establish Xbox `XMem*` ABI or placeholder/replacement semantics, console physical memory or residency, cross-thread ordering, GPU visibility or coherency, resource placement, or descriptor compatibility. No production provider is registered; no title, game file, or OS setting is used or changed by the proof.
