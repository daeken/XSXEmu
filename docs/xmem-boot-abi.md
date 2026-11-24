# Xbox XMem early boot: caller ABI and CPU limits

Read-only static observations on one AMD64 Scarlett image, SHA-256 `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993`, preferred base `0x140000000`. No new title trace: ordering below is within named routines, not proof of the first dynamic call. Leonida `docs/retail_boot_chain.md` §§1–2 reports the earliest stops on its own bring-up lane, and `docs/xmem_exe_calls.md` reports the import inventory and flags; these are factual comparators, not provider contracts. No title instructions or implementation copied.

## Imports

`xmem.dll` imports all twelve by **name**, even though the PE supplies hints. IAT and thunk addresses below are RVAs. Counts are candidates for relative branches to these thunks (not all indirect uses, and not an execution count).

| Import | Hint (decimal) | IAT | Thunk | Direct call / tail jump |
| --- | ---: | --- | --- | ---: |
| `XMemAlloc` | 0 | `06793a00` | `05f3fd90` | 3 / 0 |
| `XMemAllocDefault` | 1 | `06793a08` | `05f3fd40` | 0 / 1 |
| `XMemAllocatePhysicalPages` | 2 | `06793a10` | `05f3fcd0` | 4 / 0 |
| `XMemFree` | 5 | `06793a18` | `05f3fda0` | 2 / 1 |
| `XMemFreeDefault` | 6 | `06793a20` | `05f3fd50` | 0 / 1 |
| `XMemFreePhysicalPages` | 7 | `06793a28` | `05f3fd10` | 3 / 0 |
| `XMemGetWorkingSetStatistics` | 16 | `06793a30` | `05f3fcf0` | 3 / 0 |
| `XMemIsToolsMemAvailable` | 19 | `06793a38` | `05f3fd00` | 1 / 0 |
| `XMemMapPhysicalPages` | 21 | `06793a40` | `05f3fce0` | 12 / 0 |
| `XMemMapPhysicalPagesScatter` | 22 | `06793a48` | `05f3fd20` | 2 / 0 |
| `XMemTransferMemory` | 33 | `06793a50` | `05f3fd70` | 1 / 0 |
| `XMemVirtualAlloc` | 34 | `06793a58` | `05f3fcc0` | 23 / 0 |

## Virtual allocation

Win64 caller shape: `RCX=address`, `RDX=u64 byte_count`, `R8D=allocation_type`, `R9D=attributes`, **dword `[RSP+0x20]=protect`** at the call instruction (`+0x28` on callee entry). The first four slots have the usual Win64 home area. `RAX` is stored as an address and tested at full width. A useful local type for the observed shape is `(*mut c_void, usize, u32, u32, u32) -> *mut c_void`; zero-extension by `R8D`/`R9D` does not tell us whether the original header used a wider type for those two arguments.

In the routine at `01e1cf60`, a one-time guard and [configuration call](xbox-d3d12-abi.md#imported-startup-functions) precede two reserves. `01e1d00a` and `01e1d039` pass null bases and the **same** selected 16/24 GiB byte count, not counts of 64 KiB pages. Each reaches a break on null. The later size-dependent cases in this routine load the requested byte count from the loop's size table and use the 2 MiB reserve+commit form; their presence does not fix runtime allocation count or sizes. Leonida's report of seven startup allocations is not a count of static sites here.

All 23 direct callsite tuples, grouped by identical inputs (hex). Base is zero except the five fixed-base `20406000` calls.

| Allocation type | Attributes | Protect | Call RVAs |
| --- | --- | --- | --- |
| `20402000` | `21` | `4` | `01e1d00a`, `01e6c1a6`, `022163ad` |
| `20402000` | `3` | `801` | `01e1d039`, `01e6c1cb` |
| `20003000` | `183` | `22004` | `01e1d181`, `01e1d288`, `01e1d369` |
| `20003000` | `283` | `2404` | `01e1d4d6` |
| `20003000` | `283` | `2004` | `0193e220` |
| `20403000` | `181` | `4` | `01d6e64f`, `01d6e67a`, `05ba6c30` |
| `20402000` | `23` | `2004` | `01e6c273`, `01e6c451` |
| `20402000` | `23` | `2404` | `05eb1fbd` |
| `20401000` | `283` | `42404` | `024786b9` (size `0x10000`, null base, full-width null test) |
| `42000` | `7` | `1` | `01e8649a` |
| `20406000` | `27` | `1004`, `1404`, `8404`, `2404`, `2004` (respectively) | `01e8659e`, `01e865d0`, `01e86600`, `01e86630`, `01e8666c` |

Best-fit operation decode, not a console specification: `0x2000` reserve, `0x1000` commit, `0x40000` reserve placeholder, `0x4000` replace placeholder. `0x20000000` alone selects the presumed 2 MiB mode, and with `0x00400000` the presumed physical 64 KiB mode (page-count arithmetic below independently corroborates 64 KiB). Placeholder evidence: the five requested bases are derived inside the range returned by `01e8649a`. On non-null replacement returns the caller goes on to map at the **original requested bases**, not the returned addresses. This is not an arbitrary-address contract. `attributes` meanings, graphics protection/cache qualifiers and the `20401000` null-base commit-only form remain open. A desktop `PAGE_*` numeric match does not make ignoring those bits correct.

## Physical pages

| Import | Verified consumption in the pinned image | Limit / inference |
| --- | --- | --- |
| `XMemAllocatePhysicalPages` | `RCX` is zero-extended `0x380` at `01e6c22d`, `0x280` at `01e866e4` / `05eb27a7`, `0x180` at `02216493`. `RDX=&u64 count` initialized by caller; `R8` points to `count * 8` byte storage (e.g. `01e6c22d`). Caller consumes 32-bit `EAX`, then compares the reloaded qword count against the request. `05eb27a7` specifically compares `EAX` with **1**, not just nonzero. | A `BOOL`-like result with canonical TRUE required on the measured path. A differing or partial count is anticipated and rejected on these startup paths; its real production rules and flags are unknown. `01e6c32d` frees the mismatching count on a nonzero-result path; `01e868e2` frees a nonzero returned count on the rejection path, so output-on-failure matters. |
| `XMemMapPhysicalPages` | `RCX=base`, `RDX=page count` by value, `R8=page token array`; initial allocate→reserve→map path uses `01e6c22d` → `01e6c273` → `01e6c295` on the applicable branch, with a **64-bit RAX** zero/nonzero test on the map. Five further map sites at `01e86738` through `01e867d1` do the same and advance the array by 8 bytes per token. `02474671` only needs a one-element qword array. | Do not blindly type it as Win32's `BOOL` (contrary to the broad AWE analogy in Leonida's call-site notes). Full-width consumption establishes neither a pointer's meaning nor that the return must equal the mapped address; the measured boot caller does not use the returned value as the VA. |
| `XMemMapPhysicalPages` (unmap shape) | `024730e9`, `024730fb`, `0247310d`, `0247311f` pass null `R8` and counts derived by shifting byte lengths right by 16. No result is consumed on these paths. | Null array requests unmapping, not a zero-filled list or allocation. Prior VM state after unmapping is not established. |
| `XMemMapPhysicalPagesScatter` | `00f2cc3e`: `RCX` is the VA array, `EDX` the caller's zero-extended count, `R8` the page array. `00b18dde` uses a full qword count in `RDX` and null `R8`. **Both** use 32-bit `EAX` nonzero tests, unlike contiguous map. | `BOOL`-like; scatter granularity, duplicates and failure atomicity are unverified. |
| `XMemFreePhysicalPages` | `RCX=u64 count` by **value**, `RDX=page array` at `01e6c32d`, `01e868e2`, `02473133`; last is the sum of the counts in the four unmaps above. All ignore the return. | Return type, array mutability and whether mapped pages may be freed are not established. |

Other calls are not needed for the probe. In the tools-memory branch `02215fd7` sets no arguments in the wrapper prologue and tests `EAX`; `02216008` / `02216042` pass statistics selector `0x2000000a` in `ECX` and writable zeroed storage in `RDX` (0x78 bytes initialized; not a general layout contract), then test `EAX`. `0247454e` passes selector `0x20000001` and consumes the first two qwords of output. `0221608e` gives `ECX=1`, **`RDX=min(computed 2 MiB-rounded delta, 16 MiB)`** (16 MiB is a cap, not an unconditional argument), then tests `EAX`. These do not establish working-set policy or transfer semantics. The heap and default-hook imports remain unresolved beyond the identities above; in particular tail jumps don't prove a default-hook prototype.

## Owned proof and bounded implementation gates

`cargo test --offline --target x86_64-apple-darwin xbox_vm::boot_abi` runs the original Win64 assembly-to-Rust probe under Rosetta. It records the two 64-bit fields, all three metadata words (including the stack dword with a poisoned neighboring dword), and verifies full-width return transport with a **byte-count echo**, not an allocation result. The separate test applies the captured words to [GuestVm](../src/xbox_vm.rs), checking bounded reserve/commit-intent placement, fixed-base placeholder replacement without truncation, unchanged state on exhaustion, and explicit rejection of `20401000`. Even the 24 GiB cases allocate only interval metadata. No accessible memory is returned, no export is registered, and no behavior changes in the runtime.

### Real host reservations (standalone Darwin probe)

`tools/probe_xmem_reserve.sh arm64` and `tools/probe_xmem_reserve.sh x86_64` independently demonstrated the VA requirements of the two `20402000` startup calls on Apple Silicon (native and Rosetta). For each byte count, 16 GiB then 24 GiB, the probe holds **two simultaneous** disjoint reservations. Mach chooses each address with a 64 KiB alignment mask and no overwrite flag. Both current and maximum CPU protection are `VM_PROT_NONE` for both host ranges: this models only the address-space occupancy of a reserve, not either Xbox tuple's `protect` or `attributes` semantics.

The runner gives the standalone child 10 seconds after launch. The kernel reports each exact base and span when queried at its first and last bytes, and an attempt to enable read protection is rejected. A fixed non-overwriting request within the existing range fails with `KERN_NO_SPACE`. After releasing the first reservation the kernel confirms the whole former span is free while the other reserve remains intact; releasing the second leaves its whole span free as well. The probe creates no named backing object, commits no accessible pages, and issues no reads or writes against either reserved range. It does not measure kernel bookkeeping/residency, prove reservation-to-commit or placeholder replacement, or cover the separate 2 MiB reserve+commit calls. No runtime provider or launch path uses it.

### Trusted-offline reservation provider

The runtime binds `xmem.dll!XMemVirtualAlloc` only for a direct named root IAT import in the trusted-offline static TLS child with Rust providers enabled. The audited bridge handles all five Win64 arguments. Its two no-access shapes accept only base zero, size exactly 16 or 24 GiB, and `(allocation type, attributes, protect)` equal to `(0x20402000, 0x21, 4)` or `(0x20402000, 3, 0x801)`. Each tuple may hold one mapping, until child exit. Mach chooses a non-overwriting, 64 KiB-aligned address and both host protections are `VM_PROT_NONE`; the returned address is the actual reserved host VA. No tuple bits are interpreted as CPU or Xbox graphics protections. Unsupported inputs return null with bring-up `LastError=50`; capacity or host mapping failures return null with `LastError=8`. These diagnostic error choices are not claims about the Xbox API. No placeholders, aliases, physical page operations or guest release are implemented.

The first live reserve-plus-commit call at `01e1d181` (return `01e1d186`) passed `(base, size, type, attributes, protect) = (0, 0x49400000, 0x20003000, 0x183, 0x22004)`. Static inspection shows a full `RAX` null test, a break on null, and on success both base and size are stored and passed to the allocator initialization chain starting at `0221a4f0`. It gets 1,172 MiB of anonymous demand-zero host CPU RW, current and maximum, 2 MiB-aligned without overwriting other mappings. The alignment accommodates the observed large allocation form; it does not imply huge physical pages. The mapping is not pre-touched or wired. Diagnostics explicitly skip Xbox protection/cache, physical page and GPU semantics.

The second live reserve-plus-commit call at `01e1d4d6` (return `01e1d4db`) passed `(0, 0x89700000, 0x20003000, 0x283, 0x2404)`. On nonzero full `RAX`, the caller stores the address and unrounded byte count and passes both to the initializer at `05b1a7d0`. This tuple gets its own exact 2,199 MiB CPU RW mapping; its byte count is host-page aligned but **not** a multiple of 2 MiB. Only the base is constrained to the 2 MiB host VA alignment; the provider does not round the byte count up.

The third live call at `01e1d369` (return `01e1d36e`) passed `(0, 0x23300000, 0x20003000, 0x183, 0x22004)`. It traps on null; success stores the base and exact count and passes both to the initializer at `01d14170`. It gets a separate 563 MiB CPU RW mapping with 2 MiB host VA base alignment and no length rounding. Each of the three exact commit tuples is limited to one live mapping, at most 3,934 MiB of CPU RW combined, with no change to the earlier two no-access reserves.

`cargo test --offline --target x86_64-apple-darwin --test static_tls_lane xmem_bridge` exercises both size choices through the actual IAT bridge in owned PEs, including a poisoned upper stack dword, disjoint aligned returns, LastError behavior, and explicit rejection. The fixture also tests zero-initialized writable bytes in the first and last pages of all three committed ranges and rejects duplicates and mismatched tuples. The standalone reservation probe does not touch backing; the production mapping metadata test checks all full spans and protections, ownership and release.

The [CPU backing model](../src/xbox_vm/backing.rs) exercises aliases only over its own placeholder model, not mappings into the observed `20402000` reserves or the title's existing replacements. Its unmap drops a view without restoring a placeholder. The [host alias proof](xmem-cpu-alias.md) demonstrates shared CPU bytes at independent host-selected addresses, not fixed replacement, physical token, protection or GPU behavior. Neither is an XMem provider.

For an eventual CPU-backed lane, keep guest mappings and token/view ownership in one address-space owner. Check count/array/byte arithmetic, range authority and exact address/alignment, and validate the entire operation before publishing intervals or returning success. An interval record does not satisfy a commit, and a detached buffer does not satisfy an alias. Keep per-import diagnostics for raw flags/attributes/protect, base/size or page count, and precise unsupported reason; don't read speculative output layouts, silently ignore graphics protections, or claim GPU placement/visibility. Unsupported operations remain terminal at use until independently justified.

## Recheck

On the matching local image with read-only tools: `xcrun llvm-objdump -p "$exe"` reports the import descriptor/hints. `xcrun llvm-objdump -d --start-address=0x141e1cfea --stop-address=0x141e1d04b "$exe"` shows the first two reserves; add image base to the other listed RVAs and start at an instruction boundary. Leonida's `python3 -B -I tools/import_call_sites.py "$exe" --dll xmem.dll --json` reproduces candidate branch RVAs without writing bytecode caches. Do not infer execution order from static address order.
