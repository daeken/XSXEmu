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

## Reached physical allocation: evidence gate

The live trace on `6941c82` reached the missing `XMemAllocatePhysicalPages` import at IAT RVA `06793a10`. That diagnostic records neither its return PC nor arguments. The trace before it is not proof of which of the four static callers fired, or whether it later submits backing to a GPU. The directly observed ABI shape is `extern "win64" fn(u32, *mut u64, *mut u64) -> i32` for the consumed bits: flags in `ECX`, pointer to an in/out qword count in `RDX`, pointer to caller-owned qword slots in `R8`. Count is a number of logical pages, not bytes. Return `EAX=1` is the only success value safe for all four callsites.

| Return RVA | Flags | Count source and first consumers |
| --- | --- | --- |
| `01e6c232` | `380` | Input byte length shifted right by 16; qword count checked against request. One branch does new `20402000/23/2004` reserve at `01e6c273`, maps the tokens, then passes the mapped VA to a virtual-interface call at `01e6c2bb`. Another branch releases earlier reserves and requests a new reserve. Neither proves CPU-only use. |
| `01e866e9` | `280` | Sum of per-range page counts; temporarily writes into a stack array. Copies tokens out to retained storage and maps subarrays into several distinct caller-selected ranges derived from placeholder replacements. Cleanup may free a nonzero count even on the rejected path. |
| `02216498` | `180` | `ceil(input_bytes / 64 KiB)`. Output array is retained at RVA `071b63e8`. The pool consumer at `02216a1d` reads one token by index, creates a temporary one-qword list and calls contiguous map at a supplied VA with count 1; it tests full `RAX`. The token is not used as a CPU pointer on that path. |
| `05eb27ac` | `280` | `ceil(input_bytes / 64 KiB)`. Writes a retained global array at RVA `075eaee0` and explicitly requires `EAX == 1` and the original requested qword count. The wrapper itself does not map; that does not make dummy tokens safe. |

### Measured pool and static consumers

A scratch-only terminal diagnostic based on `1bf9f15` captured return PC `0x145eb27ac` (RVA `05eb27ac`), flags `0x280`, qword input count `0x2c60` and output array `0x1475eaee0` (RVA `075eaee0`). It did not read the output array, write outputs, or return to the caller. This request is 11,360 logical pages, **710 MiB** of backing and **`0x16300` bytes** of output tokens. The static caller `01d488bf` selects `0x2c60` or `0x1290` pages before converting to bytes; only the former was measured. It returns the page count to `05b056b5`, which stores it at `075eaeb8`. `05eb27ac` demands **exactly `EAX=1` and unchanged full qword count**; either mismatch hits `INT3` at `05eb27be`.

Read-only dataflow from the retained array (not an observed subsequent execution sequence):

1. `02473e20` computes a pool-capacity check using `075eaeb8` and constructs per-resource subranges. At `02473ec8`–`02473ee9` it sums the per-resource lengths and asks `05eb1fa0` for a VA span. The latter calls `XMemVirtualAlloc` at `05eb1fbd` with `(0, total_bytes, 0x20402000, 0x23, 0x2404)` and checks full `RAX` for null. `02473f06` retains the returned base; `02473f14` adds the accumulated resource lengths to derive per-resource bases. This is a distinct reserve tuple from the two boot reserves; its runtime size and count of spans were not measured.
2. At `02474064`–`02474074`, a selected index loads one qword from `075eaee0`, then passes it and a per-resource VA to helper `02474660`. The helper calls `XMemMapPhysicalPages` at `02474671` (`RCX=exact VA`, `RDX=1`, `R8=&token`) and breaks if full `RAX` is zero at `02474676`–`02474680`; no equality comparison to the VA. The caller steps VA by 64 KiB. It clears pool-index bitmap entries as the resource lifetime sweep progresses (`02474134`); the same token can therefore be used at multiple VAs. This loop does not unmap the old VA before reusing an index. The separate observed-static unmap/free chain at `024730e9`–`02473133` is not established as cleanup for this pool.
3. `024740af`–`024740d0` passes a resource initialization descriptor containing the mapped VA at offset `+0x10` and resource length at `+0x18` to `0131a270`. One dispatch branch goes through `04ec54f0` to `0006dc20`: it loads the descriptor VA at `0006dcc2` and, on the device path, passes that VA (or a range-relative translation) in `RDX` to virtual slot **133 (`0x428`)** at `0006dd85`, with the same resource IID, sign-test and `0xffffffff` state sentinel described in the [D3D12 ABI audit](xbox-d3d12-abi.md). The `0x980` resource branch `0193de10` also consumes this descriptor and can pass the VA into device resource calls. This establishes a GPU placement consumer; it does not establish which resource/dispatch branch executes next on a live boot.

Do not expose CPU-only aliases as usable placed GPU resources. A truthful allocation-only experiment could advance with one real bounded shared object and opaque tokens, but must explicitly stop at an unsupported resource/mapping boundary. To complete the observed-static map-to-resource path needs exact VA ownership, shared bytes across repeated token views, and a supported GPU placement/coherence contract. No CPU alias test supplies that GPU contract or selects a runtime reserve bound.

### CPU ownership model

The smallest CPU-only backing component is **real shared backing first**, then tokens: one anonymous named Mach memory object per accepted batch, `count * 64 KiB` checked against a measured cap. Opaque nonzero qwords identify a live object and a 64 KiB offset; a token is neither a CPU pointer nor a host/guest physical page number. Validate readable/writable, disjoint count and output ranges, count/byte arithmetic and available token/VA budget before publishing. Return canonical 1 only after the full object and token batch exist and the full output is published. If the reached caller needs only all-or-nothing allocation, specify and test the modeled zero-result/zero-count failure for valid output without accepting arbitrary partial count behavior. Never dereference an unvalidated guest pointer or hand out tokens that cannot participate in a real mapping.

For contiguous map, accept only a proven CPU placement path in the same VA owner. Validate exact destination bounds and 64 KiB alignment, returned token liveness, and current view state across the entire request before changing host mappings. Coalesce adjacent tokens from the same object only when offsets are consecutive; mapping works at the requested VA with shared non-executable views or fails, not at a host-selected substitute. The current alias proof only covers independent host-selected VAs; it does **not** prove fixed replacement or rollback. Prove owned exact replacement and null-array unmap/restore before enabling them, with rejection of foreign or mixed ranges rather than clobbering host memory. Track batch tokens and views separately, reject free while referenced in the initial model, and validate the whole free before revocation. Never repurpose anonymous committed CPU pointers as alias backing. No Xbox physical residency, GPU identity/visibility, or protection semantics are provided. If the observed path needs those, leave it unsupported rather than treating the Mach object as equivalent.

## Owned proof and bounded implementation gates

`cargo test --offline --target x86_64-apple-darwin xbox_vm::boot_abi` runs the original Win64 assembly-to-Rust probe under Rosetta. It records the two 64-bit fields, all three metadata words (including the stack dword with a poisoned neighboring dword), and verifies full-width return transport with a **byte-count echo**, not an allocation result. The separate test applies the captured words to [GuestVm](../src/xbox_vm.rs), checking bounded reserve/commit-intent placement, fixed-base placeholder replacement without truncation, unchanged state on exhaustion, and explicit rejection of `20401000`. Even the 24 GiB cases allocate only interval metadata. No accessible memory is returned, no export is registered, and no behavior changes in the runtime.

### Real host reservations (standalone Darwin probe)

`tools/probe_xmem_reserve.sh arm64` and `tools/probe_xmem_reserve.sh x86_64` independently demonstrated the VA requirements of the two `20402000` startup calls on Apple Silicon (native and Rosetta). For each byte count, 16 GiB then 24 GiB, the probe holds **two simultaneous** disjoint reservations. Mach chooses each address with a 64 KiB alignment mask and no overwrite flag. Both current and maximum CPU protection are `VM_PROT_NONE` for both host ranges: this models only the address-space occupancy of a reserve, not either Xbox tuple's `protect` or `attributes` semantics.

The runner gives the standalone child 10 seconds after launch. The kernel reports each exact base and span when queried at its first and last bytes, and an attempt to enable read protection is rejected. A fixed non-overwriting request within the existing range fails with `KERN_NO_SPACE`. After releasing the first reservation the kernel confirms the whole former span is free while the other reserve remains intact; releasing the second leaves its whole span free as well. The probe creates no named backing object, commits no accessible pages, and issues no reads or writes against either reserved range. It does not measure kernel bookkeeping/residency, prove reservation-to-commit or placeholder replacement, or cover the separate 2 MiB reserve+commit calls. No runtime provider or launch path uses it.

### Trusted-offline reservation provider

The runtime binds `xmem.dll!XMemVirtualAlloc` only for a direct named root IAT import in the trusted-offline static TLS child with Rust providers enabled. The audited bridge handles all five Win64 arguments. Its two no-access shapes accept only base zero, size exactly 16 or 24 GiB, and `(allocation type, attributes, protect)` equal to `(0x20402000, 0x21, 4)` or `(0x20402000, 3, 0x801)`. Each tuple may hold one mapping, until child exit. Mach chooses a non-overwriting, 64 KiB-aligned address and both host protections are `VM_PROT_NONE`; the returned address is the actual reserved host VA. No tuple bits are interpreted as CPU or Xbox graphics protections. Unsupported inputs return null with bring-up `LastError=50`; capacity or host mapping failures return null with `LastError=8`. These diagnostic error choices are not claims about the Xbox API. No placeholders, aliases, physical page operations or guest release are implemented.

The first live reserve-plus-commit call at `01e1d181` (return `01e1d186`) passed `(base, size, type, attributes, protect) = (0, 0x49400000, 0x20003000, 0x183, 0x22004)`. Static inspection shows a full `RAX` null test, a break on null, and on success both base and size are stored and passed to the allocator initialization chain starting at `0221a4f0`. It gets 1,172 MiB of anonymous demand-zero host CPU RW, current and maximum, 2 MiB-aligned without overwriting other mappings. The alignment accommodates the observed large allocation form; it does not imply huge physical pages. The mapping is not pre-touched or wired. Diagnostics explicitly skip Xbox protection/cache, physical page and GPU semantics.

The second live reserve-plus-commit call at `01e1d4d6` (return `01e1d4db`) passed `(0, 0x89700000, 0x20003000, 0x283, 0x2404)`. On nonzero full `RAX`, the caller stores the address and unrounded byte count and passes both to the initializer at `05b1a7d0`. This tuple gets its own exact 2,199 MiB CPU RW mapping; its byte count is host-page aligned but **not** a multiple of 2 MiB. Only the base is constrained to the 2 MiB host VA alignment; the provider does not round the byte count up.

The third live call at `01e1d369` (return `01e1d36e`) passed `(0, 0x23300000, 0x20003000, 0x183, 0x22004)`. It traps on null; success stores the base and exact count and passes both to the initializer at `01d14170`. It gets a separate 563 MiB CPU RW mapping with 2 MiB host VA base alignment and no length rounding.

The fourth live call at `01e1d288` (return `01e1d28d`) passed `(0, 0x25400000, 0x20003000, 0x183, 0x22004)`. It also traps on null and feeds the exact base and byte count into `01d14170` on success. It gets its own exact 596 MiB mapping under the same host CPU RW model. All four exact commit tuples are limited to one live mapping each, at most 4,530 MiB combined, with no change to the two earlier no-access reserves.

The startup loop's switch table at RVA `0674c270` selects the four allocation paths for indexes 0, 2, 4 and 5 respectively in the live order listed above. Indexes 1 and 3 do not allocate in this switch; indexes 6–8 bypass it. The loop reads lengths from a range at `.data` RVA `071bf9b0` that is zero-fill on disk. There are no additional reserve+commit callsites in this loop, and it supplies no static justification for accepting unobserved lengths.

Outside the loop, `05ba6c30` (return `05ba6c35`) passes `(0, 0x1400000, 0x20403000, 0x181, 4)`. On non-null the caller saves the returned base and passes it via `01dadc90` and `028b7af0` to `01d14170`, with the exact 20 MiB byte count. This confirms a CPU allocator consumer at startup, not any claim about later use of all its suballocations. This exact tuple gets its own single 20 MiB demand-zero RW mapping with 64 KiB host VA alignment, for a combined bound of 4,550 MiB. The registered teardown calls `VirtualFree(base, 0, MEM_RELEASE)` at `028b7ace` through IAT RVA `06793a70`. That guest release path is not supported by this XMem provider; the mapping remains owned until child exit. No Xbox hardware backing, cache, or GPU behavior is implied.

`cargo test --offline --target x86_64-apple-darwin --test static_tls_lane xmem_bridge` exercises both size choices through the actual IAT bridge in owned PEs, including a poisoned upper stack dword, disjoint aligned returns, LastError behavior, and explicit rejection. The fixture also tests zero-initialized writable bytes in the first and last pages of all five committed ranges and rejects duplicates and mismatched tuples. The standalone reservation probe does not touch backing; the production mapping metadata test checks all full spans and protections, ownership and release.

The [CPU backing model](../src/xbox_vm/backing.rs) exercises aliases only over its own placeholder model, not mappings into the observed `20402000` reserves or the title's existing replacements. Its unmap drops a view without restoring a placeholder. The [host alias proof](xmem-cpu-alias.md) demonstrates shared CPU bytes at independent host-selected addresses, not fixed replacement, physical token, protection or GPU behavior. Neither is an XMem provider.

For an eventual CPU-backed lane, keep guest mappings and token/view ownership in one address-space owner. Check count/array/byte arithmetic, range authority and exact address/alignment, and validate the entire operation before publishing intervals or returning success. An interval record does not satisfy a commit, and a detached buffer does not satisfy an alias. Keep per-import diagnostics for raw flags/attributes/protect, base/size or page count, and precise unsupported reason; don't read speculative output layouts, silently ignore graphics protections, or claim GPU placement/visibility. Unsupported operations remain terminal at use until independently justified.

## Recheck

On the matching local image with read-only tools: `xcrun llvm-objdump -p "$exe"` reports the import descriptor/hints. `xcrun llvm-objdump -d --start-address=0x141e1cfea --stop-address=0x141e1d04b "$exe"` shows the first two reserves; add image base to the other listed RVAs and start at an instruction boundary. Leonida's `python3 -B -I tools/import_call_sites.py "$exe" --dll xmem.dll --json` reproduces candidate branch RVAs without writing bytecode caches. Do not infer execution order from static address order.
