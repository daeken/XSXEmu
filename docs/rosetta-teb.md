# AMD64 TEB and PE static TLS under Rosetta

**Decision:** keep direct Rosetta startup's static-TLS rejection. A private GS
switch works in an isolated synthetic test, but it replaces the base used by
host pthread TSD and is not a guest/host ABI. The public Mach path tested here
acknowledges a changed GS base without applying it. Prefer a controlled AMD64
execution engine with an explicit per-guest-thread GS base as the supported path.

## Reproduction and measurements

Run `tools/probe_rosetta_teb.sh [private|mach-baseline|mach-change] ...` on
Apple Silicon with Rosetta, a Rust toolchain with the `x86_64-apple-darwin`
target, macOS linker tools, and Python 3. The runner builds a standalone Rust
executable with `rustc`, using `global_asm!` for the small assembly boundary.
With no arguments it runs all three modes. Each is a separate x86_64 subprocess, verifies
`sysctl.proc_translated == 1`, and is time-bounded. Status 0 means the mode's
checks passed; status 1 for `mach-change` means the requested change was **not
established** (so the all-modes command exits 1 on this host). There are no PE
inputs, Wine binaries, privileges, or OS security changes. The one LDT entry
is confined to the Mach test processes and dies with them; it is never loaded
as a selector. No loader/runtime code links this probe.

Observed on `Mac16,13`, macOS `27.0.1` (`26A434`), SDK `27.0`, rustc `1.99.1`
(`58cf8f9c3`). Rosetta receipt `com.apple.pkg.RosettaUpdateAuto`
version `1.0.0.0.1790234402`; `libRosettaRuntime` arm64 UUID
`A1DA2B2A-3D68-33CB-A631-FA772DCDD167`. Example addresses below vary with ASLR.

**Private hook, status 0.** A controlled worker saves the host base via
`THREAD_IDENTIFIER_INFO.thread_handle`, calls libSystem's private
`_thread_set_tsd_base`, runs an original assembly leaf, then restores the host
base before returning to Rust. It reads `GS:[0x30]` (self), reads `GS:[0x58]`
(TLS vector), follows an indexed 64-bit TLS block pointer, writes the block,
and writes `GS:[0x68]` (last-error). For example:

```text
private: translated=1
guest self=0x7ff1d1904400 vector=0x7ff1d19043e0 value=0x12345678abcddcba TLS write=0xedcba98754322345 last-error=0x55aa1234
host gs:[0]/[30] before=0x30d66c000/0x0 after=0x30d66c000/0x0
private: subprocess status 0
```

**Public Mach baseline, status 0.** `x86_THREAD_STATE64` exposes the GS
*selector*, not its base. `x86_THREAD_FULL_STATE64` has `__gsbase` and the
public APIs can read it here once the process has an LDT. Separate unchanged
GET/SET control on a suspended worker:

```text
STATE64 get=0 count=42 GS selector=0x0
FULL_STATE64 get before LDT=5
FULL_STATE64 get after LDT=0 count=50
FULL_STATE64 set unchanged=0 host base=0x30d1960e0 requested=0x30d1960e0
FULL_STATE64 immediate readback=0 base=0x30d1960e0
FULL_STATE64 parked readback=0 base=0x30d1960e0
FULL_STATE64 restore host=0
worker active gs:[0]/[30]/[58]=0x30d196000/0x0/0x0
host gs:[0]/[30] before=0x30d196000/0x0 after=0x30d196000/0x0
mach-baseline: subprocess status 0
```

**Public Mach changed-base test, status 1.** SET returned `KERN_SUCCESS` but
both immediate (still suspended) and parked GET returned the original base.
The resumed worker independently read the original GS values. No synthetic
pointer was followed when the GS self/vector reads did not match; the worker
was resumed with the original base and its two host GS samples matched.

```text
STATE64 get=0 count=42 GS selector=0x0
FULL_STATE64 get before LDT=5
FULL_STATE64 get after LDT=0 count=50
FULL_STATE64 set guest=0 host base=0x30cd710e0 requested=0x7f80faf051c0
FULL_STATE64 immediate readback=0 base=0x30cd710e0
FULL_STATE64 parked readback=0 base=0x30cd710e0
FULL_STATE64 restore host=0
worker active gs:[0]/[30]/[58]=0x30cd71000/0x0/0x0
guest self=0x0 vector=0x0 value=0x0 TLS write=0x0 last-error=0x0
host gs:[0]/[30] before=0x30cd71000/0x0 after=0x30cd71000/0x0
mach-change: subprocess status 1
```

Those results do not generalize to Intel macOS or other Rosetta builds. For
comparison, [public Intel XNU source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/i386/pcb.c)
requires a custom LDT for full state and passes `gsbase` to its TSD-base
setter. That code is not a specification of Rosetta's translated Mach state.
The earlier isolated `RDGSBASE` / `WRGSBASE` probes hit SIGILL; a separate
scratch test loading a nonzero LDT selector into GS from 64-bit code aborted
with Rosetta's `setting GS to a nonzero selector is unsupported` diagnostic.
`pthread_key_*` manages host TLS values and cannot change the meaning of an
AMD64 guest GS operand. Avoid fault-driven shims: valid GS operands may
read mapped host TLS without a fault (the unmodified `GS:[0x30]` read is one
example). A VM or a full emulator with the proper guest OS is an alternative
execution model, not a substitute for this loader's GS contract.

## What transfers from Alkyhol, and what does not

Local Alkyhol `b91b62f`: Win64 does not provide a TEB or static TLS. Its
[PE32 design](https://github.com/daeken/Alkyhol/blob/b91b62f/docs/pe32.md)
uses an LDT-backed **FS** in compatibility mode (TEB self at `FS:[0x18]`,
static TLS vector at `FS:[0x2c]`). That is not AMD64 **GS**. Alkyhol's
`jit32/src/process.rs` and `jit32/src/compiler.rs` offer design precedent:
copy relocated templates, assign stable indices, make the TEB/vector guest
memory, and apply segment bases during instruction lowering. The PE32
layouts, addressing and instruction support are not a Win64 engine.

Wine 11.0 (`db11d0fe6a169c457e23d007e20404643d067aa8`) is a source reference
for [the private Apple thunk](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll/unix/signal_x86_64.c#L64-L73)
and [host base retrieval via `THREAD_IDENTIFIER_INFO`](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll/unix/signal_x86_64.c#L2809-L2825),
not a runtime dependency or source imported into XSXEmu. Its
[signal entry and exit code](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll/unix/signal_x86_64.c#L908-L949)
installs host TSD on handler entry and reinstalls guest GS on exit only when
not returning to the signal or syscall stack. Its assembly dispatcher
[switches to host GS and reconstructs the `%rcx` frame pointer after `syscall`](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll/unix/signal_x86_64.c#L3113-L3135)
and [switches back to guest GS, saving and restoring `%rax` and `%rcx`](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll/unix/signal_x86_64.c#L3181-L3190).
The original `tools/teb-probe` private test proves only one synchronous
leaf interval on one worker. The standalone follow-ups below exercise nested
boundaries, directed signals, and default termination on guest faults. No
production hooks are installed.

## Standalone boundary fixture

```sh
tools/probe_rosetta_teb_boundary.sh                         # synchronous check
tools/probe_rosetta_teb_boundary.sh signal-host signal-guest # optional observations
```

The runner builds a Rust/assembly x86-64 Mach-O and gives each mode a fresh
Rosetta subprocess with a 10-second deadline. It uses only an owned TEB,
TLS vector/block, and test routines; no C source, Wine runtime, PE input,
production startup changes, or OS security changes. The private libSystem
`_thread_set_tsd_base` and `THREAD_IDENTIFIER_INFO.thread_handle` are the
same mechanism tested by `tools/teb-probe`, not a supported macOS interface.

**Observed on Apple Silicon, macOS 27.0.1 (26A434):**

- `sync`: host → Win64 guest → Rust Win64 provider (host GS) → nested Win64
  callback (guest GS) → provider (host GS) → outer guest → restored host.
  Mixed positional GPR/XMM arguments and integer/floating stack arguments
  matched bit-for-bit in both directions, as did the integer provider return
  and floating callback return. Guest RDI/RSI and XMM6/XMM15 sentinels survived.
  The callback read and changed guest TLS and `GS:[0x68]`; the outer guest
  saw both changes. The provider read, changed and rechecked independent
  Rust thread-local TLS/last-error values and Darwin `errno`; the final host
  saw the provider's values and the original host GS observations. Rust
  last-error here is a fixture model, not the production provider's state.
- `signal-host` / `signal-guest`: a sender used `pthread_kill(SIGUSR1)` after
  the target parked in assembly. The assembly-only handler saw the
  interrupted context's GS (host and guest, respectively), and the target
  saw that same GS after handler return. Final host GS checks passed in both
  modes. In particular, **signal entry did not automatically restore host
  GS** when the interrupted leaf held guest GS. The handler did not call
  Rust, access host TLS, or switch GS.

## Fail-closed signal experiment

```sh
tools/probe_rosetta_teb_boundary.sh masked fault-ill fault-access fault-unmapped fault-trap fault-div
```

On the same host, `masked` passed with **one guest execution thread** and a
host-only test sender. The target installed and verified an asynchronous
signal mask with host GS, before the first switch, then kept it unchanged
through the entire call tree, including the host-GS provider and nested
callback. It did not unmask between guest windows. The sender used
`pthread_kill` only after each assembly checkpoint validated guest GS, and
acknowledged only after a successful send. `SIGUSR1`, `SIGUSR2`, and `SIGALRM`
were sent during outer guest entry, nested guest callback, and resumed outer
guest, respectively. The provider checked the effective mask and cumulative
pending bits on both sides of the nested call. After the outer return all
three signals were pending and the assembly observer had not run. Restoring
the exact saved mask **after verifying restored host GS** delivered only
`SIGUSR1` and `SIGALRM`; `SIGUSR2`, intentionally blocked in the saved mask,
stayed pending until the test separately unblocked it. The observer counted
exactly one of each and sampled host GS at every delivery. Distinct signal
numbers avoid assuming standard signals queue multiple instances.

The Darwin probe mask blocks maskable signals except the fault/abort-like
set (`SIGILL`, `SIGTRAP`, `SIGABRT`, `SIGEMT`, `SIGFPE`, `SIGBUS`, `SIGSEGV`,
`SIGSYS`). Those dispositions are reset to `SIG_DFL` **only in the disposable
child**, including any Rust stack-overflow signal handler. Entry is refused
if a fault-like signal was already blocked, if setup fails, or if effective
mask readback does not match. A mask selects signal numbers, not sources:
even an asynchronously sent fault-like number remains unblocked. Do not
block hardware-generated `SIGILL`, `SIGFPE`, `SIGBUS`, or `SIGSEGV` and rely on
POSIX behavior; the result is undefined. `SIGKILL` and `SIGSTOP` cannot be
masked, and `SIGCONT` can continue a stopped process even while blocked.

Each fault mode uses the same mask and no fault handler, with a private
scratch marker shared with the runner. Assembly marks the selected fault
site only after seeing the expected guest GS. The runner requires both the
marker and the exact negative child status; a normal return, early death,
wrong signal, or timeout fails. On macOS 27.0.1 (26A434):

| Guest instruction | Observed child status |
| --- | --- |
| `ud2` | `-4` (`SIGILL`) |
| Read from a private `PROT_NONE` mapping | `-10` (`SIGBUS`) |
| Read from unmapped address zero | `-11` (`SIGSEGV`) |
| `int3` | `-5` (`SIGTRAP`) |
| Integer divide by zero | `-8` (`SIGFPE`) |

These statuses describe BSD signal termination, not the underlying Mach
exception type or its dispatch order. BSD thread masks do not disable Mach
exception delivery to thread/task/host exception ports (including debugger
handling); no Mach exception ports were installed or exercised by this
probe. Other faults, stack exhaustion, and SEH/unwind or recovery across a
GS switch are not covered. This is not evidence that an unmasked host
handler can safely run on guest GS. Only three thread-directed signals were
tested, at stable points, not process-directed routing, reentrant handlers,
profilers, cancellation, or attachment by a debugger. A per-thread mask
is not a process-wide barrier. All findings are specific to the tested
Rosetta build/private setter; no PE, UCRT, or title was run.

**Policy implication:** keep direct Rosetta static TLS rejected by default.
If an opt-in experiment is built, restrict it to a trusted, original,
single-thread PE fixture in a dedicated, time-bounded child. With host GS,
verify mask/disposition setup before entering; span the entire guest/provider
call tree with the mask, and restore the caller's exact mask only after
verifying host GS on normal return. Keep guest code on normal-return paths
through owned thunks (no guest-created threads, direct host syscalls, or
unwind/nonlocal exits across the boundary). On any setup mismatch, fault,
unexpected exit or timeout, treat the child run as failed; do not try to
continue, resume guest execution, or run cleanup in-process with unknown GS.
This is containment by child failure, not a guest security sandbox or a
replacement for a controlled execution engine.

## Standalone original PE proof

```sh
tools/probe_rosetta_tls_owned_pe.sh
```

The runner takes no arguments. It builds and runs a single-threaded x86_64
child under Rosetta with a ten-second deadline. The child generates a fixed
AMD64 PE32+ EXE in memory from owned assembly, not from an external image.
It uses `Pe::materialize_into` at a nonpreferred address,
checks all six DIR64 relocations, gives the EXE's TLS module index zero via
`static_tls::Plan`, and seals the mapping with `GuestMemory`. The planner
snapshots a relocated pointer and a nonzero seed and adds eight zero bytes
in a 16-byte-aligned block; the PE's initially nonzero index DWORD is patched
to zero. The test TEB points to the planner's vector at `GS:[0x58]`.

The child binds exactly one named import (`owned-probe.dll!RoundTrip`) at the
fixture's fixed IAT slot to an assembly thunk. No DLL is loaded. The outer
boundary calls TLS process attach, EXE entry, then TLS process detach. Entry
calls through the IAT; the thunk restores and checks host GS before it calls
Rust. The provider invokes a distinct, validated callback in the same mapped
`.text` via a second thunk that switches to guest GS and restores host GS
before returning to Rust. The first thunk then restores guest GS for entry.
The fixed Win64 calls check mixed GPR/XMM arguments and two stack arguments in
each direction, an integer provider result, and a floating-point callback
result. Guest RDI/RSI and XMM6/XMM15 sentinels survive the import call.

Attach, nested callback, resumed entry and detach advance one TLS block in
that order. They follow the image's index through `GS:[0x58]` and check the
relocated pointer before mutating initialized state and the zero-fill word.
Attach and detach also check image base, reason and the null reserved argument.
The provider verifies host thread-local state and the effective mask on both
sides of the nested call. On macOS 27.0.1 (26A434) under Rosetta, entry returned
42 and final TLS held state `0x33300303` and scratch `0xc3`. The outer boundary
checked host GS slots before Rust restored and verified the original mask.
The runner requires both a success record and exit status zero.

The child reuses the fail-closed mask and default dispositions above; it sends
no signals and tests no fault handling. Only the private setter, assembly and
owned PE execute with guest GS. Unexpected exits and timeouts fail the probe.
Detach is an explicit normal-return step, not process teardown emulation.
There are no external PE inputs, extra guest threads, or Wine dependency.
Default startup still rejects static TLS. This standalone proof is neither a
general import bridge nor a sandbox for other images.

## Opt-in child: audited provider bridges

`run <trusted-fixture.exe> --experimental-static-tls --rust-providers` permits
only exact Win32 provider identities with audited bridges. Registry aliases
are accepted only if they resolve to an audited identity; ntdll
`Rtl*LastWin32Error` identities are distinct. Win32 `Tls*` slots are
provider-managed and separate from the PE static TLS vector at `GS:[0x58]`.

`LoadLibraryExW` never searches for DLLs, even in the static import graph.
Except for the explicit startup mappings described below, well-formed
requests return `NULL` with `ERROR_MOD_NOT_FOUND`; invalid or unsupported
requests return their validation errors instead.
`GetModuleHandleA` and `GetModuleHandleW` return a borrowed PE base from the registered guest image
graph: null selects the root EXE, and non-null names use the ordinary mapped
module lookup (CP1252 for `A`, UTF-16 for `W`). Neither loads images nor creates handles for Rust providers
or API-set contracts. Success preserves `LastError`; an unmatched name
returns `NULL` and sets `ERROR_MOD_NOT_FOUND` in the guest TEB.

`GetLogicalProcessorInformation` exposes a modeled single-group topology, not
host physical topology or an Xbox CPU profile. It uses the same process-stable
logical count as `GetSystemInfo`/`GetNativeSystemInfo`: host available
parallelism capped at 64 (fallback 1). Each logical processor is represented
by one `RelationProcessorCore` record with a distinct mask bit and no SMT flag.
No package, NUMA, cache, or other relationships are modeled. A null or short
buffer with a valid length pointer returns the required byte count and
`ERROR_INSUFFICIENT_BUFFER` without writing records. A null length pointer
returns `ERROR_INVALID_PARAMETER`. Success returns the bytes written and
preserves `LastError`. The startup consumer probes with a null buffer and zero
length, checks error 122, and retries. It walks 32-byte records, counting only
core records and summing the popcounts of their masks; it does not read the
union or require any other relationship.

`GetSystemTimeAsFileTime` uses the same host UTC wall clock as the ordinary
provider. It writes one Win64 `FILETIME` (two DWORDs encoding 100 ns ticks
since 1601-01-01 UTC) and preserves `LastError` on success.
`Sleep` uses the existing `synch-l1-2-0` binding and a one-DWORD void
bridge, preserving `LastError`. A zero duration yields, a finite duration
sleeps on the host thread, and `INFINITE` parks without returning (the
launcher may still terminate the child). The title's thread-creation
failure path calls `Sleep(250)` before retrying; bridging the delay does
not make a failed `CreateThread` succeed.

In the explicit trusted-offline static TLS lane, the guest sees 16
virtual logical processors in one group (`0xffff`), independent of host
CPU count. `SystemInfo`, legacy logical-processor records, and thread group
affinity share this topology. The legacy records expose one bit per virtual
processor with no SMT or host core relationships inferred. Other execution
profiles retain their previous topology.

The suspended-worker continuation requests normal priority and changes the
queried group's mask to `0x1f00` before resuming. The audited affinity query
requires an owned thread handle with query access and writes all 16 bytes
(mask, group zero, reserved zero). The priority and affinity setters do not
change host scheduling or guest state: with a valid request handle and
required access, they log the offline limitation and return `FALSE` with
`ERROR_NOT_SUPPORTED`. Affinity rejection leaves the previous-state output
untouched. No mask is remapped or used to pin a host thread.

`GetTickCount64` models guest uptime with the macOS raw monotonic clock,
including host sleep. It returns whole milliseconds as an unsigned 64-bit
value and preserves `LastError`. Its epoch is independent of the guest's
`QueryPerformanceCounter` origin.

`run --experimental-static-tls --trusted-offline --map-extra-dll PATH`
explicitly maps one additional trusted, entryless PE DLL without imports,
delay imports or TLS. It uses the file's actual basename and mapped base;
duplicate mapped basenames are refused. The extra PE is appended after
static binding, so the option does not change API-set routing or static
imports. The usual mapping and CFG validation still apply.

To build the owned synchronization facade into a fresh directory (no SDK or
external DLL required):

```sh
out=$(mktemp -d)
rustc --edition 2024 tools/build-sync-facade.rs -o "$out/build-sync-facade"
"$out/build-sync-facade" "$out/api-ms-win-core-synch-l1-2-0.dll"
```

Pass the generated DLL's path to `--map-extra-dll` along with the usual
`--rust-providers --experimental-static-tls --trusted-offline` flags. The PE
has exactly two GuardCF-admitted exports. With a zero-initialized condition
variable and no possible guest peer threads, `WakeAllConditionVariable` has
no waiters and preserves LastError. `SleepConditionVariableCS` requires a
caller-held critical section; a zero-duration poll returns false and sets
`ERROR_TIMEOUT` (there is no peer to observe a release/reacquire). Nonzero
waits or a nonzero condition-variable state hit `UD2`; no blocking, wakeup,
or lock-ownership validation is implemented by this diagnostic facade.

`run --experimental-static-tls --trusted-offline --rust-providers
--xgameruntime-dll PATH` opts into one separately supplied AMD64 PE DLL named
`xgameruntime.dll` (ASCII case-insensitive). It is a second startup root,
not a replacement for any ordinary static import. Normal imports resolve
through the ordinary PE/API-set/provider rules and `--dll-dir`/EXE directory
search; the supplied file's directory is not added automatically. Missing or
unaudited bindings anywhere in that root's dependency closure are errors even
with `--trace-missing-imports`. Normal startup validation and dependency-first
attach/reverse-order detach apply, not the entryless `--map-extra-dll` path.

After DLL attach, `LoadLibraryExW` can acquire this mapping only by its full
basename, null file, and flags `0x800` (`SYSTEM32`) or `0xA00`
(`APPLICATION_DIR | SYSTEM32`). Both are explicit overrides to the same mapped
file; neither searches any directory at call time. `FreeLibrary` balances
guest references without unloading startup's mapping. The TLS `GetProcAddress`
policy is unchanged: only direct named PE exports admitted by checked CFG
metadata, not ordinals, unchecked RVAs, forwarded or raw Rust addresses.
That option does not emulate XGameRuntime or COM. The owned PE in its
regression test is only a loader fixture; no genuine XGameRuntime DLL was tested.

`--xgameruntime-compat` instead builds an original AMD64 PE in memory under
`C:/Windows/System32/xgameruntime.dll`. It requires the same three run flags
and is mutually exclusive with `--xgameruntime-dll PATH`. It shares the
same startup-root admission, attach/ready/detach sequence, loader flags,
reference counting, and named export checks. Its relocated vtable and its
exports refer to mapped guest thunks checked by the same GuardCF machinery;
private slots lead to the audited GS-switching bridges. It is not a static
import provider, a general GDK replacement, or a substitute for a genuine DLL.

The model accepts only the pinned `InitializeApiImplEx2` packed values
(`0x633600002712`, `0x65f400001edd`), flags `2`, and null options. Other
configurations return `E_NOTIMPL`; a repeat while initialized fails. It
exports `QueryApiImpl`, `UninitializeApiImpl`, and `XErrorReport` (logs the
HRESULT, does not read the guest message). It exposes only `XThreadingImpl`
and its `IUnknown` identity (`QueryInterface`, `AddRef`, `Release`). The
assertion at slot 29 applies to the sole modeled guest thread, which is
not time sensitive. Uninitialize invalidates methods on existing objects
but still allows release; detach frees the process-owned storage.

Queue creation accepts the pinned work and completion modes `(1, 1)`
(`ThreadPool, ThreadPool`), stores both modes, and returns an opaque
registered queue handle independent of the creating interface's lifetime.
No workers or submission are implemented. Empty queue cleanup supports
termination without a callback, zero-timeout polling (returns false, no
callback ran), and close. Handle values are never reused during the
process; uninitialize clears outstanding queues. Unsupported modes,
blocking waits, callbacks and interfaces fail; known vtable slots with
unmodeled signatures report the slot and stop the child instead of
inventing a return value. The owned Win64 fixture verifies these behaviors
and the ordered trace under Rosetta with checked CFG and a rebased runtime.
No title execution or device progress has been validated by this fixture.

`--gameinput-no-devices` is a separate opt-in requiring `--trusted-offline`,
`--experimental-static-tls`, and `--rust-providers`. It handles only the
root's direct `GameInput.dll` ordinal 1, not names, forwarders, other
ordinals or dynamic lookup. A private, original guest PE contains the
relocated vtable and checked guest method entry points; its bridge slots
are not public PE exports.

Microsoft's [GameInputCreate reference](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/input/gameinput/functions/gameinputcreate)
defines `HRESULT GameInputCreate(IGameInput** out)`. In the pinned Scarlett
image the caller at RVA `0x59258c3` passes a cleared output slot, checks the
signed HRESULT and hits `INT3` on failure. Success caches the instance via
`AddRef`/`Release`; a null instance is not a fallback. The v0
[registration method](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/input/gameinput/interfaces/igameinput/methods/igameinput_registerdevicecallback)
at byte offset `0x48` is called at RVAs `0x43a109f` and `0x592586a`. The
register arguments are `this`, null device, kind (`0x10` or opaque
`0x40000`), and status filter `1`; the stack holds enumeration `2`
(blocking), context, callback and a 64-bit token output. The two shapes
are accepted as exact filters; other shapes return `E_INVALIDARG`. The
fixture verifies that neither shape invokes its callback.

The facade supplies `IUnknown` and v0 `IGameInput` identity, reference
counts and synchronous empty enumeration. Tokens are scoped to the
creating object and cannot be reused after unregister or release.
The inspected callers at RVAs `0x2211b9f`, `0x43a1e6b`, `0x2211c4c`
and `0x22127b6` pass trailing output pointers and check HRESULT at
vtable byte offsets `0x20`, `0x28`, `0x30` and `0x80` respectively.
For these empty results it clears the pointer and uses the documented
`GAMEINPUT_E_READING_NOT_FOUND` for current/next/previous reading; for
device-ID lookup `GAMEINPUT_E_DEVICE_NOT_FOUND` is the local policy for
an empty registry. There are no devices, workers or host input
dependencies. Unmodeled vtable slots stop the child with the slot number.
An owned Win64 fixture checks the ordinal gate, relocated guest vtable
addresses, checked calls, exact output writes and token isolation. It
does not establish further live title progress.

`--dstorage-factory` is a separate opt-in requiring `--trusted-offline`,
`--experimental-static-tls`, and `--rust-providers`. It admits only the root's
direct named `XCRDAPI.dll!DStorageGetFactory` import. It neither exposes dynamic
exports nor replaces desktop DirectStorage. The original private guest PE uses
audited Win64 bridges and a relocated CFG-admitted guest vtable.

At IAT RVA `0x6793fb8`, the pinned title requests factory IID
`62959d11-d45f-4884-a0a3-f7862ea243ae`. Its caller requires exactly `S_OK` and a
non-null factory, then calls factory slot 8 (`+0x40`) with `0x02000000` bytes and
asserts on a negative HRESULT. The earlier trace stops at the missing import;
these method calls are static findings, not measurements of live progress.
Microsoft's [factory](https://learn.microsoft.com/en-us/windows/win32/dstorage/dstorage/nf-dstorage-dstoragegetfactory)
and [staging size](https://learn.microsoft.com/en-us/windows/win32/dstorage/dstorage/nf-dstorage-idstoragefactory-setstagingbuffersize)
references describe the API shapes; the Xbox slot and IID are separately
corroborated by xcl's ABI notes. Leonida documents a fatal null factory on its
own run. No external implementation code is used.

The facade accepts only the pinned IID at creation and offers that interface
and `IUnknown` via `QueryInterface`. The active factory has a real reference
count. Slot 8 accepts only 32 MiB, allocates that much zero-initialized private
CPU storage on success, and reuses it on repeat calls. Allocation failure is
reported, and final `Release` frees the backing. There is no guest mapping of
that buffer, GPU/DMA support, queue submission, or decompression.

The first run with the `G:` mount reached factory slot 4 at guest return RVA
`0x28c8c21`. `OpenFile(this, path, iid, out)` accepts the Xbox file IID
`43704f9f-27c6-4a9f-8815-d16527894df4` and opens a regular file read-only through
the same descriptor-confined `--title-data DIR` mount as the attributes
precheck. No other drive or path namespace is admitted. The private file
object holds the descriptor until its final COM release; at most 64 objects
may be open. Only the file's IUnknown prefix is implemented, and no file
descriptor is exposed to the guest. Unmodeled factory/file slots are terminal.
The owned Win64 fixture exercises the import gate, rebasing, CFG, IID/output
handling, size checks and lifetime; a host test verifies the actual buffer.

Other static sites use factory slot 5 (`+0x28`, one-entry status array, HRESULT
unchecked) followed by slot 10 (`+0x50`, newer queue IID and a `0x20`-byte
queue descriptor, negative HRESULT asserts). Separate helpers use slot 4
(`+0x20`) for file open. They return/store null if it fails. On success they
retain the DirectStorage object in a wrapper that separately opens and reads
file metadata via ordinary Win32 I/O. This DirectStorage change does not
expand the Win32 mount operation set. That is not a fallback for a missing
factory or failed DirectStorage open. The inspected consumers also use queue
slot 3 to enqueue a request, queue slot 8 to close, and status-array slot 2
to release. These downstream interfaces remain unimplemented.

`GetModuleFileNameW` reads the registered UTF-16 guest path: a null handle
selects the root EXE, and a non-null handle must exactly match a mapped image
base. It performs no filesystem lookup. Success preserves `LastError`;
truncation NUL-terminates, returns the buffer capacity in UTF-16 code units,
and sets `ERROR_INSUFFICIENT_BUFFER` in the guest TEB.
`RtlPcToFileHeader` looks up PCs only in the mapped guest image graph, which
is registered before process attach. It returns and writes the image base
(or null for an unknown PC), without changing LastError.
[`DisableThreadLibraryCalls`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls)
accepts only the exact base of a mapped guest DLL, including its own handle
passed to `DllMain`. As documented, active PE static TLS prevents success.
The graph records TLS directory presence from each source PE: the TLS lane
allocates a static slot for every validated directory, even with an empty
template, and the ordinary lane rejects PE static TLS at startup. The Rust
provider uses `ERROR_INVALID_HANDLE` for non-DLL handles and
`ERROR_INVALID_PARAMETER` for a DLL with static TLS. Success preserves
LastError. On success the shared module graph suppresses worker attach/detach
for that DLL. Process attach/detach still run.
`GetCurrentThreadId` returns the existing Rust provider's nonzero, process-local
DWORD, not a macOS thread ID. The initial guest TEB's `ClientId.UniqueThread`
(`GS:[0x48]`) is seeded from the same provider before guest execution. The
bridge preserves `LastError`. Workers likewise get their own ID and matching TEB field.
An owned PE imports it through `api-ms-win-core-processthreads-l1-1-0.dll` and
checks the return against the TEB and verifies `LastError` across repeated calls.

`InitializeCriticalSection` uses the one-pointer, void bridge and the same
provider state as the spin-count initializer (with zero spin). The observed
IAT RVA `0x6793ae0` takes a writable critical-section pointer in RCX; no
return value is consumed. Successful initialization preserves LastError.

`CreateSemaphoreExW` uses the existing audited six-argument bridge. Read-only
inspection of the two direct call sites targeting IAT RVA `0x6793ac8` shows
null security and name, a caller-supplied signed initial count, maximum
`0x7fff`, zero flags, and access `0x00100002` (`SYNCHRONIZE |
SEMAPHORE_MODIFY_STATE`). The missing-import trace does not capture the
live initial count; upstream static calls pass different values.

The provider creates a typed guest handle owning a separate count/limit,
with only those two explicit access bits supported. It accepts
`0 <= initial <= maximum` and `maximum > 0`, and preserves LastError on
success. Invalid counts or flags fail with `ERROR_INVALID_PARAMETER`;
non-null security/name or unsupported access bits fail with
`ERROR_NOT_SUPPORTED`. No pointer is dereferenced. Existing ordinary
`DuplicateHandle` and `CloseHandle` share and release the object as usual;
these creation bridges do not audit those APIs for static TLS. Named objects
and security attributes remain unsupported.
The owned PE tests both stack DWORDs with nonzero upper halves, distinct
handles, and guest LastError on success and failure.

`CreateSemaphoreW` has a separate four-argument bridge for the exact
`synch-l1-2-1` import. Both calls through IAT RVA `0x6793ee8` pass
`(NULL, 0, 1, NULL)`. It uses the same typed semaphore objects and count,
pointer and LastError rules, granting `SEMAPHORE_ALL_ACCESS` to the new
handle.

The first worker statically uses `WaitForSingleObject(handle, INFINITE)`
through IAT RVA `0x6793b20` and `ReleaseSemaphore(other, 1, NULL)` through
`0x6793b08`. The release bridge operates only on semaphore objects. A semaphore wait
requires `SYNCHRONIZE`, consumes one count on success, and returns
`WAIT_TIMEOUT` without touching LastError if a zero or finite timeout expires.
An infinite wait blocks until a count is available. Release requires
`SEMAPHORE_MODIFY_STATE`, optionally writes the previous count, and rejects
nonpositive increments and overflow without modifying count or output.
Closing a handle concurrently with a wait is outside the contract. Object waits other than thread and semaphore waits, and alertable or
multiple-object waits, are unsupported.

#### Bounded guest worker threads

The first observed `CreateThread` call (IAT RVA `0x67934a0`) follows two
zero-count binary semaphores. It passes null security, `0x10000` bytes,
start RVA `0x55e8b00`, an object pointer, flags zero, and a writable thread-ID
DWORD on the caller stack. The worker immediately waits indefinitely on the
first semaphore, and releases the second on its work-loop completion path.
The first wait and release are `WaitForSingleObject` and `ReleaseSemaphore`
from `api-ms-win-core-synch-l1-1-0.dll`.

The audited six-scalar `CreateThread` bridge accepts only flags zero or
`CREATE_SUSPENDED` and null security, from the EXE entry or an existing worker start routine. It
validates the start against sealed executable PE contents and any active
CFG policy. It creates a genuine host thread (up to 32 concurrent workers),
with guarded stack space at least as large as the request plus host bridge
headroom, not Windows reserve/commit semantics. Each worker captures its own
Rosetta host GS and owns its guest TEB, static TLS vector/templates, dynamic
TLS values, LastError and ID. The Win64 entry receives the parameter in RCX,
with aligned stack/home space, and captures the DWORD return after checking
both GS domains. Loader notifications run serially: dependency-order DLLs
then EXE TLS callbacks on attach, reverse ordering on detach. Within a module,
TLS callbacks precede DllMain. No guest routine is invoked inline by the
creating bridge. The observed UCRT worker calls `FlsGetValue` (return PC `0x1802b176f`)
with an index allocated during process startup. FLS allocations are shared
across the process, but each worker starts with null values. A valid read
clears LastError, even for null; an invalid index sets `ERROR_INVALID_PARAMETER`.
`FlsFree` removes the index and all implicit fibers' values before reuse.
If a non-null value requires a registered callback on free or worker exit,
the child stops with a diagnostic instead of calling guest code or making the
thread handle ready. Fiber creation, switching, and FLS callback delivery are
not implemented.

Only thread and semaphore handles participate in non-alertable single
waits (including polling, timeout and infinite wait). Closing a thread
handle does not stop the worker. Its object signals after thread detach,
while separate host join ownership ensures workers are gone before process
detach and mapping/CFG teardown. If the EXE returns and any workers fail to
finish within 500 ms, the child exits with a diagnostic without running
process detach. No `SuspendThread`, `ExitThread`, forced termination,
alertable/multiple waits, or Windows exception unwinding is added.

The second observed `CreateThread` call (return PC `0x141ad1076`) requests
`CREATE_SUSPENDED`, a `0x57800`-byte stack, and entry RVA `0x2215ea0`. The
caller stores the returned handle in its parameter record, then invokes
`SetThreadPriority`, `GetThreadGroupAffinity`, `SetThreadGroupAffinity`, and
`ResumeThread`. The guest entry reads that published handle before invoking
its inner routine. The startup gate parks the real worker before thread
notifications and entry; the typed `ResumeThread` bridge requires
`THREAD_SUSPEND_RESUME` and returns the previous count (one at first release,
zero if already unsuspended), preserving LastError on success. Closing the
handle neither resumes nor kills the worker. An unresumed worker at teardown
is covered by the same bounded fail-closed drain. This does not implement
priority or affinity APIs, or suspension after launch.

The worker later takes its own ID from `GetCurrentThreadId` and calls
`OpenThread(0x1fffff, FALSE, id)` through IAT RVA `0x67934d8`. The audited
bridge opens a new guest handle on the existing worker object; it never
looks up a host thread. An exact `THREAD_ALL_ACCESS` request grants all
modeled rights, not support for unimplemented operations. Other access
masks must be subsets of the modeled rights. Only spawned workers have
openable IDs; unknown and completed IDs are rejected. A worker stays
openable even if every handle was closed, and existing handles retain
waitable completion after its ID is removed.

`CreateEventA` uses a four-argument bridge. The direct calls and tail thunk
referencing IAT RVA `0x6793ab0` pass null security and name, manual-reset
`FALSE` or `TRUE`, and initial state `FALSE`. The missing-import trace does
not distinguish the callers. The provider stores reset mode and signal state
on a typed, noninheritable guest event with `EVENT_ALL_ACCESS`; both Win32
BOOLs use zero/nonzero semantics. Success preserves LastError. Non-null
name or security fails with `ERROR_NOT_SUPPORTED` without dereferencing
either pointer. Ordinary handle closure and duplication use the same object
lifetime rules as for semaphores. This implements creation only: event
signaling, reset, and wait APIs remain unbound.

`CreateMutexA` uses a three-argument bridge. The tail thunk targeting IAT
RVA `0x6793ac0` passes `(NULL, FALSE, NULL)`. The provider creates a typed,
noninheritable guest mutex with `MUTEX_ALL_ACCESS`. A nonzero initial-owner
BOOL records the current modeled guest thread ID as the owner; zero creates
an unowned mutex. Success preserves LastError. Non-null security or name
returns `NULL` and `ERROR_NOT_SUPPORTED` without reading either pointer.
This implements creation only, not release, waits, or abandoned mutexes.

`AcquireSRWLockExclusive` and `ReleaseSRWLockExclusive` each use a
one-pointer void bridge. The startup acquire through IAT RVA `0x6793aa8`
and its paired release through `0x6793b00` address an aligned, zero-filled
word at RVA `0x6e04e80`. The provider uses an opaque eight-byte lock word
for modeled guest ownership with atomic acquire/release transitions. Both
preserve LastError on success. Recursive acquisition, contention, and
non-owner release terminate with a diagnostic instead of waiting or
pretending to succeed. Shared mode, try-lock, and condition-variable APIs
remain unsupported. Do not mix this word encoding with other SRW implementations.

`GetFileAttributesW` uses a one-pointer bridge returning a DWORD. At IAT RVA
`0x6793950` the startup caller replaces the executable basename returned by
`GetModuleFileNameW(NULL, ...)` with `xgameruntime.dll`. It tests only for
`INVALID_FILE_ATTRIBUTES`, not individual bits. The provider shares the
UTF-16 path rules, metadata lookup (without following the final symlink),
and attribute bits of `GetFileAttributesExW`. Neither returns a file handle
or searches DLL roots. Success preserves guest
LastError; failure returns `INVALID_FILE_ATTRIBUTES` and sets guest LastError.

`run --experimental-static-tls --trusted-offline --rust-providers --title-data DIR`
exposes the selected directory as a read-only guest `G:` drive. The drive is
absent by default. Lookups require an absolute `G:\` or `G:/` path, match
component spelling according to the host volume, and reject traversal and links
inside the mounted directory. Lookup is relative to pinned directory descriptors;
generic file creation, writes and other drives are unchanged. The observed archive
probe (return RVA `0x28c8bfe`) checks for `INVALID_FILE_ATTRIBUTES` before
proceeding to DirectStorage `OpenFile`.

The audited `CreateFileW` bridge (IAT RVA `0x6793900`) admits only the archive
call's tuple: `GENERIC_READ`, `FILE_SHARE_READ`, null security attributes,
`OPEN_EXISTING`, `FILE_FLAG_NO_BUFFERING`, and a null template. It opens an
existing regular file through the same confined mount and returns a guest file
handle that can be closed with `CloseHandle`. It logs that host cache and
alignment behavior for `FILE_FLAG_NO_BUFFERING` is not modeled. Success
preserves guest LastError; failure sets it and returns `INVALID_HANDLE_VALUE`.
This bridge does not add audited seek or read calls.

**Scarlett XGameRuntime startup.** The trace at `8eb79ce` reaches
`GetFileAttributesW`, `LoadLibraryExW`, and `ReleaseSRWLockExclusive`, then
ends with signal 5. Read-only PE inspection distinguishes three gates:

- The attribute probe checks the `xgameruntime.dll` sibling of the EXE. With
  that sibling absent the next call is literally
  `LoadLibraryExW(L"xgameruntime.dll", NULL, 0x800)` (guest System32),
  through IAT RVA `0x6793540`, return RVA `0x55e2a58`. A present sibling
  plus a separate policy check selects `0xa00` (application directory
  plus System32), still passing a bare name. At this revision the TLS
  adapter can acquire only the explicitly enabled guest entropy module;
  supplying an arbitrary on-disk DLL alone would not make it discoverable.
- A null module result becomes HRESULT `0x89240101` before any export lookup
  or runtime initializer executes. The startup call at RVA `0x5a91bd8`
  passes zero flags and null options to the init helper through `0x55dcf74`;
  a negative result reaches an explicit `INT3` at `0x5a91c21`. That branch
  explains the observed trap without attributing it to a failed runtime
  initializer. An independently failing initializer would also take it.
- If loaded, the DLL must supply `QueryApiImpl`, `XErrorReport`,
  `UninitializeApiImpl`, and at least one of `InitializeApiImpl`,
  `InitializeApiImplEx`, or `InitializeApiImplEx2` (preferred; some
  other call paths require Ex2). The Ex2 call for the observed startup
  route would pass `0x633600002712`, `0x65f400001edd`, flags `2`, and null
  options on the System32 path. Missing required exports also yield
  `0x89240101`, but that check is downstream of the observed miss.

The AMD64 caller supplies the following arguments in register order. This
is a call-site contract, not a declaration of the missing DLL's API:

| Export | Inputs used by Scarlett | Result consumed |
| --- | --- | --- |
| `InitializeApiImplEx2` | `RCX=0x633600002712`, `RDX=0x65f400001edd`, `R8=flags \| 2` on the ordinary path, `R9=options` | Signed 32-bit HRESULT |
| `InitializeApiImplEx` | Same packed `RCX`/`RDX` and `R8` values; no options argument | Signed 32-bit HRESULT |
| `InitializeApiImpl` | `ECX=0x6336`, `EDX=0x2712` (split first packed value) | Signed 32-bit HRESULT |
| `QueryApiImpl` | Pointers to class GUID, interface GUID, and writable object-pointer slot | Signed 32-bit HRESULT |
| `XErrorReport` | HRESULT in `ECX`, pointer to narrow NUL-terminated message in `RDX` | Ignored at inspected init/query error sites |
| `UninitializeApiImpl` | No arguments at the inspected call sites | Ignored at inspected sites |

The ordinary initializer choice at RVAs `0x55e2c9f`–`0x55e2d09` falls back
on **missing exports**, not on a negative result from the selected
initializer. The caller does not access the options struct on this path,
where it passes null. The independent Leonida (`runtime/shims/xgameruntime.cpp`)
and xcl (`crates/xcl/src/hle/xgameruntime/api.rs`) reference implementations
agree on the export roles but disagree about scalar widths in Ex/Ex2 and
whether report/uninitialize return a value. Preserve the full observed
register values at the boundary; the call sites cannot establish which
high bits the real callee reads or its ignored return types. The PC
references do not establish Scarlett's non-null options layout or exact
version negotiation.

The statically reachable success path already needs more than DLL presence.
Startup setup at `0x5a91c40` reaches the initially empty task queue field
at `0x71b90a0`. Via `0x1d109e0` and `0x55dd794`, it queries
`XThreadingImpl` (same class and interface ID,
`073b7dcb-1fcf-4030-94be-e3c9eb623428`) before dispatching slot 29
(`XThreadAssertNotTimeSensitive`) and, on a separate successful query,
slot 12 (`XTaskQueueCreate`, arguments `1, 1, &queue`). Each successful
query's object is released via slot 2. The queue wrapper handles an error;
this evidence does not establish that every queue call must succeed or
that these are the only interfaces needed before device creation. None
of these runtime calls was observed executing in the failing trace.

The GUID uses the Windows mixed-endian in-memory layout. A successful
query must write a real object pointer: the thunk dereferences it with
no null check, then loads a method from the vtable at object offset zero.
Method dispatch passes `this` in `RCX`; slot 29 (`+0xe8`) takes no other
observed arguments and its result is ignored, while slot 12 (`+0x60`)
receives the two modes in `EDX`/`R8D` and writable queue output in `R9`,
returning an HRESULT in `EAX`. Slot 2 (`+0x10`) is called even when the
method returns a failing HRESULT. The query helper maps
`REGDB_E_CLASSNOTREG` (`0x80040154`) to `0x89240107` and reports it, rather
than inventing an object. The cleanup path checked at RVA `0x2212c90`
only acts on a non-null queue: it uses slot 22 (`XTaskQueueTerminate`),
optionally loops on slot 16 (`XTaskQueueDispatch`, port 1, timeout 0,
boolean in `AL`), then uses slot 17 (`XTaskQueueCloseHandle`) and clears
the stored handle. This proves a queue handle has lifecycle obligations;
it does not establish that cleanup or other queue work executes before
device creation. No owned or real runtime was run for this ABI audit.

Public GDK semantics bound an original implementation of that path:

- [Dispatch modes][gdk-queue-mode] are 32-bit: Manual=0, ThreadPool=1,
  SerializedThreadPool=2, Immediate=3. The observed `1, 1` requests
  automatic thread-pool dispatch for both ports, **not** manual dispatch.
  Manual mode requires an explicit pump. [Dispatch][gdk-queue-dispatch]
  can service any mode on its calling thread; timeout zero does not wait,
  and the boolean result is false if nothing was dispatched or the queue
  is terminated.
- [Create][gdk-queue-create] returns an HRESULT and a reference-counted
  opaque queue handle on success (one 64-bit guest output slot here).
  This ownership is independent of the interface reference balanced by
  [COM Release][com-release]. [Close][gdk-queue-close] drops the queue
  reference but does not cancel pending callbacks. [Terminate][gdk-queue-stop]
  drains with canceled callbacks, rejects new submissions with `E_ABORT`
  as each port shuts down, and does not close the handle. The public
  Create page does not specify exact invalid-argument HRESULTs or the
  failure output value.
- [The time-sensitive assertion][gdk-thread-assert] only breaks into an
  attached debugger on a thread marked time-sensitive. With no debugger
  it has no externally visible effect. The interface slot takes `this`
  but no explicit arguments.

A startup-only profile can implement real local initialized state,
interface references, and empty queue ownership with both requested modes
recorded. It must not claim full queue support: without a guest callback
execution path, reject unsupported submission rather than accepting work
and losing it. Non-null init options, additional classes and slots, queue
callbacks/cancellation with pending work, and guest thread-pool execution
remain outside this call-site proof.

[gdk-queue-mode]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xtaskqueue/enums/xtaskqueuedispatchmode
[gdk-queue-dispatch]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xtaskqueue/functions/xtaskqueuedispatch
[gdk-queue-create]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xtaskqueue/functions/xtaskqueuecreate
[gdk-queue-close]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xtaskqueue/functions/xtaskqueueclosehandle
[gdk-queue-stop]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xtaskqueue/functions/xtaskqueueterminate
[gdk-thread-assert]: https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xthread/functions/xthreadassertnottimesensitive
[com-release]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release

**Optional connectivity hint after app registration.** In the live trace
`/tmp/xsxemu-breadcrumbs.M17Lku`, both app registrations are followed by
`QueryPerformanceCounter`, a rejected `QueryApiImpl` call, and `XErrorReport`
with `0x89240107`. The pinned PE calls the optional helper at RVA `0x1cf8f00`
from `0x5a61164`; its wrapper queries class
`37e56907-2f10-41e8-b72f-36edb185331a` and interface
`bf2346b2-39af-4658-b5ea-44713c7e83b3` at `0x55e0e5e`. On success it would
call slot 15 (`XNetworkingGetConnectivityHint`, corroborated by the xcl ABI
table) with an output pointer, then release the interface. Failure returns
from the helper; the trace continues to `WS2_32.dll` ordinal `#115` (IAT RVA
`0x6793ca8`, call RVA `0x5a61172`), the actual stop.

The unexecuted success branch tests byte `+0xc` of the hint. If zero, it
attempts to create an `(Immediate, Immediate)` queue and, if setup succeeds,
registers for connectivity hint changes through slot 16 of the same
interface. Leave this query unsupported rather than inventing a hint or
entering the callback path.

Local input inventory was limited to loose files in the title directory,
its `win11-arm64-reference` tree, the standalone `windlls` tree, and a
bounded filename search in nearby projects, downloads, ISO and VM
folders. The title and its GDK-linked `XCurl.dll` and
`libHttpClient.GDK.dll` are AMD64, but neither companion is the runtime.
The standalone AMD64 UCRT is unrelated; the desktop ARM64 reference
DLLs are not substitutes. No matching loose runtime or GDK installer
was identified. Local Leonida and xcl trees offer reference source, not
verified GameOS binaries. The manifest declares `Microsoft.GameOs`; the
local GameOS XVD header inventory reports version `7901.26100.0.32778`
and encryption, so its filesystem and any runtime inside remain
unverified. No ISO, VM disk, or XVD filesystem was opened for this search.
Once the loader can admit it explicitly, the shortest next input is a
lawfully supplied, matching AMD64 GameOS runtime with its dependencies.
The observed startup gate is not an optional behavior that can be skipped.

`IsProcessorFeaturePresent` uses the ordinary provider's AMD64 baseline and
runtime x86 feature detection, preserving `LastError`. It reports
`PF_FASTFAIL_AVAILABLE` (23) as false: Windows `INT 29h` fast-fail handling is
not implemented by this launcher.
The audited `GetProcAddress` bridge accepts exact mapped image bases and
case-sensitive names for direct PE exports whose RVAs were already admitted
by the image's GuardCF metadata at mapping time. It never adds CFG targets,
resolves forwarders or ordinals, or returns a Rust provider address. Success
preserves `LastError`; an invalid handle gives `ERROR_INVALID_HANDLE` and an
unavailable export gives `ERROR_PROC_NOT_FOUND`.
`LoadLibraryW` can acquire an already mapped guest `dbghelp.dll` or
`rpcrt4.dll` by basename. Unmapped optional modules are logged and return
`NULL` with `ERROR_MOD_NOT_FOUND`; no filesystem search or host loading is
performed. No minidump or UUID exports are synthesized.
`FreeLibrary` is restricted to guest references acquired through the narrowly
admitted startup mappings. Unbridged providers fail before entry unless
`--trace-missing-imports` is enabled,
which treats well-formed unavailable or unbridged slots as callable, not
as data: PE import records don't distinguish the two.
Their writes participate in the same TLS layout and overlap checks as resolved
IAT writes.

The startup binder patches and registers the actual Win64 bridge entries,
not the raw Rust exports. Using the `c800404` frame/GS proof, the thunks
preserve Win64 nonvolatiles across SysV calls, check host GS before Rust, and
check guest GS before returning. Only explicitly audited fixed scalar
signatures are supported, with up to eight argument slots. The guest DWORD at `GS:[0x68]` is
initially zero and authoritative: the adapters transfer it to/from the
ordinary provider's thread-local cell as needed and restore the previous
host value. The guest signal mask remains in place throughout. There are
no nested guest calls, dynamic loading, unwind, or additional guest threads
in this bridge lane.

`cargo test --target x86_64-apple-darwin --test static_tls_lane` runs an
original no-CRT PE that uses the static TLS vector and calls a subset of the
audited providers. The callback uses direct calls and the entry uses both
GuardCF thunks. The fixture checks last-error coherence through detach,
Win64 nonvolatile register sentinels, and six- and eight-argument text
conversions. It does not execute a game or UCRT.
A separate generated PE pair tests named lookup and GuardCF dispatch into
an owned synchronization DLL. Its wake export has no waiters in this
single-thread test model; its sleep export returns `ERROR_TIMEOUT` for a
zero-duration poll and traps on unsupported blocking waits. This is a test
fixture, not a production condition-variable implementation or an API-set
substitution.

The trace thunks are sealed RX before guest entry. GuardCF admits the exact
bound thunk addresses, not their interior, common assembly gate or reporter.
Unused thunks do not report. On the first call, the gate uses the pre-resolved
Rosetta setter and checks host GS before entering Rust. The reporter prints
the original importer, module, name or ordinal, and IAT RVA, then exits the
child with status 1. It never switches back to guest GS, resumes guest code,
runs guest detach, or restores the signal mask on this terminal path.

## Opt-in child: dormant linker guard slots

The initial title probe stopped at its PE32+ load configuration. Read-only
inspection found directory RVA `0x6158d20`, declared and directory size
`0x138`, `GUARD_CF` clear, and zero `GuardFlags`, GFID VA and GFID count.
The qwords at `+0x70` and `+0x78` address distinct read-only, aligned slots,
not the placeholder instructions themselves:

| Load-config field | Slot RVA | Preferred-base target/disassembly |
| --- | --- | --- |
| CFG check `+0x70` | `0x678f650` | `0x1456004b0`: `ret 0` |
| CFG dispatch `+0x78` | `0x678f658` | `0x1456a2090`: `jmp rax` |
| XFG check `+0x118` | `0x678f660` | same `ret 0` target |
| XFG dispatch `+0x120` | `0x678f668` | `0x1456a20b0`: `jmp [rip+disp32]` through the CFG dispatch slot |
| XFG table dispatch `+0x128` | `0x678f670` | same RIP-relative jump target |
| CastGuard `+0x130` | `0x678f678` | zero data qword |

The raw `IMAGE_LOAD_CONFIG_CODE_INTEGRITY` tuple at `+0x94` is `(Flags=1,
Catalog=0, CatalogOffset=0, Reserved=0)`; `CatalogOffset` is the DWORD at
`+0x98`, not the nonzero word at `+0x94`. This is a metadata observation,
not a signature or integrity claim; the PE certificate directory is absent.
The security-cookie field is handled independently. The dormant classifier
requires this exact layout, zero elsewhere in load config, file-backed RX
placeholder instructions and read-only slots, and exact DIR64 fixups for the
expected VA words only in the validated ranges. It does not infer inactivity
from a missing header bit alone or claim that static analysis proved the slots
unreachable.

Only the opt-in static TLS child accepts this profile. After relocation and
before any guest callback, the binder replaces the five callable slots and
seals them read-only; the CastGuard cell stays zero. By default all five are
terminal gates. An attempted call restores and checks host GS, reports the
slot kind and exits with status 86. If `--trusted-offline` is set and a mapped
image already supplies an active CFG policy, only the root executable's
dormant ordinary CFG dispatch slot uses the existing exact RAX dispatcher.
An unapproved address terminates with SIGILL. Dormant CFG check, XFG, and
all dormant DLL slots remain terminal. The slot replacement adds no targets
and never runs the original linker stubs. The tests
use only original PEs and exercise all five calls, rebasing, near-miss metadata
and the existing guarded enforcement fixtures. The title was inspected only.

For trusted input only, `run … --experimental-static-tls --trusted-offline
--no-guest-cfg` disables guest CFG enforcement and prints a warning. Validated
ordinary check and dispatch slots in mapped images, including dormant slots,
are wired to Win64 `ret` and `jmp rax` thunks. The opt-out does not build an
exact target registry or run the image's original linker stubs. It does not
relax image or slot validation, change `GetProcAddress` admission, or enable
XFG or GuardMemcpy. Omit the flag to keep the behavior described above.

## Active CFG with optional EHCONT and volatile metadata

A guarded AMD64 image can additionally carry bounded EH continuation and
volatile metadata. The parser checks preferred VAs, sizes, file backing,
permissions, ordering, disjoint metadata ranges, and the extension's DIR64
fixups. It recognizes an empty EHCONT table only with the flag and both fields
zero. Nonempty EHCONT tables contain strictly ordered code RVAs with the
GuardFlags stride and zero extra bytes. The volatile reader accepts only the
24-byte header with minimum and maximum version 1; its DWORD access RVAs and
`(start RVA, byte length)` ranges must lie in file-backed RX code.

[MSVC `/guard:ehcont`][ehcont] describes EHCONT as a list for Windows context
transfer validation, not indirect call authorization. This child has no
exception dispatch or Windows context restore. Static unwind and context
capture do not resume execution from a guest `CONTEXT`. No EHCONT address is
added to CFG: both active guard slots still enforce exact GFIDs with suppression
and the existing explicitly bound host targets. Do not reuse this admission
policy for a runtime that can restore a guest context without implementing
its continuation checks.

[MSVC `/volatileMetadata`][volatile] describes an optional memory-ordering
optimization for x86/x64 emulators. The runner doesn't consume the annotations
to weaken ordering; it relies on native x86 semantics or Rosetta. The binary
layouts are corroborated by [LLVM's COFF reader][coff] and [LIEF's volatile
metadata reader][lief], respectively. CodeIntegrity fields still block guarded
startup, as do real long-jump tables, process export-suppression opt-in, and
other unsupported guard fields. No signature validation is performed by this
profile.

[ehcont]: https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata
[volatile]: https://learn.microsoft.com/en-us/cpp/build/reference/volatile
[coff]: https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-readobj/COFFDumper.cpp
[lief]: https://lief.re/doc/latest/doxygen/classLIEF_1_1PE_1_1VolatileMetadata.html

## Opt-in child: inactive XFG/CastGuard fields on active CFG images

Read-only inspection of the MSVC companions found the `0x138` load-config
layout with active CFG but no XFG or CastGuard flags. The three XFG fields
address distinct aligned, file-backed, read-only qwords. The check target
aliases the CFG check's `ret 0`; both dispatch targets alias the same
`jmp [rip+disp32]` through the active CFG dispatch slot, whose linker default
is `jmp rax`. The CastGuard field instead addresses an aligned zero qword in
non-executable writable data (either file-backed or in the section's zero-fill
tail). This last field is a failure-mode data cell, not a fourth function slot.

The opt-in parser recognizes only those exact forms, including section
permissions, disjointness from guard metadata, and exact DIR64 fixups on
validated VAs. The CastGuard cell cannot be a relocation, cookie, IAT or TLS
index destination. It remains null at startup and retains its section's data
permissions; this does not implement CastGuard or prove what guest code may
write later. The three XFG qwords get the same read-only, terminal assembly
gates used by the dormant profile. They restore host GS and exit the child
with status 86; they do not resume the guest or fall back to CFG dispatch.
The active CFG slots retain the existing exact GFID policy. Neither this
classification nor installing a gate adds a policy target.

The non-opt-in launcher still rejects these fields. CodeIntegrity metadata
remains an independent pre-entry blocker for guarded startup. Other
unsupported guard metadata is not normalized. Only owned fixtures are
executed for this profile.

## Offline one-hop CFG linker slots

Read-only inspection of `libHttpClient.GDK.dll` found active CFG (319 GFIDs
with 5-byte entries), but no active XFG, CastGuard, or GuardMemcpy flags. Its
`0x140` load config uses a different linker form: the CFG check and XFG check
slots share a veneer to `ret 0`, the CFG dispatch slot uses a veneer to
`jmp rax`, and the XFG dispatch and table-dispatch slots share a veneer to
`jmp [rip+disp32]` through the CFG dispatch slot. Each veneer is exactly one
direct `jmp rel32`; both instructions are file-backed in same-image RX
sections. The CastGuard cell is a file-backed read-only zero qword in
`.00cfg`, not the writable data cell described above.

`xsxemu inspect FILE --offline-guard-slots` checks this exact one-hop form on
an independently trusted file. It checks slot disjointness, exact fixups on
the validated VA words, absence of fixups over either instruction span or the
null cell, and existing CFG table rules. It does not follow additional jumps
or add any CFG targets. The existing child still enforces active CFG and
routes calls through its admitted, flag-clear XFG slots to terminal gates;
this offline check does not admit the new form to either startup lane.

GuardMemcpy is separate: the DLL's `+0x138` field points to a slot whose code
is a RIP-relative indirect jump through the ordinary `VCRUNTIME140.dll`
`memcpy` import, not a CFG or XFG target. The offline guard-slot check reports
only whether that field and CodeIntegrity are nonzero; it does not validate
the GuardMemcpy slot/import, interpret CodeIntegrity, or read or verify its
embedded certificate. The existing catalog inspection and signing admission
rules are unchanged. No title or supplied DLL code was executed.

## Opt-in child: address-taken IAT validation

The static TLS child validates an address-taken IAT table using the GFID
stride with zero reserved bytes and strictly ordered IAT slot RVAs. Each slot
must resolve through static binding to an executable PE export that is
independently allowed by the existing exact CFG policy. The table cannot
unsuppress exports or authorize host, dynamic, unresolved, or traced targets.
The validated metadata and slots are sealed; no target is added to CFG. The
default startup and offline catalog inspection have no such binding checks
and continue to reject nonempty address-taken IAT fields.

## Offline CodeIntegrity and embedded certificate envelopes

For an independently trusted file, `xsxemu inspect FILE --offline-catalog-metadata`
checks and prints only the signing-metadata envelopes. It requires the guarded
load-config profile (including the same checks on any inactive XFG/CastGuard
fields as in the child), refuses `FORCE_INTEGRITY`, and recognizes exactly
`(Flags=1, Catalog=0, CatalogOffset=nonzero, Reserved=0)` with no relocation
covering the tuple. `CatalogOffset` is opaque: it is not followed as a PE file
offset, RVA or external catalog reference. No catalog is opened.

[PE directory #4][pe-format] separately supplies a file offset and size for an
embedded certificate table. This profile accepts only a single nonempty
`WIN_CERTIFICATE` with revision `0x0200` and type `0x0002`, whose length matches
the aligned directory size. The table must start at the aligned end of the
headers/section data (zero alignment padding) and end exactly at EOF. The
payload is not decoded. Read-only inspection of `msvcp140.dll` found the opaque
catalog offset `0xc0ce0` and, separately, the embedded table at file offset
`0x87800`, size `0x27f0`. Nothing from either payload is used to admit targets.
Offline inspection refuses the address-taken IAT table in `vcruntime140.dll`
because it cannot validate the bound slots. The inconsistent export suppression
stride in `msvcp140_codecvt_ids.dll` still fails the guard profile.

The [Windows SDK][ci-sdk] identifies these as CodeIntegrity information fields;
it does not establish Xbox catalog policy for this tuple. Microsoft's
[`/INTEGRITYCHECK`][integritycheck] explicitly requires load-time signature
checking; all run profiles reject `FORCE_INTEGRITY`. A clear bit is not
proof of trust or of the catalog's purpose. The inspection option reports
**signature/catalog not verified** and does not affect startup.

[pe-format]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
[ci-sdk]: https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
[integritycheck]: https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check

## Parse-only: instrumented linker slots without `GUARD_CF`

Read-only inspection of `Bink2Scarlett.dll` found an exact `0x138` PE32+
load config, clear `GUARD_CF`, and only `CF_INSTRUMENTED` in `GuardFlags`.
There are no GFID, address-taken IAT, long-jump or EH continuation tables
and no GuardMemcpy field. The `inspect` classifier checks five linker
slots and their exact DIR64s, plus an aligned null CastGuard cell entirely
in non-executable RW zero-fill. Relocations and the declared cookie, IAT
and TLS index destinations must not overlap the cell.

The classifier matches the descriptive CodeIntegrity tuple without following
its offset and checks the 24-byte volatile layout and both annotation tables.
The classifier recognizes the exact word `0x80028002`. [LIEF's decoder][lief-volatile]
prints the two halves as minimum and maximum versions masked with `0x7fff`,
but that does not establish the semantics of either high bit or rule out
further requirements. Both default execution profiles still reject the image.

A separate TLS-child-only form, tested with owned fixtures, requires all-zero
CodeIntegrity, no security directory, and the already-supported volatile
version `0x00010001`. It retains the exact slot, table and relocation checks.
It replaces all five callable slots with terminal gates (exit 86) and leaves
the null CastGuard cell RW and excluded from loader writes. It does not admit
Bink's version or CodeIntegrity tuple, change signature admission, or add CFG
targets.

[lief-volatile]: https://github.com/lief-project/LIEF/blob/main/src/PE/LoadConfigurations/VolatileMetadata.cpp

## Trusted offline diagnostic child (explicit opt-in)

For independently trusted local images only, use `run FILE --experimental-static-tls
--trusted-offline`. The second flag is unavailable without the disposable
Rosetta child. Use `audit FILE --startup-profile trusted-offline-static-tls-child`
with the same DLL roots and provider options to report file-only checks without
running the guest. Both commands warn per structurally accepted image: neither
signature nor catalog is verified; Xbox policy is not evaluated. This is not a
sandbox, authentication, or a Windows/Xbox trust decision.

In the supported active CFG and instrumented dormant layouts, the child treats
bounded CodeIntegrity fields as opaque. It does not follow the catalog offset
or parse an embedded certificate, and the separate inspection command remains
unchanged. Where those layouts carry a volatile metadata pointer, the child
still checks bounds, separation, and relocation but does not interpret its
contents or follow annotation tables. It does not perform the optimizations
those hints describe. Normal startup and `--experimental-static-tls` without
`--trusted-offline` retain their old checks. `FORCE_INTEGRITY` remains fatal;
active CFG and address-taken IAT enforcement are unchanged and unsupported
dormant calls still terminate. No host policy or PE file is modified.

The diagnostic child also recognizes the `0x140` GuardMemcpy layouts with
instrumented dormant direct guard stubs or active CFG and one-hop companion
stubs. It validates the GuardMemcpy cell's bounds, permissions, separation,
and exact relocations, seals the cell, and installs an exit-86 diagnostic if
called. It does not follow the original pointer or report a successful copy.
Unknown guard requirements and other load-config extensions are still refused.

### Offline Winsock initialization

With `--rust-providers`, the trusted offline child accepts only a direct
root-image ordinal import `WS2_32.dll!#115` (case-insensitive DLL basename).
The private IAT bridge does not match name imports, DLL importers, API-set
aliases, or PE forwarders. The local Windows 11 ARM64X `ws2_32.dll` reference
(SHA-256 `e1266872f796f68b4be9c20640ca940a7a96e1ba98c741d472ae305fccf87ca9`)
exports ordinal 115 as `WSAStartup` in both its native and hybrid export
views. Read-only Scarlett inspection confirms IAT RVA `0x6793ca8` and a call
at RVA `0x5a61172` passing `CX=0x0002` (Winsock 2.0), `RDX=&stack_buffer`,
and testing the result in `EAX`.

The Win64 signature is `int WSAStartup(WORD, WSADATA *)`. The shim negotiates
versions through 2.2 and fills a 408-byte Win64 `WSADATA` on success, including
both version words, NUL-terminated offline description/status, and a null
vendor pointer. Errors are returned directly; the output and TEB last-error
are unchanged on failure. Each successful call is counted for the lifetime
of the child. This is initialization bookkeeping only: there is no host
networking, name resolution, socket API or `WSACleanup` shim. The owned
Rosetta PE checks the ordinal call, output layout, error returns, repeated
negotiations, and unchanged TEB last-error.

## Controlled execution plan

1. Separate loading from execution. Reuse PE static TLS metadata but check
   budgets, ranges, write permissions, alignment and callback RVAs before
   entry. After rebasing/binding, copy each module's relocated template into
   an aligned per-thread block and append zero-fill. Assign stable process
   indices and write the DWORD at each `AddressOfIndex`. Build a vector of
   64-bit block pointers and put it at TEB `+0x58`; TEB self is `+0x30`.
   Initialize guest stack/last-error/other TEB fields only as supported;
   keep Win32 dynamic TLS/FLS separate and keep provider state coherent
   with any TEB fields exposed to guest code.
2. Decode/lift all executed guest code in a controlled engine; keep GS base
   in guest CPU/thread state, never in host GS. Apply it to the decoded
   memory operand's computed effective offset (after address-size wrap and
   RIP-relative effective-address calculation); check range, width and
   access against guest mappings. Cover register/SIB and displacement forms,
   `moffs`, address-size overrides, loads/stores, and RMW/atomic semantics.
   Decode string source overrides and implicit operands, or reject them
   explicitly until modeled; `LEA` does not apply a segment base. Define
   or reject guest segment/base mutations, unsupported instructions and
   non-executable targets rather than letting them escape to Rosetta.
   Invalidate decoded code on permitted executable writes or reject them.
   Byte-pattern search/rewrite cannot distinguish instruction boundaries
   from immediate/data bytes, misses valid GS forms, and can affect branch
   targets and unwind metadata.
3. Route imports, indirect calls, TLS callbacks and guest re-entry through
   explicit ABI boundaries, preserving guest thread identity, registers and
   CFG checks. Initially use an original no-CRT AMD64 PE fixture (compiler
   TLS access, nonzero index, forced relocation, zero-fill and isolation
   between guest threads). Add original TLS callbacks and DLL attach order
   only after data works; test re-entry, malformed metadata, permission
   faults and unsupported opcodes. No game or UCRT execution was needed
   for this report.
