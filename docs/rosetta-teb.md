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
These boundaries illustrate work the probe does not attempt. The fixture
proves only one synchronous leaf interval on one worker. It does
not prove imports calling host Rust/libc, host-to-guest callbacks, nesting,
thread attach/exit, signal/Mach exception delivery or return, unwind,
pthread cancellation, profiling/sampling, or interrupted install/restore.
Do not promote the private hook until those transitions and restoration
are proven, including interruption at each boundary. Masking signals is
not proof of correctness for synchronous traps or Mach exceptions.

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
