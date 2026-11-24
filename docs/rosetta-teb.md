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
import-free AMD64 PE32+ EXE in memory from original assembly, not from an
external image. It uses `Pe::materialize_into` at a nonpreferred address,
checks all six DIR64 relocations, gives the EXE's TLS module index zero via
`static_tls::Plan`, and seals the mapping with `GuestMemory`. The planner
snapshots a relocated pointer and a nonzero seed and adds eight zero bytes
in a 16-byte-aligned block; the PE's initially nonzero index DWORD is patched
to zero. The test TEB points to the planner's vector at `GS:[0x58]`.

A single assembly window calls the mapped PE's TLS callback (process attach),
EXE entry, then the same callback (process detach). Each call reads the image's
index DWORD and follows `GS:[0x58]` to the block. Each checks the relocated
pointer and the previous phase's values before mutating both the initialized
state and the zero-fill word. The callback also checks the mapped image base,
reason, and the fixture's null reserved argument. On macOS 27.0.1 (26A434)
under Rosetta, entry returned 42 and the host read final TLS state
`0x33300303` with scratch `0xc3`. The boundary checked the restored host
`GS:[0]` and `GS:[0x30]` before returning to Rust; the child then restored and
verified the original signal mask. The runner requires both a success record
and exit status zero.

Only the private setter, assembly boundary, and mapped PE execute while guest
GS is active. The child shares the preceding signal probe's mask and default
fault dispositions, with no handlers or recovery added for the PE. Guest
invariant failures and GS mismatches trap; faults, unexpected exits, and
timeouts fail the probe. The detach call is an explicit normal-return fixture
step, not an emulation of process teardown. No imports or providers, extra
threads, UCRT or title code, or OS security changes are involved. Production
startup still rejects static TLS; this is not an execution option for other
images or a security boundary.

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
