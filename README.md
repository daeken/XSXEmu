# XSXEmu

An experimental Rust loader and compatibility runtime for Xbox Series X|S AMD64 PE images. It does not use Wine. Inspection, static linking and non-executable mapping are portable. The current execution backend maps Win64 code in an x86-64 Mach-O process, using Rosetta on Apple Silicon. This is a loader bring-up, not yet a game runner or a sandbox.

## Usage

```sh
cargo run --offline -- inspect /path/to/title.exe --symbols
cargo run --offline -- map /path/to/title.exe --base 0x150000000
cargo run --offline -- audit /path/to/title.exe --dll-dir /path/to/app-local-dlls

cargo build --offline --target x86_64-apple-darwin
./target/x86_64-apple-darwin/debug/xsxemu run /path/to/trusted-fixture.exe --dll-dir /path/to/dlls
```

- `inspect` reports checked PE metadata, including static imports, exports, relocations, static TLS and the load-config cookie.
- `map` materializes headers and sections, zero-fills virtual tails and applies DIR64 relocations. It does not bind imports or execute anything.
- `audit` follows static imports and used export forwarders across user-supplied DLLs. It reports missing providers and symbols and exits unsuccessfully if any binding is unresolved. Add `--symbols` to see individual unresolved slots. Lookup uses explicit `--dll-dir` roots and the EXE's directory; it does not search the host system or download DLLs.
- `run` is for your own trusted images only. By default it fails before calling guest code if the static graph is incomplete. It always refuses startup features outside the supported profile. It maps and binds resolved PE dependencies, seals page permissions (never writable and executable), calls supported DLL process-attach entry points in dependency order, calls the EXE entry, and detaches DLLs in reverse order if control returns. It runs in the host process with your privileges. The guest is not isolated; faults or raw system calls can affect the host process or machine.

For trusted loader bring-up, `run <image.exe> --trace-missing-imports` binds static IAT slots whose provider or export is absent to diagnostic thunks. Unused slots do not prevent startup. The first call to a thunk reports the original importer path, module, name or ordinal, and IAT RVA on stderr, then exits with status 1 without returning to the guest. This is for function-call diagnostics, not missing data imports. Unresolved descriptors without slots, rejected files, malformed bindings, and startup features outside the selected profile still prevent execution. `audit` remains strict.

On Apple Silicon under Rosetta, `run <trusted-fixture.exe> --experimental-static-tls` starts an isolated, time-bounded child for the initial thread's static TLS. Adding `--rust-providers` in this lane permits only the 30 audited Win32 provider signatures observed in the UCRT fixture trace. Other providers are refused unless tracing is enabled, in which case their slots also get diagnostic thunks. Combining `--experimental-static-tls` and `--trace-missing-imports` opts into treating every traced slot as callable; PE import metadata does not identify data imports, and unresolved data imports are not supported. If called, the thunk restores and checks host GS before reporting, then exits the child without guest resume or detach. This is not a sandbox; see [the Rosetta ABI notes](docs/rosetta-teb.md#opt-in-child-audited-provider-bridges).

App-local MSVC CRT DLLs and an AMD64 `ucrtbase.dll` can be supplied as ordinary PE libraries. Nothing in this project redistributes them. Resolving an import to a CRT export does **not** mean its dependencies or startup work yet.

```sh
cargo run --offline -- audit /path/to/title.exe --dll-dir /path/to/x64-dlls \
  --api-set /path/to/apisetschema.dll --rust-providers --symbols
```

`--api-set` loads only the schema data (an ARM64 schema is fine). Lookups use exact contracts, respecting importer-specific aliases and then a default host. A desktop schema does not describe all Xbox contracts. `--rust-providers` enables the exact registered KernelBase/Kernel32 and ntdll APIs and selected legacy API-set aliases. Missing system APIs stay unresolved: this mode does not load on-disk replacements for these system providers. Diagnostics name the routed provider, if any; `--symbols` also shows the original module and symbol.

The bounded AMD64 GuardCF profile installs enforcing check and dispatch thunks before entry. Targets are limited to exact validated entries from guarded images, statically bound Rust functions, and the exact entry addresses of any bound missing-import traps; suppressed entries are denied. Other mitigation configurations can still be rejected.

With `--rust-providers`, `LoadLibraryExW` and `FreeLibrary` can acquire and release references to startup-mapped guest DLLs on the startup thread. `LoadLibraryExW` takes a bare case-insensitive DLL name (default `.dll` extension) and a null file handle. Flags `0` select the first mapped DLL with that name; `LOAD_LIBRARY_SEARCH_SYSTEM32` (`0x800`) limits matches to DLLs already registered as direct children of guest `C:\Windows\System32`. Paths and other flags are unsupported. Neither mode opens files, uses the static DLL roots as a dynamic search path, redirects API-set names, nor turns Rust providers into `HMODULE`s. A missing match returns `NULL` and `ERROR_MOD_NOT_FOUND`. A successful acquisition returns the actual PE base. `FreeLibrary` releases an acquired reference, not startup's ownership; images remain mapped through process detach. Borrowed `GetModuleHandleW` handles do not acquire a reference.

A Windows TEB, full exception dispatch, dynamic mapping of new libraries, and Xbox graphics are still unimplemented. Static AMD64 unwind primitives are available but do not provide exception dispatch. Don't substitute desktop D3D12 for `d3d12_xs.dll`: the Xbox device, memory and layout contracts need an explicit adapter.

## Verification

```sh
cargo test --offline
cargo test --offline --target x86_64-apple-darwin  # includes the original missing-import and GuardCF fixtures
# Requires LLVM-MinGW (or compatible Clang/LLD), an x86-64 Apple Rust target,
# and Rosetta if running on Apple Silicon. Builds original PE fixtures in a temp directory.
PE_CC=/path/to/x86_64-w64-mingw32-clang sh tools/smoke.sh
```

The smoke test checks that missing providers fail, then runs an EXE that relocates a DLL, calls its named and ordinal exports, and returns 42 only after successful DLL process attach. A separate fixture verifies that static TLS is reported and refused before entry until a guest TEB is available. The last fixture links against a legacy Windows API-set contract and round-trips last-error state through the Rust provider without a system DLL on disk.

### Local AMD64 UCRT fixture (static by default)

```sh
rustup target add x86_64-pc-windows-gnullvm
sh tools/ucrt-fixture.sh
```

The script builds an original freestanding Rust `no_std` PE using `rustc` and its bundled `rust-lld` (tested with Rust 1.99.1). It uses no Windows SDK, C compiler, CRT startup objects, or proprietary import libraries. The generated import library contains only references to `ucrtbase.dll!malloc` and `ucrtbase.dll!free`. The linker omits the build timestamp; the script prints the EXE hash to check reproducibility with the same toolchain and removes the temp build on exit.

The script requires `/Volumes/External2/windlls/ucrtbase.dll` with SHA-256 `7ee229626b22799faa28cd7c22d4ff2ad0603c17e5f5ee9086fa7cf6483331fb`. It symlinks that file into an otherwise empty DLL root and uses Rust Win32 providers; sibling Windows DLLs are not searched. The default schema is `/Volumes/External2/gta6/win11-arm64-reference/apisetschema.dll` (only its API-set data is read); set `UCRT_API_SET` to an absolute path to use another local schema. Neither DLL is copied or redistributed.

The default invocation builds a native-host auditor, inspects the EXE, and runs `audit --dll-dir <isolated-root> --api-set <schema> --rust-providers --symbols`. With the default schema, both EXE imports bind, but 18 of the UCRT's 134 IAT slots remain unresolved (for example `HeapCompact` and `RaiseException`): **118/136 resolved, 116 Rust, 0 descriptor failures**. The underlying audit exits nonzero; the script treats the confirmed unresolved-import report as a successful diagnostic. Provider or schema changes can change those counts. No guest code runs in the default mode.

**Verified opt-in:** use an x86-64 macOS Rust target (and Rosetta on Apple Silicon):

```sh
rustup target add x86_64-apple-darwin
sh tools/ucrt-fixture.sh --run
```

This audits first, then invokes `run <fixture.exe> --dll-dir <isolated-root> --api-set <schema> --rust-providers --trace-missing-imports`. The static import makes the loader map UCRT and call its `DLL_PROCESS_ATTACH` before the EXE entry. The EXE allocates four bytes with `malloc`, writes and reads a marker, calls `free`, and returns 42 on success (1 for a null allocation, 2 for a marker mismatch). Startup or a called missing import can stop the run before a guest result. A static audit does not establish that attach, the heap calls, or detach work. Execution is not sandboxed; this opt-in is for the trusted fixture and pinned local DLL only, never a game title.

The pinned UCRT's first attach-time dynamic probe calls `LoadLibraryExW(L"api-ms-win-core-synch-l1-2-0", NULL, 0x800)` from RVA `0x45fcb` (return RVA `0x45fd1`, IAT RVA `0xb62a8`). The UCRT helper starts at RVA `0x45f28` and uses the load to try optional exports: it caches misses and moves on to the next candidate. The isolated guest has no mapped match; a real module-not-found result lets UCRT continue without fabricating a handle. On Rosetta the fixture completes process attach and the `malloc`/`free` round trip and returns 42 without calling any unresolved static import.
