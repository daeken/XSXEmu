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
- `run` is for your own trusted images only. It fails before calling guest code if the static graph is incomplete or the image requests a startup feature outside the supported profile. It maps and binds resolved PE dependencies, seals page permissions (never writable and executable), calls supported DLL process-attach entry points in dependency order, calls the EXE entry, and detaches DLLs in reverse order if control returns. It runs in the host process with your privileges. The guest is not isolated; faults or raw system calls can affect the host process or machine.

App-local MSVC CRT DLLs and an AMD64 `ucrtbase.dll` can be supplied as ordinary PE libraries. Nothing in this project redistributes them. Resolving an import to a CRT export does **not** mean its dependencies or startup work yet.

```sh
cargo run --offline -- audit /path/to/title.exe --dll-dir /path/to/x64-dlls \
  --api-set /path/to/apisetschema.dll --rust-providers --symbols
```

`--api-set` loads only the schema data (an ARM64 schema is fine). Lookups use exact contracts, respecting importer-specific aliases and then a default host. A desktop schema does not describe all Xbox contracts. `--rust-providers` enables the exact registered KernelBase/Kernel32 and ntdll APIs and selected legacy API-set aliases. Missing system APIs stay unresolved: this mode does not load on-disk replacements for these system providers. Diagnostics name the routed provider, if any; `--symbols` also shows the original module and symbol.

A real Windows TEB, exception handling/unwind, GuardCF startup support, dynamic library loading, and Xbox graphics are still unimplemented. Don't substitute desktop D3D12 for `d3d12_xs.dll`: the Xbox device, memory and layout contracts need an explicit adapter.

## Verification

```sh
cargo test --offline
# Requires LLVM-MinGW (or compatible Clang/LLD), an x86-64 Apple Rust target,
# and Rosetta if running on Apple Silicon. Builds original PE fixtures in a temp directory.
PE_CC=/path/to/x86_64-w64-mingw32-clang sh tools/smoke.sh
```

The smoke test checks that missing providers fail, then runs an EXE that relocates a DLL, calls its named and ordinal exports, and returns 42 only after successful DLL process attach. A separate fixture verifies that static TLS is reported and refused before entry until a guest TEB is available. The last fixture links against a legacy Windows API-set contract and round-trips last-error state through the Rust provider without a system DLL on disk.
