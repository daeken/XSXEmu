# Prioritizing reachable compute translation

The read-only inventory now accepts a **local extracted native FSSM directory**. It does not extract anything or open the archive/TOC in this mode. The separately compiled pipeline library and DLL-embedded shaders are outside this census. There are no emitted per-file records, shader names, offsets, operands, disassembly or bytes.

```sh
M=tools/shader-inventory/Cargo.toml
L=/path/to/trusted/AMDGPU-enabled/LLVM-21/libLLVM.dylib
cargo run --release --locked --manifest-path "$M" -- \
  --reachable-compute "$L" gfx1013 /path/to/local/native
cargo run --release --locked --manifest-path "$M" -- \
  --reachable-compute "$L" gfx1030 /path/to/local/native
```

The directory reader considers regular `.fssm` files only, checks v0x101, and uses the observed internal compute stage byte (6 at `+0x100`, from Leonida's behavioural findings). Bounds, final word and compute metadata are checked as in the [linear census](shader-archive.md#compute-census-explicit-llvm-reference-targets). The LLVM profile is explicit on each invocation and wave width comes from FSSM; neither CPU is treated as an Xbox dialect. AMD's GFX10 SOPP definition and LLVM's AMDGPU decoder are the branch encoding references; the XCL and Leonida findings guided profile selection and the distinction between skipped data and reachable code. No upstream implementation was copied.

The shared Rust CFG walker starts at the established code entry, visits both successors of supported SCC/VCC/EXEC conditional branches, and verifies signed dword-relative offsets, widths and overlap with other reachable instructions. It stops at supported `s_endpgm` exits and reports the first blocker per failed graph (LLVM reject, unmodeled PC effect, malformed edge, or no exit). It does not guess targets for indirect transfers, special exits, calls, traps or debug branches. Histograms count *only* completely walked graphs with at least one exit. This is static reachability under the model, not proof that a branch predicate is feasible, the program terminates, or the backend can run it. Non-control instructions' semantics are not validated by the walk.

## Local count-only results

LLVM **21.1.6**; **26,698** native inputs, **2,689** compute, no read/header/span/observed metadata failures. The compute count matches the earlier archive census; no per-file identity claim is made by this mode.

| | gfx1013 | gfx1030 |
|---|---:|---:|
| Complete reachable graphs | 2,676 | 1,206 |
| Static instructions in complete graphs | 14,992,363 | 850,615 |
| Complete graphs with multiple exit nodes | 660 | 202 |
| Complete graphs with a nonforward edge | 1,974 | 557 |
| Complete graphs that skip at least one dword | 1,548 | 410 |
| Complete graphs whose linear walk rejects a skipped word | 1,004 | 77 |
| Complete graphs whose linear walk rejects an extension word | 0 | 0 |
| First blocker: LLVM instruction reject | 0 | 1,471 |
| First blocker: unmodeled `s_setpc_b64` | 13 | 12 |

The earlier archive linear `gfx1013` walk completed 1,680 spans. The paired counters here compare each *complete* graph to a linear walk of the same extracted payload, locating the first linear reject either outside the graph or inside a reachable instruction's extension. They exclude graphs that already stopped at reachable blockers. Skipped words are not all necessarily data; the paired comparison shows precisely which linear rejects do not block the reachable graph. The `gfx1030` run is an independent reference, not a fallback and not a candidate to merge into the `gfx1013` report.

## What to translate first

Filter complete graphs to 1D wave32 groups of at most 32 threads, with forward-only edges, no LDS, no scratch or group-size input in observed metadata, and no image, atomic, barrier, flat/global, explicit scratch, lane transfer/swizzle or SDWA indicators. This is a shortlist, not a support claim. On `gfx1013` it leaves **18** payloads. Of these, **16** contain vector buffers and **16** have `s_load_dwordx4` and `s_waitcnt`; **12** have `s_cbranch_execz`, **10** of them also have `v_cmpx_gt_u32_e32`. Only **one** shortlisted graph contains an SCC branch, so SCC lowering is deferred behind EXEC plus memory. **Two** `1×1×1` payloads have a single raw store site under the mnemonic screen; the smaller graph has **10** nodes. No shader was run to establish these counts.

The first owned step implements the comparison/branch pair rather than adding arbitrary ALU opcodes. `exec_fixture.s` is an original GFX10.3 wave32 fixture, checked with LLVM assembly. Its typed Rust model intersects EXEC with an unsigned inline-constant comparison, then takes `s_cbranch_execz` on an empty mask. Generated MSL keeps even guest-inactive lanes on the uniform scalar path; `simd_any` decides the branch, only guest-active lanes write payload values, and the two distinct exits have test-only markers. Apple M4 API/GPU validation matched **165/165 CPU/Metal words** across five cases, including strict boundary comparison, sparse survivors, and EXEC empty initially or emptied by compare. The CPU suite also tests a surviving bit-31 lane. This subset does not model EXEC restore, SCC/VCC branches, wave64, partial host SIMD groups, loops, or guest descriptor bindings.

Next, combine this EXEC path with the [owned descriptor/store probe](../tools/shader-inventory/BUFFER-PROBE.md) while validating the actual reachable operands and user-data contract for the smallest raw-store slice. Keep waits and memory ordering explicit; neither the counts nor the synthetic buffer ABI licenses running a retail payload. Do not generalize dynamic PC from the 13 stopped graphs without proving targets independently.
