# Shader archive inventory and Metal bring-up

This work is independent of PE boot. The archive was opened read-only. No title code or retail shader was executed, and no assets were written out. The tool prints aggregates only.

## What is readable

The local file is **411,695,600 bytes (`0x1889f9f0`)**. A read-only check reproduced these fixed-prefix fields:

| Offset | Type | Observed | Interpretation |
|---|---|---|---|
| `+0x00` | 4 bytes | `9FPR` | RPF9 magic (`0x52504639` as LE u32) |
| `+0x04` | LE u32 | `0x8640` | Data start, following Leonida's `docs/rpf.md`; public `SGD5` magic is visible later at `0x9000` |
| `+0x08` | LE u32 | `0x8620` | Unknown; not treated as a count, a byte length, or a flag |
| `+0x0c` | LE u32 | `0xa0` | Candidate EOF trailer size per Leonida's cross-archive survey; contents and purpose unknown |

`--header-only` reads exactly the 16-byte prefix and uses the file length to check the data start (`0x10 <= start < EOF`). The full scanner additionally requires an aligned trailer *length* (multiple of 16), checked subtraction, and a nonempty data interval. Here the resulting half-open scan window is `[0x8640, 0x1889f950)`, leaving `[0x10, 0x8640)` and `[0x1889f950, 0x1889f9f0)` opaque. The first span may include other header fields or padding as well as TOC bytes; its boundaries are not an exact TOC extent. Leonida's survey was inconclusive about the last stored file in `shaders.rpf`. Our pipeline-library walk ends five bytes before the proposed trailer; this is consistent with the convention, not independent proof of the exact last member boundary. One `9FPR` match, at offset zero, was observed at 2 KiB strides; that does not exclude unaligned matches.

### Record scans are not TOC readers

- **XCL (`91f9a5e`):** README shows `xcl rpf --extract`; `crates/xcl/src/main.rs` dispatches it to `rpf::run`. `crates/xcl/src/rpf.rs` checks root magic, then calls `gpu::pack::scan(&data, 0x40)`, the same heuristic used by `xcl shaders` for RPF9. It scans for an inline length byte, identifier (allowing `:` after the first character), NUL, and flag byte; the four LE u32s that follow are two matching stored lengths with an opaque word between them, then an inflated length. The scanner bounds the stored extent within the file, with `0 < stored < 16 MiB` and `0 < inflated < 64 MiB`; the separate inflater enforces the declared output size for raw DEFLATE. Listing or extracting an inline name does not recover a TOC entry or its original path. The `0x40` scan start is not a TOC schema or a data offset read from the header.
- **XCL structural probe:** `crates/xcl/src/rpf_probe.rs` is used explicitly with `--probe`, by default above 1 GiB unless `--full`, or as a summary after a scan finds no inline records. It checks aligned magic and prints the three words without interpreting them. Its equality comparison at `+0x40..+0x60` needs at least two candidates to make a comparison. Neither equality nor inequality establishes encryption (and neither gives a TOC extent); the local aligned check has only one candidate. XCL's `HANDOFF.md` describes a TOC it could not read, not a decoder.
- **Earlier plaintext variants:** The [GTAMods RPF archive notes](https://gtamods.com/wiki/RPF_archive#RPF_Version_2) document RPF2's zero encryption flag and its own TOC layout at `0x800`. [CodeWalker's GTA V reader](https://github.com/dexyfex/CodeWalker/blob/master/CodeWalker.Core/GameFiles/RpfFile.cs) checks for RPF7 and recognizes `NONE` and `OPEN` as plaintext TOC/name-table modes. Neither layout or flag applies to an RPF9 archive merely because it shares the RPF name.
- **Actual RPF9 TOC:** Leonida's `docs/rpf.md` describes encrypted/packed metadata and explicitly leaves it undecoded; its ImHex pattern, carve/name tools and `rpf9-explorer`-backed recovery tool do not provide original TOC entries. [PercyStar](https://github.com/rpatty-dev/PercyStar) likewise documents scanning and skipping encrypted data, not TOC decryption. No documented or supplied authorized RPF9 TOC decoder or verified plaintext entry schema was identified in the sources checked. No claim is made about the cipher, packing, entry counts, or correspondence between scanned records and TOC entries. A checked TOC parser needs a verified plaintext schema/fixture or an authorized decoder; this work implements only the public prefix and bounds. No reference implementation code was copied.

The local reader validates raw DEFLATE records with the observed `_Wrapped` marker, two matching stored-length fields and an exact inflated length. In all accepted records the stored span includes 12 opaque bytes after the DEFLATE stream. Within the DXBC envelope the nominal DXIL bitcode position points to `NOBC`, **not desktop LLVM/DXIL bitcode**. The DXIL-labelled chunk also contains an XDAT directory. The reader checks each tag `0x0d` extent and its `XBCH` v3 zlib stream for exact consumption/length and `FSSM` v0x101 magic/version. It preserves the number of payloads per envelope, without claiming to parse the FSSM code or metadata. All stage/model values come from the DXIL-shaped program header, not the plaintext suffix.

| Stage (all SM 6.6) | DXBC envelopes | XBCH / FSSM payloads |
|---|---:|---:|
| Pixel | 12,101 | 12,101 |
| Mesh | 9,282 | 9,282 |
| Compute | 2,689 | 2,689 |
| Vertex | 2,236 | 2,431 |
| Geometry | 195 | 195 |
| **Total** | **26,503** | **26,698** |

Zero `_Wrapped` candidates were rejected. The 195 extra native payloads are in vertex-labelled envelopes; this count does not determine their individual ABI or stage. The observed DXBC chunk set is `SFI0 ISG1 OSG1 PSV0 HASH DXIL PRIV`. No claim that this is an exhaustive RPF listing.

A separate library at `0x10579000` (whose first inflated block starts with `PS 00 09` magic) comprises 4,205 zlib streams (275,540,780 inflated bytes, five bytes before the proposed archive trailer after stream end). The header declares 25,471 graphics pipelines, 2,693 compute pipelines, 54,576 blobs and 21,522 programs. The reader verifies the aggregate section arithmetic and actual stream boundaries and sizes; it does **not** walk each pipeline/blob/program table entry. Leonida's `docs/shader_library.md` independently reports that the library contains separately compiled RDNA programs linked by digest, not byte-identical duplicates of the source FSSM programs; inventorying the two forms does not prove interchangeability. Its library-stage counts are 9,996 PS, 7,498 MS, 2,684 CS, 1,343 VS and one unidentified program (reported, not re-measured here).

The Rust tool is a bounded layout-specific scanner, not a general unpacker. It caps archive size at 512 MiB, individual inflated blobs at 8 MiB, and library streams at 64 KiB. It buffers the data region but does not concatenate the library; the local release run took ~2.8 seconds and ~414 MB peak resident memory. Original synthetic tests cover duplicate XBCH entries, corrupt lengths/offsets, truncation, trailer bounds and multi-stream library stitching.

```sh
M=tools/shader-inventory/Cargo.toml
cargo test --locked --manifest-path "$M" --all-features
cargo run --locked --release --manifest-path "$M" -- --header-only /path/to/shaders.rpf
cargo run --locked --release --manifest-path "$M" -- /path/to/shaders.rpf
cargo run --locked --release --manifest-path "$M" --features metal-probe --bin shader-metal-probe
```

## Selecting a small compute target

A separate read-only pass over the 2,689 compute FSSM payloads checked FSSM-relative code spans against the recorded length and end field (including the documented unset sentinel), skipped the 0x28-byte prefix, and checked for the final terminator after trimming trailing `s_code_end` words. All 2,689 spans passed. The metadata flags indicate 1,535 wave32 and 1,154 wave64. Of the wave32 group, 1,227 declare no LDS and a one-dimensional workgroup of at most 32 threads.

Sorting that group by trimmed code size and screening with LLVM 21 `gfx1013` found an 8-byte `1×1×1` decode target with two scalar instructions and no store. The smallest target with exactly one store under the same straight-line screen (no detected branches, image/LDS/atomic/scratch or lane-transfer instructions) was 48 bytes and 10 instructions, also `1×1×1`. It advertises five user SGPRs, loads a four-dword descriptor, and performs a 16-byte buffer store. These are local triage counts, not a complete instruction/ABI audit or evidence of executable retail translation.

## First GPU milestone: owned GFX10.3 fixture

Homebrew LLVM 21.1.6 `llvm-mc -triple=amdgcn -mcpu=gfx1030 -show-encoding tools/shader-inventory/fixture.s` assembled the two ALU instructions and terminator. `llvm-mc -triple=amdgcn -mcpu=gfx1030 -disassemble` decoded the same bytes (`00 01 02 4a / c1 02 02 3a / 00 00 81 bf`). At this milestone the lifter accepted only exact fixture words, verifying operands and termination before interpreting or emitting MSL. The host supplies the synthetic VGPR input/output and initial EXEC, so this fixture exercises no guest resource mapping or memory instruction.

On Apple M4, the generated MSL compiled with Metal and dispatched one 32-lane SIMD group. Sparse (including bit 31), all-active, and all-inactive masks compared **96/96 words** against Rust readback expectations, including wraparound inputs and preservation of the inactive-lane sentinel. Non-32-lane hardware is rejected. This is a single fixture using a host-provided static mask, not evidence of dynamic EXEC, wave64, or retail shader compatibility. SDK/runtime compilation, capability checking, buffer setup, dispatch and readback are real.

The separate [owned buffer probe](../tools/shader-inventory/BUFFER-PROBE.md) follows up on the single-store target. It reported **316/316 GPU words** matching its reference. Neither probe executes a retail payload.

## Where the decoder ends and the Xbox ABI starts

* **Standard GFX10.3:** Use AMD's [public machine-readable ISA](https://gpuopen.com/machine-readable-isa/) and its RDNA 2 ISA reference for instruction lengths, operands, modifiers and semantics. Use LLVM AMDGPU `gfx1030` assembly/disassembly differentially for standard encodings, not as a semantic oracle. Separately consult Mesa [ACO `aco_opcodes.py`](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/src/amd/compiler/aco_opcodes.py), [`aco_ir.h`](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/src/amd/compiler/aco_ir.h) and [`gfx103.json`](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/src/amd/registers/gfx103.json) / [`gfx10-rsrc.json`](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/src/amd/registers/gfx10-rsrc.json) for instruction classes, special registers, compute/stage state and descriptor field definitions. The Mesa mirror's ACO opcode and IR sources carry MIT notices; the register JSONs were consulted as references, not licensed for reuse by inference. No upstream code/tables were copied; check each file's provenance/license before any future reuse.
* **Xbox encoding profile:** XCL (`91f9a5e`) `crates/xcl/src/gpu/rdna2.rs` identifies encodings and handles extension words (literal, DPP, SDWA, NSA); `rdna2_spec.rs` is generated from AMD's public ISA XML; `rdna2_xbox.rs` documents compatibility deltas including non-fused multiply-add forms retained from GFX10.1. Leonida `docs/fssm_crosscheck.md` reports better `gfx1013` decoding of this corpus than `gfx1030`, not that Xbox is fully identical to GFX10.1. Example reproduced on LLVM 21: `gfx1013` assembles `v_mad_legacy_f32 v1, v0, v0, v0` to `01 00 40 d5 00 01 02 04`, which `gfx1030` disassembles as `v_fma_legacy_f32`. Decoding success alone can silently select different arithmetic. Keep an explicit Xbox profile with evidence per override, never fall through by choosing whichever target decoded more words.
* **Xbox dispatch/stage ABI:** FSSM in XDAT/XBCH, pipeline-library programs and FSPX may share machine instructions but require different metadata parsing. Leonida `docs/embedded_shaders.md` reports DLL-only FSPX/ACCC and mixed genuine DXIL/native containers; do not apply this archive's `NOBC` rule to every Xbox image. XCL `crates/xcl/src/gpu/recomp/` and `docs/wave64-on-wave32.md` show which wave/descriptor/export dependencies a practical recompiler has to model, not code for XSXEmu. XCL and Leonida were used as behavioral/factual GPL references only. Alkyhol (MIT) `docs/shaders.md` demonstrates host resource mapping and DXIL → SPIR-V → MSL for eligible desktop bitcode, **not** the `NOBC` corpus. Treat actual desktop DXIL as a separately validated path, not a fallback for this archive.

## Compute census: explicit LLVM reference targets

Use a trusted, locally installed AMDGPU-enabled LLVM 21 shared library. Both targets are required and may be swapped.

```sh
M=tools/shader-inventory/Cargo.toml
cargo run --locked --release --manifest-path "$M" -- \
  --compute-isa /path/to/libLLVM.dylib gfx1013 gfx1030 /path/to/shaders.rpf
LLVM_DISASM_LIB=/path/to/libLLVM.dylib LLVM_MC=/path/to/llvm-mc \
  cargo test --locked --all-features --manifest-path "$M"
```

The census runs only on the validated compute-labelled XDAT/XBCH payloads, not the compiled pipeline library. It checks the FSSM-relative `code_off + 0x28` through `code_off + code_size` interval, validates the recorded end or its unset sentinel, and drops only trailing `s_code_end` words, and then requires the `s_endpgm` footer. It checks the observed wave-width, `COMPUTE_PGM_RSRC2` and thread-group fields, **not** the full Xbox ABI. This uses the layout findings in Leonida `docs/fssm_crosscheck.md` and `docs/design.md`, cross-referenced to AMD/Mesa compute register definitions. LLVM's C disassembler is run separately for the two requested CPUs with explicit FSSM wavefront width, and never serves as a decoder fallback. XCL's Xbox override notes motivated comparing LLVM mnemonics at shared instruction boundaries, not adopting either CPU as an Xbox dialect.

Each pass walks from entry until first reject or span end; it does not stop at the first `s_endpgm`, skip rejected words, or follow branches. It emits counts of LLVM mnemonic spellings (including form suffixes), overlapping feature indicators and payloads exhibiting each indicator. It emits no operands, listings, shader PCs, bytes, names or hashes. Comparison ends at the first loss of a shared boundary but each independent pass continues according to its own result. A name match is not a semantic match. Valid code after a reject is unwalked; data that decodes in a linear walk can inflate counts. These are not counts of reachable instructions, supported operand forms, translated programs, or backend successes.

Measured locally with LLVM **21.1.6**: **2,689/2,689** spans and observed compute metadata records validated (4 unset end fields); **1,535 wave32**, **1,154 wave64**, **485** with nonzero LDS allocation. The three most common group dimensions were `32×1×1` (1,253), `8×8×1` (416) and `64×1×1` (301).

| Linear census | gfx1013 primary | gfx1030 reference |
|---|---:|---:|
| Complete, with decoded final `s_endpgm` | 1,680 | 1,129 |
| Stopped early | 1,009 | 1,560 |
| Decoded / total input bytes | 85,280,604 / 85,448,024 | 18,375,948 / 85,448,024 |
| Decoded instructions | 15,590,488 | 3,343,262 |
| Distinct LLVM mnemonic spellings | 482 | 468 |

Across 3,343,262 compared same-width steps, **4,658** mnemonics differed. There were **1,483** payloads where only the reference rejected at the first loss of a shared boundary; no opposite rejects or first width divergences. On the gfx1013 walk, **2,500** payloads contained direct-branch-like mnemonics, **2,511** explicit mask/compare indicators, **2,267** image mnemonics (**40** BVH), **2,172** vector-buffer, **596** LDS-family and **206** barrier mnemonics. These labels flag gaps in general support, not legal/illegal encodings or exclusive classes.

## Owned reachable CFG and literal probe

The Rust walker accepts a caller-selected decoder and typed fallthrough, direct jump, two-edge conditional or exit. It bounds successors and instruction widths, rejects overlaps with any other reachable instruction (including extension words), and can represent loops or a later exit without scanning skipped data. It does not identify secondary entries or prove that a reachable-looking word is code without external layout evidence. There is no indirect PC support. The corpus census does **not** use this walker yet.

The original `tools/shader-inventory/branch_fixture.s` assembles with LLVM `gfx1030`. It jumps across an invalid word to a two-word `v_xor_b32_e32` with a literal. The restricted ALU lifter flattens only a finite unconditional path, checks initialization, and refuses conditionals and cycles in both CPU and Metal backends. On Apple M4, the owned branch/literal fixture matched **96/96** CPU/Metal words under API/GPU validation, including the all-inactive and sparse lane masks; the existing ALU and buffer probes still matched **96/96** and **316/316**. The mask is host supplied; no dynamic EXEC, Xbox resource mapping, retail shader lowering or title execution is implied.

## Next gated milestones

1. **Measure reachability before claiming support.** Extend the linear census with a profile-gated reachable analysis and operand-variant counts. Keep pipeline-library programs separate and distinguish parser/decode, semantic and backend failures. Leonida `docs/shader_validation.md` shows why compilation or `spirv-val` does not prove semantics.
2. **Wave and EXEC.** Add owned fixtures for SALU state (SGPR/SCC), VGPR writes and `EXEC`/`VCC`/compare/branch masks, including inactive lanes and partial last waves. Validate variable-length decode and control-flow instruction boundaries; never stop at the first `s_endpgm` if branches reach later code. Compare a Rust ISA model, generated Metal readback and, where available, native AMD oracle results. Gate the initial backend to a measured matching wave width; refuse wave64 until cross-half ballot/lane reads and reconvergence are tested. If emulating one wave64 with two SIMD groups, budget shared memory and use only proven uniform group barriers; don't assume GPU forward progress across SIMD groups.
3. **Descriptors and memory.** Build on the owned buffer probe with checked console root/user-data SGPR bindings and coverage of additional raw buffer forms. Separate guest V#/T#/S# descriptors and console GPU addresses from Metal resource objects/indices; validate lengths, format, swizzle, alignment and aliasing. Then cover LDS, scratch, atomics, ordering (`waitcnt`, coherent accesses, barriers) and Metal device limits. Don't approximate unknown ordering/cache flags by silently dropping them. Host resource metadata and limits become part of the pipeline cache key along with decoder profile, shader variant and wave size.
4. **Graphics later.** Establish VS/PS signature linkage, interpolation and position/depth/color exports (channel masks, compressed pairs, kill/helper lanes) on owned render/readback. Mesh/NGG, geometry expansion and ray operations need separate capability gates and output validation, not stage renaming. A future SPIR-V/MSL backend would need the same feature and differential checks; a syntactically valid module is insufficient.
