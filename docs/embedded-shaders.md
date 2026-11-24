# Embedded PE shader census

The package's root AMD64 EXE and 16 DLLs are a separate shipped-input surface from `shaders.rpf` and the expanded PS/0/9 library. Run a read-only, count-only check on each local image:

```sh
cargo build --locked --release --manifest-path tools/shader-inventory/Cargo.toml
for p in "$PKG"/*.exe "$PKG"/*.dll; do
  printf '%s\n' "${p##*/}"
  tools/shader-inventory/target/release/xsx-shader-inventory --embedded-shaders "$p"
done
```

| Image | Structural DXBC | `RTS0` present | Checked profile | Rejected magic hits |
|---|---:|---:|---|---:|
| `game_scarlett_master.exe` | 10 | 0 | 9 PS and 1 VS, `DXIL/NOBC` + `XBCH/FSSM` | 1 |
| `XboxBvhBuilder.dll` | 52 | 52 | 52 CS, `DXIL` bitcode marker + `XBCH/FSSM`, distinct `STAT` bitcode marker | 0 |
| `amd_fidelityfx_upscaler_xbox.dll` | 29 | 29 | 29 CS, `ACCC/FSPX`; wave32 bit set in 24, clear in 5 | 1 |
| Other 14 root DLLs | 0 | 0 | — | 0 |

All 91 structural hits match a checked profile. The scan searches file-backed PE section ranges bytewise, including unaligned candidates, not headers, overlays, non-PE files, compressed data or runtime allocations. Each hit must fit its section, have DXBC version word 1, and contain 1–64 unique, bounded, nonoverlapping chunks. It has a 128 MiB input and 8 MiB container/inflate limit. It reports structurally valid but unmatched containers separately from bad magic candidates. It does not validate DXBC checksums, execute software, or write any index, extracted payload or instruction listing.

## DXIL with console extensions

At DXIL-part `+8` the magic is `DXIL`; the outer size-in-dwords at `+4` equals the part extent. The nominal span starts at `8 + u32(+16)`, with byte extent `u32(+20)`. At `+24` there is `XDAT`; count at `+28` and directory offset `36` at `+32`. Each 12-byte entry is `(tag, offset from part, byte size)`. Nonempty entries fit after the table and do not overlap one another. Stage (high 16 bits of DXIL word 0) agrees with byte `+28` of the `PSV0` part (within the observed 52-byte runtime-info block).

* Tag `0x0d`: checked by the same `XBCH` v3 exact zlib envelope and inflated `FSSM` v`0x101` prefix as the archive scanner. This is not a code-span, dispatch or stage-ABI validation of the FSSM body.
* Tag `0x07`: another DXIL header. The outer nominal span and the inner nominal span designate **the same range** when measured in the outer part. For the 10 EXE stubs this is `NOBC`; the 28-byte inner record has high bit set in its `+4` word, which is **not** a plain size-in-dwords. Its low bits are not interpreted here. For the 52 builder records, the inner size-in-dwords matches the inner extent and the shared nominal span starts with LLVM's bitcode marker. In all 52, the separate `STAT` part has its own bounded, byte-distinct nominal range with that marker. This command does not parse bitcode modules, validate desktop DXIL eligibility, or select a DXIL fallback.

## FidelityFX ACCC/FSPX, version 1

The observed strict profile is an ACCC part with magic `FSPX`, `u32` version 1, count 4, and exact byte extent, followed by four 16-byte `(kind, offset from part, byte size, zero)` entries. The kinds below must occur once each, have nonempty nonoverlapping spans, and be outside the directory.

| Kind | Checked fields |
|---|---|
| 0 | 28-byte dispatch span using the same shape as the PS/0/9 compute leaf. Word 3 low/high halfwords encode X/Y and word 4 low halfword encodes Z: **29/29** agree with `PSV0` u32s at part offsets 40, 44 and 48. Word 4 bit 20 is counted but no ISA implication is proved here. |
| 1 | 20 bytes, contents opaque. |
| 6 | Dword-sized span starting at `+0x100`, at least 36 bytes. The first three 12-byte groups have high halfword `0xd580` in their first dword. The low halfwords at offsets 0 and 12 match digest bytes `[0..2]` and `[8..10]`; the dwords at 8 and 20 match `[4..8]` and `[12..16]`. This partial fingerprint is not evidence that the prefix is safe to skip, nor does the scan infer executable bounds. |
| 7 | Same checked item/footer **framing** as the PS/0/9 compute layout: `0x403` head, 32-byte `0x41`/`0x42` items and 32-byte `0x43` footer. Footer bytes `[4..20]` equal the 16 bytes after the first word of the container's 20-byte `HASH` part in **29/29**. This is stored-byte correspondence, not a recomputed hash, identity across representations, or descriptor binding. |

Record framing was hypothesized using Leonida's `docs/embedded_shaders.md` and `docs/fspx.md` as factual references and checked here with our own parser and fixtures. None of these counts are PSO, translation, Metal compilation, or execution coverage.

## FSPX layout versus same-container RTS0

A separate numeric audit accepts the observed RTS0 version-2 wire layout, not general root signatures. The 24-byte header supplies parameter count/offset at `+4/+8`, static sampler count/offset at `+12/+16` and zero flags at `+20`. Parameter headers are 12-byte `(type, visibility, payload offset)` rows. Table bodies are 8-byte `(range count, range offset)` pairs; their ranges are 24-byte rows with class, count, first register and space in their first four words. A root CBV body is 12 bytes with register and space first. Each 52-byte static sampler has register, space and visibility at `+40/+44/+48`. Offsets address the RTS0 payload. Claimed extents are aligned, bounded and disjoint, with at most 64 rows per table; visibility-all and finite space-zero declarations only. Other root parameter types are unsupported for this audit. Range offsets into descriptor heaps, flags in parameter bodies and sampler state are not interpreted.

Of **29/29** accepted roots, all **150 layout items** (90 tag `0x41`, 60 tag `0x42`) have the item's word 3 in at least one same-container declaration interval, **41** in exactly one and **109** in multiple. The comparison deliberately ignores layout register class and uses declaration multiplicity, not a deduplicated set of register numbers. Grouping by tag and word 1 produces these falsifiable class hypotheses:

| Tag | Word 1 | Single / multiple declarations | Classes present among the numeric candidates for every item in the group |
|---|---|---:|---|
| `0x41` | `0x102` | 1 / 28 | CBV |
| `0x41` | `0x300` | 17 / 8 | SRV |
| `0x41` | `0x303` | 3 / 32 | UAV |
| `0x41` | `0x401` | 0 / 1 | All four classes, so no class is distinguished |
| `0x42` | `0x000` | 20 / 40 | None; no single class covers all these items |

This is stronger than finding a register number somewhere in a root signature, but it is not enough to decode an item into a root slot or to assign a descriptor class in the translator. Other fields, variant selection, live user-data and descriptor-heap contents remain unknown. Neither the FSPX class hypotheses nor static roots can be transferred to FSSM/library profiles without independent checks.
