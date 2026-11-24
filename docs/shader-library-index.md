# Expanded PS/0/9 library: structural index audit

`cargo run --release --locked --manifest-path tools/shader-inventory/Cargo.toml -- --pipeline-index /path/to/local/library.bin` audits the expanded library read-only. It reads the 0x80-byte header and four index tables only; no blob or program body is read, no external JSON index is trusted or consulted, and output is aggregate-only. It is intentionally separate from archive framing and the native FSSM census.

All checked integer fields below are little-endian. The map was implemented from the field findings in Leonida `docs/shader_library.md` and checked independently on the local extraction; no implementation was copied.

| Region | Layout used by this audit |
|---|---|
| Header | `PS 00 09` magic; at `+0x50` four u32 table counts in graphics, compute, blob, program order; at `+0x60/+0x64`, u32 blob/code section lengths in bytes. Header strings, hash and remaining fields are not interpreted. |
| Graphics rows | 112 bytes; u32 blob indices at `+0x08/+0x0c`; the seven `(u32 program, u32 stage blob)` pairs start at `+0x38`, stride 8. Either optional member may be `0xffffffff`, tracked separately. Hash and the 40 bytes preceding the pairs are opaque. |
| Compute rows | 24 bytes; u32 blob indices at `+0x08/+0x0c/+0x14`, program index at `+0x10`. They are required in this profile. No interpretation of blob contents. |
| Blob table | `(u32 byte offset, u32 byte size)` rows, offset relative to blob section. Positive extents, contiguous in index order, cover their section exactly. |
| Program table | Same row fields relative to code section. Positive dword-sized records, ordered and nonoverlapping, with 256-byte-aligned starts. Gap sizes are counted, not classified as padding. |

The header and these tables in the stated order are followed by the blob section and code section. Sizes must account for the physical file exactly, and every non-sentinel reference must fit the appropriate table. The auditor refuses short reads and caps index memory (32 MiB), independently of the existing 512 MiB archive limit. Synthetic tests cover truncation, reference overflow, overlapping or out-of-bounds extents and absent optional stage metadata.

## Measured results

The local expanded library has **25,471 graphics** and **2,693 compute** rows and **3,526,168 bytes** of index tables. All **54,576 blobs** and **21,522 programs** have at least one reference, all indices are in range, no program appears in two distinct slot roles, and **2,064,700 code section bytes** are outside declared program extents. Slot roles are observed reference positions, not deduced from instruction semantics.

| Role(s) | Distinct programs by role | Graphics pipeline rows by program presence |
|---|---:|---:|
| Slot 0 (reported PS) | 9,996 | — |
| Slot 1 (reported VS) | 1,343 | 24 slot 1 only; 13,383 with slot 0 |
| Slot 2 (reported MS) | 7,498 | 1,336 slot 2 only; 10,726 with slot 0 |
| Slots 3–5 | 0 | 0 |
| Slot 6 (unknown) | 1 | 2, both alongside slots 0 and 1 |
| Compute | 2,684 | — |

The two slot-6 references both lack a companion stage blob. All populated slots 0–2 have stage blobs, and there are no orphan stage blobs in inactive slots. This confirms a **structural join**, not compiled pipeline support. Next: validate compute state/layout blob contents and program reference roles independently of wrapped FSSM, then reconstruct graphics state and the unknown slot before counting complete precompilable PSOs.
