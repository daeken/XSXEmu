# RPF9: static Scarlett title-reader findings

This is a format investigation, not a decoder. The inputs were the local `game_scarlett_master.exe` (120,181,760 bytes, SHA-256 `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993`) and `shaders.rpf` (411,695,600 bytes). Both were opened read-only; no title code was executed, no key material was read out or sought, and no title instructions, archive bytes, or decoded assets are included here.

## Finding the reader

A literal byte search of the PE found three `9FPR` matches, all in `.text`: immediate fields at RVAs `fc21d9`, `1fb2619`, and `1fb2692`. Exact `shaders.rpf` was absent as ASCII and UTF-16LE. Bounded x86-64 disassembly at the containing `.pdata` ranges turned all three hits into comparisons against the RPF9 magic. The `fc21c0` path gates construction of the backing archive object on the magic **if** a preloaded pointer is supplied. The two comparisons in `1fb2600` belong to the metadata loader used by `fc2540` (call at `fc263d`) and the mode-zero wrapper `28cdfc0` (call at `28ce002`). A separate positional-read wrapper at `28cd360` calls the reader vtable slot `+0x60` with a backing handle, position, destination and length. This corroborates the read signature used by `1fb2600`; assigning a concrete host file API to every device implementation is unnecessary to infer the read ranges.

Reproduction: locate the immediate byte pattern in the PE's raw file, map the hits using each section's `PointerToRawData` and `VirtualAddress`, and use the exception directory for function boundaries. The references below are **RVAs**; add `0x140000000` to pass them as addresses to `llvm-objdump -d --x86-asm-syntax=intel --start-address=… --stop-address=…`. Verify candidate direct calls in disassembly instead of assuming every matching rel32 is an instruction.

## Observed prefix and read order

For the file-backed path without a supplied prefix, `1fb2600` reads exactly `0x10` bytes at the incoming archive base. It checks the returned byte count before the magic. It then allocates a buffer sized by `u32 +0x04` in mode 0 or `u32 +0x08` in any nonzero mode, copies the checked prefix in, and reads the remaining bytes up to that endpoint, checking the returned count again. Mode 1 additionally reads `[+0x08, +0x04)` into a separate buffer if those two values differ; the source is still relative to the archive base, **not EOF**. Other nonzero modes do not take that extra read. The routine also has distinct supplied-prefix (copy 16 bytes then check magic) and supplied-buffer (check magic, no I/O) paths. Mode is an argument to the reader, not an interpretation of the `+0x08` field.

| Offset | LE field | Local value | Evidence |
|---|---|---:|---|
| `0x00` | u32 | RPF9 magic | Compared as `0x52504639` |
| `0x04` | u32 | `0x8640` | Full prefix-read endpoint; data boundary per prior archive measurements |
| `0x08` | u32 | `0x8620` | Split prefix-read endpoint and inline location of the split table in mode 0; not an entry count |
| `0x0c` | u32 | `0xa0` | Not consumed by this loader. Candidate EOF trailer length from the cross-archive survey; this pass does not independently verify the title's use of it |

The split prefix segment for this sample is thus `[0x8620,0x8640)`, distinct from Leonida's candidate EOF trailer `[0x1889f950,0x1889f9f0)`. The loader does not establish the logical contents of either entire span. Its visible subtraction/multiplication sequences are not checked arithmetic for hostile inputs; don't copy those validation assumptions into a host reader.

## Extended header and metadata views

`87aec0` → `87af70` → `87aff0` computes views of the loaded prefix before preparation. The inspected header fields are little-endian. These names describe the observed access patterns, not original title symbols.

| Offset | Width | Local value | Observed use |
|---|---|---:|---|
| `0x1a` | u16 | `4` | Count of typed-section directory records |
| `0x1c` | u32 | `0x150` | Length of the following section arena |
| `0x20` | u16 | `5` | Count of 24-byte column descriptors |
| `0x22` | u16 | `1` | Number of those columns whose lookup matrix is split off at `+0x08` |
| `0x24` | u32 | `3` | Lookup matrix row count |
| `0x28` | u32 | — | Compared with a derived value by `c63230` during later object initialization |
| `0x2c` | u8 | `1` | Matrix element width; also used as an alignment in the view calculations |
| `0x2d` | u8 | `0x0f` | Bit 0 selects the wider alignment family; bit 3 selects a type-9-section path in `c63230` |
| `0x2e` | u8 | `9` | Initial transform selector |
| `0x30` | u32 | `0x10` | With odd nonzero selector, excluded tail length of the arena in the initial transform |

The formulas below describe pointer arithmetic for a suitably aligned base and non-wrapping inputs. `align` rounds up to a boundary. The `0x40` in the first formula is a fixed base in the calculation, not proof that the directory immediately follows a 64-byte header.

| Region | Placement | Computed for `shaders.rpf` |
|---|---|---|
| Typed-section directory | `align(0x40 + matrix_rows, a)`; `8 * directory_count` bytes; `a = 16` if bit 0 set, else `4` | `[0x50,0x70)` |
| Section arena | After directory, rounded to `b`; `b = 16` if bit 0 set, else `8` | `[0x70,0x1c0)` |
| Column descriptors | After arena, rounded to `b`; `24 * column_count` bytes | `[0x1c0,0x238)` |
| Inline lookup matrix | After descriptors, rounded to element width; `rows * (columns - split_columns) * width` bytes | `[0x238,0x244)` before rounding to 8 then 16; those endpoints are `0x248` and `0x250` |
| Split lookup matrix | Mode 0: archive base plus `u32 +0x08`, rounded to element width. Mode 1: analogous pointer into the separate read buffer. `rows * split_columns * width` bytes | `[0x8620,0x8623)` before rounding to 8 then 16; endpoints `0x8628` and `0x8630` |

The computed endpoints describe these tables, **not** complete metadata coverage: e.g. `[0x244,0x8620)` is not thereby padding. `6bd110` uses most of that region in a later preparation span. The meanings of remaining header bytes, the region before the typed-section directory, and metadata outside these identified views are not fully traced.

### Record layouts seen in consumers (after preparation where required)

- **8-byte typed-section directory record** (`4e6f740`/`4e6f780`): `u16 +0` is a type ID, `u32 +4` is a section-arena-relative byte offset, and `+2..+4` was not interpreted. Lookup compares IDs linearly up to the header count and returns no section on a miss. The type-3 section consumer treats the section as a leading `u32` count followed (starting at section `+8`) by 264-byte records; its path opens a subordinate object by path and checks a 16-byte identity prefix (`28ce280`, `28ce450`, `28ce4d0`). That is a different table from the archive's member entries.
- **24-byte column descriptor** (`28cd240`, `28ce110`, `55b2600`): `u64 +0` is a kind ID, `u32 +8` is a length returned by the column span accessor, `u32 +0x0c` is the column-base-relative byte offset, `u16 +0x10` is element stride. The accessor selects the inline or split column-data base according to the last `split_columns` descriptors, and uses offset plus stride times index. Meanings of the remaining descriptor bytes were not established.
- **Lookup matrices** (`4db65b0`/`4db6600`): row-major by matrix row and column within its inline/split group. The title multiplies the row by the group column count and adds column index. Widths 1, 2 and 4 are read; all ones acts as missing in each supported width. The result indexes the column. This is a columnar typed-member representation, not a fixed-size flat table containing offset, size and name for each member.
- **Member information** (`1330ad0`, `1331670`): distinct kind-ID queries feed different unpacking rules. One reads a `u32` at typed value `+8` and multiplies by 16 for one size accessor; another takes a shifted and masked field from a `u64` at `+8`. The corresponding position accessor reads low 44 bits at typed value `+0x10` in the latter case, low 48 bits at `+8` in a fallback kind, or a sum of masked dwords at `+0` and `+4` in the first kind. These are access patterns, not a verified per-kind on-disk member schema; no name/path table or complete bitfield model was validated against retail members.

## Preparation and validation order

The following is order on the traced `fc2540` path; it is not a claim every device or mount follows all the same branches.

1. Load/check prefix and selected metadata ranges (`1fb2600`), then calculate metadata views (`1fb2780` → `87aec0`). No comprehensive all-view bounds checking was seen before pointer construction.
2. `8ec210` calls `a348a0` first. That stage skips its transform for selector zero. Nonzero even selects a single span (aligned typed directory and full arena); nonzero odd selects two spans (aligned typed directory, then the arena except its last `u32 +0x30` bytes). The upper selector bits (`selector >> 1`) choose a context. For local selector `9`, this describes `[0x50,0x70)` and `[0x70,0x1b0)` on this path. The transform routine submits each span with the same source and destination pointer, checks update/finalize status, and propagates failure (`6bd160`). The primitive and any key or context data were not recovered.
3. Subject to a backing-object flag, `28ce530` then tries typed section 6, otherwise section 2, and rejects failure. The common handler at `daed80` checks that its selected input extent lies within the section arena before dispatching the next operation. This is a preparation/validation gate; its full semantics were not established.
4. If typed section 1 exists, `6bd040` then submits another in-place span. Let `S = 0x40 + align(8*directory_count,16) + arena_size` and `L = u32(+0x08) - S`. With `u32 +0x30` zero the span starts at `S` and has length `L`; otherwise it starts at the actual arena end minus `u32 +0x30` and has length `L + u32(+0x30)`. Keep pointer and length separate: substituting the local fields with nonzero `+0x30` gives start `0x1b0` and length `0x8480`, **not** a claimed observed transform ending at `0x8620`. The section's presence and actual call path were not verified for the sample. In modes 0/1, `8ec350` next submits `u32(+0x04) - u32(+0x08)` bytes at the split pointer when that pointer and length are nonzero. Both stages check status.
5. Only after successful preparation does `fc2540` install the view and conditionally invoke `28ce230` (type-3 subordinate setup and the `c63230` comparison). That comparison's result is saved into an object bit, not an unconditional rejection in this caller. Type-3 subordinate opens separately check exact 16-byte reads and identity before accepting a handle.

## Boundary of this result

The raw extended header is coherent with the reader's layout math, but this sample selects a nontrivial transform. The raw descriptor and directory spans cannot be treated as confirmed plaintext records. XCL (`91f9a5e` `HANDOFF.md`, `crates/xcl/src/rpf.rs` and `rpf_probe.rs`) and Leonida (`docs/rpf.md`, especially its EOF survey) document carving/probing, not original TOC entries. This pass adds static title-side evidence for a split, typed metadata layout; it does not validate a transform-free archive, recover keys, produce an archive listing, or replace the shader inventory's scan. No synthetic TOC fixture or Rust TOC parser was added: the missing evidence is a confirmed plaintext/authorized decoded fixture that links the typed record kinds, their bounds and member identities to actual archive extents. Selector zero alone only skips the initial transform; it does not establish that all subsequent stages are no-ops.
