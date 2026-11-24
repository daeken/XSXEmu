# RPF9: static Scarlett title-reader findings

This describes the format investigation and the resulting checked decoder for the tested Scarlett shader archive. The inputs were the local `game_scarlett_master.exe` (120,181,760 bytes, SHA-256 `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993`) and `shaders.rpf` (411,695,600 bytes). Both were opened read-only; no title code was executed, no key material was read out or sought, and no title instructions, archive bytes, or decoded assets are included here.

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

The formulas below describe pointer arithmetic for a suitably aligned base and non-wrapping inputs. `align` rounds up to a boundary. For the tested aligned layout the directory starts immediately after the 64-byte header. The row count is only used for the matrices, not the directory start.

| Region | Placement | Computed for `shaders.rpf` |
|---|---|---|
| Typed-section directory | At `0x40`; `8 * directory_count` bytes | `[0x40,0x60)` |
| Section arena | After directory, rounded to `b`; `b = 16` if bit 0 set, else `8` | `[0x60,0x1b0)` |
| Column descriptors | After arena, rounded to `b`; `24 * column_count` bytes | `[0x1b0,0x228)` |
| Inline lookup matrix | After descriptors, rounded to element width; `rows * (columns - split_columns) * width` bytes | `[0x228,0x234)`; column data starts at the next 8-byte boundary, `0x238` |
| Split lookup matrix | Mode 0: archive base plus `u32 +0x08`, rounded to element width. Mode 1: analogous pointer into the separate read buffer. `rows * split_columns * width` bytes | `[0x8620,0x8623)` before rounding to 8 then 16; endpoints `0x8628` and `0x8630` |

The computed endpoints describe these tables, **not** complete metadata coverage: the space between each matrix and the end of its metadata span includes indexed column values, not merely padding. Meanings of remaining header bytes and other metadata are not fully traced.

### Record layouts seen in consumers (after preparation where required)

- **8-byte typed-section directory record** (`4e6f740`/`4e6f780`): `u16 +0` is a type ID, `u32 +4` is a section-arena-relative byte offset, and `+2..+4` was not interpreted. Lookup compares IDs linearly up to the header count and returns no section on a miss. The type-3 section consumer treats the section as a leading `u32` count followed (starting at section `+8`) by 264-byte records; its path opens a subordinate object by path and checks a 16-byte identity prefix (`28ce280`, `28ce450`, `28ce4d0`). That is a different table from the archive's member entries.
- **24-byte column descriptor** (`28cd240`, `28ce110`, `55b2600`): `u64 +0` is a kind ID, `u32 +8` is a length returned by the column span accessor, `u32 +0x0c` is the column-base-relative byte offset, `u16 +0x10` is element stride. The accessor selects the inline or split column-data base according to the last `split_columns` descriptors, and uses offset plus stride times index. Meanings of the remaining descriptor bytes were not established.
- **Lookup matrices** (`4db65b0`/`4db6600`): row-major by matrix row and column within its inline/split group. The title multiplies the row by the group column count and adds column index. Widths 1, 2 and 4 are read; all ones acts as missing in each supported width. The result indexes the column. This is a columnar typed-member representation, not a fixed-size flat table containing offset, size and name for each member.
- **Direct members** (`c6950`, `1330ad0`, `1331670`): for kind `0x33f70dfaf2c50989`, the low 40 bits of the first and second words give position and stored span, both in 16-byte units; the low 44 bits of the third word give logical length in bytes. The three local ranges are non-overlapping; the first two begin at `SGD5` and the last ends at the proposed trailer boundary. The stored span can include padding; when it is shorter than logical length, reading that span does not produce the logical payload. Other member kinds and paths are not implemented.

## Preparation and validation order

The following is order on the traced `fc2540` path; it is not a claim every device or mount follows all the same branches.

1. Load/check prefix and selected metadata ranges (`1fb2600`), then calculate metadata views (`1fb2780` → `87aec0`). No comprehensive all-view bounds checking was seen before pointer construction.
2. `8ec210` calls `a348a0` first. That stage skips its transform for selector zero. Nonzero even selects a single span (aligned typed directory and full arena); nonzero odd selects two spans (aligned typed directory, then the arena except its last `u32 +0x30` bytes). The upper selector bits (`selector >> 1`) choose a context. For local selector `9`, the spans are `[0x40,0x60)` and `[0x60,0x1a0)` and share one CBC chain (`6bd160`). Algorithm `0x10` uses 16-byte blocks, a table-driven inverse block transform, and XOR with the previous ciphertext block. The initial context and IV are read from the supplied executable; neither material is distributed with the library.
3. Subject to a backing-object flag, `28ce530` then tries typed section 6, otherwise section 2, and rejects failure. The common handler at `daed80` checks that its selected input extent lies within the section arena before dispatching the next operation. This is a preparation/validation gate; its full semantics were not established.
4. If typed section 1 exists, `6bd040` then submits another in-place span. Let `S = 0x40 + align(8*directory_count,16) + arena_size` and `L = u32(+0x08) - S`. With `u32 +0x30` zero the span starts at `S` and has length `L`; otherwise it starts at the actual arena end minus `u32 +0x30` and has length `L + u32(+0x30)`. The supported layout has actual arena end equal to `S`; the second pass decrypts `[0x1a0,0x8620)` in the sample. In modes 0/1 `8ec350` separately decrypts `[0x8620,0x8640)` starting again at the section-1 IV. Section 1 stores the secondary context ID (u32), algorithm (u16), and a 16-byte IV. Both stages check status.
5. Only after successful preparation does `fc2540` install the view and conditionally invoke `28ce230` (type-3 subordinate setup and the `c63230` comparison). That comparison's result is saved into an object bit, not an unconditional rejection in this caller. Type-3 subordinate opens separately check exact 16-byte reads and identity before accepting a handle.

## Prepared parser

`xsxemu::rpf9::Archive::from_prepared(backing, prefix)` owns an already decoded prefix ending at header `+4` (exclusive). The backing reader supplies the file length and stored member bytes. The parser validates directory IDs and arena-relative offsets (nonzero unique IDs, unique in-arena offsets), both index matrix extents, column extents and every non-sentinel cell index. It checks direct member extents when accessed. These are structural checks, not archive authentication or proof that a plausible decoded directory used the right key.

`cargo test --locked --lib rpf9` covers an owned synthetic decoded prefix including inline and split columns, malformed fields, index bounds and stored reads. This parser has no executable loader, transform, or retail fixture. `stored_member` does not decrypt/decompress payloads. It does not implement paths, nested archives, other member kinds or signature verification.

## Opt-in retail adapter

Enable `rpf9-retail` and call `xsxemu::rpf9_retail::open(archive, executable)` with locally supplied, read-only `Read + Seek` inputs. The adapter pins the exact executable size and SHA-256 listed above. It hashes a bounded snapshot before any fixed-offset reads; the reads use those same bytes and the snapshot is discarded when opening completes. It neither executes the binary nor emits transform material or decoded bytes. Archive reads and metadata allocation are bounded. The digest identifies the executable layout only: neither CBC nor the TOC checks authenticate the archive, and the section-6/2 title validation path is not implemented.

Stage one on the local sample yields four unique section IDs (1, 5, 6, 9) with arena-relative offsets `0`, `0x18`, `0x30`, `0x140`. The adapter rejects duplicate or zero IDs, duplicate or out-of-arena section starts, a missing section 1, or a section 1 whose 22-byte descriptor crosses the next section or the stage-one plaintext boundary. It additionally requires a supported algorithm and executable context. A directory that merely looks plausible is not enough: stage two must yield bounded typed columns and valid cell indices, and stored member spans must be in file. These independent checks still do not establish authenticity.

The local test verifies three rows and five columns, all three exact non-overlapping stored spans, and `SGD5` magic at the first two member starts. The third span starts exactly at the independently scanned PS/0/9 zlib pipeline library and ends at the proposed EOF trailer. A scratch instrumentation run of the existing shader inventory counted accepted wrapped records by full containment of the scanner's `[suffix offset, record end)` in each member span:

| Stored span | Accepted wrapped records |
|---|---:|
| `[0x9000,0x10286f20)` | 24,804 |
| `[0x10287000,0x10578a30)` | 1,699 |
| `[0x10579000,0x1889f950)` | 0 |
| Outside all three | 0 |

Thus **two of three TOC rows** contain **all 26,503 records** found by the existing wrapped-record scan, not one TOC row per shader. This is not a complete shader inventory: the third row correlates to the separate pipeline library, and the TOC parser does not enumerate its logical programs or unpack payloads. No temporary instrumentation or retail inputs are in Git.

```sh
cargo test --locked --lib rpf9
cargo test --locked --features rpf9-retail --lib rpf9
RPF9_EXE=/path/to/game_scarlett_master.exe RPF9_ARCHIVE=/path/to/shaders.rpf \
  cargo test --locked --features rpf9-retail --test rpf9_local -- --ignored
```
