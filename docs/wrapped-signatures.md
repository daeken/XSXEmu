# Wrapped DXBC stage signatures

```sh
cargo run --locked --release --manifest-path tools/shader-inventory/Cargo.toml -- \
  --wrapped-signatures "$WRAPPED_DXBC_DIR"
```

Read-only aggregate check, no names, bytes or per-file IDs emitted. The command checks the version-1 DXBC chunk directory and requires exactly one each of `DXIL`, `PSV0`, `ISG1`, and `OSG1`. Every observed `PSV0` starts with the 52-byte runtime-info size and its stage byte at payload offset 28 agrees with the upper 16 bits of `DXIL` word 0. These are envelope stage labels, not proofs about every native variant.

Both signature chunks start with a little-endian entry count and row offset 8, followed by 32-byte rows. Within a row:

| Offset | Checked field |
|---|---|
| +0 | Stream index, zero in the checked profile |
| +4 | Byte offset from chunk start to a nonempty NUL-terminated ASCII semantic name, after the row array |
| +8 | Semantic index, used in the same-wrapper correspondence check |
| +12 | System-value field; only zero versus nonzero counted |
| +16 | Component-type field, observed values 1, 2, 3, 6 |
| +20 | Source signature register field, compared to PSV0 packing below, not mapped to native registers |
| +24/+25 | Primary and secondary mask bytes respectively; nonzero primary nibble and secondary nibble |
| +26/+27 | Zero padding |
| +28 | Minimum-precision field, zero in the checked profile |

| Stage | Files | Input rows | Output rows | Output rows with secondary bits outside primary |
|---|---:|---:|---:|---:|
| PS | 12,101 | 101,024 | 30,461 | 5,854 |
| VS | 2,236 | 3,743 | 13,402 | 6,906 |
| GS | 195 | 385 | 970 | 580 |
| CS | 2,689 | 0 | 0 | 0 |
| MS | 9,282 | 0 | 74,393 | 32,487 |
| Total | 26,503 | 105,152 | 119,226 | 45,827 |

No input row has secondary bits outside its primary mask. An input-style subset rule is therefore unsuitable as a validator for outputs. The empty MS inputs do not imply absence of resource, payload or other launch data. This command does not resolve producer/consumer pairs, infer interpolation or hardware export indices, or establish a Metal stage interface. An owned fixture checks offset bounds, mask asymmetry, a name without a terminator, and unsupported fields.

## PSV0 runtime-info fields

The 52-byte block begins after its size word. Payload offsets `+20` and `+24` are the ordered expected minimum/maximum wave-lane counts; `+40`, `+44`, `+48` are the X/Y/Z thread dimensions. The `+52` word is an offset into the string table after the resource declarations, not an offset into DXBC or the native program. All 26,503 offsets resolve to nonempty, NUL-terminated ASCII; the scanner validates the span without printing names.

Four of 2,689 CS wrappers declare `(32, 32)` wave bounds. All other wrappers have `(0, 0xffffffff)`, the unspecified pair; this is not evidence for wave64 or for a particular native wave mode. All CS and MS wrappers have three nonzero thread dimensions; all PS, VS and GS wrappers have three zero dimensions. These are source declarations, not validated native launch dimensions or Metal device limits.

For the compute wrappers only, the scanner compares PSV0 launch fields against the same-wrapper FSSM metadata. All 2,689 wrappers have exactly one payload with native stage byte `6` at `+0x100` and readable compute metadata. The XYZ words at FSSM `+0x13c`, `+0x140`, `+0x144` agree with PSV0 in every pair. The FSSM wave32 bit (`+0xd4` bit 5) is set in 1,535 payloads including all four with fixed wave32 source bounds. The unspecified source pair is not compared to a native wave width. This check is not applied to graphics variants and does not validate the launch ABI against a real dispatch.

For PS, payload bytes `+4` and `+5` are the `DepthOutput` and `SampleFrequency` flags. `SampleFrequency` is zero throughout. All 1,171 wrappers with `DepthOutput = 1` have exactly one unallocated PSV0 output element with semantic kind `Depth` (1,156), `DepthLessEqual` (12), or `DepthGreaterEqual` (3). The 10,930 remaining PS wrappers have no depth-kind or unallocated output element. “Unallocated” here means outside the packed vector signature, not absent from shader outputs or proof of native depth export behavior.

## Wrapped stage labels versus FSSM stage bytes

The scanner uses the bounded XDAT/XBCH reader for every wrapper and groups the FSSM byte at `+0x100` in native payload directory order. The observed raw sequences account for all 26,698 native payloads in 26,503 wrappers:

| DXIL/PSV0 label | FSSM stage-byte sequence | Wrappers |
|---|---|---:|
| PS | `[5]` | 12,101 |
| VS | `[4]` | 2,041 |
| VS | `[2, 4]` | 195 |
| GS | `[3]` | 195 |
| CS | `[6]` | 2,689 |
| MS | `[7]` | 9,282 |

The byte is present on every validated payload. The VS dual-payload case is ordered in this directory, not necessarily in execution. Neither the numeric stage tags nor the equal counts of dual-payload VS and GS wrappers identify linkage, hardware roles, or call order. A synthetic two-variant wrapper checks that the unrestricted reader visits both payloads in directory order and emits neither when late framing fails.

## PSV0 resource declarations

After the 52-byte runtime-info block, the payload has a `u32` row count at `+56`. If nonzero, a `u32` stride at `+60` is 24 in every checked file, with rows starting at `+64`. If zero, no stride word is consumed. The six little-endian row words are resource type, register space, lower bound, upper bound, kind and flags. The checker verifies type in 1–8, ordered bounds, and complete table extent. The resource checker stops at the end of this table; the element checker starts there.

| Stage | Rows | Files with zero rows | Nonzero space | Nonzero flags |
|---|---:|---:|---:|---:|
| PS | 202,028 | 435 | 71,939 | 952 |
| VS | 16,437 | 195 | 8,885 | 0 |
| GS | 390 | 0 | 0 | 0 |
| CS | 97,993 | 5 | 36,622 | 2 |
| MS | 128,546 | 0 | 73,599 | 0 |
| Total | 445,394 | 635 | 191,045 | 954 |

Every lower bound equals its upper bound in the checked corpus; the parser accepts ordered non-singleton declarations rather than assuming the observed singleton property is a wire requirement. The resource rows give source register-space evidence, not an assignment to an Xbox root slot or SGPR. The zero-count/no-stride case, ordered bounds and truncated rows are checked on owned data.

## PSV0 signature element tables

After the resources, a `u32` byte length prefixes a dword-aligned NUL-terminated string table. A `u32` entry count then prefixes that many `u32` semantic indices. Payload bytes `32`, `33` and `34` count the input, output and patch/primitive element groups. If their sum is nonzero, a `u32` stride of 16 precedes those elements. If the sum is zero, there is no stride word. An element's first two words address the string table (byte offset) and semantic-index table (row index), and byte 8 gives the number of semantic indices used. Both ranges are checked. Names can be empty here, unlike `ISG1`/`OSG1`.

All 26,503 files agree on `PSV0` versus `ISG1`/`OSG1` input and output **row counts** independently; none has patch/primitive rows. An owned fixture checks scope and bounds of both references and the exact start of the suffix.

All 224,378 `PSV0` elements span one row in this corpus. For each named single-row element, the scanner consumes one matching signature key (ASCII case-folded name and semantic index) in the **same file and direction**. It counts ordinal disagreement separately, comparing the key at each element's original position without compacting away nameless elements. It counts and skips nameless single-row elements and multi-row elements instead of assuming a mapping for them.

| Direction | Named single-row | Unmatched by key multiplicity | Different or missing key at same ordinal | Nameless single-row | Multi-row |
|---|---:|---:|---:|---:|---:|
| Input | 87,879 | 0 | 26,037 | 17,273 | 0 |
| Output | 75,115 | 0 | 20,759 | 44,111 | 0 |

The named keys correspond, but a positional join does not. Neither the residual unmatched DXBC rows nor ordinal position establish an identity for individual nameless elements. This key comparison alone does not establish type or mask equivalence, producer/consumer linkage, or hardware register layout. An owned fixture covers reordered keys, duplicate consumption, missing keys, and excluded element cases.

## PSV0 signature packing

The public DXC `PSVSignatureElement0` layout gives the following remaining fields within each 16-byte element:

| Offset | Field |
|---|---|
| +9 | Start row, meaningful only if allocated |
| +10 | Column count (bits 0–3), start column (4–5), allocated (6), zero bit (7) |
| +11/+12/+13 | Semantic kind, component type, interpolation mode; pixel depth kinds checked above, component type and interpolation not compared |
| +14 | Dynamic-index mask (0–3), output stream (4–5), zero bits (6–7) |
| +15 | Reserved zero byte |

For input and output elements, the checker verifies that allocated rectangles fit four columns and the declared vector extent, and occupy disjoint components within a direction and stream. It does not use the start coordinates for unallocated elements. All 105,152 input and 118,055 output allocations pass; the other 1,171 outputs are unallocated. No element has a nonzero dynamic-index mask.

The scanner compares the start row to `ISG1`/`OSG1` register and the allocated column span to the **primary** mask only for named, allocated single-row stream-0 elements whose key occurs exactly once in each same-wrapper table. Groups containing multi-row elements are excluded from this comparison because their keys are not expanded. All 87,879 named input pairs and 75,115 named output pairs qualify, and all agree on both fields. The match is between two source signature encodings, not evidence of physical registers, native export indices, or a link between shader stages. Owned fixtures reject overlapping and out-of-extent rectangles, ignore unallocated coordinates, and distinguish unique-key packing differences from duplicate-key ambiguity.

## PSV0 input-to-output dependency tables

The bytes after the signature elements are fully accounted for by the no-ViewID branch of the public [DXC PSV layout](https://github.com/microsoft/DirectXShaderCompiler/blob/main/include/dxc/DxilContainer/DxilPipelineStateValidation.h) (`PSVRuntimeInfo1`, `PSVDependencyTable`). Payload byte 29 (`UsesViewID`) is zero in all files. Byte 35 gives the input vector count, and bytes 36–39 give output vector counts per stream. Only stream 0 is used for PS, VS and CS; GS can have four separate tables, in stream order. MS has no input-to-output table in this profile. The scanner rejects out-of-profile ViewID and stage values rather than applying the rule to their suffixes.

For each applicable stream with nonzero input and output vector counts, the table contains `4 × input_vectors` consecutive masks of `ceil(output_vectors / 8)` little-endian dwords each. Each mask has one bit per output component (four per output vector). The checker requires the tables to consume the suffix exactly and separately counts masks with high bits outside the output vector extent. An owned fixture covers multiple GS streams, a multi-dword mask, padding bits, truncation and trailing bytes.

| Stage | Files with tables | Dependency dwords |
|---|---:|---:|
| PS | 10,487 | 353,880 |
| VS | 2,236 | 18,156 |
| GS | 195 | 1,540 |
| CS | 0 | 0 |
| MS | 0 | 0 |
| Total | 12,918 | 373,576 |

All 26,503 suffix extents match, with no mask bits set outside the declared vector extent. The checker also compares the tables against actual allocated components, not just the vector bounds:

| Stage | Masks | Nonzero masks | Masks for unallocated input components |
|---|---:|---:|---:|
| PS | 353,880 | 187,141 | 45,464 |
| VS | 14,972 | 6,715 | 8,037 |
| GS | 1,540 | 965 | 380 |
| Total | 370,392 | 194,821 | 53,881 |

Every mask for an unallocated input component is zero, and no bit names an unallocated output component in the corresponding stream. The owned fixture covers an allocated pair and nonzero masks outside the allocated input/output sets. These are same-shader source signature dependencies; the check does not tie those bits to native instructions, stage linkage or verified execution.
