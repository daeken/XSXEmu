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
| +8 | Semantic index, not used in this census |
| +12 | System-value field; only zero versus nonzero counted |
| +16 | Component-type field, observed values 1, 2, 3, 6 |
| +20 | Register field, not mapped to native registers here |
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

No input row has secondary bits outside its primary mask. An input-style subset rule is therefore unsuitable as a validator for outputs. The empty MS inputs do not imply absence of resource, payload or other launch data. This command does not decode PSV0 tables after the resource rows, resolve producer/consumer pairs, infer interpolation or hardware export indices, or establish a Metal stage interface. An owned fixture checks offset bounds, mask asymmetry, a name without a terminator, and unsupported fields.

## PSV0 resource declarations

After the 52-byte runtime-info block, the payload has a `u32` row count at `+56`. If nonzero, a `u32` stride at `+60` is 24 in every checked file, with rows starting at `+64`. If zero, no stride word is consumed. The six little-endian row words are resource type, register space, lower bound, upper bound, kind and flags. The checker verifies type in 1–8, ordered bounds, and complete table extent. The remaining payload is outside this check.

| Stage | Rows | Files with zero rows | Nonzero space | Nonzero flags |
|---|---:|---:|---:|---:|
| PS | 202,028 | 435 | 71,939 | 952 |
| VS | 16,437 | 195 | 8,885 | 0 |
| GS | 390 | 0 | 0 | 0 |
| CS | 97,993 | 5 | 36,622 | 2 |
| MS | 128,546 | 0 | 73,599 | 0 |
| Total | 445,394 | 635 | 191,045 | 954 |

Every lower bound equals its upper bound in the checked corpus; the parser accepts ordered non-singleton declarations rather than assuming the observed singleton property is a wire requirement. The resource rows give source register-space evidence, not an assignment to an Xbox root slot or SGPR. The zero-count/no-stride case, ordered bounds and truncated rows are checked on owned data.
