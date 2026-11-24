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

No input row has secondary bits outside its primary mask. An input-style subset rule is therefore unsuitable as a validator for outputs. The empty MS inputs do not imply absence of resource, payload or other launch data. This command does not decode later PSV0 tables, resolve producer/consumer pairs, infer interpolation or hardware export indices, or establish a Metal stage interface. An owned fixture checks offset bounds, mask asymmetry, a name without a terminator, and unsupported fields.
