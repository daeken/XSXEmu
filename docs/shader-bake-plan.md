# Fail-closed shipped PSO bake planner

`shader-bake-plan` is a read-only preflight for one pinned, inflated PS/0/9 library. It uses the [checked library parser](shader-pipeline-library.md) to walk every shipped library PSO occurrence in table order, and uses [checked compute leaf framing](shader-compute-blobs.md) to classify compute rows. It does not invent PSO combinations, pick a wrapper variant, guess missing state, generate source, invoke Metal, or create a cache entry. It does not cover loose wrapped shaders, embedded containers, or runtime requests outside the library.

```sh
cargo run --manifest-path tools/shader-inventory/Cargo.toml --locked --release \
  --features bake-planner --bin shader-bake-plan -- "$LIBRARY" "$EXPECTED_SHA256"
cargo test --manifest-path tools/shader-inventory/Cargo.toml --locked \
  --features bake-planner --bin shader-bake-plan
```

Pass the expected SHA-256 of the **inflated file** from a trusted local build ledger; do not substitute the opaque PSO keys or automatically trust a newly computed hash. A pin verifies that the bytes match that ledger, not that the ledger came from a particular retail package. The planner admits only a bounded regular file, hashes the same bytes it parses, and rejects an incorrect pin or invalid table/reference structure before emitting a plan. It prints no filenames, hashes, row IDs, references, or payloads. A successful exit means a report was produced, **not** that any row is bakeable; input rejection exits nonzero.

## Report semantics

Every row is visited once, retaining duplicate occurrences even when all reference fields repeat. Cohorts partition rows; blocker counts can overlap. Graphics grouping uses the observed slot mask, not guessed stages in otherwise unknown slots. A missing stage blob and an unsupported stage combination are independent blockers. The compute wave cohorts are the flag set/clear in a structurally validated compute leaf, not proof of native wave behavior. A failed leaf check is a row blocker, not a dropped row; a broken graph edge is a file-level error.

Measured on the pinned local extraction:

| Inventory | Rows | Ready |
|---|---:|---:|
| Compute, wave32 flag set | 1,535 | 0 |
| Compute, wave32 flag clear | 1,158 | 0 |
| Graphics, VS only | 24 | 0 |
| Graphics, VS + PS | 13,383 | 0 |
| Graphics, MS only | 1,336 | 0 |
| Graphics, MS + PS | 10,726 | 0 |
| Graphics, mask `0x43` (PS + VS + unidentified slot 6) | 2 | 0 |
| **Total** | **28,164** | **0** |

The compute counts are PSO occurrences, not the 2,684 distinct compute program IDs. All compute leaves pass structural checks; both mask `0x43` rows are also missing stage metadata. No program from the 21,522-entry table was submitted for lowering. Each row still needs an exact executable entry and verified lowering, a resource binding contract, and a specialization/target contract. Compute also needs a verified dispatch contract; graphics also needs native stage linkage and a complete render state/input layout. Checked source declarations and owned archive replay are different evidence and cannot clear those gates.

A future ready-plan schema must consume verified evidence tied to the exact row and program variants, plus a normalized pipeline contract and explicit target profile. Only then should it emit jobs with stable cache keys. This version has no ready-job representation or bake backend. Keep any later local manifests and artifacts outside Git.
