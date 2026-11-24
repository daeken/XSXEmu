# Fail-closed shipped PSO bake planner

`shader-bake-plan` is a read-only preflight for one pinned, inflated PS/0/9 library. It uses the [checked library parser](shader-pipeline-library.md) to walk every shipped library PSO occurrence in table order, and uses [checked compute leaf framing](shader-compute-blobs.md) to classify compute rows. It does not invent PSO combinations, pick a wrapper variant, guess missing state, generate source, invoke Metal, or create a cache entry. It does not cover loose wrapped shaders, embedded containers, or runtime requests outside the library.

```sh
cargo run --manifest-path tools/shader-inventory/Cargo.toml --locked --release \
  --features bake-planner --bin shader-bake-plan -- "$LIBRARY" "$EXPECTED_SHA256" "$WRAPPED_DXBC_DIR"
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

## Source-family evidence

The optional wrapped DXBC directory adds a read-only join using the same checked stage/digest functions as the wrapped-library audit. A one-wrapper family still selects neither a native variant nor executable entry; a multi-wrapper family is never silently resolved by projection equality. Without that directory the report explicitly marks source evidence as not supplied. With it, the local run reports these stage-keyed families (only those referenced by checked PSO metadata):

| Stage | No wrapper | One wrapper | Multiple wrappers | Ready |
|---|---:|---:|---:|---:|
| PS | 5 | 8,491 | 25 | 0 |
| VS | 3 | 1,103 | 39 | 0 |
| MS | 0 | 5,801 | 524 | 0 |
| CS | 4 | 2,672 | 8 | 0 |

2 rows have an edge with no checked digest; 25 have a missing wrapper family and 2,143 have an ambiguous wrapper family. Counts are independent and coexist with the native ABI and state blockers. The report also gives per-stage edge counts, which include repeated references and are not family counts.

## Exact-evidence key admission (owned tests only)

The in-process `bake_keys::Request` contract is separate from source-family reporting. Trusted producers must supply a verified build namespace, an exact selected native program/entry and variant contract, stage ABI, exact translated module/entry, an explicitly supported normalized descriptor, and an exact target contract. The API is not a sidecar reader and does not authenticate a caller's `Validated` assertion. No retail producer currently calls it. Missing, ambiguous, unsupported, conflicting or malformed inputs produce no key. Unknown render state cannot be projected onto the narrow procedural render subset. Its ABI is supplied by the validator, not baked into the schema.

The key separates schema, backend/translator/compiler/device, selected stage programs, and the normalized descriptor. Bindings, specialization and stage lists are canonicalized by key; duplicates are rejected. Keys deduplicate identical owned rows and change for distinct variants, entries, linkage/layout, fixed state, specialization or target identities. Owned tests are synthetic contracts, not an invocation of Metal or a claim of shipped pipeline baking. Keep any later local manifests and artifacts outside Git.
