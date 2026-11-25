# Standalone D3D12 command state

`xsxemu::d3d12_command_state` is host-independent Rust bookkeeping, not an
Xbox guest provider. One `CommandState` owns the typed allocator, list, and
queue handles for one domain. It checks exact kind matching for Direct,
Compute, and Copy. There are no raw descriptor parameters, guest pointers,
COM objects, recorded command payloads, GPU work, or synthetic fence signals.
Bundles, video, object release, and device loss are outside this model.

## Evidence and scope

[The caller-side Xbox ABI map](xbox-d3d12-abi.md) documents allocator creation
at device slot 9 (the output consumed by slot 73), queue creation at slots 8
and 48, and the slot-73 console-list creation variant. The initialized bytes
at those callsites are not sufficient to decode either Xbox description or
identify subsequent queue/list methods. The leading words 0 and 2 are
consistent with desktop direct and compute types; the Rust kinds are semantic
labels, not accepted wire values. Copy is included from the public lifecycle,
not from a measured Xbox call. Neither XCL call shapes nor VIctory behavior
establish Xbox lifetime or GPU-completion semantics for this model; no
reference implementation was ported.

This follows the lifecycle in the public D3D12 documentation:
[`CreateCommandList`][create] starts recording;
[`Close`][close] ends recording;
[`ID3D12GraphicsCommandList::Reset`][list-reset] requires a closed list and a
matching allocator not used by another recording list; and
[`ID3D12CommandAllocator::Reset`][alloc-reset] cannot reclaim storage while it
is recording or GPU work still uses it. An allocator reset advances its epoch,
invalidating earlier closed recordings for submission. In keeping with
[`ExecuteCommandLists`][execute] validation, an in-flight list cannot be
resubmitted, even to a different queue. Resetting a closed list before its
submission completes is allowed, but cannot change which allocator that
submission pins. Empty and duplicate-list batches fail explicitly in this
model; errors are Rust values, not Xbox HRESULT or device-removal claims.

## Backend seam

1. Call `prepare_submission(queue, lists)` to validate the entire ordered
   batch and borrow the model exclusively. The preparation exposes the
   validated queue and list order. If the backend rejects the batch without
   accepting work, drop the preparation: there is no state change.
2. Call `commit()` only after the backend accepts the batch. The returned
   token identifies the tracked batch; it is not a fence or proof of GPU
   progress. Every allocator used by the accepted batch stays pinned until
   retirement, including when shared by submissions on different queues.
3. Serialize completion ingestion with acceptance. Associate the token with
   an external point proving the **entire prefix on that queue** has finished
   (for example, a backend fence signal ordered after the batch, once that
   fence value has actually completed). Call `complete_through(queue, token)`
   only on that evidence. This retires the prefix in submission order, never
   later batches or work on another queue. Cross-queue tokens and regressed
   watermarks fail; repeating the current watermark has no effect. A call into
   this bookkeeping layer cannot itself authenticate the backend's evidence.

Run the owned lifecycle fixtures with
`cargo test --offline --test d3d12_command_state`. They supply explicit
completion inputs and need no GPU, console DLL, or title assets.

[create]: https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-createcommandlist
[close]: https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12graphicscommandlist-close
[list-reset]: https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12graphicscommandlist-reset
[alloc-reset]: https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12commandallocator-reset
[execute]: https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12commandqueue-executecommandlists
