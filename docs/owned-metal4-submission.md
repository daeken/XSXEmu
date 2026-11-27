# Owned Metal 4 submission and completion

`tools/mtl4-submission-smoke.m` is an independent host-only smoke. It uses the installed Metal SDK declarations (`MTLDevice.h`, `MTL4CommandBuffer.h`, `MTL4CommandQueue.h`, `MTL4CommitFeedback.h`, `MTLEvent.h`), with no guest-side ABI or translated title data.

From the repository root:

```sh
out=$(mktemp -d)
for cpu in arm64 x86_64; do
    xcrun clang -arch "$cpu" -mmacosx-version-min=26 -O2 -Wall -Wextra -Werror \
        -fobjc-arc -framework Foundation -framework Metal \
        tools/mtl4-submission-smoke.m -o "$out/$cpu" || exit
    MTL_DEBUG_LAYER=1 arch -"$cpu" "$out/$cpu" || exit
done
```

Each case uses a real Metal 4 queue, allocator and command buffer verified to belong to the same device. Each generation begins and ends one buffer, passes an array of one buffer to `commit:count:options:`, then queues `signalEvent:value:`. The SDK specifies that the signal runs after earlier GPU work on that queue; the CPU never sets the event. The test requires the generation's event value within 3 seconds and independent per-commit feedback without a GPU error within a second 3-second wait. References to the queue, allocator, buffer, event, and marker resources survive through both checks. A failure exits the process instead of unwinding while GPU work may still be in flight.

Validated with macOS SDK 27.0 on macOS 27.0.1 (`26A434`), Apple M4, API Validation Enabled (`MTL_DEBUG_LAYER=1`):

| Architecture | Empty ended buffer | Owned marker | Recycled slot |
| --- | --- | --- | --- |
| arm64 native | Event `1`, no feedback error, zero encoders | Event `1`, no feedback error, 64/64 expected bytes | Events `1` then `2`, no feedback errors, 128/128 expected bytes |
| x86_64 under Rosetta | Event `1`, no feedback error, zero encoders | Event `1`, no feedback error, 64/64 expected bytes | Events `1` then `2`, no feedback errors, 128/128 expected bytes |

The marker fills 32 bytes of a resident shared buffer with `0xa6` and reads back after completion; the 32 surrounding bytes retain `0x17`.

The recycled-slot case checks that the same command buffer and allocator can record and submit a fresh generation after retirement. Generation 1 writes `0xa6` to bytes `[16, 32)`. Only after the queue signal, feedback, and full readback does the test reset the allocator and restore all 64 bytes to `0x17`. It then begins the **same** command buffer with the **same** allocator; generation 2 writes `0x59` to `[32, 48)`. The first range must stay at `0x17` in the second readback, so replay of the previous recording cannot pass. This is serial host reuse, not an attempt to reset an in-flight allocator.

The [standalone command-state tests](d3d12-command-state.md) already cover stale recordings, in-flight pinning, and ordered prefix retirement in the model. This smoke checks actual Metal 4 re-recording after completion; it does not exercise the model's admission path, title queue slot 35, guest ownership or token semantics, or any guest recording/reset path.
