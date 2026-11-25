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

Both cases use a real Metal 4 queue, allocator and command buffer verified to belong to the same device. Each begins and ends one buffer, passes an array of one buffer to `commit:count:options:`, then queues `signalEvent:value:`. The SDK specifies that the signal runs after earlier GPU work on that queue; the CPU never sets the event. The test requires event value `1` within 3 seconds and independent commit feedback without a GPU error within a second 3-second wait. References to the queue, allocator, buffer, event, and marker resources survive through both checks. A failure exits the process instead of unwinding while GPU work may still be in flight.

Validated with macOS SDK 27.0 on macOS 27.0.1 (`26A434`), Apple M4, API Validation Enabled (`MTL_DEBUG_LAYER=1`):

| Architecture | Empty ended buffer | Owned marker |
| --- | --- | --- |
| arm64 native | Event `1`, no feedback error, zero encoders | Event `1`, no feedback error, 64/64 expected bytes |
| x86_64 under Rosetta | Event `1`, no feedback error, zero encoders | Event `1`, no feedback error, 64/64 expected bytes |

The marker fills 32 bytes of a resident shared buffer with `0xa6` and reads back after completion; the 32 surrounding bytes retain `0x17`. This demonstrates host submission and ordered completion for a single empty buffer and a single deterministic write on this device. It does not test title queue slot 35, guest ownership or token semantics, or any guest recording/reset path.
