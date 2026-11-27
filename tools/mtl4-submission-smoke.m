// Original Metal 4 host-only submission/completion smoke. Compile with ARC.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEEP __attribute__((objc_precise_lifetime))

static void require(BOOL ok, const char *why) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", why);
        // Do not unwind and release possibly in-flight objects on timeout.
        _Exit(1);
    }
}

static void commit_and_wait(id<MTL4CommandQueue> q, id<MTL4CommandBuffer> cb,
                            id<MTLSharedEvent> event, uint64_t generation) {
    KEEP MTL4CommitOptions *options = [MTL4CommitOptions new];
    KEEP dispatch_semaphore_t feedbackDone = dispatch_semaphore_create(0);
    __block NSError *gpuError = nil;
    [options addFeedbackHandler:^(id<MTL4CommitFeedback> result) {
        gpuError = result.error;
        dispatch_semaphore_signal(feedbackDone);
    }];
    id<MTL4CommandBuffer> packet[] = { cb };
    require(event.signaledValue == generation - 1, "wrong prior completion value");
    [q commit:packet count:1 options:options];
    [q signalEvent:event value:generation];
    require([event waitUntilSignaledValue:generation timeoutMS:3000], "queue-ordered event timeout");
    require(event.signaledValue == generation, "wrong completion value");
    require(dispatch_semaphore_wait(feedbackDone, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0,
            "commit feedback timeout");
    if (gpuError) fprintf(stderr, "feedback: %s\n", gpuError.description.UTF8String);
    require(gpuError == nil, "Metal commit feedback reported an error");
}

typedef enum { SmokeEmpty, SmokeMarker, SmokeRecycle } SmokeCase;

static void exercise(id<MTLDevice> dev, SmokeCase which) {
    const NSUInteger size = 64;
    const uint8_t initial = 0x17;
    const BOOL marker = which != SmokeEmpty;
    KEEP id<MTL4CommandQueue> q = [dev newMTL4CommandQueue];
    KEEP id<MTL4CommandAllocator> allocator = [dev newCommandAllocator];
    KEEP id<MTL4CommandBuffer> cb = [dev newCommandBuffer];
    KEEP id<MTLSharedEvent> event = [dev newSharedEvent];
    require(q && allocator && cb && event, "Metal 4 objects unavailable");
    require(q.device == dev && allocator.device == dev && cb.device == dev && event.device == dev,
            "objects must share the device");
    require(event.signaledValue == 0, "event must start unsignaled");

    KEEP id<MTLBuffer> bytes = nil;
    KEEP id<MTLResidencySet> residency = nil;
    if (marker) {
        bytes = [dev newBufferWithLength:size options:MTLResourceStorageModeShared];
        NSError *error = nil;
        residency = [dev newResidencySetWithDescriptor:[MTLResidencySetDescriptor new] error:&error];
        if (error) fprintf(stderr, "residency: %s\n", error.description.UTF8String);
        require(bytes && bytes.contents && bytes.device == dev && residency, "marker resources unavailable");
        [residency addAllocation:bytes];
        [residency commit];
        [q addResidencySet:residency];
    }

    const uint64_t generations = which == SmokeRecycle ? 2 : 1;
    for (uint64_t generation = 1; generation <= generations; generation++) {
        // The same physical slot is recycled only after the prior queue signal,
        // commit feedback and readback. Never test an illegal early Metal reset.
        if (generation == 2) [allocator reset];
        const NSUInteger start = generation == 1 ? 16 : 32;
        const NSUInteger length = which == SmokeRecycle ? 16 : 32;
        const uint8_t written = generation == 1 ? 0xa6 : 0x59;
        // Clear the previous marker so replay of the old (disjoint) range is observable.
        if (marker) memset(bytes.contents, initial, size);
        [cb beginCommandBufferWithAllocator:allocator];
        if (marker) {
            id<MTL4ComputeCommandEncoder> encoder = [cb computeCommandEncoder];
            require(encoder != nil, "compute encoder unavailable");
            [encoder fillBuffer:bytes range:NSMakeRange(start, length) value:written];
            [encoder endEncoding];
        }
        [cb endCommandBuffer];
        commit_and_wait(q, cb, event, generation);

        if (!marker) {
            puts("empty: event=1 feedback=no-error encoders=0");
            continue;
        }
        const uint8_t *readback = bytes.contents;
        NSUInteger matched = 0;
        for (NSUInteger i = 0; i < size; i++) {
            uint8_t expected = (i >= start && i < start + length) ? written : initial;
            matched += (readback[i] == expected);
        }
        require(matched == size, "marker readback or outer canaries differ");
        printf("%s: event=%llu feedback=no-error readback=%lu/%lu (%lu changed, %lu untouched)\n",
               which == SmokeRecycle ? "recycle" : "marker", (unsigned long long)generation,
               (unsigned long)matched, (unsigned long)size,
               (unsigned long)length, (unsigned long)(size - length));
    }
    if (marker) [q removeResidencySet:residency];
}

int main(void) {
    @autoreleasepool {
        const char *debug = getenv("MTL_DEBUG_LAYER");
        require(debug && strcmp(debug, "1") == 0, "run with MTL_DEBUG_LAYER=1");
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        require(dev && [dev supportsFamily:MTLGPUFamilyMetal4], "Metal 4 device unavailable");
#if defined(__arm64__)
        const char *arch = "arm64";
#elif defined(__x86_64__)
        const char *arch = "x86_64";
#endif
        printf("arch=%s device=%s MTL_DEBUG_LAYER=%s\n", arch, dev.name.UTF8String, debug);
        fflush(stdout);
        exercise(dev, SmokeEmpty);
        fflush(stdout);
        exercise(dev, SmokeMarker);
        fflush(stdout);
        exercise(dev, SmokeRecycle);
    }
    return 0;
}
