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

static void exercise(id<MTLDevice> dev, BOOL marker) {
    const NSUInteger size = 64, start = 16, length = 32;
    const uint8_t initial = 0x17, written = 0xa6;
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
        memset(bytes.contents, initial, size);
        [residency addAllocation:bytes];
        [residency commit];
        [q addResidencySet:residency];
    }

    [cb beginCommandBufferWithAllocator:allocator];
    if (marker) {
        id<MTL4ComputeCommandEncoder> encoder = [cb computeCommandEncoder];
        require(encoder != nil, "compute encoder unavailable");
        [encoder fillBuffer:bytes range:NSMakeRange(start, length) value:written];
        [encoder endEncoding];
    }
    [cb endCommandBuffer];

    KEEP MTL4CommitOptions *options = [MTL4CommitOptions new];
    KEEP dispatch_semaphore_t feedbackDone = dispatch_semaphore_create(0);
    __block NSError *gpuError = nil;
    [options addFeedbackHandler:^(id<MTL4CommitFeedback> result) {
        gpuError = result.error;
        dispatch_semaphore_signal(feedbackDone);
    }];
    id<MTL4CommandBuffer> packet[] = { cb };
    [q commit:packet count:1 options:options];
    [q signalEvent:event value:1];
    require([event waitUntilSignaledValue:1 timeoutMS:3000], "queue-ordered event timeout");
    require(event.signaledValue == 1, "wrong completion value");
    require(dispatch_semaphore_wait(feedbackDone, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0,
            "commit feedback timeout");
    if (gpuError) fprintf(stderr, "feedback: %s\n", gpuError.description.UTF8String);
    require(gpuError == nil, "Metal commit feedback reported an error");

    if (marker) {
        const uint8_t *readback = bytes.contents;
        NSUInteger matched = 0;
        for (NSUInteger i = 0; i < size; i++) {
            uint8_t expected = (i >= start && i < start + length) ? written : initial;
            matched += (readback[i] == expected);
        }
        require(matched == size, "marker readback or outer canaries differ");
        printf("marker: event=1 feedback=no-error readback=%lu/%lu (32 changed, 32 untouched)\n",
               (unsigned long)matched, (unsigned long)size);
        [q removeResidencySet:residency];
    } else {
        puts("empty: event=1 feedback=no-error encoders=0");
    }
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
        exercise(dev, NO);
        fflush(stdout);
        exercise(dev, YES);
    }
    return 0;
}
