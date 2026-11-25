use crate::{
    host_backing::{Backing, Error as BackingError, PAGE, View},
    metal_backing,
};
use metal::{
    CommandQueueRef, CompileOptions, ComputePipelineStateRef, Device, MTLCommandBufferStatus,
    MTLSize,
};
use objc::rc::autoreleasepool;

const VIEW_LEN: u64 = 2 * PAGE;
const LAST_WORD: u64 = PAGE - 4;
const KERN_INVALID_ADDRESS: i32 = 1;
const KERNEL: &str = r#"
#include <metal_stdlib>
using namespace metal;
kernel void exercise(device uint *words [[buffer(0)]], uint tid [[thread_position_in_grid]]) {
    if (tid == 0) words[0] ^= 0x13579bdfu;
    if (tid == 1) words[16383] ^= 0x2468ace0u;
}
"#;

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getpagesize() -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

fn sample_mapping(address: u64) -> Result<u8, i32> {
    let (mut byte, mut size) = (0_u8, 0);
    // SAFETY: Destination is a writable stack byte, the kernel checks source VA.
    let status = unsafe {
        mach_vm_read_overwrite(
            mach_task_self_,
            address,
            1,
            (&raw mut byte).addr() as u64,
            &mut size,
        )
    };
    if status != 0 {
        return Err(status);
    }
    assert_eq!(size, 1);
    Ok(byte)
}

pub(crate) fn check_unmapped(base: u64, len: u64) {
    for address in [base, base + len - 1] {
        assert_eq!(
            sample_mapping(address),
            Err(KERN_INVALID_ADDRESS),
            "former mapping endpoint {address:#x}"
        );
    }
}

fn word(view: &View, offset: u64) -> u32 {
    let mut dst = [0; 4];
    view.read(offset, &mut dst).unwrap();
    u32::from_ne_bytes(dst)
}

fn store(view: &View, offset: u64, val: u32) {
    view.write(offset, &val.to_ne_bytes()).unwrap();
}

fn dispatch(
    queue: &CommandQueueRef,
    pipeline: &ComputePipelineStateRef,
    buffer: &metal::BufferRef,
) -> Result<(), String> {
    let work = queue.new_command_buffer();
    let enc = work.new_compute_command_encoder();
    enc.set_compute_pipeline_state(pipeline);
    enc.set_buffer(0, Some(buffer), 0);
    enc.dispatch_threads(MTLSize::new(2, 1, 1), MTLSize::new(2, 1, 1));
    enc.end_encoding();
    work.commit();
    work.wait_until_completed();
    if work.status() != MTLCommandBufferStatus::Completed {
        return Err(format!(
            "Metal command completed with status {:?}",
            work.status()
        ));
    }
    Ok(())
}

pub fn run() -> Result<(), String> {
    autoreleasepool(|| {
        let device = Device::system_default().ok_or("MTLCreateSystemDefaultDevice returned nil")?;
        // SAFETY: libSystem reports this process's page size.
        let host_page = unsafe { getpagesize() };
        println!(
            "Metal device={:?} arch={} getpagesize={host_page} logical_page={PAGE}",
            device.name(),
            std::env::consts::ARCH
        );
        let backing = Backing::new(3 * PAGE).map_err(|e| format!("create backing: {e:?}"))?;
        for (name, offset, len) in [
            ("zero length", 0, 0),
            ("unaligned offset", 1, PAGE),
            ("unaligned length", 0, PAGE - 1),
            ("out of view", PAGE, 2 * PAGE),
            ("overflow", u64::MAX - PAGE + 1, PAGE),
        ] {
            let view = backing.map(0, VIEW_LEN).unwrap();
            let base = view.base_address();
            // SAFETY: No submission or concurrent access. Every request is rejected before Metal.
            let rejected = unsafe { metal_backing::import(&device, view, offset, len) };
            assert_eq!(
                rejected.err(),
                Some(metal_backing::Error::Range(BackingError::InvalidRange)),
                "{name}"
            );
            check_unmapped(base, VIEW_LEN);
            println!("PASS rejected {name}, consumed view unmapped");
        }
        let mapped = backing
            .map(0, VIEW_LEN)
            .map_err(|e| format!("map import view: {e:?}"))?;
        let cpu = backing
            .map(PAGE, VIEW_LEN)
            .map_err(|e| format!("map CPU alias: {e:?}"))?;
        let (base, cpu_base) = (mapped.base_address(), cpu.base_address());
        assert!(base.is_multiple_of(PAGE) && cpu_base.is_multiple_of(PAGE));
        assert!(base + VIEW_LEN <= cpu_base || cpu_base + VIEW_LEN <= base);
        store(&mapped, LAST_WORD, 0xa5a5a5a5); // Before imported range.
        store(&cpu, PAGE, 0x12345678); // After imported range.
        store(&cpu, 0, 0xf1e2d3c4);
        drop(backing);
        autoreleasepool(|| {
            // SAFETY: All aliased access in this test is on the same thread and
            // each dispatch finishes successfully before any further CPU access.
            let buffer = match unsafe { metal_backing::import(&device, mapped, PAGE, PAGE) } {
                Ok(buffer) => buffer,
                Err(e) => {
                    return Err(format!(
                        "newBufferWithBytesNoCopy shared Mach VA {:#x} length {PAGE}: {e:?}; no fallback",
                        base + PAGE
                    ));
                }
            };
            // SAFETY: The checked buffer has the same pointer and page extent;
            // it is live and idle and the address is properly aligned for u32.
            assert_eq!(
                unsafe { buffer.contents().cast::<u32>().read_volatile() },
                0xf1e2d3c4
            );
            // SAFETY: Same as above; no Rust references to the mapped bytes.
            unsafe { buffer.contents().cast::<u32>().write_volatile(0xc001cafe) };
            assert_eq!(word(&cpu, 0), 0xc001cafe);
            println!(
                "PASS Metal contents pointer identity and CPU/Metal host writes in both directions"
            );

            let retained = buffer.clone();
            drop(buffer);
            let library = device.new_library_with_source(KERNEL, &CompileOptions::new())?;
            let function = library.get_function("exercise", None)?;
            let pipeline = device.new_compute_pipeline_state_with_function(&function)?;
            let queue = device.new_command_queue();
            for (a, b) in [(0x01020304, 0x11223344), (0xfeedface, 0x9abcdef0)] {
                // Fresh CPU writes after import, no copy or explicit flush.
                store(&cpu, 0, a);
                store(&cpu, LAST_WORD, b);
                assert_eq!(sample_mapping(base + PAGE), Ok(a as u8));
                dispatch(&queue, &pipeline, &retained)?;
                assert_eq!(word(&cpu, 0), a ^ 0x13579bdf);
                assert_eq!(word(&cpu, LAST_WORD), b ^ 0x2468ace0);
                assert_eq!(word(&cpu, PAGE), 0x12345678);
                assert_eq!(sample_mapping(base + LAST_WORD), Ok(0xa5));
            }
            println!(
                "PASS 4/4 in-place GPU RMW words via CPU alias after command completion; adjacent pages untouched"
            );
            Ok(())
        })?;
        // Drop the retained buffer and drain autoreleased Metal work before testing
        // unmap, then ensure the independent CPU view remains live and writable.
        check_unmapped(base, VIEW_LEN);
        assert_eq!(word(&cpu, 0), 0xfeedface ^ 0x13579bdf);
        store(&cpu, 0, 0x99);
        assert_eq!(word(&cpu, 0), 0x99);
        drop(cpu);
        check_unmapped(cpu_base, VIEW_LEN);
        println!(
            "PASS retained Metal buffer pinned full import view; final release unmapped it, CPU alias survived until its own drop"
        );
        Ok(())
    })
}
