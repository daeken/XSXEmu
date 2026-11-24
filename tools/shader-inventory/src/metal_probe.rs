#[cfg(target_os = "macos")]
mod alu;

#[cfg(target_os = "macos")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use alu::{FIXTURE, LANES, MASK, SENTINEL};
    use metal::{CompileOptions, Device, MTLCommandBufferStatus, MTLResourceOptions, MTLSize};
    let dev = Device::system_default().ok_or("unsupported: no Metal device")?;
    let source = alu::msl(&FIXTURE)?;
    let lib = dev.new_library_with_source(&source, &CompileOptions::new())?;
    let function = lib.get_function("fixture", None)?;
    let pipeline = dev.new_compute_pipeline_state_with_function(&function)?;
    if pipeline.thread_execution_width() != LANES as u64
        || pipeline.max_total_threads_per_threadgroup() < LANES as u64
    {
        return Err("unsupported: fixture requires one 32-lane SIMD group".into());
    }
    let queue = dev.new_command_queue();
    let mut input: [u32; LANES] = std::array::from_fn(|i| (i as u32).wrapping_mul(0x9e3779b9));
    input[0] = u32::MAX;
    input[1] = 0x8000_0000;
    let initialized = [SENTINEL; LANES];
    let opts = MTLResourceOptions::StorageModeShared;
    let bytes = size_of_val(&input) as u64;
    for mask in [MASK, u32::MAX, 0] {
        let expected = alu::cpu(&FIXTURE, &input, mask)?;
        let ins = dev.new_buffer_with_data(input.as_ptr().cast(), bytes, opts);
        let outs = dev.new_buffer_with_data(initialized.as_ptr().cast(), bytes, opts);
        let exec =
            dev.new_buffer_with_data((&raw const mask).cast(), size_of::<u32>() as u64, opts);
        let work = queue.new_command_buffer();
        let encoder = work.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        for (slot, buffer) in [&ins, &outs, &exec].into_iter().enumerate() {
            encoder.set_buffer(slot as u64, Some(buffer), 0);
        }
        encoder.dispatch_thread_groups(MTLSize::new(1, 1, 1), MTLSize::new(LANES as u64, 1, 1));
        encoder.end_encoding();
        work.commit();
        work.wait_until_completed();
        if work.status() != MTLCommandBufferStatus::Completed {
            return Err(format!("Metal command failed ({:?})", work.status()).into());
        }
        // The shared buffer is `bytes` long and aligned; GPU completion precedes the host read.
        let actual = unsafe { std::slice::from_raw_parts(outs.contents().cast::<u32>(), LANES) };
        if let Some(lane) = actual.iter().zip(expected).position(|(&a, b)| a != b) {
            return Err(format!(
                "mask {mask:#010x}, lane {lane}: got {:#010x}, expected {:#010x}",
                actual[lane], expected[lane]
            )
            .into());
        }
    }
    println!(
        "{}: {}-lane fixture, 96/96 CPU/Metal readback words match",
        dev.name(),
        pipeline.thread_execution_width()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = metal::objc::rc::autoreleasepool(run) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("unsupported: shader-metal-probe requires macOS Metal");
    std::process::exit(1);
}
