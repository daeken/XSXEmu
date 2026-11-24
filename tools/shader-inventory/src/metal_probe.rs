#[cfg(any(target_os = "macos", test))]
mod alu;
#[cfg(any(target_os = "macos", test))]
mod buffer;
#[cfg(any(target_os = "macos", test))]
mod cfg;
#[cfg(any(target_os = "macos", test))]
mod exec;

#[cfg(target_os = "macos")]
fn run_alu(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
    label: &str,
    code: &[u32],
) -> Result<(), Box<dyn std::error::Error>> {
    use alu::{LANES, MASK, SENTINEL};
    use metal::{CompileOptions, MTLCommandBufferStatus, MTLResourceOptions, MTLSize};
    let source = alu::msl(code)?;
    let lib = dev.new_library_with_source(&source, &CompileOptions::new())?;
    let function = lib.get_function("fixture", None)?;
    let pipeline = dev.new_compute_pipeline_state_with_function(&function)?;
    if pipeline.thread_execution_width() != LANES as u64
        || pipeline.max_total_threads_per_threadgroup() < LANES as u64
    {
        return Err("unsupported: fixture requires one 32-lane SIMD group".into());
    }
    let mut input: [u32; LANES] = std::array::from_fn(|i| (i as u32).wrapping_mul(0x9e3779b9));
    input[0] = u32::MAX;
    input[1] = 0x8000_0000;
    let initialized = [SENTINEL; LANES];
    let opts = MTLResourceOptions::StorageModeShared;
    let bytes = size_of_val(&input) as u64;
    for mask in [MASK, u32::MAX, 0] {
        let expected = alu::cpu(code, &input, mask)?;
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
        "{}: {}-lane {label} fixture, 96/96 CPU/Metal readback words match",
        dev.name(),
        pipeline.thread_execution_width()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_exec(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
) -> Result<(), Box<dyn std::error::Error>> {
    use metal::{CompileOptions, MTLCommandBufferStatus, MTLResourceOptions, MTLSize};
    let program = exec::Program::decode(&exec::FIXTURE)?;
    let lib = dev.new_library_with_source(&program.msl(), &CompileOptions::new())?;
    let function = lib.get_function("exec_fixture", None)?;
    let pipeline = dev.new_compute_pipeline_state_with_function(&function)?;
    if pipeline.thread_execution_width() != exec::LANES as u64
        || pipeline.max_total_threads_per_threadgroup() < exec::LANES as u64
    {
        return Err("unsupported: EXEC fixture requires a full wave32-sized SIMD group".into());
    }
    let opts = MTLResourceOptions::StorageModeShared;
    let input = std::array::from_fn(|lane| lane as u32);
    let initialized = [exec::SENTINEL; exec::OUTPUT_WORDS];
    let input_buf =
        dev.new_buffer_with_data(input.as_ptr().cast(), size_of_val(&input) as u64, opts);
    for (mask, survivors, exit) in exec::CASES {
        let expected = exec::expected(survivors, exit);
        if program.run(&input, mask) != expected {
            return Err("EXEC fixture disagrees with CPU oracle".into());
        }
        let output = dev.new_buffer_with_data(
            initialized.as_ptr().cast(),
            size_of_val(&initialized) as u64,
            opts,
        );
        let work = queue.new_command_buffer();
        let encoder = work.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        encoder.set_buffer(0, Some(&input_buf), 0);
        encoder.set_buffer(1, Some(&output), 0);
        encoder.set_bytes(2, size_of::<u32>() as u64, (&raw const mask).cast());
        encoder.dispatch_thread_groups(
            MTLSize::new(1, 1, 1),
            MTLSize::new(exec::LANES as u64, 1, 1),
        );
        encoder.end_encoding();
        work.commit();
        work.wait_until_completed();
        if work.status() != MTLCommandBufferStatus::Completed {
            return Err(format!("EXEC Metal command failed ({:?})", work.status()).into());
        }
        // The aligned shared output was allocated for this many words; the GPU is done.
        let actual = unsafe {
            std::slice::from_raw_parts(output.contents().cast::<u32>(), exec::OUTPUT_WORDS)
        };
        if let Some(word) = actual.iter().zip(expected).position(|(&a, b)| a != b) {
            return Err(format!("owned EXEC mismatch: mask {mask:#x}, output index {word}").into());
        }
    }
    let words = exec::CASES.len() * exec::OUTPUT_WORDS;
    println!(
        "{}: owned wave32 EXEC/branch, {words}/{words} CPU/Metal words match (including exits)",
        dev.name()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_buffer(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
) -> Result<(), Box<dyn std::error::Error>> {
    use metal::{CompileOptions, MTLCommandBufferStatus, MTLResourceOptions, MTLSize};

    let program = buffer::Program::decode(&buffer::FIXTURE)?;
    let lib = dev.new_library_with_source(&program.msl(), &CompileOptions::new())?;
    let function = lib.get_function("buffer_fixture", None)?;
    let pipeline = dev.new_compute_pipeline_state_with_function(&function)?;
    let opts = MTLResourceOptions::StorageModeShared;
    let mut words = 0;
    let cases = buffer::cases();
    for case in &cases {
        let table = case.table();
        let initial = vec![buffer::SENTINEL; case.output_words];
        let mut expected = initial.clone();
        program.cpu(table, &mut expected, case.input);
        if expected != case.expected() {
            return Err(format!("{}: CPU disagrees with fixture oracle", case.name).into());
        }
        let table_buf =
            dev.new_buffer_with_data(table.as_ptr().cast(), size_of_val(table) as u64, opts);
        let output_buf = dev.new_buffer_with_data(
            initial.as_ptr().cast(),
            size_of_val(initial.as_slice()) as u64,
            opts,
        );
        let [v0, v9, v10, v11] = case.input.data;
        // Lengths are derived from the actual bound slices, never from the descriptor.
        let args = [
            case.input.table_base,
            u32::try_from(table.len())?,
            u32::try_from(initial.len())?,
            case.input.lane_offset,
            v0,
            v9,
            v10,
            v11,
        ];
        let work = queue.new_command_buffer();
        let encoder = work.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        encoder.set_buffer(0, Some(&table_buf), 0);
        encoder.set_buffer(1, Some(&output_buf), 0);
        encoder.set_bytes(2, size_of_val(&args) as u64, args.as_ptr().cast());
        let one = MTLSize::new(1, 1, 1);
        encoder.dispatch_thread_groups(one, one);
        encoder.end_encoding();
        work.commit();
        work.wait_until_completed();
        if work.status() != MTLCommandBufferStatus::Completed {
            return Err(
                format!("{}: Metal command failed ({:?})", case.name, work.status()).into(),
            );
        }
        // The shared allocation holds `initial.len()` aligned u32s. GPU work has completed.
        let actual = unsafe {
            std::slice::from_raw_parts(output_buf.contents().cast::<u32>(), initial.len())
        };
        if let Some(i) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
            return Err(format!(
                "{}: output word {i}: got {:#010x}, expected {:#010x}",
                case.name, actual[i], expected[i]
            )
            .into());
        }
        words += actual.len();
    }
    println!(
        "{}: owned buffer fixture: {} cases, {words}/{words} CPU/Metal readback words match",
        dev.name(),
        cases.len()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let dev = metal::Device::system_default().ok_or("unsupported: no Metal device")?;
    let queue = dev.new_command_queue();
    run_alu(&dev, &queue, "ALU", &alu::FIXTURE)?;
    run_alu(&dev, &queue, "branch/literal", &alu::BRANCH_FIXTURE)?;
    run_exec(&dev, &queue)?;
    run_buffer(&dev, &queue)
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
