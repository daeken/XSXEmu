#[cfg(any(target_os = "macos", test))]
mod alu;
#[cfg(any(target_os = "macos", test))]
mod buffer;
#[cfg(any(target_os = "macos", test))]
mod cfg;
#[cfg(any(target_os = "macos", test))]
mod exec;
#[cfg(any(target_os = "macos", test))]
mod exec_store;
#[cfg(target_os = "macos")]
mod metal_artifact;
#[cfg(any(target_os = "macos", test))]
mod metal_cache;
#[cfg(target_os = "macos")]
use metal_artifact::file_url;

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
enum ExecArchive {
    Bake(std::path::PathBuf),
    Replay(std::path::PathBuf),
    Library(std::path::PathBuf, Option<(bool, std::path::PathBuf)>),
}

#[cfg(target_os = "macos")]
fn owned_pipeline(
    dev: &metal::DeviceRef,
    source: &str,
    name: &str,
    archive: Option<ExecArchive>,
) -> Result<Option<metal::ComputePipelineState>, Box<dyn std::error::Error>> {
    use metal::{
        BinaryArchiveDescriptor, CompileOptions, ComputePipelineDescriptor, MTLPipelineOption,
    };
    let (lib, archive) = match archive {
        Some(ExecArchive::Library(path, archive)) => {
            file_url(&path, false)?;
            let lib = dev.new_library_with_file(&path)?;
            let archive = archive.map(|(bake, path)| {
                if bake {
                    ExecArchive::Bake(path)
                } else {
                    ExecArchive::Replay(path)
                }
            });
            (lib, archive)
        }
        archive => (
            dev.new_library_with_source(source, &CompileOptions::new())?,
            archive,
        ),
    };
    let function = lib.get_function(name, None)?;
    let pipeline = match archive {
        None => dev.new_compute_pipeline_state_with_function(&function)?,
        Some(ExecArchive::Library(..)) => unreachable!("external library mode was separated above"),
        Some(ExecArchive::Bake(path)) => {
            let url = file_url(&path, true)?;
            let archive = dev.new_binary_archive_with_descriptor(&BinaryArchiveDescriptor::new())?;
            let desc = ComputePipelineDescriptor::new();
            desc.set_compute_function(Some(&function));
            desc.set_binary_archives(&[&archive]);
            if dev
                .new_compute_pipeline_state_with_reflection(
                    &desc,
                    MTLPipelineOption::FailOnBinaryArchiveMiss,
                )
                .is_ok()
            {
                return Err("expected strict miss with an empty Metal binary archive".into());
            }
            // Populate using the same function and descriptor settings as replay.
            desc.set_binary_archives(&[]);
            if !archive.add_compute_pipeline_functions_with_descriptor(&desc)?
                || !archive.serialize_to_url(&url)?
            {
                return Err("Metal did not write the owned compute archive".into());
            }
            println!(
                "{}: empty archive refused; baked owned {name} pipeline",
                dev.name()
            );
            return Ok(None);
        }
        Some(ExecArchive::Replay(path)) => {
            let url = file_url(&path, false)?;
            let archive_desc = BinaryArchiveDescriptor::new();
            archive_desc.set_url(&url);
            let archive = dev.new_binary_archive_with_descriptor(&archive_desc)?;
            let desc = ComputePipelineDescriptor::new();
            desc.set_compute_function(Some(&function));
            desc.set_binary_archives(&[&archive]);
            let (pipeline, _) = dev.new_compute_pipeline_state_with_reflection(
                &desc,
                MTLPipelineOption::FailOnBinaryArchiveMiss,
            )?;
            println!(
                "{}: owned {name} compute pipeline created with FailOnBinaryArchiveMiss",
                dev.name()
            );
            pipeline
        }
    };
    Ok(Some(pipeline))
}

#[cfg(target_os = "macos")]
fn run_exec(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
    archive: Option<ExecArchive>,
) -> Result<(), Box<dyn std::error::Error>> {
    use metal::{MTLCommandBufferStatus, MTLResourceOptions, MTLSize};
    let program = exec::Program::decode(&exec::FIXTURE)?;
    let Some(pipeline) = owned_pipeline(dev, &program.msl(), "exec_fixture", archive)? else {
        return Ok(());
    };
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
const STORE_ENTRY: &str = "exec_store_fixture";
#[cfg(target_os = "macos")]
const STORE_BUFFER_SLOTS: [u64; 3] = [0, 1, 2];
#[cfg(target_os = "macos")]
const STORE_ARGS_WORDS: usize = 8;

#[cfg(target_os = "macos")]
fn keyed_exec_store(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
    bake: bool,
    [library, archive, profile, manifest_path]: [std::path::PathBuf; 4],
) -> Result<(), Box<dyn std::error::Error>> {
    use metal_cache::{Key, digest_file, manifest};
    use std::io::{Read, Write};
    file_url(&library, false)?;
    file_url(&profile, false)?;
    file_url(&archive, bake)?;
    file_url(&manifest_path, bake)?;
    if std::fs::metadata(&profile)?.len() == 0 {
        return Err("owned cache compiler profile is empty".into());
    }
    let os_build = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-buildVersion")
        .output()?;
    if !os_build.status.success() || os_build.stdout.is_empty() {
        return Err("owned cache requires the macOS build version".into());
    }
    let source = exec_store::Program::decode(&exec_store::FIXTURE)?.msl();
    let debug_layer = std::env::var_os("MTL_DEBUG_LAYER").unwrap_or_default();
    let mut key = Key::new();
    key.field("stage-entry", STORE_ENTRY.as_bytes())
        .field("msl", source.as_bytes())
        .field("metallib-sha256", &digest_file(&library)?)
        .field("compiler-profile-sha256", &digest_file(&profile)?)
        .field("os-build", &os_build.stdout)
        .field("host-arch", std::env::consts::ARCH.as_bytes())
        .field("device-name", dev.name().as_bytes())
        .field("device-registry-id", &dev.registry_id().to_le_bytes())
        .field("metal-debug-layer", debug_layer.as_encoded_bytes())
        .field(
            "pipeline-descriptor",
            b"compute defaults plus entry; no specialization",
        )
        .field(
            "binding-abi",
            b"shared u32 table ro, shared u32 output rw, inline constants; offset zero",
        )
        .field("inline-arg-count", &(STORE_ARGS_WORDS as u64).to_le_bytes())
        .field(
            "inline-arg-layout",
            b"u32 table_base,table_words,last_output_index,exec,data[4]",
        )
        .field(
            "launch-profile",
            b"one group; y=z=1; SIMD width must equal local x",
        )
        .field("local-x", &(exec_store::LANES as u64).to_le_bytes());
    for slot in STORE_BUFFER_SLOTS {
        key.field("slot", &slot.to_le_bytes());
    }
    let key = key.finish();
    if !bake {
        let expected = manifest(key, digest_file(&archive)?);
        let mut bytes = Vec::with_capacity(expected.len() + 1);
        std::fs::File::open(&manifest_path)?
            .take((expected.len() + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes != expected {
            return Err("owned cache identity mismatch (rejected before pipeline creation)".into());
        }
    }
    run_exec_store(
        dev,
        queue,
        Some(ExecArchive::Library(library, Some((bake, archive.clone())))),
    )?;
    if bake {
        let bytes = manifest(key, digest_file(&archive)?);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(manifest_path)?
            .write_all(&bytes)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_exec_store(
    dev: &metal::DeviceRef,
    queue: &metal::CommandQueueRef,
    archive: Option<ExecArchive>,
) -> Result<(), Box<dyn std::error::Error>> {
    use metal::{MTLCommandBufferStatus, MTLResourceOptions, MTLSize};
    let program = exec_store::Program::decode(&exec_store::FIXTURE)?;
    let Some(pipeline) = owned_pipeline(dev, &program.msl(), STORE_ENTRY, archive)? else {
        return Ok(());
    };
    let lanes = exec_store::LANES as u64;
    if pipeline.thread_execution_width() != lanes
        || pipeline.max_total_threads_per_threadgroup() < lanes
    {
        return Err("unsupported: EXEC-store requires a full wave32-sized SIMD group".into());
    }
    let opts = MTLResourceOptions::StorageModeShared;
    let initial = [buffer::SENTINEL; exec_store::OUTPUT];
    let mut verified = 0;
    for (index, case) in exec_store::cases().iter().enumerate() {
        let expected = case.expected();
        if program.cpu(case) != expected {
            return Err(format!("EXEC-store case {index}: CPU oracle mismatch").into());
        }
        let table = case.owned_table();
        let table = &table[..case.table_words()];
        let table_buf =
            dev.new_buffer_with_data(table.as_ptr().cast(), size_of_val(table) as u64, opts);
        let output =
            dev.new_buffer_with_data(initial.as_ptr().cast(), size_of_val(&initial) as u64, opts);
        let args: [u32; STORE_ARGS_WORDS] = [
            case.table_base,
            table.len() as u32,
            (initial.len() - 1) as u32,
            case.exec,
            0,
            0x8000_0000,
            0,
            u32::MAX,
        ];
        let work = queue.new_command_buffer();
        let encoder = work.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        let [table_slot, output_slot, args_slot] = STORE_BUFFER_SLOTS;
        encoder.set_buffer(table_slot, Some(&table_buf), 0);
        encoder.set_buffer(output_slot, Some(&output), 0);
        encoder.set_bytes(args_slot, size_of_val(&args) as u64, args.as_ptr().cast());
        encoder.dispatch_thread_groups(MTLSize::new(1, 1, 1), MTLSize::new(lanes, 1, 1));
        encoder.end_encoding();
        work.commit();
        work.wait_until_completed();
        if work.status() != MTLCommandBufferStatus::Completed {
            return Err(format!("EXEC-store Metal command failed ({:?})", work.status()).into());
        }
        // Metal has completed and the shared allocation contains all output words.
        let actual =
            unsafe { std::slice::from_raw_parts(output.contents().cast::<u32>(), initial.len()) };
        if let Some(word) = actual.iter().zip(expected).position(|(&a, b)| a != b) {
            return Err(format!("EXEC-store case {index}: mismatch at word {word}").into());
        }
        verified += actual.len();
    }
    println!(
        "{}: owned EXEC + bounded store, {verified}/{verified} CPU/Metal words match",
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
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    if mode.as_deref() == Some(std::ffi::OsStr::new("--emit-exec-store-msl")) {
        if args.next().is_some() {
            return Err("--emit-exec-store-msl takes no arguments".into());
        }
        use std::io::Write as _;
        let program = exec_store::Program::decode(&exec_store::FIXTURE)?;
        std::io::stdout()
            .lock()
            .write_all(program.msl().as_bytes())?;
        return Ok(());
    }
    let dev = metal::Device::system_default().ok_or("unsupported: no Metal device")?;
    let queue = dev.new_command_queue();
    if let Some(mode) = mode {
        if mode == "--load-exec-store-metallib" {
            let path = args
                .next()
                .filter(|_| args.next().is_none())
                .ok_or("--load-exec-store-metallib <owned library>")?;
            return run_exec_store(&dev, &queue, Some(ExecArchive::Library(path.into(), None)));
        }
        let usage = "usage: shader-metal-probe [--bake-exec-archive | --replay-exec-archive | --bake-exec-store-archive | --replay-exec-store-archive] [file]";
        if std::env::var_os("MTL_SHADER_VALIDATION").is_some_and(|v| v != "0" && !v.is_empty()) {
            return Err("this binary archive probe does not support Metal GPU shader validation instrumentation; use the regular probe for GPU validation".into());
        }
        if mode == "--bake-keyed-exec-store-archive" || mode == "--replay-keyed-exec-store-archive"
        {
            let usage = "--bake-keyed-exec-store-archive|--replay-keyed-exec-store-archive <owned metallib> <archive> <compiler profile> <manifest>";
            let paths = args
                .map(std::path::PathBuf::from)
                .take(5)
                .collect::<Vec<_>>();
            return keyed_exec_store(
                &dev,
                &queue,
                mode == "--bake-keyed-exec-store-archive",
                paths.try_into().map_err(|_| usage)?,
            );
        }
        if mode == "--bake-exec-store-metallib-archive"
            || mode == "--replay-exec-store-metallib-archive"
        {
            let usage = "--bake-exec-store-metallib-archive|--replay-exec-store-metallib-archive <owned library> <archive>";
            let lib = args.next().ok_or(usage)?;
            let path = args.next().filter(|_| args.next().is_none()).ok_or(usage)?;
            let bake = mode == "--bake-exec-store-metallib-archive";
            return run_exec_store(
                &dev,
                &queue,
                Some(ExecArchive::Library(lib.into(), Some((bake, path.into())))),
            );
        }
        let path = args
            .next()
            .filter(|_| args.next().is_none())
            .ok_or(usage)?
            .into();
        match mode.to_str() {
            Some("--bake-exec-archive") => {
                return run_exec(&dev, &queue, Some(ExecArchive::Bake(path)));
            }
            Some("--replay-exec-archive") => {
                return run_exec(&dev, &queue, Some(ExecArchive::Replay(path)));
            }
            Some("--bake-exec-store-archive") => {
                return run_exec_store(&dev, &queue, Some(ExecArchive::Bake(path)));
            }
            Some("--replay-exec-store-archive") => {
                return run_exec_store(&dev, &queue, Some(ExecArchive::Replay(path)));
            }
            _ => return Err(usage.into()),
        }
    }
    run_alu(&dev, &queue, "ALU", &alu::FIXTURE)?;
    run_alu(&dev, &queue, "branch/literal", &alu::BRANCH_FIXTURE)?;
    run_alu(&dev, &queue, "owned forward PC", &alu::PC_FORWARD_FIXTURE)?;
    run_alu(&dev, &queue, "owned backward PC", &alu::PC_BACKWARD_FIXTURE)?;
    run_exec(&dev, &queue, None)?;
    run_buffer(&dev, &queue)?;
    run_exec_store(&dev, &queue, None)
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
