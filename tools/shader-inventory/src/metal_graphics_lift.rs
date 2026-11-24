//! Execution and archive verification for the owned native graphics lift.
#[cfg(any(test, target_os = "macos"))]
mod graphics_lift;
#[cfg(target_os = "macos")]
mod metal_artifact;

// Integer oracle for the chosen fullscreen triangle and no-perspective varying.
// Red = (x + 0.5)/16 + native literal (1/4 or 1/2); GB are native export swizzles.
#[cfg(any(test, target_os = "macos"))]
fn expected(x: usize, mutated: bool) -> [u8; 4] {
    let red_numerator = 2 * x + 1 + if mutated { 16 } else { 8 };
    [((red_numerator * 255 + 16) / 32) as u8, 191, 64, 255]
}

#[cfg(target_os = "macos")]
mod gpu {
    use super::*;
    use metal::*;
    use std::path::Path;

    enum Mode<'a> {
        Source,
        Load(&'a Path, bool),
        Archive(&'a Path, &'a Path, bool),
    }

    fn strict(
        dev: &DeviceRef,
        desc: &RenderPipelineDescriptorRef,
    ) -> Result<RenderPipelineState, String> {
        dev.new_render_pipeline_state_with_reflection(
            desc,
            MTLPipelineOption::FailOnBinaryArchiveMiss,
        )
        .map(|(p, _)| p)
        .map_err(|err| {
            err.lines()
                .next()
                .unwrap_or("no Metal error description")
                .trim()
                .to_owned()
        })
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let mode = match args.as_slice() {
            [] => Mode::Source,
            [mode] if mode == "--emit-msl" || mode == "--emit-mutated-msl" => {
                let literal = (mode == "--emit-mutated-msl").then_some(0x3f00_0000);
                print!("{}", graphics_lift::translate_fixture(literal).map_err(|e| format!("lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode, lib] if mode == "--load-metallib" || mode == "--load-mutated-metallib" => Mode::Load(Path::new(lib), mode == "--load-mutated-metallib"),
            [mode, lib, archive] if mode == "--bake-archive" || mode == "--replay-archive" => Mode::Archive(Path::new(lib), Path::new(archive), mode == "--bake-archive"),
            _ => return Err("usage: shader-metal-graphics-lift [--emit-msl | --emit-mutated-msl | --load-metallib LIB | --load-mutated-metallib LIB | --bake-archive LIB ARCHIVE | --replay-archive LIB ARCHIVE]".into()),
        };
        let dev = Device::system_default().ok_or("no Metal device")?;
        let lib = match mode {
            Mode::Source => {
                let msl = graphics_lift::translate_fixture(None)
                    .map_err(|e| format!("lift rejected: {e:?}"))?;
                let options = CompileOptions::new();
                options.set_fast_math_enabled(false);
                dev.new_library_with_source(&msl, &options)?
            }
            Mode::Load(path, _) | Mode::Archive(path, _, _) => {
                metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
                dev.new_library_with_file(path)?
            }
        };
        let desc = RenderPipelineDescriptor::new();
        let format = MTLPixelFormat::RGBA8Unorm;
        let vs = lib.get_function("translated_vs", None)?;
        let ps = lib.get_function("translated_ps", None)?;
        desc.set_vertex_function(Some(&vs));
        desc.set_fragment_function(Some(&ps));
        desc.set_raster_sample_count(1);
        desc.color_attachments()
            .object_at(0)
            .ok_or("no color slot")?
            .set_pixel_format(format);
        let pipeline = match mode {
            Mode::Archive(_, path, bake) => {
                if std::env::var_os("MTL_SHADER_VALIDATION").is_some() {
                    return Err(
                        "translated archive fixture requires MTL_SHADER_VALIDATION unset".into(),
                    );
                }
                let url = metal_artifact::file_url(path, bake).map_err(|e| e.to_string())?;
                let descriptor = BinaryArchiveDescriptor::new();
                if !bake {
                    descriptor.set_url(&url);
                }
                let archive = dev.new_binary_archive_with_descriptor(&descriptor)?;
                desc.set_binary_archives(&[&archive]);
                if bake {
                    let miss = strict(&dev, &desc)
                        .err()
                        .ok_or("unexpected strict hit in empty archive")?;
                    if !miss.contains("in binary archives") {
                        return Err(format!("expected empty-archive miss: {miss}"));
                    }
                    println!("empty archive rejected: {miss}");
                    if !archive.add_render_pipeline_functions_with_descriptor(&desc)?
                        || !archive.serialize_to_url(&url)?
                    {
                        return Err("could not add or serialize translated pipeline".into());
                    }
                }
                let p = strict(&dev, &desc)?;
                println!("strict translated VS+PS archive hit");
                p
            }
            _ => dev.new_render_pipeline_state(&desc)?,
        };
        let texture_desc = TextureDescriptor::new();
        const SIDE: usize = 8;
        const STRIDE: usize = 256;
        const BYTES: usize = STRIDE * SIDE;
        texture_desc.set_width(SIDE as u64);
        texture_desc.set_height(SIDE as u64);
        texture_desc.set_pixel_format(format);
        texture_desc.set_usage(MTLTextureUsage::RenderTarget);
        texture_desc.set_storage_mode(MTLStorageMode::Private);
        let color = dev.new_texture(&texture_desc);
        let pass = RenderPassDescriptor::new();
        let attachment = pass
            .color_attachments()
            .object_at(0)
            .ok_or("no pass color slot")?;
        attachment.set_texture(Some(&color));
        attachment.set_clear_color(MTLClearColor::new(1., 0., 1., 0.));
        attachment.set_load_action(MTLLoadAction::Clear);
        attachment.set_store_action(MTLStoreAction::Store);
        let queue = dev.new_command_queue();
        let cmd = queue.new_command_buffer();
        let enc = cmd.new_render_command_encoder(pass);
        enc.set_render_pipeline_state(&pipeline);
        // Three records of {position float4, one native PARAM0 input float4}.
        let vertices: [[f32; 8]; 3] = [
            [-1., -1., 0., 1., 0., 0.25, 0.75, 1.],
            [3., -1., 0., 1., 1., 0.25, 0.75, 1.],
            [-1., 3., 0., 1., 0., 0.25, 0.75, 1.],
        ];
        enc.set_vertex_bytes(
            0,
            std::mem::size_of_val(&vertices) as u64,
            vertices.as_ptr().cast(),
        );
        enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
        enc.end_encoding();
        let readback = dev.new_buffer(BYTES as u64, MTLResourceOptions::StorageModeShared);
        let ptr = readback.contents().cast::<u8>();
        if ptr.is_null() {
            return Err("unmapped graphics readback".into());
        }
        // No CPU access to the shared buffer while the GPU executes.
        unsafe { ptr.write_bytes(0xa5, BYTES) };
        let blit = cmd.new_blit_command_encoder();
        blit.copy_from_texture_to_buffer(
            &color,
            0,
            0,
            MTLOrigin { x: 0, y: 0, z: 0 },
            MTLSize::new(SIDE as u64, SIDE as u64, 1),
            &readback,
            0,
            STRIDE as u64,
            0,
            MTLBlitOption::None,
        );
        blit.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        if cmd.status() != MTLCommandBufferStatus::Completed {
            return Err(format!("translated render command: {:?}", cmd.status()));
        }
        // The GPU writes have completed and the owned buffer remains alive through the last read.
        let pixels = unsafe { std::slice::from_raw_parts(ptr, BYTES) };
        let mutated = matches!(mode, Mode::Load(_, true));
        for y in 0..SIDE {
            for x in 0..SIDE {
                let expected = expected(x, mutated);
                let at = y * STRIDE + x * 4;
                let got = &pixels[at..at + 4];
                if got != expected {
                    return Err(format!(
                        "pixel ({x},{y}): expected {expected:?}, got {got:?}"
                    ));
                }
            }
        }
        println!(
            "{} translated GFX10 VS+PS (mutated={mutated}): {n}/{n} pixels matched",
            dev.name(),
            n = SIDE * SIDE
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(err) = metal::objc::rc::autoreleasepool(gpu::run) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("unsupported: shader-metal-graphics-lift requires macOS Metal");
    std::process::exit(1);
}

#[test]
fn oracle_endpoints_and_gradient() {
    assert_eq!(expected(0, false), [72, 191, 64, 255]);
    assert_eq!(expected(7, false), [183, 191, 64, 255]);
    assert_eq!(expected(0, true), [135, 191, 64, 255]);
    assert_eq!(expected(7, true), [247, 191, 64, 255]);
}
