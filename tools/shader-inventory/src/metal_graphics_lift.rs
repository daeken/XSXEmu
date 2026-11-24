//! Execution and archive verification for the owned native graphics lift.
#[cfg(any(test, target_os = "macos"))]
mod graphics_decode;
#[cfg(any(test, target_os = "macos"))]
mod graphics_lift;
#[cfg(target_os = "macos")]
mod metal_artifact;
#[cfg(any(test, target_os = "macos"))]
#[allow(dead_code)]
// The graphics probe uses the shared framing, not the compute key or unbounded reader.
mod metal_cache;
#[cfg(target_os = "macos")]
mod owned_graphics_artifact;
#[cfg(any(test, target_os = "macos"))]
mod owned_graphics_job;

// Integer oracle for the chosen fullscreen triangle and no-perspective varying.
// Blue is half red. Alpha is legacy zero times a negative finite number.
// Green uses the exact fused integer result
// 4097*4097 - 16785408 = 1. Separate float32 multiply rounds to 16785408.
#[cfg(any(test, target_os = "macos"))]
fn expected(x: usize, mutated: bool) -> [u8; 4] {
    let red_numerator = 2 * x + 1 + if mutated { 16 } else { 8 };
    let gradient = ((red_numerator * 255 + 16) / 32) as u8;
    [gradient, 255, ((red_numerator * 255 + 32) / 64) as u8, 0]
}

// Independent integer depth oracle (depth in eighths), with literal expected
// colors rather than extracting values from the native ABI input words.
#[cfg(any(test, target_os = "macos"))]
fn expected_depth(x: usize, y: usize, raster: bool, writes: bool) -> [f32; 4] {
    let mut z = 4;
    let mut color = [1., 0., 1., 0.];
    for (xs, vertex_z, shader_z, rgba) in [
        (2..6, 7, 1, [-2., 0.25, 1.5, -0.5]),
        (4..8, 1, 2, [0., 1., 0., 1.]),
    ] {
        let candidate = if raster { vertex_z } else { shader_z };
        if xs.contains(&x) && (1..6).contains(&y) && candidate < z {
            color = rgba;
            if writes {
                z = candidate;
            }
        }
    }
    color
}

#[test]
fn depth_oracle_distinguishes_raster_depth_and_disabled_writes() {
    assert_ne!(
        expected_depth(2, 1, false, true),
        expected_depth(2, 1, true, true)
    );
    assert_ne!(
        expected_depth(4, 1, false, true),
        expected_depth(4, 1, false, false)
    );
    assert_eq!(expected_depth(6, 1, false, true), [0., 1., 0., 1.]);
    assert_eq!(expected_depth(0, 0, false, true), [1., 0., 1., 0.]);
}

#[cfg(target_os = "macos")]
mod gpu {
    use super::*;
    use metal::*;
    use std::path::Path;

    enum Mode<'a> {
        Source,
        PackedSource(bool),
        PackedLoad(&'a Path, bool),
        MultiSource,
        MultiLoad(&'a Path),
        DepthSource,
        DepthLoad(&'a Path),
        Load(&'a Path, bool),
        Archive(&'a Path, &'a Path, bool, bool, [u8; 32]),
        ExpectStrictMiss(&'a Path, &'a Path),
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
            [mode] if mode == "--multi-source" => Mode::MultiSource,
            [mode, lib] if mode == "--load-multi-metallib" => Mode::MultiLoad(Path::new(lib)),
            [mode] if mode == "--emit-multi-msl" => {
                print!("{}", graphics_lift::translate_multi_vertex_fixture().map_err(|e| format!("multi lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--depth-source" => Mode::DepthSource,
            [mode, lib] if mode == "--load-depth-metallib" => Mode::DepthLoad(Path::new(lib)),
            [mode] if mode == "--emit-depth-msl" => {
                print!("{}", graphics_lift::translate_depth_fixture().map_err(|e| format!("depth lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--packed-source" || mode == "--packed-rg-source" => Mode::PackedSource(mode == "--packed-rg-source"),
            [mode, lib] if mode == "--load-packed-metallib" || mode == "--load-packed-rg-metallib" => Mode::PackedLoad(Path::new(lib), mode == "--load-packed-rg-metallib"),
            [mode] if mode == "--emit-packed-msl" || mode == "--emit-packed-rg-msl" => {
                print!("{}", graphics_lift::translate_packed_color_fixture(mode == "--emit-packed-rg-msl").map_err(|e| format!("packed lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--emit-msl" || mode == "--emit-mutated-msl" => {
                let literal = (mode == "--emit-mutated-msl").then_some(owned_graphics_job::MUTATED_LITERAL);
                print!("{}", graphics_lift::translate_fixture(literal).map_err(|e| format!("lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode, lib] if mode == "--load-metallib" || mode == "--load-mutated-metallib" => Mode::Load(Path::new(lib), mode == "--load-mutated-metallib"),
            [mode, lib, archive] if mode == "--expect-owned-metal-miss" => Mode::ExpectStrictMiss(Path::new(lib), Path::new(archive)),
            [mode, lib, archive, compiler] if mode == "--bake-archive" || mode == "--replay-archive" || mode == "--replay-mutated-archive" => Mode::Archive(Path::new(lib), Path::new(archive), mode == "--bake-archive", mode == "--replay-mutated-archive", owned_graphics_artifact::compiler_profile(compiler)?),
            _ => return Err("usage: shader-metal-graphics-lift [--multi-source | --emit-multi-msl | --load-multi-metallib LIB | --packed-rg-source | --emit-packed-rg-msl | --load-packed-rg-metallib LIB | --depth-source | --emit-depth-msl | --load-depth-metallib LIB | --packed-source | --emit-packed-msl | --load-packed-metallib LIB | --emit-msl | --emit-mutated-msl | --load-metallib LIB | --load-mutated-metallib LIB | {--bake-archive|--replay-archive|--replay-mutated-archive} LIB ARCHIVE COMPILER_SHA256 | --expect-owned-metal-miss MUTATED_LIB ARCHIVE]".into()),
        };
        if matches!(mode, Mode::Archive(..) | Mode::ExpectStrictMiss(..))
            && std::env::var_os("MTL_SHADER_VALIDATION").is_some()
        {
            return Err("translated archive fixture requires MTL_SHADER_VALIDATION unset".into());
        }
        let dev = Device::system_default().ok_or("no Metal device")?;
        let admitted = if let Mode::Archive(lib, path, bake, mutated, compiler) = mode {
            let profile = owned_graphics_artifact::device_profile(&dev)?;
            let job = owned_graphics_job::ready(mutated, compiler, profile)?;
            let lib = owned_graphics_artifact::artifact_digest(lib)?;
            if bake {
                owned_graphics_artifact::require_new_identity(path)?;
            } else {
                owned_graphics_artifact::verify(&job, lib, path)?;
                println!("owned graphics artifact identity matched");
            }
            Some((job, lib))
        } else {
            None
        };
        let packed = matches!(mode, Mode::PackedSource(_) | Mode::PackedLoad(..));
        let partial = matches!(mode, Mode::PackedSource(true) | Mode::PackedLoad(_, true));
        let depth = matches!(mode, Mode::DepthSource | Mode::DepthLoad(_));
        let multi = matches!(mode, Mode::MultiSource | Mode::MultiLoad(_));
        let lib = match mode {
            Mode::Source | Mode::PackedSource(_) | Mode::DepthSource | Mode::MultiSource => {
                let msl = if multi {
                    graphics_lift::translate_multi_vertex_fixture()
                } else if depth {
                    graphics_lift::translate_depth_fixture()
                } else if packed {
                    graphics_lift::translate_packed_color_fixture(partial)
                } else {
                    graphics_lift::translate_fixture(None)
                }
                .map_err(|e| format!("lift rejected: {e:?}"))?;
                let options = CompileOptions::new();
                options.set_fast_math_enabled(false);
                dev.new_library_with_source(&msl, &options)?
            }
            Mode::PackedLoad(path, _)
            | Mode::MultiLoad(path)
            | Mode::DepthLoad(path)
            | Mode::Load(path, _)
            | Mode::Archive(path, _, _, _, _)
            | Mode::ExpectStrictMiss(path, _) => {
                metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
                dev.new_library_with_file(path)?
            }
        };
        let desc = RenderPipelineDescriptor::new();
        const DEPTH_FORMAT: MTLPixelFormat = MTLPixelFormat::Depth32Float;
        let (format, pixel_bytes, default_ps) = if multi {
            (MTLPixelFormat::RGBA32Float, 16, "multi_ps")
        } else if depth {
            desc.set_depth_attachment_pixel_format(DEPTH_FORMAT);
            (MTLPixelFormat::RGBA32Float, 16, "depth_ps")
        } else if packed {
            (
                MTLPixelFormat::RGBA32Float,
                16,
                if partial { "packed_rg_ps" } else { "packed_ps" },
            )
        } else {
            (MTLPixelFormat::RGBA8Unorm, 4, "translated_ps")
        };
        let (vs, ps) = admitted.as_ref().map_or(
            (if multi { "multi_vs" } else { "translated_vs" }, default_ps),
            |(job, _)| {
                (
                    job.stages()[0].translated_entry.as_str(),
                    job.stages()[1].translated_entry.as_str(),
                )
            },
        );
        let vs = lib.get_function(vs, None)?;
        let ps = lib.get_function(ps, None)?;
        desc.set_vertex_function(Some(&vs));
        desc.set_fragment_function(Some(&ps));
        desc.set_raster_sample_count(1);
        let color_attachment = desc
            .color_attachments()
            .object_at(0)
            .ok_or("no color slot")?;
        color_attachment.set_pixel_format(format);
        color_attachment.set_write_mask(if partial {
            MTLColorWriteMask::Red | MTLColorWriteMask::Green
        } else {
            MTLColorWriteMask::All
        });
        color_attachment.set_blending_enabled(false);
        // Independent owned negative control. No sidecar is read or written;
        // success is possible only for the specific Metal archive-miss error.
        if let Mode::ExpectStrictMiss(_, path) = mode {
            let url = metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
            let descriptor = BinaryArchiveDescriptor::new();
            descriptor.set_url(&url);
            let archive = dev.new_binary_archive_with_descriptor(&descriptor)?;
            desc.set_binary_archives(&[&archive]);
            return match strict(&dev, &desc) {
                Err(err)
                    if err.contains("Unable to find function \"translated_ps\"")
                        && err.contains("in binary archives") =>
                {
                    println!("independent Metal strict miss: {err}");
                    Ok(())
                }
                Err(err) => Err(format!("unexpected Metal strict-probe error: {err}")),
                Ok(_) => Err("unexpected Metal strict hit for owned negative control".into()),
            };
        }
        let pipeline = match mode {
            Mode::Archive(_, path, bake, _, _) => {
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
        attachment.set_clear_color(MTLClearColor::new(
            1.,
            0.,
            1.,
            if partial { 0.75 } else { 0. },
        ));
        attachment.set_load_action(MTLLoadAction::Clear);
        attachment.set_store_action(MTLStoreAction::Store);
        let depth_texture = depth.then(|| {
            texture_desc.set_pixel_format(DEPTH_FORMAT);
            dev.new_texture(&texture_desc)
        });
        let depth_state = depth_texture.as_ref().map(|texture| {
            let attachment = pass.depth_attachment().expect("depth attachment");
            attachment.set_texture(Some(texture));
            attachment.set_clear_depth(0.5);
            attachment.set_load_action(MTLLoadAction::Clear);
            attachment.set_store_action(MTLStoreAction::DontCare);
            let descriptor = DepthStencilDescriptor::new();
            descriptor.set_depth_compare_function(MTLCompareFunction::Less);
            descriptor.set_depth_write_enabled(true);
            dev.new_depth_stencil_state(&descriptor)
        });
        let queue = dev.new_command_queue();
        let cmd = queue.new_command_buffer();
        let enc = cmd.new_render_command_encoder(pass);
        enc.set_render_pipeline_state(&pipeline);
        // Three records of {position float4, one native PARAM0 input float4}.
        let vertices: [[f32; 8]; 3] = [
            [-1., -1., 0., 1., 0., 4097., 4097., -16785408.],
            [3., -1., 0., 1., 1., 4097., 4097., -16785408.],
            [-1., 3., 0., 1., 0., 4097., 4097., -16785408.],
        ];
        enc.set_vertex_bytes(
            0,
            std::mem::size_of_val(&vertices) as u64,
            vertices.as_ptr().cast(),
        );
        if multi {
            let mut data = [[[0.0f32; 4]; 8]; 3];
            for (v, row) in data.iter_mut().enumerate() {
                row[0].copy_from_slice(&vertices[v][..4]);
                for n in 1..=7 {
                    let k = n as f32;
                    row[n] = [k + if v == 1 { 2. } else { 0. }, k + 8., k + 16., k + 24.];
                }
            }
            enc.set_vertex_bytes(0, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
        }
        if let Some(state) = depth_state.as_ref() {
            enc.set_depth_stencil_state(state);
            for (x, clip_z, inputs) in [
                (2, 0.875f32, [0xb800_3e00u32, 0x3400_c000, 0x3e00_0000, 0]),
                (4, 0.125f32, [0x3c00_0000u32, 0x3c00_0000, 0x3e80_0000, 0]),
            ] {
                let mut tri = vertices;
                for vertex in &mut tri {
                    vertex[2] = clip_z;
                }
                enc.set_vertex_bytes(0, std::mem::size_of_val(&tri) as u64, tri.as_ptr().cast());
                enc.set_scissor_rect(MTLScissorRect {
                    x,
                    y: 1,
                    width: 4,
                    height: 5,
                });
                enc.set_fragment_bytes(
                    0,
                    std::mem::size_of_val(&inputs) as u64,
                    inputs.as_ptr().cast(),
                );
                enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
            }
        } else if packed {
            enc.set_scissor_rect(MTLScissorRect {
                x: 2,
                y: 1,
                width: 4,
                height: 5,
            });
            let inputs = [0xb800_3e00u32, 0x3400_c000u32];
            enc.set_fragment_bytes(
                0,
                std::mem::size_of_val(&inputs) as u64,
                inputs.as_ptr().cast(),
            );
        }
        if !depth {
            enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
        }
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
        let mutated = matches!(mode, Mode::Load(_, true) | Mode::Archive(_, _, _, true, _));
        for y in 0..SIDE {
            for x in 0..SIDE {
                let at = y * STRIDE + x * pixel_bytes;
                let got = &pixels[at..at + pixel_bytes];
                let ordinary;
                let fp32;
                let expected: &[u8] = if multi {
                    // Independent analytic sum: sum 1²..7² = 140, sum 1..7 = 28.
                    // dyadic pixel centers, with the same X gradient in each varying.
                    let rgba: [f32; 4] = [(2240 + 28 * (2 * x + 1)) as f32 / 16., 364., 588., 812.];
                    fp32 = rgba.map(f32::to_le_bytes).as_flattened().to_owned();
                    &fp32
                } else if depth {
                    fp32 = expected_depth(x, y, false, true)
                        .map(f32::to_le_bytes)
                        .as_flattened()
                        .to_owned();
                    &fp32
                } else if packed {
                    // Independent numeric oracle; this does not unpack input dwords.
                    let rgba: [f32; 4] = if (2..6).contains(&x) && (1..6).contains(&y) {
                        if partial {
                            [-2., 0.25, 1., 0.75]
                        } else {
                            [-2., 0.25, 1.5, -0.5]
                        }
                    } else {
                        [1., 0., 1., if partial { 0.75 } else { 0. }]
                    };
                    fp32 = rgba.map(f32::to_le_bytes).as_flattened().to_owned();
                    &fp32
                } else {
                    ordinary = expected(x, mutated);
                    &ordinary
                };
                if got != expected {
                    return Err(format!(
                        "pixel ({x},{y}): expected {expected:?}, got {got:?}"
                    ));
                }
            }
        }
        if let (Mode::Archive(_, path, true, _, _), Some((job, lib))) = (mode, admitted) {
            owned_graphics_artifact::publish(&job, lib, path)?;
            println!("published owned graphics artifact identity");
        }
        println!(
            "{} translated GFX10 VS+PS (mutated={mutated}, packed={packed}, partial={partial}, depth={depth}, multi={multi}): {n}/{n} pixels matched",
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
    assert_eq!(4097_i64 * 4097 - 16785408, 1);
    assert_eq!(4097_f32 * 4097. - 16785408., 0.);
    assert_eq!(expected(0, false), [72, 255, 36, 0]);
    assert_eq!(expected(7, false), [183, 255, 92, 0]);
    assert_eq!(expected(0, true), [135, 255, 68, 0]);
    assert_eq!(expected(7, true), [247, 255, 124, 0]);
}
