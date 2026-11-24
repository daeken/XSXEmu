//! Owned fixed-function render probe; no title formats or production shader translations.
#![cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]

const WIDTH: usize = 8;
const HEIGHT: usize = 4;
const CLEAR: [u8; 4] = [0, 0, 0, 255];

#[derive(Clone, Copy)]
enum ColorPipeline {
    Rgba,
    Green,
    AlphaBlend,
}

impl ColorPipeline {
    const ALL: [Self; 3] = [Self::Rgba, Self::Green, Self::AlphaBlend];
}

#[derive(Clone, Copy)]
struct Draw {
    x: (usize, usize), // Half-open scissor interval, full height.
    depth_eighths: u8,
    color: [u8; 4], // UNORM values expressed as bytes.
    pipeline: ColorPipeline,
    depth_write: bool,
}

fn draws(overlay_depth_write: bool) -> [Draw; 5] {
    [
        Draw {
            x: (0, 7),
            depth_eighths: 6,
            color: [255, 0, 0, 255],
            pipeline: ColorPipeline::Rgba,
            depth_write: true,
        },
        Draw {
            x: (4, 7),
            depth_eighths: 2,
            color: [0, 255, 0, 0],
            pipeline: ColorPipeline::Green,
            depth_write: overlay_depth_write,
        },
        Draw {
            x: (0, 2),
            depth_eighths: 7,
            color: [255; 4],
            pipeline: ColorPipeline::Rgba,
            depth_write: true,
        },
        Draw {
            x: (2, 6),
            depth_eighths: 4,
            color: [0, 0, 255, 255],
            pipeline: ColorPipeline::Rgba,
            depth_write: true,
        },
        Draw {
            x: (1, 2),
            depth_eighths: 1,
            color: [0, 255, 0, 102],
            pipeline: ColorPipeline::AlphaBlend,
            depth_write: false,
        },
    ]
}

fn reference(draws: &[Draw]) -> [[u8; 4]; WIDTH] {
    // All shader invocations and scissor ranges are uniform along Y. Integer
    // comparisons are equivalent to Less on these exactly representable depths.
    let mut row = [CLEAR; WIDTH];
    let mut depth = [8; WIDTH];
    for draw in draws {
        for x in draw.x.0..draw.x.1 {
            if draw.depth_eighths >= depth[x] {
                continue;
            }
            match draw.pipeline {
                ColorPipeline::Rgba => row[x] = draw.color,
                ColorPipeline::Green => row[x][1] = draw.color[1],
                ColorPipeline::AlphaBlend => {
                    let a = u32::from(draw.color[3]);
                    for (src, dst) in draw.color[..3].iter().zip(&mut row[x][..3]) {
                        // Integer oracle for src*a + dst*(1-a), rounded to UNORM8.
                        *dst =
                            ((u32::from(*src) * a + u32::from(*dst) * (255 - a) + 127) / 255) as u8;
                    }
                    row[x][3] = row[x][3].saturating_sub(draw.color[3]);
                }
            }
            if draw.depth_write {
                depth[x] = draw.depth_eighths;
            }
        }
    }
    row
}

#[cfg(test)]
#[test]
fn oracle_distinguishes_blend_mask_scissor_depth_test_and_depth_write() {
    let red = [255, 0, 0, 255];
    let blended = [153, 102, 0, 153];
    let yellow = [255, 255, 0, 255];
    let blue = [0, 0, 255, 255];
    assert_eq!(
        reference(&draws(true)),
        [red, blended, blue, blue, yellow, yellow, yellow, CLEAR]
    );
    assert_eq!(
        reference(&draws(false)),
        [red, blended, blue, blue, blue, blue, yellow, CLEAR]
    );
}

#[cfg(target_os = "macos")]
mod metal_artifact;

#[cfg(target_os = "macos")]
mod gpu {
    use super::*;
    use metal::*;
    use std::path::Path;

    fn strict_pipeline(
        dev: &DeviceRef,
        desc: &RenderPipelineDescriptorRef,
    ) -> Result<RenderPipelineState, String> {
        dev.new_render_pipeline_state_with_reflection(
            desc,
            MTLPipelineOption::FailOnBinaryArchiveMiss,
        )
        .map(|(pipeline, _)| pipeline)
    }

    const COLOR: MTLPixelFormat = MTLPixelFormat::RGBA8Unorm;
    const DEPTH: MTLPixelFormat = MTLPixelFormat::Depth32Float;
    // Fullscreen triangle without edge, interpolation or vertex-fetch ambiguity.
    const MSL: &str = r#"
#include <metal_stdlib>
using namespace metal;
vertex float4 owned_vertex(uint id [[vertex_id]], constant float &z [[buffer(0)]]) {
    const float2 corners[3] = { float2(-1, -1), float2(3, -1), float2(-1, 3) };
    return float4(corners[id], z, 1);
}
fragment float4 owned_fragment(constant float4 &color [[buffer(0)]]) { return color; }
"#;

    fn pipeline_descriptor(
        lib: &LibraryRef,
        pipeline: ColorPipeline,
    ) -> Result<RenderPipelineDescriptor, String> {
        let desc = RenderPipelineDescriptor::new();
        let vs = lib.get_function("owned_vertex", None)?;
        let ps = lib.get_function("owned_fragment", None)?;
        desc.set_vertex_function(Some(&vs));
        desc.set_fragment_function(Some(&ps));
        desc.set_raster_sample_count(1);
        desc.set_depth_attachment_pixel_format(DEPTH);
        let color = desc
            .color_attachments()
            .object_at(0)
            .ok_or("missing pipeline color slot")?;
        color.set_pixel_format(COLOR);
        color.set_blending_enabled(matches!(pipeline, ColorPipeline::AlphaBlend));
        color.set_write_mask(match pipeline {
            ColorPipeline::Rgba | ColorPipeline::AlphaBlend => MTLColorWriteMask::All,
            ColorPipeline::Green => MTLColorWriteMask::Green,
        });
        if matches!(pipeline, ColorPipeline::AlphaBlend) {
            color.set_rgb_blend_operation(MTLBlendOperation::Add);
            color.set_source_rgb_blend_factor(MTLBlendFactor::SourceAlpha);
            color.set_destination_rgb_blend_factor(MTLBlendFactor::OneMinusSourceAlpha);
            color.set_alpha_blend_operation(MTLBlendOperation::ReverseSubtract);
            color.set_source_alpha_blend_factor(MTLBlendFactor::One);
            color.set_destination_alpha_blend_factor(MTLBlendFactor::One);
        }
        Ok(desc)
    }

    fn depth_state(dev: &DeviceRef, write: bool) -> DepthStencilState {
        let depth = DepthStencilDescriptor::new();
        depth.set_depth_compare_function(MTLCompareFunction::Less);
        depth.set_depth_write_enabled(write);
        dev.new_depth_stencil_state(&depth)
    }

    fn texture(dev: &DeviceRef, format: MTLPixelFormat) -> Texture {
        let desc = TextureDescriptor::new();
        desc.set_width(WIDTH as u64);
        desc.set_height(HEIGHT as u64);
        desc.set_pixel_format(format);
        desc.set_storage_mode(MTLStorageMode::Private);
        desc.set_usage(MTLTextureUsage::RenderTarget);
        dev.new_texture(&desc)
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let (library, archive) = match args.as_slice() {
            [] => (None, None),
            [mode] if mode == "--emit-msl" => {
                print!("{MSL}");
                return Ok(());
            }
            [mode, lib] if mode == "--load-metallib" => (Some(Path::new(lib)), None),
            [mode, lib, path] if mode == "--bake-archive" || mode == "--replay-archive" => {
                (Some(Path::new(lib)), Some((Path::new(path), mode == "--bake-archive")))
            }
            _ => return Err("usage: shader-metal-render-probe [--emit-msl | --load-metallib LIB | --bake-archive LIB ARCHIVE | --replay-archive LIB ARCHIVE]".into()),
        };
        let dev = Device::system_default().ok_or("no Metal device")?;
        let lib = if let Some(path) = library {
            // Apply the same regular-file check as the compute fixture.
            metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
            dev.new_library_with_file(path)?
        } else {
            dev.new_library_with_source(MSL, &CompileOptions::new())?
        };
        let descriptors: Vec<_> = ColorPipeline::ALL
            .into_iter()
            .map(|pipeline| pipeline_descriptor(&lib, pipeline))
            .collect::<Result<_, _>>()?;
        let pipelines: Vec<_> = match archive {
            None => descriptors
                .iter()
                .map(|desc| dev.new_render_pipeline_state(desc))
                .collect::<Result<_, _>>()?,
            Some((path, bake)) => {
                let url = metal_artifact::file_url(path, bake).map_err(|e| e.to_string())?;
                let desc = BinaryArchiveDescriptor::new();
                if !bake {
                    desc.set_url(&url);
                }
                let archive = dev.new_binary_archive_with_descriptor(&desc)?;
                for desc in &descriptors {
                    desc.set_binary_archives(&[&archive]);
                }
                if bake {
                    for desc in &descriptors {
                        if strict_pipeline(&dev, desc).is_ok() {
                            return Err("expected strict misses for all render descriptors with an empty binary archive".into());
                        }
                        desc.set_binary_archives(&[]);
                    }
                    for desc in &descriptors {
                        if !archive.add_render_pipeline_functions_with_descriptor(desc)? {
                            return Err("Metal did not add the owned render descriptor".into());
                        }
                    }
                    if !archive.serialize_to_url(&url)? {
                        return Err("Metal did not write the owned render archive".into());
                    }
                    println!(
                        "{}: empty archive refused; baked {} owned render descriptors",
                        dev.name(),
                        descriptors.len()
                    );
                    return Ok(());
                }
                let strict = descriptors
                    .iter()
                    .map(|desc| strict_pipeline(&dev, desc))
                    .collect::<Result<_, _>>()?;
                println!(
                    "{}: {} owned render pipelines created with FailOnBinaryArchiveMiss",
                    dev.name(),
                    descriptors.len()
                );
                strict
            }
        };
        let queue = dev.new_command_queue();
        let write = depth_state(&dev, true);
        let retain = depth_state(&dev, false);
        for overlay_depth_write in [true, false] {
            let draws = draws(overlay_depth_write);
            let color = texture(&dev, COLOR);
            let depth = texture(&dev, DEPTH);
            let pass = RenderPassDescriptor::new();
            let c = pass
                .color_attachments()
                .object_at(0)
                .ok_or("missing pass color slot")?;
            c.set_texture(Some(&color));
            c.set_load_action(MTLLoadAction::Clear);
            c.set_clear_color(MTLClearColor::new(0., 0., 0., 1.));
            c.set_store_action(MTLStoreAction::Store);
            let d = pass.depth_attachment().ok_or("missing pass depth slot")?;
            d.set_texture(Some(&depth));
            d.set_load_action(MTLLoadAction::Clear);
            d.set_clear_depth(1.);
            d.set_store_action(MTLStoreAction::DontCare);
            let cmd = queue.new_command_buffer();
            let enc = cmd.new_render_command_encoder(pass);
            for draw in draws {
                enc.set_render_pipeline_state(&pipelines[draw.pipeline as usize]);
                enc.set_depth_stencil_state(if draw.depth_write { &write } else { &retain });
                enc.set_scissor_rect(MTLScissorRect {
                    x: draw.x.0 as u64,
                    y: 0,
                    width: (draw.x.1 - draw.x.0) as u64,
                    height: HEIGHT as u64,
                });
                let z = f32::from(draw.depth_eighths) / 8.;
                let rgba = draw.color.map(|v| f32::from(v) / 255.);
                enc.set_vertex_bytes(0, 4, (&raw const z).cast());
                enc.set_fragment_bytes(0, 16, rgba.as_ptr().cast());
                enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
            }
            enc.end_encoding();
            const STRIDE: usize = 256;
            let readback = dev.new_buffer(
                (STRIDE * HEIGHT) as u64,
                MTLResourceOptions::StorageModeShared,
            );
            let ptr = readback.contents().cast::<u8>();
            if ptr.is_null() {
                return Err("unmapped shared readback".into());
            }
            // Initialize the entire allocation, including pitch padding, before
            // the GPU writes to it. No CPU alias is used during execution.
            unsafe { ptr.write_bytes(0xa5, STRIDE * HEIGHT) };
            let blit = cmd.new_blit_command_encoder();
            blit.copy_from_texture_to_buffer(
                &color,
                0,
                0,
                MTLOrigin { x: 0, y: 0, z: 0 },
                MTLSize::new(WIDTH as u64, HEIGHT as u64, 1),
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
                return Err(format!("render/blit command status: {:?}", cmd.status()));
            }
            // The completed GPU write is visible in shared storage, which the
            // owned Metal buffer keeps live until after the last read below.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, STRIDE * HEIGHT) };
            let expected = reference(&draws);
            for y in 0..HEIGHT {
                for (x, rgba) in expected.iter().enumerate() {
                    let offset = y * STRIDE + x * 4;
                    let got = &bytes[offset..offset + 4];
                    if got != rgba {
                        return Err(format!(
                            "overlay depth write {overlay_depth_write}, pixel ({x},{y}): expected {rgba:?}, got {got:?}"
                        ));
                    }
                }
            }
            println!(
                "{} owned render, overlay depth write {overlay_depth_write}: {}/{} pixels matched",
                dev.name(),
                WIDTH * HEIGHT,
                WIDTH * HEIGHT
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = metal::objc::rc::autoreleasepool(gpu::run) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("unsupported: shader-metal-render-probe requires macOS Metal");
    std::process::exit(1);
}
