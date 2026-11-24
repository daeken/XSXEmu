//! Owned fixed-function render probe; no title formats or production shader translations.
#![cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]

const WIDTH: usize = 8;
const HEIGHT: usize = 4;
const CLEAR: [u8; 4] = [0, 0, 0, 255];

#[derive(Clone, Copy)]
enum ColorWrites {
    Rgba,
    Green,
}

#[derive(Clone, Copy)]
struct Draw {
    x: (usize, usize), // Half-open scissor interval, full height.
    depth_eighths: u8,
    color: [u8; 4], // Exact UNORM endpoints, expressed as bytes.
    writes: ColorWrites,
    depth_write: bool,
}

fn draws(overlay_depth_write: bool) -> [Draw; 4] {
    [
        Draw {
            x: (0, 7),
            depth_eighths: 6,
            color: [255, 0, 0, 255],
            writes: ColorWrites::Rgba,
            depth_write: true,
        },
        Draw {
            x: (4, 7),
            depth_eighths: 2,
            color: [0, 255, 0, 0],
            writes: ColorWrites::Green,
            depth_write: overlay_depth_write,
        },
        Draw {
            x: (0, 2),
            depth_eighths: 7,
            color: [255; 4],
            writes: ColorWrites::Rgba,
            depth_write: true,
        },
        Draw {
            x: (2, 6),
            depth_eighths: 4,
            color: [0, 0, 255, 255],
            writes: ColorWrites::Rgba,
            depth_write: true,
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
            match draw.writes {
                ColorWrites::Rgba => row[x] = draw.color,
                ColorWrites::Green => row[x][1] = draw.color[1],
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
fn oracle_distinguishes_mask_scissor_depth_test_and_depth_write() {
    let red = [255, 0, 0, 255];
    let yellow = [255, 255, 0, 255];
    let blue = [0, 0, 255, 255];
    assert_eq!(
        reference(&draws(true)),
        [red, red, blue, blue, yellow, yellow, yellow, CLEAR]
    );
    assert_eq!(
        reference(&draws(false)),
        [red, red, blue, blue, blue, blue, yellow, CLEAR]
    );
}

#[cfg(target_os = "macos")]
mod gpu {
    use super::*;
    use metal::*;

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
        writes: ColorWrites,
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
        color.set_blending_enabled(false);
        color.set_write_mask(match writes {
            ColorWrites::Rgba => MTLColorWriteMask::All,
            ColorWrites::Green => MTLColorWriteMask::Green,
        });
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
        if std::env::args_os().len() != 1 {
            return Err("usage: shader-metal-render-probe".into());
        }
        let dev = Device::system_default().ok_or("no Metal device")?;
        let queue = dev.new_command_queue();
        let lib = dev.new_library_with_source(MSL, &CompileOptions::new())?;
        let all_desc = pipeline_descriptor(&lib, ColorWrites::Rgba)?;
        let green_desc = pipeline_descriptor(&lib, ColorWrites::Green)?;
        let all = dev.new_render_pipeline_state(&all_desc)?;
        let green = dev.new_render_pipeline_state(&green_desc)?;
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
                enc.set_render_pipeline_state(match draw.writes {
                    ColorWrites::Rgba => &all,
                    ColorWrites::Green => &green,
                });
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
