//! Owned mesh/fragment fixture, not a retail launch or linkage model.
#[cfg(target_os = "macos")]
mod gpu {
    use metal::*;

    const SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;
struct Vertex { float4 position [[position]]; float green; };
struct Primitive { float blue [[flat]]; };
struct Fragment { float green; float blue [[flat]]; };
[[mesh]] void owned_mesh(mesh<Vertex, Primitive, 3, 1, topology::triangle> out,
                         constant uint &count [[buffer(0)]]) {
    out.set_vertex(0, Vertex{float4(-1, -1, 0, 1), 1});
    out.set_vertex(1, Vertex{float4( 3, -1, 0, 1), 1});
    out.set_vertex(2, Vertex{float4(-1,  3, 0, 1), 1});
    out.set_index(0, 0);
    out.set_index(1, 1);
    out.set_index(2, 2);
    out.set_primitive(0, Primitive{1});
    out.set_primitive_count(count);
}
fragment float4 owned_mesh_fragment(Fragment in [[stage_in]]) {
    return float4(0, in.green, in.blue, 1);
}
"#;

    pub fn run() -> Result<(), String> {
        let dev = Device::system_default().ok_or("missing Metal device")?;
        if !dev.supports_family(MTLGPUFamily::Apple7) {
            return Err("owned mesh probe requires Apple GPU family 7 or newer".into());
        }
        let lib = dev.new_library_with_source(SOURCE, &CompileOptions::new())?;
        let mesh = lib.get_function("owned_mesh", None)?;
        let frag = lib.get_function("owned_mesh_fragment", None)?;
        let desc = MeshRenderPipelineDescriptor::new();
        let format = MTLPixelFormat::RGBA8Unorm;
        desc.set_mesh_function(Some(&mesh));
        desc.set_fragment_function(Some(&frag));
        desc.set_max_total_threads_per_mesh_threadgroup(1);
        desc.color_attachments()
            .object_at(0)
            .ok_or("missing color slot")?
            .set_pixel_format(format);
        let pipeline = dev.new_mesh_render_pipeline_state(&desc)?;
        let queue = dev.new_command_queue();
        let tex_desc = TextureDescriptor::new();
        const SIDE: usize = 8;
        const STRIDE: usize = 256;
        const BYTES: usize = STRIDE * SIDE;
        tex_desc.set_width(SIDE as u64);
        tex_desc.set_height(SIDE as u64);
        tex_desc.set_pixel_format(format);
        tex_desc.set_storage_mode(MTLStorageMode::Private);
        tex_desc.set_usage(MTLTextureUsage::RenderTarget);
        let color = dev.new_texture(&tex_desc);
        for (count, expected) in [(0u32, [255, 0, 0, 255]), (1, [0, 255, 255, 255])] {
            let pass = RenderPassDescriptor::new();
            let c = pass
                .color_attachments()
                .object_at(0)
                .ok_or("missing pass color slot")?;
            c.set_texture(Some(&color));
            c.set_clear_color(MTLClearColor::new(1., 0., 0., 1.));
            c.set_load_action(MTLLoadAction::Clear);
            c.set_store_action(MTLStoreAction::Store);
            let cmd = queue.new_command_buffer();
            let enc = cmd.new_render_command_encoder(pass);
            enc.set_render_pipeline_state(&pipeline);
            enc.set_mesh_bytes(0, 4, (&raw const count).cast());
            let one = MTLSize::new(1, 1, 1);
            enc.draw_mesh_threadgroups(one, one, one);
            enc.end_encoding();
            let readback = dev.new_buffer(BYTES as u64, MTLResourceOptions::StorageModeShared);
            let ptr = readback.contents().cast::<u8>();
            if ptr.is_null() {
                return Err("unmapped shared readback".into());
            }
            // Initialize padding too; the CPU does not access shared memory while the GPU writes.
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
                return Err(format!("mesh/blit command status: {:?}", cmd.status()));
            }
            // The owned buffer remains alive until after all completed GPU writes are read.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, BYTES) };
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let at = STRIDE * y + 4 * x;
                    let actual = &bytes[at..at + 4];
                    if actual != expected {
                        return Err(format!(
                            "primitive count {count}, pixel ({x},{y}): expected {expected:?}, got {actual:?}"
                        ));
                    }
                }
            }
            println!(
                "{} owned mesh, primitive count {count}: {pixels}/{pixels} pixels matched",
                dev.name(),
                pixels = SIDE * SIDE
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
    eprintln!("unsupported: shader-metal-mesh-probe requires macOS Metal");
    std::process::exit(1);
}
