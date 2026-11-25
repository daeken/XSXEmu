//! Owned mesh/fragment fixture, not a retail launch or linkage model.
#[cfg(target_os = "macos")]
mod metal_artifact;

#[cfg(target_os = "macos")]
mod gpu {
    use metal::*;
    use std::path::Path;

    // Authored fixture ABI, not an M0 or native PRIM payload layout.
    #[derive(Clone, Copy)]
    struct MeshInput {
        vertices: u32,
        allocated: u32,
        valid: bool,
        indices: [u32; 3],
    }

    impl MeshInput {
        fn checked_words(self) -> Result<[u32; 6], String> {
            let [a, b, c] = self.indices;
            if self.vertices > 4 || self.allocated > 1 || (self.valid && self.allocated == 0) {
                return Err("invalid owned mesh counts or validity".into());
            }
            if self.valid
                && (a >= self.vertices
                    || b >= self.vertices
                    || c >= self.vertices
                    || a == b
                    || b == c
                    || a == c)
            {
                return Err("invalid owned triangle indices".into());
            }
            Ok([
                self.vertices,
                self.allocated,
                u32::from(self.valid),
                a,
                b,
                c,
            ])
        }
    }

    const FULL: MeshInput = MeshInput {
        vertices: 4,
        allocated: 1,
        valid: true,
        indices: [0, 1, 2],
    };
    const CASES: [(&str, MeshInput, [usize; 8]); 4] = [
        (
            "no allocation",
            MeshInput {
                allocated: 0,
                valid: false,
                ..FULL
            },
            [0; 8],
        ),
        (
            "allocated, invalid",
            MeshInput {
                valid: false,
                ..FULL
            },
            [0; 8],
        ),
        ("valid full triangle", FULL, [8; 8]),
        // Top-down pixel centers, x < -(y+1)/4; no centers land on the sloped edge.
        (
            "valid redirected index",
            MeshInput {
                indices: [0, 3, 2],
                ..FULL
            },
            [2, 2, 3, 3, 3, 3, 4, 4],
        ),
    ];

    #[test]
    fn owned_mesh_contract_checks_counts_and_indices() {
        for (_, input, _) in CASES {
            assert!(input.checked_words().is_ok());
        }
        assert_eq!(FULL.checked_words().unwrap(), [4, 1, 1, 0, 1, 2]);
        assert!(
            MeshInput {
                vertices: 3,
                ..FULL
            }
            .checked_words()
            .is_ok()
        );
        for input in [
            MeshInput {
                allocated: 0,
                ..FULL
            },
            MeshInput {
                allocated: 2,
                ..FULL
            },
            MeshInput {
                vertices: 5,
                ..FULL
            },
            MeshInput {
                vertices: 3,
                indices: [0, 3, 2],
                ..FULL
            },
            MeshInput {
                indices: [0, 0, 2],
                ..FULL
            },
        ] {
            assert!(input.checked_words().is_err());
        }
    }

    const SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;
struct Vertex { float4 position [[position]]; float green; };
struct Primitive { float blue [[flat]]; };
struct Fragment { float green; float blue [[flat]]; };
[[mesh]] void owned_mesh(mesh<Vertex, Primitive, 4, 1, topology::triangle> out,
                         constant uint *input [[buffer(0)]]) {
    if (input[1] == 0 || input[2] == 0) {
        out.set_primitive_count(0);
        return;
    }
    const float4 positions[4] = {
        float4(-1, -1, 0, 1), float4(3, -1, 0, 1),
        float4(-1, 3, 0, 1), float4(0, -1, 0, 1)
    };
    for (uint i = 0; i < input[0]; ++i) {
        out.set_vertex(i, Vertex{positions[i], 1});
    }
    out.set_index(0, input[3]);
    out.set_index(1, input[4]);
    out.set_index(2, input[5]);
    out.set_primitive(0, Primitive{1});
    out.set_primitive_count(1);
}
fragment float4 owned_mesh_fragment(Fragment in [[stage_in]]) {
    return float4(0, in.green, in.blue, 1);
}
"#;

    // The SDK's macOS 15 mesh archive methods are not wrapped by metal 0.33.
    #[allow(unexpected_cfgs)]
    fn archive_pipeline(
        dev: &DeviceRef,
        desc: &MeshRenderPipelineDescriptorRef,
        path: &Path,
        bake: bool,
    ) -> Result<RenderPipelineState, String> {
        use metal::{
            foreign_types::ForeignType,
            objc::{
                msg_send,
                runtime::{BOOL, Object, YES},
                sel, sel_impl,
            },
        };
        if std::env::var_os("MTL_SHADER_VALIDATION").is_some() {
            return Err("owned mesh archive requires GPU instrumentation disabled (unset MTL_SHADER_VALIDATION)".into());
        }
        let url = super::metal_artifact::file_url(path, bake).map_err(|e| e.to_string())?;
        let archive_desc = BinaryArchiveDescriptor::new();
        if !bake {
            archive_desc.set_url(&url);
        }
        let archive = dev.new_binary_archive_with_descriptor(&archive_desc)?;
        let strict = || unsafe {
            let mut error: *mut Object = std::ptr::null_mut();
            let reflection: *mut *mut Object = std::ptr::null_mut();
            let raw: *mut MTLRenderPipelineState = msg_send![dev, newRenderPipelineStateWithMeshDescriptor:desc
                options:MTLPipelineOption::FailOnBinaryArchiveMiss reflection:reflection error:&mut error];
            if raw.is_null() {
                let message = if error.is_null() {
                    "unknown Metal error".into()
                } else {
                    let ns: *mut Object = msg_send![error, localizedDescription];
                    let text: *const std::ffi::c_char = msg_send![ns, UTF8String];
                    if text.is_null() {
                        "missing NSError description".into()
                    } else {
                        std::ffi::CStr::from_ptr(text)
                            .to_string_lossy()
                            .lines()
                            .next()
                            .unwrap_or("empty NSError description")
                            .trim()
                            .to_owned()
                    }
                };
                Err(format!("strict mesh pipeline: {message}"))
            } else {
                // The create selector returns an owned (+1) reference.
                Ok(RenderPipelineState::from_ptr(raw))
            }
        };
        // All receivers and arguments stay live across these synchronous Metal calls.
        unsafe {
            let supported: BOOL = msg_send![desc, respondsToSelector:sel!(setBinaryArchives:)];
            if supported != YES {
                return Err("mesh pipeline binary archives require macOS 15 or newer".into());
            }
            let supported: BOOL = msg_send![&*archive, respondsToSelector:sel!(addMeshRenderPipelineFunctionsWithDescriptor:error:)];
            if supported != YES {
                return Err("mesh archive insertion unavailable".into());
            }
            let archives = Array::<BinaryArchive>::from_slice(&[&archive]);
            let _: () = msg_send![desc, setBinaryArchives:archives];
            if bake {
                let miss = strict()
                    .err()
                    .ok_or("unexpected strict mesh hit in empty archive")?;
                if !miss.contains("in binary archives") {
                    return Err(format!("expected empty mesh archive miss: {miss}"));
                }
                println!("empty archive rejected: {miss}");
                let mut error: *mut Object = std::ptr::null_mut();
                let added: BOOL = msg_send![&*archive, addMeshRenderPipelineFunctionsWithDescriptor:desc error:&mut error];
                if added != YES {
                    return Err("failed to add owned mesh descriptor to archive".into());
                }
            }
        }
        if bake && !archive.serialize_to_url(&url)? {
            return Err("failed to serialize owned mesh archive".into());
        }
        let pipeline = strict()?;
        println!("strict owned mesh archive hit");
        Ok(pipeline)
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let (path, archive, mutate_expected) = match args.as_slice() {
            [] => (None, None, false),
            [mode] if mode == "--emit-msl" => {
                print!("{SOURCE}");
                return Ok(());
            }
            [mode, path] if mode == "--load-metallib" || mode == "--load-mutated-metallib" => (
                Some(Path::new(path)),
                None,
                mode == "--load-mutated-metallib",
            ),
            [mode, lib, path] if mode == "--bake-archive" || mode == "--replay-archive" => (
                Some(Path::new(lib)),
                Some((Path::new(path), mode == "--bake-archive")),
                false,
            ),
            _ => {
                return Err(
                    "usage: shader-metal-mesh-probe [--emit-msl | --load-metallib LIB | --load-mutated-metallib LIB | --bake-archive LIB ARCHIVE | --replay-archive LIB ARCHIVE]".into(),
                );
            }
        };
        let dev = Device::system_default().ok_or("missing Metal device")?;
        if !dev.supports_family(MTLGPUFamily::Apple7) {
            return Err("owned mesh probe requires Apple GPU family 7 or newer".into());
        }
        let lib = if let Some(path) = path {
            super::metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
            dev.new_library_with_file(path)?
        } else {
            dev.new_library_with_source(SOURCE, &CompileOptions::new())?
        };
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
        let pipeline = if let Some((path, bake)) = archive {
            archive_pipeline(&dev, &desc, path, bake)?
        } else {
            dev.new_mesh_render_pipeline_state(&desc)?
        };
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
        let blue = if mutate_expected { 0 } else { 255 };
        for (case, input, row_coverage) in CASES {
            let words = input.checked_words()?;
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
            enc.set_cull_mode(MTLCullMode::None);
            enc.set_mesh_bytes(
                0,
                std::mem::size_of_val(&words) as u64,
                words.as_ptr().cast(),
            );
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
            for (y, covered) in row_coverage.into_iter().enumerate() {
                for x in 0..SIDE {
                    let expected = if x < covered {
                        [0, 255, blue, 255]
                    } else {
                        [255, 0, 0, 255]
                    };
                    let at = STRIDE * y + 4 * x;
                    let actual = &bytes[at..at + 4];
                    if actual != expected {
                        return Err(format!(
                            "{case}, pixel ({x},{y}): expected {expected:?}, got {actual:?}"
                        ));
                    }
                }
            }
            println!(
                "{} owned mesh, {case}: {pixels}/{pixels} pixels matched ({covered} covered)",
                dev.name(),
                covered = row_coverage.iter().sum::<usize>(),
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
