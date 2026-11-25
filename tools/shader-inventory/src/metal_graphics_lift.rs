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

// Literal expected colors, not decoded from input bits. The first draw
// owns the overlap because its snapped Z is 1/8 (strictly less than 1/4).
#[cfg(any(test, target_os = "macos"))]
fn expected_wait_depth(x: usize, y: usize) -> [f32; 4] {
    if (1..6).contains(&y) {
        if (2..6).contains(&x) {
            return [0., 1.8125, 0.5, 1.];
        }
        if (6..8).contains(&x) {
            return [0., 1.875, 1., -0.5];
        }
    }
    [1., 0., 1., 0.]
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
    use graphics_lift::{InterpFixture, MrtFixture};
    use metal::*;
    use std::path::Path;

    fn expected_interp(x: usize, y: usize, mode: InterpFixture) -> f32 {
        // Screen positions are (0,8), (16,8), (0,-8) in Metal coordinates.
        let b = (x as f64 + 0.5) / 16.;
        let c = (7.5 - y as f64) / 16.;
        let mut weights = [1. - b - c, b, c];
        if matches!(mode, InterpFixture::WrongPerspective) {
            weights[1] /= 2.;
            weights[2] /= 4.;
        }
        let values = if matches!(mode, InterpFixture::AffineZ | InterpFixture::WrongChannel) {
            [0.75, 0.25, 0.5]
        } else {
            [0.125, 0.625, 0.375]
        };
        (weights
            .into_iter()
            .zip(values)
            .map(|(w, v)| w * v)
            .sum::<f64>()
            / weights.iter().sum::<f64>()) as f32
    }

    enum Mode<'a> {
        Source,
        PackedSource(bool),
        PackedLoad(&'a Path, bool),
        MrtSource(MrtFixture),
        SwappedTripleSource,
        MrtLoad(&'a Path, MrtFixture),
        InterpSource(InterpFixture),
        InterpLoad(&'a Path, InterpFixture),
        BoundAffineSource(bool),
        BoundAffineLoad(&'a Path, bool),
        ConstantRtzSource(bool),
        ConstantRtzLoad(&'a Path, bool),
        BoundSource(bool),
        BoundSwappedSource,
        BoundLoad(&'a Path, bool),
        PosFirstSource,
        PosFirstLoad(&'a Path),
        WaitPosSource(bool),
        WaitPosLoad(&'a Path),
        UnpackSource(bool),
        UnpackLoad(&'a Path, bool),
        MultiSource,
        MultiLoad(&'a Path),
        DepthSource(bool),
        DepthLoad(&'a Path, bool),
        WaitDepthSource(bool),
        WaitDepthLoad(&'a Path),
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
            [mode] if mode == "--dual-source" => Mode::MrtSource(MrtFixture::Dual),
            [mode] if mode == "--triple-source" => Mode::MrtSource(MrtFixture::Triple),
            [mode] if mode == "--triple-rg-source" => Mode::MrtSource(MrtFixture::TripleRg),
            [mode] if mode == "--expect-swapped-triple" => Mode::SwappedTripleSource,
            [mode, lib] if mode == "--load-dual-metallib" => Mode::MrtLoad(Path::new(lib), MrtFixture::Dual),
            [mode, lib] if mode == "--load-triple-metallib" => Mode::MrtLoad(Path::new(lib), MrtFixture::Triple),
            [mode, lib] if mode == "--load-triple-rg-metallib" => Mode::MrtLoad(Path::new(lib), MrtFixture::TripleRg),
            [mode] if mode == "--emit-dual-msl" || mode == "--emit-triple-msl" || mode == "--emit-triple-rg-msl" => {
                let fixture = if mode == "--emit-triple-rg-msl" { MrtFixture::TripleRg } else if mode == "--emit-triple-msl" { MrtFixture::Triple } else { MrtFixture::Dual };
                print!("{}", graphics_lift::translate_mrt_fixture(fixture).map_err(|e| format!("MRT lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--bound-affine-x-source" || mode == "--bound-affine-z-source" => Mode::BoundAffineSource(mode == "--bound-affine-z-source"),
            [mode, lib] if mode == "--load-bound-affine-x-metallib" || mode == "--load-bound-affine-z-metallib" => Mode::BoundAffineLoad(Path::new(lib), mode == "--load-bound-affine-z-metallib"),
            [mode] if mode == "--emit-bound-affine-x-msl" || mode == "--emit-bound-affine-z-msl" => {
                print!("{}", graphics_lift::bound::owned_affine(mode == "--emit-bound-affine-z-msl").map_err(|e| format!("affine binding rejected: {e:?}"))?.source);
                return Ok(());
            }
            [mode] if mode == "--interp-x-source" => Mode::InterpSource(InterpFixture::AffineX),
            [mode] if mode == "--interp-z-source" => Mode::InterpSource(InterpFixture::AffineZ),
            [mode] if mode == "--expect-interp-wrong-mode" => Mode::InterpSource(InterpFixture::WrongPerspective),
            [mode] if mode == "--expect-interp-wrong-channel" => Mode::InterpSource(InterpFixture::WrongChannel),
            [mode, lib] if mode == "--load-interp-x-metallib" => Mode::InterpLoad(Path::new(lib), InterpFixture::AffineX),
            [mode, lib] if mode == "--load-interp-z-metallib" => Mode::InterpLoad(Path::new(lib), InterpFixture::AffineZ),
            [mode] if mode == "--emit-interp-x-msl" || mode == "--emit-interp-z-msl" => {
                let fixture = if mode == "--emit-interp-z-msl" { InterpFixture::AffineZ } else { InterpFixture::AffineX };
                print!("{}", graphics_lift::translate_interp_fixture(fixture).map_err(|e| format!("interpolation lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--constant-rtz-source" || mode == "--constant-rtz-rg-source" => Mode::ConstantRtzSource(mode == "--constant-rtz-rg-source"),
            [mode, lib] if mode == "--load-constant-rtz-metallib" || mode == "--load-constant-rtz-rg-metallib" => Mode::ConstantRtzLoad(Path::new(lib), mode == "--load-constant-rtz-rg-metallib"),
            [mode] if mode == "--emit-constant-rtz-msl" || mode == "--emit-constant-rtz-rg-msl" => {
                print!("{}", graphics_lift::translate_constant_rtz_fixture(mode == "--emit-constant-rtz-rg-msl").map_err(|e| format!("constant RTZ rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--expect-bound-swapped-component" => Mode::BoundSwappedSource,
            [mode] if mode == "--bound-source" || mode == "--bound-rg-source" => Mode::BoundSource(mode == "--bound-rg-source"),
            [mode, lib] if mode == "--load-bound-metallib" || mode == "--load-bound-rg-metallib" => Mode::BoundLoad(Path::new(lib), mode == "--load-bound-rg-metallib"),
            [mode] if mode == "--emit-bound-msl" || mode == "--emit-bound-rg-msl" => {
                print!("{}", graphics_lift::bound::owned_pair(mode == "--emit-bound-rg-msl").map_err(|e| format!("explicit binding rejected: {e:?}"))?.source);
                return Ok(());
            }
            [mode] if mode == "--pos-first-source" => Mode::PosFirstSource,
            [mode, lib] if mode == "--load-pos-first-metallib" => Mode::PosFirstLoad(Path::new(lib)),
            [mode] if mode == "--emit-pos-first-msl" => {
                print!("{}", graphics_lift::translate_pos_first_fixture().map_err(|e| format!("POS0 first lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--wait-pos-source" || mode == "--expect-late-pos-read" => Mode::WaitPosSource(mode == "--expect-late-pos-read"),
            [mode, lib] if mode == "--load-wait-pos-metallib" => Mode::WaitPosLoad(Path::new(lib)),
            [mode] if mode == "--emit-wait-pos-msl" => {
                print!("{}", graphics_lift::translate_wait_pos_fixture(false).map_err(|e| format!("position wait lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--unpack-byte-source" || mode == "--unpack-uint-source" => Mode::UnpackSource(mode == "--unpack-uint-source"),
            [mode, lib] if mode == "--load-unpack-byte-metallib" || mode == "--load-unpack-uint-metallib" => Mode::UnpackLoad(Path::new(lib), mode == "--load-unpack-uint-metallib"),
            [mode] if mode == "--emit-unpack-byte-msl" || mode == "--emit-unpack-uint-msl" => {
                print!("{}", graphics_lift::translate_unpack_fixture(mode == "--emit-unpack-uint-msl").map_err(|e| format!("unpack lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--multi-source" => Mode::MultiSource,
            [mode, lib] if mode == "--load-multi-metallib" => Mode::MultiLoad(Path::new(lib)),
            [mode] if mode == "--emit-multi-msl" => {
                print!("{}", graphics_lift::translate_multi_vertex_fixture().map_err(|e| format!("multi lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--wait-depth-source" || mode == "--expect-late-depth-read" => Mode::WaitDepthSource(mode == "--expect-late-depth-read"),
            [mode, lib] if mode == "--load-wait-depth-metallib" => Mode::WaitDepthLoad(Path::new(lib)),
            [mode] if mode == "--emit-wait-depth-msl" => {
                print!("{}", graphics_lift::translate_wait_depth_fixture(false).map_err(|e| format!("wait depth lift rejected: {e:?}"))?);
                return Ok(());
            }
            [mode] if mode == "--depth-source" || mode == "--early-depth-source" => Mode::DepthSource(mode == "--early-depth-source"),
            [mode, lib] if mode == "--load-depth-metallib" || mode == "--load-early-depth-metallib" => Mode::DepthLoad(Path::new(lib), mode == "--load-early-depth-metallib"),
            [mode] if mode == "--emit-depth-msl" || mode == "--emit-early-depth-msl" => {
                print!("{}", graphics_lift::translate_depth_fixture(mode == "--emit-early-depth-msl").map_err(|e| format!("depth lift rejected: {e:?}"))?);
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
            _ => return Err("usage: shader-metal-graphics-lift [--expect-swapped-triple | --triple-rg-source | --emit-triple-rg-msl | --load-triple-rg-metallib LIB | --triple-source | --emit-triple-msl | --load-triple-metallib LIB | --dual-source | --emit-dual-msl | --load-dual-metallib LIB | --bound-affine-{x,z}-source | --emit-bound-affine-{x,z}-msl | --load-bound-affine-{x,z}-metallib LIB | --interp-x-source | --interp-z-source | --expect-interp-wrong-mode | --expect-interp-wrong-channel | --emit-interp-x-msl | --emit-interp-z-msl | --load-interp-x-metallib LIB | --load-interp-z-metallib LIB | --constant-rtz[-rg]-source | --emit-constant-rtz[-rg]-msl | --load-constant-rtz[-rg]-metallib LIB | --expect-bound-swapped-component | --bound[-rg]-source | --emit-bound[-rg]-msl | --load-bound[-rg]-metallib LIB | --pos-first-source | --emit-pos-first-msl | --load-pos-first-metallib LIB | --wait-pos-source | --emit-wait-pos-msl | --load-wait-pos-metallib LIB | --expect-late-pos-read | --unpack-{byte,uint}-source | --emit-unpack-{byte,uint}-msl | --load-unpack-{byte,uint}-metallib LIB | --multi-source | --emit-multi-msl | --load-multi-metallib LIB | --packed-rg-source | --emit-packed-rg-msl | --load-packed-rg-metallib LIB | --wait-depth-source | --emit-wait-depth-msl | --load-wait-depth-metallib LIB | --expect-late-depth-read | --early-depth-source | --emit-early-depth-msl | --load-early-depth-metallib LIB | --depth-source | --emit-depth-msl | --load-depth-metallib LIB | --packed-source | --emit-packed-msl | --load-packed-metallib LIB | --emit-msl | --emit-mutated-msl | --load-metallib LIB | --load-mutated-metallib LIB | {--bake-archive|--replay-archive|--replay-mutated-archive} LIB ARCHIVE COMPILER_SHA256 | --expect-owned-metal-miss MUTATED_LIB ARCHIVE]".into()),
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
        let wait_depth = matches!(mode, Mode::WaitDepthSource(_) | Mode::WaitDepthLoad(_));
        let late_read = matches!(mode, Mode::WaitDepthSource(true));
        let depth = wait_depth || matches!(mode, Mode::DepthSource(_) | Mode::DepthLoad(..));
        let early_depth = matches!(mode, Mode::DepthSource(true) | Mode::DepthLoad(_, true));
        let bound_affine = match mode {
            Mode::BoundAffineSource(z) | Mode::BoundAffineLoad(_, z) => Some(z),
            _ => None,
        };
        let interp = match mode {
            Mode::InterpSource(f) | Mode::InterpLoad(_, f) => Some(f),
            Mode::BoundAffineSource(z) | Mode::BoundAffineLoad(_, z) => Some(if z {
                InterpFixture::AffineZ
            } else {
                InterpFixture::AffineX
            }),
            _ => None,
        };
        let constant_rtz = match mode {
            Mode::ConstantRtzSource(rg) | Mode::ConstantRtzLoad(_, rg) => Some(rg),
            _ => None,
        };
        let bound_swap = matches!(mode, Mode::BoundSwappedSource);
        let bound_pair = match mode {
            Mode::BoundSwappedSource => Some(
                graphics_lift::bound::owned_swapped_pair()
                    .map_err(|e| format!("explicit binding rejected: {e:?}"))?,
            ),
            Mode::BoundSource(rg) | Mode::BoundLoad(_, rg) => Some(
                graphics_lift::bound::owned_pair(rg)
                    .map_err(|e| format!("explicit binding rejected: {e:?}"))?,
            ),
            _ => None,
        };
        let bound_rg = bound_pair
            .as_ref()
            .map(|plan| plan.color.mask == graphics_lift::bound::Mask::Rg);
        let partial = partial || constant_rtz == Some(true) || bound_rg == Some(true);
        let wait_pos = matches!(mode, Mode::WaitPosSource(_) | Mode::WaitPosLoad(_));
        let pos_first = matches!(mode, Mode::PosFirstSource | Mode::PosFirstLoad(_));
        let late_pos = matches!(mode, Mode::WaitPosSource(true));
        let unpack = match mode {
            Mode::UnpackSource(uint) | Mode::UnpackLoad(_, uint) => Some(uint),
            _ => None,
        };
        let multi = matches!(mode, Mode::MultiSource | Mode::MultiLoad(_));
        let fixture = match mode {
            Mode::MrtSource(f) | Mode::MrtLoad(_, f) => Some(f),
            Mode::SwappedTripleSource => Some(MrtFixture::Triple),
            _ => None,
        };
        let mrt = fixture.is_some();
        let partial_mrt = matches!(fixture, Some(MrtFixture::TripleRg));
        let swapped = matches!(mode, Mode::SwappedTripleSource);
        let attachment_count = match fixture {
            None => 1,
            Some(MrtFixture::Dual) => 2,
            _ => 3,
        };
        let lib = match mode {
            Mode::Source
            | Mode::PackedSource(_)
            | Mode::DepthSource(_)
            | Mode::WaitDepthSource(_)
            | Mode::InterpSource(_)
            | Mode::BoundAffineSource(_)
            | Mode::ConstantRtzSource(_)
            | Mode::BoundSource(_)
            | Mode::BoundSwappedSource
            | Mode::PosFirstSource
            | Mode::WaitPosSource(_)
            | Mode::UnpackSource(_)
            | Mode::MultiSource
            | Mode::MrtSource(_)
            | Mode::SwappedTripleSource => {
                let msl = if let Some(fixture) = fixture {
                    graphics_lift::translate_mrt_fixture(fixture)
                } else if let Some(z) = bound_affine {
                    Ok(graphics_lift::bound::owned_affine(z)
                        .map_err(|e| format!("affine binding rejected: {e:?}"))?
                        .source)
                } else if let Some(interp) = interp {
                    graphics_lift::translate_interp_fixture(interp)
                } else if let Some(plan) = &bound_pair {
                    Ok(plan.source.clone())
                } else if let Some(rg) = constant_rtz {
                    graphics_lift::translate_constant_rtz_fixture(rg)
                } else if pos_first {
                    graphics_lift::translate_pos_first_fixture()
                } else if wait_pos {
                    graphics_lift::translate_wait_pos_fixture(late_pos)
                } else if let Some(uint) = unpack {
                    graphics_lift::translate_unpack_fixture(uint)
                } else if multi {
                    graphics_lift::translate_multi_vertex_fixture()
                } else if wait_depth {
                    graphics_lift::translate_wait_depth_fixture(late_read)
                } else if depth {
                    graphics_lift::translate_depth_fixture(early_depth)
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
            | Mode::InterpLoad(path, _)
            | Mode::BoundAffineLoad(path, _)
            | Mode::ConstantRtzLoad(path, _)
            | Mode::BoundLoad(path, _)
            | Mode::PosFirstLoad(path)
            | Mode::WaitPosLoad(path)
            | Mode::UnpackLoad(path, _)
            | Mode::MultiLoad(path)
            | Mode::MrtLoad(path, _)
            | Mode::DepthLoad(path, _)
            | Mode::WaitDepthLoad(path)
            | Mode::Load(path, _)
            | Mode::Archive(path, _, _, _, _)
            | Mode::ExpectStrictMiss(path, _) => {
                metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
                dev.new_library_with_file(path)?
            }
        };
        let desc = RenderPipelineDescriptor::new();
        const DEPTH_FORMAT: MTLPixelFormat = MTLPixelFormat::Depth32Float;
        let (format, pixel_bytes, default_ps) = if let Some(fixture) = fixture {
            (MTLPixelFormat::RGBA32Float, 16, fixture.entry())
        } else if bound_pair.is_some() {
            (MTLPixelFormat::RGBA32Float, 16, "bound_ps")
        } else if constant_rtz.is_some() {
            (MTLPixelFormat::RGBA32Float, 16, "constant_rtz_ps")
        } else if pos_first {
            (MTLPixelFormat::RGBA32Float, 16, "pos_first_ps")
        } else if wait_pos {
            (MTLPixelFormat::RGBA32Float, 16, "wait_pos_ps")
        } else if unpack.is_some() {
            (MTLPixelFormat::RGBA32Float, 16, "unpack_ps")
        } else if bound_affine.is_some() {
            (MTLPixelFormat::RGBA32Float, 16, "bound_ps")
        } else if interp.is_some() {
            (MTLPixelFormat::RGBA32Float, 16, "interp_ps")
        } else if multi {
            (MTLPixelFormat::RGBA32Float, 16, "multi_ps")
        } else if depth {
            desc.set_depth_attachment_pixel_format(DEPTH_FORMAT);
            (
                MTLPixelFormat::RGBA32Float,
                16,
                if wait_depth {
                    "wait_depth_ps"
                } else if early_depth {
                    "early_depth_ps"
                } else {
                    "depth_ps"
                },
            )
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
        for slot in 1..attachment_count {
            let attachment = desc
                .color_attachments()
                .object_at(slot as u64)
                .ok_or_else(|| format!("no pipeline slot {slot}"))?;
            attachment.set_pixel_format(format);
            attachment.set_write_mask(if partial_mrt && slot == 1 {
                MTLColorWriteMask::Red | MTLColorWriteMask::Green
            } else {
                MTLColorWriteMask::All
            });
            attachment.set_blending_enabled(false);
        }
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
        let mut colors = vec![color];
        for _ in 1..attachment_count {
            colors.push(dev.new_texture(&texture_desc));
        }
        for (index, clear) in [
            MTLClearColor::new(0., 0.5, if partial_mrt { 0.75 } else { 0. }, 1.),
            MTLClearColor::new(0.25, 1., 0.5, 0.),
        ]
        .into_iter()
        .take(attachment_count - 1)
        .enumerate()
        {
            let slot = index + 1;
            let bound = if swapped { 3 - slot } else { slot };
            let attachment = pass
                .color_attachments()
                .object_at(slot as u64)
                .ok_or_else(|| format!("no pass slot {slot}"))?;
            attachment.set_texture(Some(&colors[bound]));
            attachment.set_clear_color(clear);
            attachment.set_load_action(MTLLoadAction::Clear);
            attachment.set_store_action(MTLStoreAction::Store);
        }
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
        if bound_rg == Some(true) {
            // The second VS uses different native VGPRs and slot-6 records [z,x,w,y].
            let data: [[u32; 4]; 3] =
                [[0.0f32, -1., 1., -1.], [0., 1., 1., -1.], [0., -1., 1., 3.]]
                    .map(|record| record.map(f32::to_bits));
            enc.set_vertex_bytes(6, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
        } else if bound_pair.is_some() {
            // Raw uint4 records [w,y,x,z] at the explicitly bound slot 5.
            let data: [[u32; 4]; 3] =
                [[1.0f32, -1., -1., 0.], [1., -1., 1., 0.], [1., 3., -1., 0.]]
                    .map(|record| record.map(f32::to_bits));
            enc.set_vertex_bytes(5, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
        }
        if interp.is_some() {
            // Equal NDC positions to the baseline, but W varies across vertices.
            let data: [[f32; 8]; 3] = [
                [-1., -1., 0., 1., 0.125, 0., 0.75, 0.],
                [6., -2., 0., 2., 0.625, 0., 0.25, 0.],
                [-4., 12., 0., 4., 0.375, 0., 0.5, 0.],
            ];
            if bound_affine.is_some() {
                let position = data.map(|r| [r[0], r[1], r[2], r[3]]);
                let param = data.map(|r| [r[4], r[5], r[6], r[7]]);
                enc.set_vertex_bytes(
                    0,
                    std::mem::size_of_val(&position) as u64,
                    position.as_ptr().cast(),
                );
                enc.set_vertex_bytes(
                    1,
                    std::mem::size_of_val(&param) as u64,
                    param.as_ptr().cast(),
                );
            } else {
                enc.set_vertex_bytes(0, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
            }
        }
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
        if wait_pos || pos_first {
            // The wait control uses constant replacement X to degenerate the triangle.
            // The non-overlapping POS0-first path adds 0.25 to this red varying.
            let data = vertices.map(|v| [v[0], v[1], v[2], v[3], 0.25, 0.5, 0.75, 1.]);
            enc.set_scissor_rect(MTLScissorRect {
                x: 2,
                y: 1,
                width: 4,
                height: 5,
            });
            enc.set_vertex_bytes(0, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
        }
        if unpack.is_some() {
            // Each pair drives a two-column stripe with the same words at
            // all three vertices. The MSB of the shift source is discarded.
            for (stripe, [a, b]) in [
                [1, 0x8000_0000],
                [0x0200_0003, 0x8000_0001],
                [0x0200_0007, 0xffff_fffe],
                [0xffff_ffff, 0xffff_ffff],
            ]
            .into_iter()
            .enumerate()
            {
                let data: [[u32; 8]; 3] = vertices.map(|v| {
                    [
                        v[0].to_bits(),
                        v[1].to_bits(),
                        v[2].to_bits(),
                        v[3].to_bits(),
                        a,
                        b,
                        0,
                        0,
                    ]
                });
                enc.set_vertex_bytes(0, std::mem::size_of_val(&data) as u64, data.as_ptr().cast());
                enc.set_scissor_rect(MTLScissorRect {
                    x: (2 * stripe) as u64,
                    y: 0,
                    width: 2,
                    height: SIDE as u64,
                });
                enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
            }
        }
        if let Some(state) = depth_state.as_ref() {
            enc.set_depth_stencil_state(state);
            let draws = if wait_depth {
                // Positive F32 inputs above a half-ULP midpoint; RTZ must
                // produce 0x3f40/0x3f80 in the high half. A late depth read
                // interprets the packed words as 3/4 or 1, both above clear.
                [
                    (2, 0.875f32, [0u32, 0x3fe8_1800, 0x3e00_0000, 0x3c00_3800]),
                    (4, 0.125f32, [0u32, 0x3ff0_1800, 0x3e80_0000, 0xb800_3c00]),
                ]
            } else {
                [
                    (2, 0.875f32, [0xb800_3e00u32, 0x3400_c000, 0x3e00_0000, 0]),
                    (4, 0.125f32, [0x3c00_0000u32, 0x3c00_0000, 0x3e80_0000, 0]),
                ]
            };
            for (x, clip_z, inputs) in draws {
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
        } else if packed || mrt {
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
        if !depth && unpack.is_none() {
            enc.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
        }
        enc.end_encoding();
        let extent = attachment_count * BYTES;
        let readback = dev.new_buffer(extent as u64, MTLResourceOptions::StorageModeShared);
        let ptr = readback.contents().cast::<u8>();
        if ptr.is_null() {
            return Err("unmapped graphics readback".into());
        }
        // No CPU access to the shared buffer while the GPU executes.
        unsafe { ptr.write_bytes(0xa5, extent) };
        let blit = cmd.new_blit_command_encoder();
        for (slot, texture) in colors.iter().enumerate() {
            blit.copy_from_texture_to_buffer(
                texture,
                0,
                0,
                MTLOrigin { x: 0, y: 0, z: 0 },
                MTLSize::new(SIDE as u64, SIDE as u64, 1),
                &readback,
                (slot * BYTES) as u64,
                STRIDE as u64,
                0,
                MTLBlitOption::None,
            );
        }
        blit.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        if cmd.status() != MTLCommandBufferStatus::Completed {
            return Err(format!("translated render command: {:?}", cmd.status()));
        }
        // The GPU writes have completed and the owned buffer remains alive through the last read.
        let pixels = unsafe { std::slice::from_raw_parts(ptr, extent) };
        if let Some(rg) = bound_rg {
            // The diagonal in Metal screen space joins (0,-8) to (8,8).
            let written: [u32; 4] = if rg {
                [0x3f80_0000, 0xc000_0000, 0x3f80_0000, 0x3f40_0000]
            } else {
                [0x3f80_0000, 0xc000_0000, 0x8000_0000, 0x3880_0000]
            };
            let clear = [
                0x3f80_0000,
                0,
                0x3f80_0000,
                if rg { 0x3f40_0000 } else { 0 },
            ];
            let mut covered = 0;
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let inside = 2 * (2 * x + 1) < 16 + (2 * y + 1);
                    covered += usize::from(inside);
                    // X/Z swapped makes every clip X zero, degenerating the triangle.
                    let want = if inside && !bound_swap {
                        written
                    } else {
                        clear
                    };
                    let at = y * STRIDE + x * 16;
                    let got = std::array::from_fn(|i| {
                        u32::from_le_bytes(pixels[at + 4 * i..at + 4 * i + 4].try_into().unwrap())
                    });
                    if got != want {
                        return Err(format!(
                            "explicitly bound pair ({x},{y}): expected {want:08x?}, got {got:08x?}"
                        ));
                    }
                }
            }
            if bound_swap {
                println!(
                    "{} swapped X/Z binding: 64/64 pixels clear; {covered} expected writes lost",
                    dev.name()
                );
            } else {
                println!(
                    "{} explicitly bound pair (RG={rg}): 64/64 pixels bit-exact; {covered} covered",
                    dev.name()
                );
            }
            return Ok(());
        }
        if let Some(rg) = constant_rtz {
            // RTZ not RNE for ±normal inputs above the half midpoint.
            // Full writes include -0 and minimum half normal; RG preserves clear B/A.
            let want = if rg {
                [0x3f80_0000, 0xc000_0000, 0x3f80_0000, 0x3f40_0000]
            } else {
                [0x3f80_0000, 0xc000_0000, 0x8000_0000, 0x3880_0000]
            };
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let at = y * STRIDE + x * 16;
                    let got: [u32; 4] = std::array::from_fn(|i| {
                        u32::from_le_bytes(pixels[at + 4 * i..at + 4 * i + 4].try_into().unwrap())
                    });
                    if got != want {
                        return Err(format!(
                            "constant RTZ ({x},{y}): expected {want:08x?}, got {got:08x?}"
                        ));
                    }
                }
            }
            println!(
                "{} owned constant packed RTZ (RG-only={rg}): 64/64 pixels bit-exact",
                dev.name()
            );
            return Ok(());
        }
        if wait_pos || pos_first {
            let mut writes = 0;
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let covered = (2..6).contains(&x) && (1..6).contains(&y);
                    writes += usize::from(covered);
                    let want: [f32; 4] = if covered && !late_pos {
                        [if pos_first { 0.5 } else { 0.25 }, 0.5, 0.75, 1.]
                    } else {
                        [1., 0., 1., 0.]
                    };
                    let at = y * STRIDE + x * 16;
                    for (part, value) in pixels[at..at + 16].chunks_exact(4).zip(want) {
                        let got = f32::from_le_bytes(part.try_into().unwrap());
                        if !got.is_finite() || (got - value).abs() > 0.000001 {
                            return Err(format!(
                                "POS0 (position-first={pos_first}, late={late_pos}) ({x},{y}): expected {value}, got {got}"
                            ));
                        }
                    }
                }
            }
            println!(
                "{} owned POS0 {} (late={late_pos}): 64/64 pixels matched; {}",
                dev.name(),
                if pos_first {
                    "DONE → ADD → PARAM0"
                } else {
                    "export snapshot"
                },
                if late_pos {
                    format!("{writes} expected writes lost")
                } else {
                    format!("{writes} correct color writes")
                }
            );
            return Ok(());
        }
        if let Some(uint) = unpack {
            // Independent expected [2*x-1, 1-2*y, x, y]. The U32 table
            // explicitly fixes both ties at 2^25 and the carry to 2^32.
            let expected: [[f32; 4]; 4] = if uint {
                [
                    [-1., 1., 0., 0.],
                    [67_108_864., -3., 33_554_432., 2.],
                    [67_108_880., 1., 33_554_440., 0.],
                    [8_589_934_592., -3., 4_294_967_296., 2.],
                ]
            } else {
                [
                    [-1., 1., 0., 0.],
                    [3., -3., 2., 2.],
                    [3., 1., 2., 0.],
                    [3., -3., 2., 2.],
                ]
            };
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let want = expected[x / 2].map(f32::to_bits);
                    let at = y * STRIDE + x * 16;
                    let got: [u32; 4] = std::array::from_fn(|i| {
                        u32::from_le_bytes(pixels[at + 4 * i..at + 4 * i + 4].try_into().unwrap())
                    });
                    if got != want {
                        return Err(format!(
                            "unpack uint={uint} ({x},{y}): expected {want:08x?}, got {got:08x?}"
                        ));
                    }
                }
            }
            println!(
                "{} owned native VS unpack/FMA (uint={uint}): 64/64 pixels bit-exact",
                dev.name()
            );
            return Ok(());
        }
        if let Some(interp) = interp {
            let negative = matches!(
                interp,
                InterpFixture::WrongPerspective | InterpFixture::WrongChannel
            );
            let label = match interp {
                InterpFixture::AffineX => "affine X",
                InterpFixture::AffineZ => "affine Z",
                InterpFixture::WrongPerspective => "wrong perspective mode",
                InterpFixture::WrongChannel => "wrong channel",
            };
            let mut differs = 0;
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let want = expected_interp(x, y, interp);
                    let at = y * STRIDE + x * 16;
                    for component in pixels[at..at + 16].chunks_exact(4) {
                        let got = f32::from_le_bytes(component.try_into().unwrap());
                        // Raster interpolation rounds even for affine dyadics.
                        let ok = got.is_finite() && (got - want).abs() < 0.000001;
                        if !ok {
                            return Err(format!(
                                "{label} at ({x},{y}): expected {want}, got {got}"
                            ));
                        }
                    }
                    differs += usize::from(
                        (want - expected_interp(x, y, InterpFixture::AffineX)).abs() > 0.000001,
                    );
                }
            }
            if negative && differs != SIDE * SIDE {
                return Err(format!("{label} only discriminates {differs} pixels"));
            }
            println!(
                "{} owned native VS→PS {label}: 64/64 pixels matched{}",
                dev.name(),
                if negative {
                    " predicted control, all differ from affine X"
                } else {
                    ""
                }
            );
            return Ok(());
        }
        let mutated = matches!(mode, Mode::Load(_, true) | Mode::Archive(_, _, _, true, _));
        let mut mapping_mismatches = 0;
        let mut late_read_differences = 0;
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
                } else if wait_depth {
                    let correct = expected_wait_depth(x, y);
                    let clear: [f32; 4] = [1., 0., 1., 0.];
                    late_read_differences += usize::from(correct != clear);
                    fp32 = (if late_read { clear } else { correct })
                        .map(f32::to_le_bytes)
                        .as_flattened()
                        .to_owned();
                    &fp32
                } else if depth {
                    fp32 = expected_depth(x, y, false, true)
                        .map(f32::to_le_bytes)
                        .as_flattened()
                        .to_owned();
                    &fp32
                } else if packed || mrt {
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
                // Distinct per-slot writes and clears detect swaps, missing
                // writes and out-of-scissor writes without unpacking inputs.
                let inside = (2..6).contains(&x) && (1..6).contains(&y);
                let extra: [[f32; 4]; 2] = if inside {
                    [
                        if partial_mrt {
                            [1.5, -0.5, 0.75, 1.]
                        } else {
                            [1.5, -0.5, -2., 0.25]
                        },
                        [-2., 0.25, -2., 0.25],
                    ]
                } else {
                    [
                        [0., 0.5, if partial_mrt { 0.75 } else { 0. }, 1.],
                        [0.25, 1., 0.5, 0.],
                    ]
                };
                let extra = extra.map(|rgba| rgba.map(f32::to_le_bytes).as_flattened().to_owned());
                for index in 0..attachment_count - 1 {
                    let slot = index + 1;
                    let at = slot * BYTES + at;
                    let got = &pixels[at..at + pixel_bytes];
                    mapping_mismatches += usize::from(got != extra[index]);
                    let expected = &extra[if swapped { 1 - index } else { index }];
                    if got != expected {
                        return Err(format!(
                            "slot {slot} pixel ({x},{y}): expected {expected:?}, got {got:?}"
                        ));
                    }
                }
                if got != expected {
                    return Err(format!(
                        "pixel ({x},{y}): expected {expected:?}, got {got:?}"
                    ));
                }
            }
        }
        if late_read {
            if late_read_differences != 30 {
                return Err("late depth fixture oracle must distinguish 30 pixels".into());
            }
            println!(
                "late depth source read rejected by oracle: all 64 pixels cleared, including {late_read_differences} expected color writes"
            );
            return Ok(());
        }
        if swapped {
            if mapping_mismatches != 2 * SIDE * SIDE {
                return Err(format!(
                    "expected all 128 swapped-slot pixels to differ, got {mapping_mismatches}"
                ));
            }
            println!(
                "swapped MRT1/MRT2 binding rejected by oracle: all {mapping_mismatches} swapped-slot pixels differ from the normal mapping and match the predicted swap"
            );
            return Ok(());
        }
        if let (Mode::Archive(_, path, true, _, _), Some((job, lib))) = (mode, admitted) {
            owned_graphics_artifact::publish(&job, lib, path)?;
            println!("published owned graphics artifact identity");
        }
        println!(
            "{} translated GFX10 VS+PS (mutated={mutated}, packed={packed}, partial={partial}, depth={depth}, early_depth={early_depth}, wait_depth={wait_depth}, multi={multi}, partial_mrt={partial_mrt}, colors={attachment_count}): {n}/{n} attachment pixels matched",
            dev.name(),
            n = SIDE * SIDE * attachment_count
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
