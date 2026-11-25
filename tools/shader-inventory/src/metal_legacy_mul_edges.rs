//! Bit-exact arithmetic probe, separate from the synthetic graphics ABI.
#[cfg(target_os = "macos")]
mod graphics_decode;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
mod graphics_lift;
#[cfg(target_os = "macos")]
mod metal_artifact;

#[cfg(target_os = "macos")]
mod gpu {
    use metal::*;
    use std::path::Path;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() == 1 && args[0] == "--emit-msl" {
            print!(
                "{}",
                super::graphics_lift::translate_legacy_edge_fixture()
                    .map_err(|e| format!("decode: {e:?}"))?
            );
            return Ok(());
        }
        let [mode, lib, path] = args.as_slice() else {
            return Err(
                "usage: shader-legacy-mul-edges --emit-msl | <--bake|--replay> LIB ARCHIVE".into(),
            );
        };
        let bake = mode == "--bake";
        if (!bake && mode != "--replay") || std::env::var_os("MTL_SHADER_VALIDATION").is_some() {
            return Err("expected --bake or --replay with MTL_SHADER_VALIDATION unset".into());
        }
        let dev = Device::system_default().ok_or("no Metal device")?;
        super::metal_artifact::file_url(Path::new(lib), false)?;
        let lib = dev.new_library_with_file(Path::new(lib))?;
        let function = lib.get_function("legacy_edges", None)?;
        let url = super::metal_artifact::file_url(Path::new(path), bake)?;
        let ad = BinaryArchiveDescriptor::new();
        if !bake {
            ad.set_url(&url);
        }
        let archive = dev.new_binary_archive_with_descriptor(&ad)?;
        let pd = ComputePipelineDescriptor::new();
        pd.set_compute_function(Some(&function));
        if bake
            && (!archive.add_compute_pipeline_functions_with_descriptor(&pd)?
                || !archive.serialize_to_url(&url)?)
        {
            return Err("could not bake owned edge archive".into());
        }
        pd.set_binary_archives(&[&archive]);
        let (pipeline, _) = dev.new_compute_pipeline_state_with_reflection(
            &pd,
            MTLPipelineOption::FailOnBinaryArchiveMiss,
        )?;
        const P0: u32 = 0;
        const N0: u32 = 0x8000_0000;
        const INF: u32 = 0x7f80_0000;
        const NINF: u32 = 0xff80_0000;
        const NAN: u32 = 0x7fc1_2345;
        const N2: u32 = 0xc000_0000;
        const P3: u32 = 0x4040_0000;
        const N6: u32 = 0xc0c0_0000;
        const N_HALF: u32 = 0xbf00_0000;
        const P_THREE_QUARTERS: u32 = 0x3f40_0000;
        // Independent oracle: (a,b), then legacy (a*b, (1/4)*b) exact IEEE words.
        // No assertion of payload preservation when neither input has magnitude zero.
        let cases = [
            ([N0, INF], [P0, INF]),
            ([NAN, N0], [P0, P0]),
            ([P0, NINF], [P0, NINF]),
            ([NINF, P0], [P0, P0]),
            ([N0, N2], [P0, N_HALF]),
            ([N2, N0], [P0, P0]),
            ([P3, N2], [N6, N_HALF]),
            ([N2, P3], [N6, P_THREE_QUARTERS]),
        ];
        let mut inputs: Vec<_> = cases.iter().map(|([a, b], _)| [*a, *b, 0, 0]).collect();
        inputs.extend([
            [
                4097_f32.to_bits(),
                4097_f32.to_bits(),
                (-16785408_f32).to_bits(),
                0,
            ],
            [P3, N2, 7_f32.to_bits(), 0],
        ]);
        let rtz_start = inputs.len();
        // First row is above the half-ULP tie in both components: nearest-even
        // would give 0xc0013c01. Golden words are literal and do not use the helper.
        let rtz = [
            ([0x3f80_1800, 0xc000_1800], 0xc000_3c00, 0xc000_bc00),
            ([N0, 0x3e80_0000], 0x3400_8000, 0x3400_0000),
            ([0x3e80_0000, P0], 0x0000_3400, 0x0000_b400),
            ([P0, N0], 0x8000_0000, 0x8000_8000),
            ([0xc000_1800, 0x3f80_1800], 0x3c00_c000, 0x3c00_4000),
        ];
        inputs.extend(rtz.iter().map(|([a, b], _, _)| [*a, *b, 0, 0]));
        let nan_zero_row = inputs.len();
        inputs.push([NAN, P0, 0, 0]);
        // At magnitude one, half an ULP is 2^-24. Include ties in both
        // rounding directions, signed zeros and exact cancellation.
        let add_cases = [
            ([0x3f80_0000, 0x3380_0000], 0x3f80_0000),
            ([0x3f80_0001, 0x3380_0000], 0x3f80_0002),
            ([0xbf80_0001, 0xb380_0000], 0xbf80_0002),
            ([0x3f80_0000, 0x3380_0001], 0x3f80_0001),
            ([N0, N0], N0),
            ([P0, N0], P0),
            ([N0, P0], P0),
            ([N2, 0x4000_0000], P0),
        ];
        let add_start = inputs.len();
        inputs.extend(add_cases.iter().map(|([a, b], _)| [*a, *b, 0, 0]));
        // Independent raw goldens for -1+x: half-ULP on each side of -1,
        // both even choices, exact cancellation and both adjacent inputs to +1.
        let inline_add_cases = [
            (0x3300_0000, 0xbf80_0000), // +2^-25, tie to -1
            (0x33c0_0000, 0xbf7f_fffe), // +3*2^-25, tie away from -1
            (0xb380_0000, 0xbf80_0000), // -2^-24, tie to -1
            (0xb440_0000, 0xbf80_0002), // -3*2^-24, tie away from -1
            (0x3f80_0000, P0),
            (0x3f7f_ffff, 0xb380_0000),
            (0x3f80_0001, 0x3400_0000),
        ];
        let inline_add_start = inputs.len();
        inputs.extend(inline_add_cases.iter().map(|(x, _)| [*x, 0, 0, 0]));
        // Same inputs, independent raw goldens for +1-x. In particular,
        // cancellation is +0, not the -0 from negating a rounded add.
        let inline_sub_expected = [
            0x3f80_0000,
            0x3f7f_fffe,
            0x3f80_0000,
            0x3f80_0002,
            P0,
            0x3380_0000,
            0xb400_0000,
        ];
        // Independent literal (unscaled, scaled) goldens; odd integers
        // on either side of a rounding tie, both signs, and signed extrema.
        let cvt_cases: [(i32, u32, u32); 9] = [
            (0, 0, 0),
            (1, 0x3f80_0000, 0x4000_0000),
            (-1, 0xbf80_0000, 0xc000_0000),
            (16_777_217, 0x4b80_0000, 0x4c00_0000),
            (16_777_219, 0x4b80_0002, 0x4c00_0002),
            (-16_777_217, 0xcb80_0000, 0xcc00_0000),
            (-16_777_219, 0xcb80_0002, 0xcc00_0002),
            (i32::MAX, 0x4f00_0000, 0x4f80_0000),
            (i32::MIN, 0xcf00_0000, 0xcf80_0000),
        ];
        let cvt_start = inputs.len();
        inputs.extend(cvt_cases.iter().map(|(x, _, _)| [*x as u32, 0, 0, 0]));
        let bytes = std::mem::size_of_val(inputs.as_slice());
        let usage = MTLResourceOptions::StorageModeShared;
        let input = dev.new_buffer_with_data(inputs.as_ptr().cast(), bytes as u64, usage);
        let output = dev.new_buffer(5 * bytes as u64, usage);
        let out = output.contents().cast::<[u32; 4]>();
        let neg_output = dev.new_buffer((inputs.len() * 4) as u64, usage);
        let neg_out = neg_output.contents().cast::<u32>();
        if out.is_null() || neg_out.is_null() {
            return Err("unmapped readback".into());
        }
        // Shared buffer is owned here; no CPU access during execution.
        unsafe { out.write_bytes(0xa5, 5 * inputs.len()) };
        unsafe { neg_out.write_bytes(0xa5, inputs.len()) };
        let queue = dev.new_command_queue();
        let cmd = queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(&pipeline);
        enc.set_buffer(0, Some(&input), 0);
        enc.set_buffer(1, Some(&output), 0);
        enc.set_buffer(2, Some(&neg_output), 0);
        enc.dispatch_threads(
            MTLSize::new(inputs.len() as u64, 1, 1),
            MTLSize::new(inputs.len() as u64, 1, 1),
        );
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        if cmd.status() != MTLCommandBufferStatus::Completed {
            return Err("edge command did not complete".into());
        }
        for (i, (_, expected)) in cases.into_iter().enumerate() {
            // Exact dispatched extent, completed writes, owned allocation still live.
            let actual = unsafe { out.add(5 * i).read() };
            if actual[..2] != expected {
                return Err(
                    format!("edge row {i}: got {actual:08x?}, expected {expected:08x?}").into(),
                );
            }
        }
        // Integer oracle: 4097² - 16785408 and 3 × -2 + 7 both equal 1.
        // The first loses that unit if the multiplication rounds before the add.
        assert_eq!(4097_i64 * 4097 - 16785408, 1);
        assert_eq!(4097_f32 * 4097. - 16785408., 0.);
        for i in cases.len()..rtz_start {
            let got = unsafe { out.add(5 * i).read() }[2];
            if got != 1_f32.to_bits() {
                return Err(format!("FMAC row {i} returned {got:08x}").into());
            }
        }
        for (i, (_, expected, expected_neg)) in rtz.into_iter().enumerate() {
            let got = unsafe { out.add(5 * (rtz_start + i)).read() }[3];
            let got_neg = unsafe { neg_out.add(rtz_start + i).read() };
            if got != expected || got_neg != expected_neg {
                return Err(format!("RTZ row {i}: e32/e64 got {got:08x}/{got_neg:08x}, expected {expected:08x}/{expected_neg:08x}").into());
            }
        }
        let mov_oracle = [0, 0.5_f32.to_bits(), 1_f32.to_bits(), 0x7fc1_2345];
        for i in 0..inputs.len() {
            let got = unsafe { out.add(5 * i + 1).read() };
            if got != mov_oracle {
                return Err(
                    format!("MOV row {i}: got {got:08x?}, expected {mov_oracle:08x?}").into(),
                );
            }
        }
        // Literal result rows for (+0,-Inf), (NaN,+0), (-0,+Inf), and (+3,-2).
        // The '-0' input is nonzero as an unsigned integer, and the second
        // comparison must overwrite the first predicate (rather than OR it).
        for (i, expected) in [
            (2, [NAN, P0]),
            (nan_zero_row, [P0, N0]),
            (0, [INF, N0]),
            (6, [N2, P3]),
        ] {
            let got = unsafe { out.add(5 * i + 2).read() };
            if got[..2] != expected {
                return Err(format!(
                    "conditional row {i}: got {got:08x?}, expected {expected:08x?}"
                )
                .into());
            }
        }
        // +0 minus either signed zero is +0 under round-to-nearest; a
        // sign-bit XOR would incorrectly make the +0 input negative zero.
        for (i, expected) in [
            (2, [P0, INF]),
            (4, [P0, 0x4000_0000]),
            (6, [0xc040_0000, 0x4000_0000]),
            (0, [P0, NINF]),
        ] {
            let got = unsafe { out.add(5 * i + 2).read() };
            if got[2..] != expected {
                return Err(format!(
                    "subtract row {i}: got {:08x?}, expected {expected:08x?}",
                    &got[2..]
                )
                .into());
            }
        }
        // Ordinary (not legacy) multiply: both 0*Inf and NaN*0 are NaN;
        // compare classification only, not sign or payload. Finite, signed
        // zero and a product requiring one rounding use independent goldens.
        for i in [0, 1, 2, 3, nan_zero_row] {
            let got = unsafe { out.add(5 * i + 3).read() }[0];
            if !f32::from_bits(got).is_nan() {
                return Err(
                    format!("ordinary multiply row {i}: expected NaN, got {got:08x}").into(),
                );
            }
        }
        for (i, expected) in [(4, P0), (5, P0), (6, N6), (7, N6), (8, 0x4b80_1000)] {
            let got = unsafe { out.add(5 * i + 3).read() }[0];
            if got != expected {
                return Err(format!(
                    "ordinary multiply row {i}: expected {expected:08x}, got {got:08x}"
                )
                .into());
            }
        }
        // Reuse the (-0, +1/4) input to check a negative result zero.
        let got = unsafe { out.add(5 * (rtz_start + 1) + 3).read() }[0];
        if got != N0 {
            return Err(
                format!("ordinary multiply signed zero: expected -0, got {got:08x}").into(),
            );
        }
        for (i, (_, want)) in add_cases.into_iter().enumerate() {
            let got = unsafe { out.add(5 * (add_start + i) + 3).read() }[1];
            if got != want {
                return Err(
                    format!("ordinary add row {i}: expected {want:08x}, got {got:08x}").into(),
                );
            }
        }
        for (i, (_, want)) in inline_add_cases.into_iter().enumerate() {
            let got = unsafe { out.add(5 * (inline_add_start + i) + 3).read() }[2];
            if got != want {
                return Err(
                    format!("inline -1 add row {i}: expected {want:08x}, got {got:08x}").into(),
                );
            }
        }
        for (i, want) in inline_sub_expected.into_iter().enumerate() {
            let got = unsafe { out.add(5 * (inline_add_start + i) + 3).read() }[3];
            if got != want {
                return Err(format!(
                    "inline +1 subtract row {i}: expected {want:08x}, got {got:08x}"
                )
                .into());
            }
        }
        for (i, (x, plain, scaled)) in cvt_cases.into_iter().enumerate() {
            assert_eq!((f64::from(x) as f32).to_bits(), plain);
            assert_eq!(((f64::from(x) * 2.0) as f32).to_bits(), scaled);
            let want = [scaled, scaled, plain, plain];
            let got = unsafe { out.add(5 * (cvt_start + i) + 4).read() };
            if got != want {
                return Err(format!(
                    "OMOD1 conversion row {i}: got {got:08x?}, expected {want:08x?}"
                )
                .into());
            }
        }
        println!(
            "{}: strict arithmetic archive, 16/16 legacy words, 2/2 FMAC words, 5/5 e32 packed RTZ words, 5/5 e64 NEG0 packed RTZ words, {mov_words}/{mov_words} raw MOV words 8/8 select words, 8/8 subtract words 11/11 ordinary multiply checks 8/8 ordinary add words 7/7 inline -1 add words 7/7 inline +1 subtract words and 36/36 mode-dependent CVT words",
            dev.name(),
            mov_words = 4 * inputs.len()
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    metal::objc::rc::autoreleasepool(gpu::run)
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Metal required");
    std::process::exit(1);
}
