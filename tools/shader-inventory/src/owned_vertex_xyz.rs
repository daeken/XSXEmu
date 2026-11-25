//! Explicit launch inputs and independent raw-word goldens for an owned probe.
use metal::*;
use std::{error::Error, mem::size_of_val};

const ENTRY_V0: [u32; 4] = [0xa5a5_fffc, 0x1234_5679, 0xffff_fffe, 0xffff_ffff];
// (IEEE, F32 denorm mode bits) and independently listed OMOD decision.
const POLICIES: [(u32, bool); 8] = [
    (0x000, true),
    (0x010, true),
    (0x020, false),
    (0x030, false),
    (0x200, false),
    (0x210, false),
    (0x220, false),
    (0x230, false),
];
const XY_SCALED: [[u32; 2]; 4] = [
    [0xbf80_0000, 0x3f80_0000],
    [0xbf80_0000, 0xc040_0000],
    [0x4040_0000, 0x3f80_0000],
    [0x4040_0000, 0xc040_0000],
];
const XY_SUPPRESSED: [[u32; 2]; 4] = [
    [0xbf80_0000, 0x3f80_0000],
    [0xbf80_0000, 0xbf80_0000],
    [0x3f80_0000, 0x3f80_0000],
    [0x3f80_0000, 0xbf80_0000],
];
// s10 and literal goldens (CVT, Z) by rounding mode (RN, RU, RD, RZ).
const SCALARS: [(u32, [[u32; 2]; 4]); 4] = [
    (0, [[0, 0]; 4]),
    (
        65_535,
        [
            [0x477f_ff00, 0x3f80_0000],
            [0x477f_ff00, 0x3f80_0000],
            [0x477f_ff00, 0x3f7f_ffff],
            [0x477f_ff00, 0x3f7f_ffff],
        ],
    ),
    (
        16_777_217,
        [
            [0x4b80_0000, 0x4380_0080],
            [0x4b80_0001, 0x4380_0082],
            [0x4b80_0000, 0x4380_0080],
            [0x4b80_0000, 0x4380_0080],
        ],
    ),
    (
        u32::MAX,
        [
            [0x4f80_0000, 0x4780_0080],
            [0x4f80_0000, 0x4780_0080],
            [0x4f7f_ffff, 0x4780_007f],
            [0x4f7f_ffff, 0x4780_007f],
        ],
    ),
];

pub fn check(
    dev: &Device,
    pipeline: &ComputePipelineState,
    profile: &str,
) -> Result<(), Box<dyn Error>> {
    let mut launches = Vec::new();
    let mut expected = Vec::new();
    for (policy, scaled) in POLICIES {
        let xy = if scaled { XY_SCALED } else { XY_SUPPRESSED };
        for (s10, stages) in SCALARS {
            for (round, [cvt, z]) in stages.into_iter().enumerate() {
                launches.push([policy | round as u32, s10]);
                expected.extend(xy.map(|[x, y]| [x, y, z, cvt]));
            }
        }
    }

    let shared = MTLResourceOptions::StorageModeShared;
    let state = dev.new_buffer_with_data(
        launches.as_ptr().cast(),
        size_of_val(launches.as_slice()) as u64,
        shared,
    );
    let lanes = dev.new_buffer_with_data(
        ENTRY_V0.as_ptr().cast(),
        size_of_val(&ENTRY_V0) as u64,
        shared,
    );
    let output = dev.new_buffer(size_of_val(expected.as_slice()) as u64, shared);
    let words = output.contents().cast::<[u32; 4]>();
    if words.is_null() {
        return Err("unmapped vertex XYZ readback".into());
    }
    unsafe { words.write_bytes(0xa5, expected.len()) };
    let queue = dev.new_command_queue();
    let command = queue.new_command_buffer();
    let encoder = command.new_compute_command_encoder();
    encoder.set_compute_pipeline_state(pipeline);
    encoder.set_buffer(0, Some(&state), 0);
    encoder.set_buffer(1, Some(&lanes), 0);
    encoder.set_buffer(2, Some(&output), 0);
    encoder.dispatch_threads(
        MTLSize::new(expected.len() as u64, 1, 1),
        MTLSize::new(4, 1, 1),
    );
    encoder.end_encoding();
    command.commit();
    command.wait_until_completed();
    if command.status() != MTLCommandBufferStatus::Completed {
        return Err(format!(
            "vertex XYZ dispatch did not complete: {:?}",
            command.status()
        )
        .into());
    }
    let readback = unsafe { std::slice::from_raw_parts(words, expected.len()) };
    for (id, (got, want)) in readback.iter().zip(&expected).enumerate() {
        if got != want {
            let [mode, s10] = launches[id / 4];
            return Err(format!("{profile} vertex XYZ MODE {mode:#x} s10 {s10:#x} lane {}: got {got:08x?}, expected {want:08x?}", id % 4).into());
        }
    }
    let count = expected.len() * 4;
    println!(
        "{} {profile}: owned vertex XYZ + intermediate CVT {count}/{count} raw words ({} MODE/s10 profiles × 4 lanes)",
        dev.name(),
        launches.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent of the MSL significand code: binary64 exactly represents
    // the input integer and the product of these binary32 operands. Round
    // each operation separately and compare the RNE result to the exact value.
    fn round_positive(exact: f64, mode: usize) -> u32 {
        let nearest = exact as f32;
        let rounded = f64::from(nearest);
        let bits = nearest.to_bits();
        match mode {
            1 if rounded < exact => bits + 1,
            2 | 3 if rounded > exact => bits - 1,
            _ => bits,
        }
    }

    #[test]
    fn literal_goldens_cross_check_both_rounding_steps() {
        for (s10, stages) in SCALARS {
            for (mode, [cvt, z]) in stages.into_iter().enumerate() {
                assert_eq!(cvt, round_positive(f64::from(s10), mode));
                let exact_product = f64::from(f32::from_bits(cvt)) * (65_537.0 / 4_294_967_296.0);
                assert_eq!(z, round_positive(exact_product, mode));
            }
        }
        assert_eq!(SCALARS[1].1[0][0], SCALARS[1].1[2][0]); // CVT unchanged.
        assert_ne!(SCALARS[1].1[0][1], SCALARS[1].1[2][1]); // MUL rounding changed.
        assert_ne!(SCALARS[2].1[0][0], SCALARS[2].1[1][0]); // CVT rounding changed.
        let single_round =
            round_positive(f64::from(SCALARS[2].0) * (65_537.0 / 4_294_967_296.0), 0);
        assert_eq!(single_round, 0x4380_0081);
        assert_ne!(single_round, SCALARS[2].1[0][1]);
    }
}
