//! Test-only GFX10.3 subset. Not a console shader or dispatch ABI.
use crate::cfg::{self, Flow, Instruction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alu {
    DoubleInput,
    XorOutput(u32),
    Control,
}

pub const LANES: usize = 32;
pub const SENTINEL: u32 = 0xdecafbad;
pub const MASK: u32 = 0x8001_a53f;
pub const FIXTURE: [u32; 3] = [0x4a020100, 0x3a0202c1, 0xbf810000];
pub const BRANCH_FIXTURE: [u32; 6] = [
    0x4a020100, 0xbf820001, 0xffffffff, 0x3a0202ff, 0xa5a5a5a5, 0xbf810000,
];

pub const PC_FORWARD_FIXTURE: [u32; 10] = [
    0x4a020100, 0xbe941f00, 0x8014ff14, 20, 0x82158015, 0xbe802014, 0xffffffff, 0x3a0202ff,
    0xa5a5a5a5, 0xbf810000,
];
pub const PC_BACKWARD_FIXTURE: [u32; 10] = [
    0x4a020100, 0xbf820003, 0x3a0202ff, 0xa5a5a5a5, 0xbf810000, 0xbe941f00, 0x8094ff14, 16,
    0x82958015, 0xbe802014,
];

// Test-only fusion for the exact owned s[20:21] sequence. It has no externally
// visible scalar state in this backend; no supported instruction reads SCC or
// these SGPRs. The CFG checks the five dwords as a single extent, rejecting any
// reachable edge into the middle, including jumps into the literal itself.
fn pc_jump(words: &[u32]) -> Option<i16> {
    let [0xbe941f00, low, literal, high, 0xbe802014, ..] = words else {
        return None;
    };
    if literal % 4 != 0 {
        return None;
    }
    let dwords = i64::from(literal / 4);
    let delta = match (*low, *high) {
        (0x8014ff14, 0x82158015) => dwords,
        (0x8094ff14, 0x82958015) => -dwords,
        _ => return None,
    };
    // GETPC returns the next dword, while Flow::Jump is relative to the end of
    // the fused five-dword sequence.
    i16::try_from(delta - 4).ok()
}

fn decode_one(words: &[u32]) -> Option<Instruction<Alu>> {
    let word = *words.first()?;
    let (width, flow, op) = match word {
        0x4a020100 => (1, Flow::Next, Alu::DoubleInput),
        0x3a0202c1 => (1, Flow::Next, Alu::XorOutput(u32::MAX)),
        0x3a0202ff => (2, Flow::Next, Alu::XorOutput(*words.get(1)?)),
        0xbe941f00 => (5, Flow::Jump(pc_jump(words)?), Alu::Control),
        0xbf810000 => (1, Flow::Stop, Alu::Control),
        0xbf820000..=0xbf82ffff => (1, Flow::Jump(word as i16), Alu::Control),
        // Recognize the two edges, but do not lower conditional SCC branches yet.
        0xbf840000..=0xbf85ffff => (1, Flow::Fork(word as i16), Alu::Control),
        _ => return None,
    };
    Some(Instruction { width, flow, op })
}

fn decode(code: &[u32]) -> Result<Vec<Alu>, &'static str> {
    let graph = cfg::walk(code, decode_one)
        .map_err(|_| "invalid or unsupported reachable instruction graph")?;
    let mut result = Vec::new();
    let mut initialized = false;
    let mut pc = 0;
    // Our backend only flattens a finite, unconditional path. A path with
    // more steps than graph nodes has repeated a PC and will never exit.
    for _ in 0..graph.len() {
        let inst = &graph[&pc];
        let next = pc + inst.width;
        match inst.op {
            Alu::DoubleInput => {
                initialized = true;
                result.push(inst.op);
            }
            Alu::XorOutput(_) if initialized => result.push(inst.op),
            Alu::XorOutput(_) => return Err("read of uninitialized v1"),
            Alu::Control => (),
        }
        pc = match inst.flow {
            Flow::Stop if initialized => return Ok(result),
            Flow::Stop => return Err("uninitialized output at exit"),
            Flow::Next => next,
            Flow::Jump(d) => cfg::relative(next, d).unwrap(),
            Flow::Fork(_) => return Err("backend does not lower conditional branches"),
        };
    }
    Err("backend does not lower cycles")
}

pub fn cpu(code: &[u32], input: &[u32; LANES], mask: u32) -> Result<[u32; LANES], &'static str> {
    let ops = decode(code)?;
    let mut result = [SENTINEL; LANES];
    for (lane, dst) in result.iter_mut().enumerate() {
        if mask & (1 << lane) != 0 {
            for op in &ops {
                match op {
                    Alu::DoubleInput => *dst = input[lane].wrapping_add(input[lane]),
                    Alu::XorOutput(imm) => *dst ^= imm,
                    Alu::Control => unreachable!(),
                }
            }
        }
    }
    Ok(result)
}

pub fn msl(code: &[u32]) -> Result<String, &'static str> {
    let mut source = String::from(
        "#include <metal_stdlib>\nusing namespace metal;\n\
        kernel void fixture(device const uint* input [[buffer(0)]],\n\
        device uint* output [[buffer(1)]], constant uint& exec [[buffer(2)]],\n\
        uint lane [[thread_index_in_simdgroup]]) {\n\
        if (((exec >> lane) & 1u) == 0u) return;\n\
        uint v0 = input[lane];\nuint v1;\n",
    );
    for op in decode(code)? {
        use std::fmt::Write;
        match op {
            Alu::DoubleInput => source.push_str("v1 = v0 + v0;\n"),
            Alu::XorOutput(imm) => writeln!(source, "v1 = {imm:#010x}u ^ v1;").unwrap(),
            Alu::Control => unreachable!(),
        }
    }
    source.push_str("output[lane] = v1;\n}\n");
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_and_exec() {
        let mut input = [0u32; LANES];
        input[0] = u32::MAX;
        input[1] = 0x8000_0000;
        input[3] = 7;
        input[31] = 1;
        let result = cpu(&FIXTURE, &input, 0x8000_0003).unwrap();
        assert_eq!(&result[..4], &[1, u32::MAX, SENTINEL, SENTINEL]);
        assert_eq!(result[31], 0xffff_fffd);
        assert_eq!(cpu(&FIXTURE, &input, 0).unwrap(), [SENTINEL; LANES]);
        assert_eq!(cpu(&FIXTURE, &input, MASK).unwrap()[0], 1);
    }

    #[test]
    fn branch_skips_data_and_literal_is_not_an_instruction() {
        let mut input = [3; LANES];
        input[31] = 0x8000_0000;
        let output = cpu(&BRANCH_FIXTURE, &input, 0x8000_0001).unwrap();
        assert_eq!(output[0], 0xa5a5a5a3);
        assert_eq!(output[31], 0xa5a5a5a5);
        assert_eq!(output[1..31], [SENTINEL; 30]);
        let mut bad = BRANCH_FIXTURE;
        bad[1] = 0xbf820000; // reach the invalid skipped word
        assert!(msl(&bad).is_err());
        assert!(
            msl(&BRANCH_FIXTURE)
                .unwrap()
                .contains("v1 = 0xa5a5a5a5u ^ v1;")
        );
    }

    #[test]
    fn owned_pc_jump_preserves_alu_path_and_rejects_wrong_edges() {
        let expected = cpu(&BRANCH_FIXTURE, &[3; LANES], MASK).unwrap();
        for code in [&PC_FORWARD_FIXTURE, &PC_BACKWARD_FIXTURE] {
            assert_eq!(cpu(code, &[3; LANES], MASK).unwrap(), expected);
            assert_eq!(msl(code), msl(&BRANCH_FIXTURE));
        }
        for literal in [0, 3, 0x10000] {
            let mut bad = PC_FORWARD_FIXTURE;
            bad[3] = literal;
            assert!(msl(&bad).is_err());
            assert!(cpu(&bad, &[3; LANES], MASK).is_err());
        }
        let mut mixed = PC_BACKWARD_FIXTURE;
        mixed[8] = 0x82158015;
        assert!(msl(&mixed).is_err());
    }

    #[test]
    fn unsupported_forms_error_on_both_paths() {
        for code in [
            &FIXTURE[..2],
            &FIXTURE[1..],
            &[FIXTURE[0] ^ 1, FIXTURE[2]],
            &[FIXTURE[0], 0xbf82ffff],             // reachable cycle
            &[FIXTURE[0], 0xbf840000, FIXTURE[2]], // conditional (backend refusal)
            &BRANCH_FIXTURE[..4],                  // truncated literal
            &[FIXTURE[0], 0xbf82000f, FIXTURE[2]], // out of bounds
        ] {
            assert!(cpu(code, &[0; LANES], 1).is_err());
            assert!(msl(code).is_err());
        }
        let source = msl(&FIXTURE).unwrap();
        assert!(source.contains("v1 = v0 + v0;\nv1 = 0xffffffffu ^ v1;"));
        assert!(!msl(&[FIXTURE[0], FIXTURE[2]]).unwrap().contains("^"));
    }
}
