//! Owned GFX10.3 wave32 subset: EXEC intersection and a uniform EXECZ branch.
//! The host initializes the x input and EXEC, observes v1 writes, and receives
//! an extra test-only exit ordinal. This is not an FSSM dispatch ABI.
use crate::cfg::{self, Flow, Instruction};
use std::collections::BTreeMap;
use std::fmt::Write;

pub const LANES: usize = 32;
pub const OUTPUT_WORDS: usize = LANES + 1;
pub const SENTINEL: u32 = 0xdecafbad;
pub const FIXTURE: [u32; 5] = [0x7da80088, 0xbf880002, 0x4a020100, 0xbf810000, 0xbf810000];

#[derive(Debug)]
enum Op {
    CompareLimitGtV0(u32),
    DoubleV0IntoV1,
    End,
    BranchExecZero,
}

pub struct Program(BTreeMap<usize, Instruction<Op>>);

fn decode(words: &[u32]) -> Option<Instruction<Op>> {
    let word = *words.first()?;
    let (flow, op) = match word {
        // VOPC v_cmpx_gt_u32_e32, vsrc1 = v0, src0 = unsigned inline 0..64.
        0x7da80080..=0x7da800c0 => (Flow::Next, Op::CompareLimitGtV0(word & 0x7f)),
        0x4a020100 => (Flow::Next, Op::DoubleV0IntoV1),
        0xbf810000 => (Flow::Stop, Op::End),
        0xbf880000..=0xbf88ffff => (Flow::Fork(word as i16), Op::BranchExecZero),
        _ => return None,
    };
    Some(Instruction { width: 1, flow, op })
}

impl Program {
    pub fn decode(words: &[u32]) -> Result<Self, &'static str> {
        // Compiler size bound for this owned subset, not a general ISA limit.
        if words.len() > 64 {
            return Err("owned EXEC probe program is too large");
        }
        let graph =
            cfg::walk(words, decode).map_err(|_| "invalid or unsupported EXEC probe graph")?;
        for (&pc, inst) in &graph {
            if let Flow::Fork(d) = inst.flow
                && fork_target(pc, d) <= pc
            {
                return Err("owned EXEC probe requires strictly forward edges");
            }
        }
        Ok(Self(graph))
    }

    pub fn run(&self, input: &[u32; LANES], mut exec: u32) -> [u32; OUTPUT_WORDS] {
        let mut pc = 0;
        let mut output = [SENTINEL; OUTPUT_WORDS];
        loop {
            let inst = &self.0[&pc];
            match inst.op {
                Op::CompareLimitGtV0(limit) => {
                    let passing = input
                        .iter()
                        .enumerate()
                        .fold(0, |m, (lane, &v)| m | (u32::from(limit > v) << lane));
                    exec &= passing;
                }
                Op::DoubleV0IntoV1 => {
                    for (lane, (&value, dst)) in input.iter().zip(&mut output).enumerate() {
                        if exec & (1 << lane) != 0 {
                            *dst = value.wrapping_add(value);
                        }
                    }
                }
                Op::End => {
                    output[LANES] = pc as u32;
                    return output;
                }
                Op::BranchExecZero if exec == 0 => {
                    pc = fork_target(pc, displacement(inst));
                    continue;
                }
                Op::BranchExecZero => (),
            }
            pc += 1;
        }
    }

    pub fn msl(&self) -> String {
        let mut src = String::from(
            "#include <metal_stdlib>\nusing namespace metal;\n\
            kernel void exec_fixture(device const uint* input [[buffer(0)]],\n\
            device uint* output [[buffer(1)]], constant uint& mask [[buffer(2)]],\n\
            uint lane [[thread_index_in_simdgroup]]) {\n\
            uint v0 = input[lane];\n\
            bool active = ((mask >> lane) & 1u) != 0u;\n\
            uint pc = 0u;\n",
        );
        // Every lane runs the scalar path, even when guest EXEC is zero. The
        // only predicate that can alter the shared PC is a SIMD-wide vote.
        for (&pc, inst) in &self.0 {
            writeln!(src, "if (pc == {pc}u) {{").unwrap();
            match inst.op {
                Op::CompareLimitGtV0(limit) => {
                    writeln!(
                        src,
                        "active = active && ({limit}u > v0);\npc = {}u;",
                        pc + 1
                    )
                    .unwrap();
                }
                Op::DoubleV0IntoV1 => {
                    writeln!(
                        src,
                        "if (active) output[lane] = v0 + v0;\npc = {}u;",
                        pc + 1
                    )
                    .unwrap();
                }
                Op::BranchExecZero => {
                    writeln!(
                        src,
                        "pc = simd_any(active) ? {}u : {}u;",
                        pc + 1,
                        fork_target(pc, displacement(inst))
                    )
                    .unwrap();
                }
                Op::End => {
                    writeln!(src, "if (lane == 0u) output[{LANES}] = {pc}u;\nreturn;").unwrap();
                }
            }
            src.push_str("}\n");
        }
        src.push_str("}\n");
        src
    }
}

fn displacement(inst: &Instruction<Op>) -> i16 {
    let Flow::Fork(d) = inst.flow else {
        unreachable!("validated EXEC branch")
    };
    d
}

fn fork_target(pc: usize, d: i16) -> usize {
    cfg::relative(pc + 1, d).expect("validated successor")
}

pub const CASES: [(u32, u32, u32); 5] = [
    // initial EXEC, expected survivors when v0 == lane, expected exit
    (u32::MAX, 0xff, 3),
    (0x8000_0082, 0x82, 3),
    (0x8000_0000, 0, 4),
    (0, 0, 4),
    (0x0000_0100, 0, 4), // strict comparison at v0 == limit
];

pub fn expected(survivors: u32, exit: u32) -> [u32; OUTPUT_WORDS] {
    let mut values = [SENTINEL; OUTPUT_WORDS];
    for (lane, output) in values[..LANES].iter_mut().enumerate() {
        if survivors & (1 << lane) != 0 {
            *output = (lane as u32) * 2;
        }
    }
    values[LANES] = exit;
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_exec_intersects_and_branches_even_if_entire_wave_inactive() {
        let program = Program::decode(&FIXTURE).unwrap();
        let input = std::array::from_fn(|lane| lane as u32);
        for (initial, survivors, exit) in CASES {
            assert_eq!(program.run(&input, initial), expected(survivors, exit));
        }
        let mut high_lane_value = input;
        high_lane_value[31] = 2;
        let mask = 1 << 31;
        let mut oracle = [SENTINEL; OUTPUT_WORDS];
        oracle[31] = 4;
        oracle[LANES] = 3;
        assert_eq!(program.run(&high_lane_value, mask), oracle);
        assert!(program.msl().contains("simd_any(active)"));
    }

    #[test]
    fn refuses_unmodeled_modifiers_operands_and_backward_edges() {
        for bad in [0x7da800ff, 0x7da80288, 0x7da00088, 0xbf88fffe, 0xbf887fff] {
            assert!(Program::decode(&[bad, 0xbf810000]).is_err());
        }
        assert!(Program::decode(&FIXTURE[..4]).is_err());
        assert!(Program::decode(&FIXTURE[..0]).is_err());
    }
}
