//! Owned forward EXECZ over a bounded buffer sequence. No guest GPU pointers.
use crate::{buffer, cfg, exec};

pub const FIXTURE: [u32; 11] = [
    0x7da80088, 0xbf880008, 0x34080284, 0xf4080202, 0xfa000010, 0xbf8cc07f, 0x3a100091, 0xe078100c,
    0x84020804, 0xbf810000, 0xbf810000,
];
pub const OUTPUT: usize = 136;
pub const LANES: usize = exec::LANES;

pub struct Program {
    limit: u32,
    store: buffer::Program,
}

impl Program {
    pub fn decode(code: &[u32]) -> Result<Self, &'static str> {
        // Check exact operand layout, initialization from the fixture ABI,
        // and that the empty branch jumps to its own exit past all accesses.
        let [cmp, branch, 0x34080284, store @ .., 0xbf810000] = code else {
            return Err("unsupported owned EXEC-store sequence");
        };
        let limit = exec::cmpx_limit(*cmp).ok_or("unsupported EXEC compare")?;
        if branch >> 16 != 0xbf88 || cfg::relative(2, *branch as i16) != Some(code.len() - 1) {
            return Err("invalid owned EXECZ target");
        }
        Ok(Self {
            limit,
            store: buffer::Program::decode(store)?,
        })
    }

    pub fn cpu(&self, test: &Case) -> Vec<u32> {
        let mut out = vec![buffer::SENTINEL; OUTPUT];
        let exec =
            test.exec & (0..LANES as u32).fold(0, |acc, v| acc | (u32::from(self.limit > v) << v));
        out[OUTPUT - 1] = u32::from(exec == 0);
        let table = test.owned_table();
        for lane in 0..LANES as u32 {
            if exec & (1 << lane) == 0 {
                continue;
            }
            self.store.cpu(
                &table[..test.table_words()],
                &mut out[..OUTPUT - 1],
                buffer::Input {
                    table_base: test.table_base,
                    lane_offset: lane << 4,
                    data: [lane, 0x8000_0000, 0, u32::MAX],
                },
            );
        }
        out
    }

    pub fn msl(&self) -> String {
        format!(
            r#"{}
kernel void exec_store_fixture(device const uint* table [[buffer(0)]],
                               device uint* output [[buffer(1)]],
                               constant uint* args [[buffer(2)]],
                               uint lane [[thread_index_in_simdgroup]]) {{
    bool active = (((args[3] >> lane) & 1u) != 0u) && ({limit}u > lane);
    bool empty = !simd_any(active);
    if (lane == 0) output[args[2]] = uint(empty);
    if (empty) return;
    // Scalar fixture data is uniform, immutable and synchronously read.
    // Multiples of 16 keep active-lane writes disjoint even for a clipped view.
    if (active) bounded_store(table, output, args, lane << 4, lane);
}}
"#,
            self.store.msl_helper(),
            limit = self.limit
        )
    }
}

pub struct Case {
    pub exec: u32,
    pub table_base: u32,
    binding: u32,
    extent: u32,
    table_words: usize,
    expected_exec: u32,
    expected_writes: u32,
}
impl Case {
    pub fn owned_table(&self) -> [u32; 9] {
        // Index 1 is a valid decoy if descriptor addressing accidentally wraps.

        [99, 0, 0, 144, 1, self.binding, 12, self.extent, 1]
    }
    pub fn table_words(&self) -> usize {
        self.table_words
    }
    pub fn expected(&self) -> Vec<u32> {
        let mut out = vec![buffer::SENTINEL; OUTPUT];
        for lane in 0..LANES {
            if self.expected_writes & (1 << lane) != 0 {
                let i = 7 + lane * 4;
                out[i..i + 4].copy_from_slice(&[0x11 ^ lane as u32, 0x8000_0000, 0, u32::MAX]);
            }
        }
        out[OUTPUT - 1] = u32::from(self.expected_exec == 0);
        out
    }
}

pub fn cases() -> [Case; 8] {
    let all = Case {
        exec: u32::MAX,
        table_base: 4,
        binding: 0,
        extent: 144,
        table_words: 9,
        expected_exec: 0xff,
        expected_writes: 0xff,
    };
    [
        Case { exec: 0xff, ..all },
        Case {
            exec: 0x8000_0082,
            expected_exec: 0x82,
            expected_writes: 0x82,
            ..all
        },
        Case {
            exec: 0x8000_0100,
            expected_exec: 0,
            expected_writes: 0,
            ..all
        },
        Case {
            exec: 0,
            expected_exec: 0,
            expected_writes: 0,
            ..all
        },
        Case {
            extent: 140,
            expected_writes: 0x7f,
            ..all
        },
        Case {
            table_words: 8,
            expected_writes: 0,
            ..all
        },
        Case {
            binding: 1,
            expected_writes: 0,
            ..all
        },
        Case {
            table_base: u32::MAX - 11,
            expected_writes: 0,
            ..all
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_outputs_and_refusals() {
        let p = Program::decode(&FIXTURE).unwrap();
        for case in cases() {
            assert_eq!(p.cpu(&case), case.expected());
        }
        for at in [0, 1, 2, 3, 5, 8, 9, 10] {
            let mut bad = FIXTURE;
            bad[at] ^= 0x1000;
            assert!(Program::decode(&bad).is_err(), "word {at}");
        }
    }
}
