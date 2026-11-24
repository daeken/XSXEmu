//! Owned GFX10.3 subset with a synthetic, single-invocation buffer ABI.

pub const FIXTURE: [u32; 7] = [
    0xf4080202, 0xfa000010, // s_load_dwordx4 s[8:11], s[4:5], 0x10
    0xbf8cc07f, // s_waitcnt lgkmcnt(0)
    0x3a100091, // v_xor_b32_e32 v8, 17, v0
    0xe078100c, 0x84020804, // buffer_store_dwordx4 v[8:11], v4, s[8:11], 4 offen offset:12
    0xbf810000, // s_endpgm
];
const SCALAR_OFFSET: u32 = 4;
const XOR: u32 = 17;
const RAW_WRITE: u32 = 1;
const STORE_BYTES: u64 = 16;

pub struct Program {
    load_imm: u32,
    store_imm: u32,
}

impl Program {
    // Only these register assignments, instruction order and modifiers are
    // modeled. Vary only the low 12 unsigned bits of each byte immediate.
    pub fn decode(code: &[u32]) -> Result<Self, &'static str> {
        match *code {
            [
                0xf4080202,
                load,
                0xbf8cc07f,
                0x3a100091,
                store,
                0x84020804,
                0xbf810000,
            ] if load & !0xfff == 0xfa000000 && store & !0xfff == 0xe0781000 => Ok(Self {
                load_imm: load & 0xfff,
                store_imm: store & 0xfff,
            }),
            _ => Err("unsupported instruction sequence or operands for owned buffer probe"),
        }
    }

    pub fn cpu(&self, table: &[u32], output: &mut [u32], input: Input) {
        // Model addresses as offsets into host slices, not GPU addresses.
        let desc_offset = u64::from(input.table_base) + u64::from(self.load_imm);
        if desc_offset % 4 != 0 {
            return;
        }
        let first = (desc_offset / 4) as usize;
        let Some(&[binding, base, extent, mode]) = table.get(first..first + 4) else {
            return;
        };
        if binding != 0 || mode != RAW_WRITE || base % 4 != 0 || extent % 4 != 0 {
            return;
        }
        let base = u64::from(base);
        let extent = u64::from(extent);
        if (base + extent) / 4 > output.len() as u64 {
            return;
        }
        let offset =
            u64::from(input.lane_offset) + u64::from(self.store_imm) + u64::from(SCALAR_OFFSET);
        if offset % 4 != 0 || offset + STORE_BYTES > extent {
            return;
        }
        let first = ((base + offset) / 4) as usize;
        let [v0, v9, v10, v11] = input.data;
        output[first..first + 4].copy_from_slice(&[v0 ^ XOR, v9, v10, v11]);
    }

    pub fn msl(&self) -> String {
        // The scalar load is synchronous in this lowering. The exact
        // lgkmcnt(0) is required by decode; no general waitcnt is modeled.
        format!(
            r#"#include <metal_stdlib>
using namespace metal;
kernel void buffer_fixture(device const uint* table [[buffer(0)]],
                           device uint* output [[buffer(1)]],
                           constant uint* args [[buffer(2)]]) {{
    const ulong table_bytes = ulong(args[1]) * 4ul;
    const ulong desc = ulong(args[0]) + {load_imm}ul;
    if ((desc & 3ul) != 0 || desc > table_bytes || table_bytes - desc < 16ul) return;
    const ulong i = desc / 4ul;
    const uint binding = table[i];
    const ulong base = table[i + 1];
    const ulong extent = table[i + 2];
    const uint mode = table[i + 3];
    if (binding != 0u || mode != {RAW_WRITE}u || ((base | extent) & 3ul) != 0) return;
    const ulong output_bytes = ulong(args[2]) * 4ul;
    if (base > output_bytes || extent > output_bytes - base) return;
    const ulong offset = ulong(args[3]) + {store_imm}ul + {SCALAR_OFFSET}ul;
    if ((offset & 3ul) != 0 || offset > extent || extent - offset < {STORE_BYTES}ul) return;
    const ulong dst = (base + offset) / 4ul;
    output[dst] = args[4] ^ {XOR}u;
    output[dst + 1] = args[5];
    output[dst + 2] = args[6];
    output[dst + 3] = args[7];
}}
"#,
            load_imm = self.load_imm,
            store_imm = self.store_imm,
        )
    }
}

#[derive(Clone, Copy)]
pub struct Input {
    pub table_base: u32,
    pub lane_offset: u32,
    pub data: [u32; 4],
}

pub const SENTINEL: u32 = 0xa793_2dce;
const PAYLOAD: [u32; 4] = [0x4928_31ca, 0x8000_0000, 0, u32::MAX];

#[derive(Clone, Copy)]
pub struct Case {
    pub name: &'static str,
    table: [u32; 9],
    table_words: usize,
    pub output_words: usize,
    pub input: Input,
    // Literal oracle, not computed using the decoded offsets or CPU model.
    expected_word: Option<usize>,
}

impl Case {
    pub fn table(&self) -> &[u32] {
        &self.table[..self.table_words]
    }

    pub fn expected(&self) -> Vec<u32> {
        let mut output = vec![SENTINEL; self.output_words];
        if let Some(i) = self.expected_word {
            output[i..i + 4].copy_from_slice(&[0x4928_31db, 0x8000_0000, 0, u32::MAX]);
        }
        output
    }
}

pub fn cases() -> [Case; 16] {
    // Table's last four words are a descriptor; a valid decoy at index 0
    // makes erroneous u32-wrapping SMEM address arithmetic observable.
    let valid = Case {
        name: "exact descriptor and resource end (with backing canary)",
        table: [0, 0, 52, 1, SENTINEL, 0, 12, 52, 1],
        table_words: 9,
        output_words: 20,
        input: Input {
            table_base: 4,
            lane_offset: 20,
            data: PAYLOAD,
        },
        expected_word: Some(12),
    };
    let reject = Case {
        expected_word: None,
        ..valid
    };
    let descriptor = |desc: [u32; 4]| {
        let mut table = valid.table;
        table[5..].copy_from_slice(&desc);
        table
    };
    [
        valid,
        Case {
            name: "exact backing end",
            output_words: 16,
            ..valid
        },
        Case {
            name: "dword-aligned but not 16-byte-aligned store",
            input: Input {
                lane_offset: 8,
                ..valid.input
            },
            expected_word: Some(9),
            ..valid
        },
        Case {
            name: "truncated descriptor",
            table_words: 8,
            ..reject
        },
        Case {
            name: "descriptor start beyond table",
            input: Input {
                table_base: 36,
                ..valid.input
            },
            ..reject
        },
        Case {
            name: "unaligned descriptor address",
            input: Input {
                table_base: 3,
                ..valid.input
            },
            ..reject
        },
        Case {
            name: "descriptor address would wrap u32",
            input: Input {
                table_base: u32::MAX - 15,
                ..valid.input
            },
            ..reject
        },
        Case {
            name: "unknown binding",
            table: descriptor([1, 12, 52, 1]),
            ..reject
        },
        Case {
            name: "unsupported descriptor mode",
            table: descriptor([0, 12, 52, 3]),
            ..reject
        },
        Case {
            name: "unaligned view base",
            table: descriptor([0, 13, 52, 1]),
            ..reject
        },
        Case {
            name: "unaligned view extent",
            table: descriptor([0, 12, 53, 1]),
            ..reject
        },
        Case {
            name: "view exceeds backing though store would fit",
            table: descriptor([0, 12, 72, 1]),
            ..reject
        },
        Case {
            name: "view end would wrap u32",
            table: descriptor([0, u32::MAX - 3, 52, 1]),
            ..reject
        },
        Case {
            name: "last dword of store exceeds view",
            table: descriptor([0, 12, 48, 1]),
            ..reject
        },
        Case {
            name: "unaligned relative store offset",
            input: Input {
                lane_offset: 19,
                ..valid.input
            },
            ..reject
        },
        Case {
            name: "relative store offset would wrap u32",
            input: Input {
                lane_offset: u32::MAX - 15,
                ..valid.input
            },
            ..reject
        },
    ]
}

#[cfg(test)]
mod tests;
