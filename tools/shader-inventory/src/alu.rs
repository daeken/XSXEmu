//! Test-only GFX10.3 subset. Not a console shader or dispatch ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alu {
    DoubleInput,
    InvertOutput,
}

pub const LANES: usize = 32;
pub const SENTINEL: u32 = 0xdecafbad;
pub const MASK: u32 = 0x8001_a53f;
// v_add_nc_u32_e32 v1, v0, v0; v_xor_b32_e32 v1, -1, v1; s_endpgm.
pub const FIXTURE: [u32; 3] = [0x4a020100, 0x3a0202c1, 0xbf810000];

fn decode(code: &[u32]) -> Result<Vec<Alu>, &'static str> {
    let mut result = Vec::new();
    let mut initialized = false;
    for (pc, &word) in code.iter().enumerate() {
        match word {
            0x4a020100 => {
                result.push(Alu::DoubleInput);
                initialized = true;
            }
            0x3a0202c1 if initialized => result.push(Alu::InvertOutput),
            0xbf810000 if initialized && pc + 1 == code.len() => return Ok(result),
            _ => return Err("unsupported opcode, operand, or termination for owned fixture"),
        }
    }
    Err("missing s_endpgm")
}

pub fn cpu(code: &[u32], input: &[u32; LANES], mask: u32) -> Result<[u32; LANES], &'static str> {
    let ops = decode(code)?;
    let mut result = [SENTINEL; LANES];
    for (lane, dst) in result.iter_mut().enumerate() {
        if mask & (1 << lane) != 0 {
            for op in &ops {
                *dst = match op {
                    Alu::DoubleInput => input[lane].wrapping_add(input[lane]),
                    Alu::InvertOutput => !*dst,
                };
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
        source.push_str(match op {
            Alu::DoubleInput => "v1 = v0 + v0;\n",
            Alu::InvertOutput => "v1 = 0xffffffffu ^ v1;\n",
        });
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
    fn unsupported_forms_error_on_both_paths() {
        for code in [
            &FIXTURE[..2],
            &FIXTURE[1..],
            &[FIXTURE[0] ^ 1, FIXTURE[2]],
            &[FIXTURE[0], FIXTURE[2], 0],
        ] {
            assert!(cpu(code, &[0; LANES], 1).is_err());
            assert!(msl(code).is_err());
        }
        let source = msl(&FIXTURE).unwrap();
        assert!(source.contains("v1 = v0 + v0;\nv1 = 0xffffffffu ^ v1;"));
        assert!(!msl(&[FIXTURE[0], FIXTURE[2]]).unwrap().contains("^"));
    }
}
