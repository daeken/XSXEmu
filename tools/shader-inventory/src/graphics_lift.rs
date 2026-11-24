//! Strict, synthetic VS+PS contract for a small public GFX10 instruction subset.
use std::fmt::Write;

use crate::graphics_decode::{DecodeError, FloatSource, Op, Target, Vgpr, decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Vertex,
    Pixel,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Extent,
    Unsupported(usize),
    Truncated(usize),
    Uninitialized(usize, u8),
    BadExports(usize),
    BadEnd(usize),
}

// Owned fixture words, independently checked against LLVM MC. No container entry
// or implicit ABI is selected by this translator.
const VS: &[u32] = &[
    0x7e10_0304, // v_mov_b32_e32 v8, v4
    0xf800_020f,
    0x0706_0508, // exp param0 v8, v5, v6, v7
    0xf800_08cf,
    0x0302_0100, // exp pos0 v0, v1, v2, v3 done
    0xbf81_0000, // s_endpgm
];
const PS: &[u32] = &[
    0x0608_00ff,
    0x3e80_0000, // v_add_f32_e32 v4, 0.25, v0
    0xd54b_0005,
    0x040e_0501, // v_fma_f32 v5, v1, v2, v3
    0x0e0c_0905, // v_mul_legacy_f32_e32 v6, v5, v4
    0x0e0c_0cf0, // v_mul_legacy_f32_e32 v6, 0.5, v6
    0x0e0e_0680, // v_mul_legacy_f32_e32 v7, 0, v3
    0xf800_080f,
    0x0706_0504, // exp mrt0 v4, v5, v6, v7 done
    0xbf81_0000, // s_endpgm
];

impl Stage {
    fn input_registers(self) -> usize {
        match self {
            Stage::Vertex => 8,
            Stage::Pixel => 4,
        }
    }

    fn exports(self) -> &'static [(Target, bool)] {
        match self {
            Stage::Vertex => &[(Target::Parameter, false), (Target::Position, true)],
            Stage::Pixel => &[(Target::Color, true)],
        }
    }
}

fn lift(stage: Stage, words: &[u32]) -> Result<Vec<Op>, Reject> {
    if words.is_empty() || words.len() > 1024 {
        return Err(Reject::Extent);
    }
    let mut live = [false; 256];
    live[..stage.input_registers()].fill(true);
    let mut ops = Vec::new();
    let mut pc = 0;
    let mut exported = 0;
    while pc < words.len() {
        let (width, op) = decode(words, pc).map_err(|err| match err {
            DecodeError::Unsupported(pc) => Reject::Unsupported(pc),
            DecodeError::Truncated(pc) => Reject::Truncated(pc),
        })?;
        let require = |Vgpr(r)| {
            live[usize::from(r)]
                .then_some(())
                .ok_or(Reject::Uninitialized(pc, r))
        };
        if exported == stage.exports().len() && op != Op::End {
            return Err(Reject::BadEnd(pc));
        }
        match op {
            Op::Move { dst, src } | Op::AddF32Literal { dst, src, .. } => {
                require(src)?;
                live[usize::from(dst.0)] = true;
            }
            Op::MulLegacyF32 { dst, lhs, rhs } => {
                if let FloatSource::Vgpr(r) = lhs {
                    require(r)?;
                }
                require(rhs)?;
                live[usize::from(dst.0)] = true;
            }
            Op::FmaF32 { dst, src } => {
                for r in src {
                    require(r)?;
                }
                live[usize::from(dst.0)] = true;
            }
            Op::Export { target, src, done } => {
                if stage.exports().get(exported) != Some(&(target, done)) {
                    return Err(Reject::BadExports(pc));
                }
                for r in src {
                    require(r)?;
                }
                exported += 1;
            }
            Op::End => {
                if pc + width != words.len() || exported != stage.exports().len() {
                    return Err(Reject::BadEnd(pc));
                }
                ops.push(op);
                return Ok(ops);
            }
        }
        ops.push(op);
        pc += width;
    }
    Err(Reject::BadEnd(pc))
}

fn body(out: &mut String, ops: &[Op]) {
    for op in ops {
        match *op {
            Op::Move {
                dst: Vgpr(dst),
                src: Vgpr(src),
            } => {
                writeln!(out, "  r[{dst}] = r[{src}];").unwrap();
            }
            Op::AddF32Literal {
                dst: Vgpr(dst),
                src: Vgpr(src),
                literal_bits,
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(as_type<float>(0x{literal_bits:08x}u) + as_type<float>(r[{src}]));").unwrap();
            }
            Op::MulLegacyF32 {
                dst: Vgpr(dst),
                lhs,
                rhs: Vgpr(rhs),
            } => {
                let lhs = match lhs {
                    FloatSource::Vgpr(Vgpr(r)) => format!("r[{r}]"),
                    FloatSource::InlineBits(bits) => format!("0x{bits:08x}u"),
                };
                writeln!(out, "  r[{dst}] = mul_legacy_f32_bits({lhs}, r[{rhs}]);").unwrap();
            }
            Op::FmaF32 {
                dst: Vgpr(dst),
                src: [Vgpr(a), Vgpr(b), Vgpr(c)],
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(fma(as_type<float>(r[{a}]), as_type<float>(r[{b}]), as_type<float>(r[{c}])));").unwrap();
            }
            Op::Export {
                target,
                src: [Vgpr(a), Vgpr(b), Vgpr(c), Vgpr(d)],
                ..
            } => {
                let field = match target {
                    Target::Position => "out.position",
                    Target::Parameter => "out.parameter",
                    Target::Color => "out",
                };
                writeln!(
                    out,
                    "  {field} = as_type<float4>(uint4(r[{a}], r[{b}], r[{c}], r[{d}]));"
                )
                .unwrap();
            }
            Op::End => out.push_str("  return out;\n}\n"),
        }
    }
}

pub fn fixture_programs(literal_bits: Option<u32>) -> (&'static [u32], Vec<u32>) {
    let mut ps = PS.to_vec();
    if let Some(bits) = literal_bits {
        ps[1] = bits;
    }
    (VS, ps)
}

pub fn translate_fixture(literal_bits: Option<u32>) -> Result<String, Reject> {
    let (vs, ps) = fixture_programs(literal_bits);
    let vs = lift(Stage::Vertex, vs)?;
    let ps = lift(Stage::Pixel, &ps)?;
    // Only the entry/binding convention and one interpolation rule are authored
    // here. All moves, arithmetic, output operands and returns come from the lift.
    let mut msl = String::from(
        "#include <metal_stdlib>\nusing namespace metal;\n\
static uint mul_legacy_f32_bits(uint a, uint b) {\n\
  if ((a & 0x7fffffffu) == 0 || (b & 0x7fffffffu) == 0) return 0u;\n\
  return as_type<uint>(as_type<float>(a) * as_type<float>(b));\n\
}\n\
struct VertexInput { float4 position; float4 parameter; };\n\
struct Varyings { float4 position [[position]]; float4 parameter [[center_no_perspective]]; };\n\
vertex Varyings translated_vs(uint vid [[vertex_id]], const device VertexInput *input [[buffer(0)]]) {\n\
  uint r[256]; Varyings out;\n\
  const uint4 p = as_type<uint4>(input[vid].position);\n\
  const uint4 a = as_type<uint4>(input[vid].parameter);\n\
  r[0] = p.x; r[1] = p.y; r[2] = p.z; r[3] = p.w;\n\
  r[4] = a.x; r[5] = a.y; r[6] = a.z; r[7] = a.w;\n",
    );
    body(&mut msl, &vs);
    msl.push_str(
        "fragment float4 translated_ps(Varyings in [[stage_in]]) {\n\
  uint r[256]; float4 out;\n\
  const uint4 a = as_type<uint4>(in.parameter);\n\
  r[0] = a.x; r[1] = a.y; r[2] = a.z; r[3] = a.w;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_words_match_llvm_mc_on_both_reference_cpus() {
        let Some(mc) = std::env::var_os("LLVM_MC") else {
            return;
        };
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let asm = "v_mov_b32_e32 v8, v4\nexp param0 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\nv_add_f32_e32 v4, 0.25, v0\nv_fma_f32 v5, v1, v2, v3\nv_mul_legacy_f32_e32 v6, v5, v4\nv_mul_legacy_f32_e32 v6, 0.5, v6\nv_mul_legacy_f32_e32 v7, 0, v3\nexp mrt0 v4, v5, v6, v7 done\ns_endpgm\n";
        let expected: Vec<u8> = VS.iter().chain(PS).flat_map(|w| w.to_le_bytes()).collect();
        for cpu in ["gfx1013", "gfx1030"] {
            let mut child = Command::new(&mc)
                .args(["-triple=amdgcn", &format!("-mcpu={cpu}"), "--show-encoding"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(asm.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(result.status.success());
            let output = String::from_utf8(result.stdout).unwrap();
            let bytes: Vec<u8> = output
                .lines()
                .filter_map(|line| line.split_once("encoding: [").map(|(_, rest)| rest))
                .flat_map(|row| row.trim_end_matches(']').split(','))
                .map(|hex| u8::from_str_radix(hex.trim().strip_prefix("0x").unwrap(), 16).unwrap())
                .collect();
            assert_eq!(bytes, expected, "{cpu}");
        }
    }

    #[test]
    fn strict_graphics_lift_rejects_bad_operand_export_and_extent() {
        assert_eq!(lift(Stage::Vertex, VS).unwrap().len(), 4);
        assert_eq!(lift(Stage::Pixel, PS).unwrap().len(), 7);
        let mut vs = VS.to_vec();
        vs[0] |= 128;
        assert_eq!(lift(Stage::Vertex, &vs), Err(Reject::Uninitialized(0, 132)));
        assert_eq!(lift(Stage::Pixel, &PS[..1]), Err(Reject::Truncated(0)));
        assert_eq!(lift(Stage::Pixel, &PS[..9]), Err(Reject::BadEnd(9)));
        let mut ps = PS.to_vec();
        ps[3] ^= 1 << 29; // Unmodeled negative modifier.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(2)));
        ps[3] = PS[3] & !(1 << 17); // SGPR instead of ordinary VGPR.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(2)));
        ps[3] = PS[3];
        ps[4] &= !(1 << 8); // SGPR source is outside the legacy multiply subset.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(4)));
        ps[4] = PS[4];
        ps[7] |= 0x400; // compressed export is unsupported, not lowered as four lanes
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(7)));
        ps[7] = 0xf800_000f; // missing DONE
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::BadExports(7)));
        ps[7] = PS[7];
        ps.push(0);
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::BadEnd(9)));
    }

    #[test]
    fn native_literal_changes_emitted_fragment() {
        let msl = translate_fixture(None).unwrap();
        let changed = translate_fixture(Some(0x3f00_0000)).unwrap();
        assert_eq!(changed, msl.replace("0x3e800000u", "0x3f000000u"));
        assert_ne!(changed, msl);
    }
}
