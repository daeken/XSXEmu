//! Strict, synthetic VS+PS contract for a small public GFX10 instruction subset.
use std::fmt::Write;

use crate::graphics_decode::{DecodeError, FloatSource, Op, Target, Vgpr, decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Vertex,
    Pixel,
    PackedPixel,
    DepthPixel,
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

const PACKED_PS: &[u32] = &[
    0xf800_1c0f,
    0x0000_0001, // exp mrt0 v1, v1, v0, v0 done compr vm
    0xbf81_0000,
];

const DEPTH_PS: &[u32] = &[
    0xf800_040f,
    1, // exp mrt0 v1, v1, v0, v0 compr
    0xf800_1881,
    2, // exp mrtz v2, off, off, off done vm
    0xbf81_0000,
];

impl Stage {
    fn input_registers(self) -> usize {
        match self {
            Stage::Vertex => 8,
            Stage::Pixel => 4,
            Stage::PackedPixel => 2,
            Stage::DepthPixel => 3,
        }
    }

    fn exports(self) -> &'static [(Target, bool)] {
        match self {
            Stage::Vertex => &[(Target::Parameter, false), (Target::Position, true)],
            Stage::Pixel => &[(Target::Color, true)],
            Stage::PackedPixel | Stage::DepthPixel => &[],
        }
    }

    fn export_count(self) -> usize {
        match self {
            Stage::PackedPixel => 1,
            Stage::DepthPixel => 2,
            _ => self.exports().len(),
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
        if exported == stage.export_count() && op != Op::End {
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
            Op::FmaF32 { dst, src, .. } => {
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
            Op::PackedColor0 { src, done, vm } => {
                // An explicit FP16_ABGR target. Neither profile changes EXEC;
                // the final export must communicate ordinary raster coverage.
                let valid = match stage {
                    Stage::PackedPixel => done && vm,
                    Stage::DepthPixel => !done && !vm,
                    _ => false,
                };
                if !valid || exported != 0 {
                    return Err(Reject::BadExports(pc));
                }
                for r in src {
                    require(r)?;
                }
                exported += 1;
            }
            Op::FinalPixelDepth { src } => {
                if stage != Stage::DepthPixel || exported != 1 {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
                exported += 1;
            }
            // The separate owned raw-bit probe establishes the value domain.
            Op::PackHalfRtz { .. } => return Err(Reject::Unsupported(pc)),
            Op::End => {
                if pc + width != words.len() || exported != stage.export_count() {
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
    emit_body(out, ops, "out");
}

fn emit_body(out: &mut String, ops: &[Op], packed_color_lvalue: &str) {
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
                    FloatSource::InlineBits(bits) | FloatSource::LiteralBits(bits) => {
                        format!("0x{bits:08x}u")
                    }
                };
                writeln!(out, "  r[{dst}] = mul_legacy_f32_bits({lhs}, r[{rhs}]);").unwrap();
            }
            Op::FmaF32 {
                dst: Vgpr(dst),
                src: [Vgpr(a), Vgpr(b), Vgpr(c)],
                ..
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
            Op::PackedColor0 {
                src: [Vgpr(rg), Vgpr(ba)],
                ..
            } => {
                writeln!(out, "  {packed_color_lvalue} = float4(float(as_type<half>(ushort(r[{rg}]))), float(as_type<half>(ushort(r[{rg}] >> 16))), float(as_type<half>(ushort(r[{ba}]))), float(as_type<half>(ushort(r[{ba}] >> 16))));").unwrap();
            }
            Op::FinalPixelDepth { src: Vgpr(r) } => {
                writeln!(out, "  out.depth = as_type<float>(r[{r}]);").unwrap();
            }
            Op::PackHalfRtz {
                dst: Vgpr(dst),
                src: [Vgpr(lo), Vgpr(hi)],
            } => {
                writeln!(
                    out,
                    "  r[{dst}] = half_rtz_bits(r[{lo}]) | (half_rtz_bits(r[{hi}]) << 16);"
                )
                .unwrap();
            }
            Op::End => out.push_str("  return out;\n}\n"),
        }
    }
}

const MSL_HEADER: &str = "#include <metal_stdlib>\nusing namespace metal;\n\
static uint mul_legacy_f32_bits(uint a, uint b) {\n\
  if ((a & 0x7fffffffu) == 0 || (b & 0x7fffffffu) == 0) return 0u;\n\
  return as_type<uint>(as_type<float>(a) * as_type<float>(b));\n\
}\n";

// The probe covers finite normal results and signed zero. No guest denormal
// mode or NaN payload mapping is established by this helper.
const RTZ_HELPER: &str = "static uint half_rtz_bits(uint a) {\n\
  uint sign = (a >> 16) & 0x8000u;\n\
  uint exp = (a >> 23) & 255u;\n\
  uint fraction = a & 0x7fffffu;\n\
  if (exp == 255u) return sign | (fraction != 0u ? 0x7e00u : 0x7c00u);\n\
  if (exp > 142u) return sign | 0x7bffu;\n\
  if (exp >= 113u) return sign | ((exp - 112u) << 10) | (fraction >> 13);\n\
  if (exp < 103u) return sign;\n\
  return sign | ((fraction | 0x800000u) >> (126u - exp));\n\
}\n";

const EDGE_VGPR: &[u32] = &[0x0e04_0300]; // v_mul_legacy_f32_e32 v2, v0, v1
const EDGE_LITERAL: &[u32] = &[0x0e06_02ff, 0x3e80_0000]; // v_mul_legacy_f32_e32 v3, 0.25, v1
const EDGE_FMAC: &[u32] = &[0x5608_0300]; // v_fmac_f32_e32 v4, v0, v1
const EDGE_RTZ: &[u32] = &[0x5e0a_0300]; // v_cvt_pkrtz_f16_f32_e32 v5, v0, v1

#[allow(dead_code)] // Used by the separate owned bit-exact edge probe.
pub fn translate_legacy_edge_fixture() -> Result<String, DecodeError> {
    let (a_width, a) = decode(EDGE_VGPR, 0)?;
    let (b_width, b) = decode(EDGE_LITERAL, 0)?;
    let (c_width, c) = decode(EDGE_FMAC, 0)?;
    let (d_width, d) = decode(EDGE_RTZ, 0)?;
    if (a_width, b_width, c_width, d_width) != (1, 2, 1, 1)
        || !matches!(d, Op::PackHalfRtz { .. })
        || !matches!(
            c,
            Op::FmaF32 {
                accumulate: true,
                ..
            }
        )
        || !matches!(a, Op::MulLegacyF32 { .. })
        || !matches!(b, Op::MulLegacyF32 { .. })
    {
        return Err(DecodeError::Unsupported(0));
    }
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str(RTZ_HELPER);
    msl.push_str("kernel void legacy_edges(const device uint4 *in [[buffer(0)]], device uint4 *out [[buffer(1)]], uint id [[thread_position_in_grid]]) {\n  uint r[256]; r[0] = in[id].x; r[1] = in[id].y; r[4] = in[id].z;\n");
    body(&mut msl, &[a, b, c, d]);
    msl.push_str("  out[id] = uint4(r[2], r[3], r[4], r[5]);\n}\n");
    Ok(msl)
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
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "fragment float4 translated_ps(Varyings in [[stage_in]]) {\n\
  uint r[256]; float4 out;\n\
  const uint4 a = as_type<uint4>(in.parameter);\n\
  r[0] = a.x; r[1] = a.y; r[2] = a.z; r[3] = a.w;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[allow(dead_code)] // Separate owned render probe, not the keyed graphics fixture.
pub fn translate_packed_color_fixture() -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = lift(Stage::PackedPixel, PACKED_PS)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "fragment float4 packed_ps(constant uint2 &input [[buffer(0)]]) {\n\
  uint r[256]; float4 out;\n\
  r[0] = input.x; r[1] = input.y;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[allow(dead_code)] // Separate owned depth probe, not the keyed graphics fixture.
pub fn translate_depth_fixture() -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = lift(Stage::DepthPixel, DEPTH_PS)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "struct DepthOutputs { float4 color [[color(0)]]; float depth [[depth(any)]]; };\n\
fragment DepthOutputs depth_ps(constant uint4 &input [[buffer(0)]]) {\n\
  uint r[256]; DepthOutputs out;\n\
  r[0] = input.x; r[1] = input.y; r[2] = input.z;\n",
    );
    emit_body(&mut msl, &ps, "out.color");
    Ok(msl)
}

fn vertex_module(vs: &[Op]) -> String {
    // Only the entry/binding convention and one interpolation rule are authored
    // here. All moves, arithmetic, output operands and returns come from the lift.
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str(
        "struct VertexInput { float4 position; float4 parameter; };\n\
struct Varyings { float4 position [[position]]; float4 parameter [[center_no_perspective]]; };\n\
vertex Varyings translated_vs(uint vid [[vertex_id]], const device VertexInput *input [[buffer(0)]]) {\n\
  uint r[256]; Varyings out;\n\
  const uint4 p = as_type<uint4>(input[vid].position);\n\
  const uint4 a = as_type<uint4>(input[vid].parameter);\n\
  r[0] = p.x; r[1] = p.y; r[2] = p.z; r[3] = p.w;\n\
  r[4] = a.x; r[5] = a.y; r[6] = a.z; r[7] = a.w;\n",
    );
    body(&mut msl, vs);
    msl
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
        let asm = "v_mov_b32_e32 v8, v4\nexp param0 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\nv_add_f32_e32 v4, 0.25, v0\nv_fma_f32 v5, v1, v2, v3\nv_mul_legacy_f32_e32 v6, v5, v4\nv_mul_legacy_f32_e32 v6, 0.5, v6\nv_mul_legacy_f32_e32 v7, 0, v3\nexp mrt0 v4, v5, v6, v7 done\ns_endpgm\nv_mul_legacy_f32_e32 v2, v0, v1\nv_mul_legacy_f32_e32 v3, 0.25, v1\nv_fmac_f32_e32 v4, v0, v1\nv_cvt_pkrtz_f16_f32_e32 v5, v0, v1\nexp mrt0 v1, v1, v0, v0 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrtz v2, off, off, off done vm\ns_endpgm\n";
        let expected: Vec<u8> = VS
            .iter()
            .chain(PS)
            .chain(EDGE_VGPR)
            .chain(EDGE_LITERAL)
            .chain(EDGE_FMAC)
            .chain(EDGE_RTZ)
            .chain(PACKED_PS)
            .chain(DEPTH_PS)
            .flat_map(|w| w.to_le_bytes())
            .collect();
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
    fn packed_color_requires_its_own_format_live_sources_and_complete_mask() {
        assert_eq!(lift(Stage::PackedPixel, PACKED_PS).unwrap().len(), 2);
        assert_eq!(lift(Stage::Pixel, PACKED_PS), Err(Reject::BadExports(0)));
        assert_eq!(
            lift(Stage::PackedPixel, &PACKED_PS[..2]),
            Err(Reject::BadEnd(2))
        );
        let mut ps = PACKED_PS.to_vec();
        ps[1] = 0x0801;
        assert_eq!(
            lift(Stage::PackedPixel, &ps),
            Err(Reject::Uninitialized(0, 8))
        );
        ps[1] = PACKED_PS[1];
        ps[0] &= !0x1800;
        assert_eq!(lift(Stage::PackedPixel, &ps), Err(Reject::BadExports(0)));
        for header in [
            0xf800_0c0f,
            0xf800_140f,
            0xf800_1c03,
            0xf800_1c1f,
            0xf800_3c0f,
        ] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[PACKED_PS[0], 0x10001], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn depth_profile_requires_color_then_depth_and_a_real_end() {
        assert_eq!(lift(Stage::DepthPixel, DEPTH_PS).unwrap().len(), 3);
        assert_eq!(
            lift(Stage::DepthPixel, &DEPTH_PS[..4]),
            Err(Reject::BadEnd(4))
        );
        let mut ps = DEPTH_PS.to_vec();
        ps[0] = PACKED_PS[0]; // premature DONE+VM
        assert_eq!(lift(Stage::DepthPixel, &ps), Err(Reject::BadExports(0)));
        ps[0] = DEPTH_PS[0];
        ps[3] = 3;
        assert_eq!(
            lift(Stage::DepthPixel, &ps),
            Err(Reject::Uninitialized(2, 3))
        );
        assert_eq!(
            lift(Stage::PackedPixel, &DEPTH_PS[2..]),
            Err(Reject::BadExports(0))
        );
        for header in [
            0xf800_0081,
            0xf800_0881,
            0xf800_1081,
            0xf800_1883,
            0xf800_1c81,
        ] {
            assert_eq!(decode(&[header, 2], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[DEPTH_PS[2], 0x0102], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn packed_rtz_rejects_scalar_source_and_unvalidated_graphics_fp_mode() {
        assert_eq!(
            decode(&[EDGE_RTZ[0] & !0x100], 0),
            Err(DecodeError::Unsupported(0))
        );
        assert_eq!(lift(Stage::Pixel, EDGE_RTZ), Err(Reject::Unsupported(0)));
    }

    #[test]
    fn fmac_reads_old_destination_and_rejects_scalar_sources() {
        assert_eq!(
            lift(Stage::Pixel, EDGE_FMAC),
            Err(Reject::Uninitialized(0, 4))
        );
        assert_eq!(
            decode(&[EDGE_FMAC[0] & !(1 << 8)], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn legacy_literal_extent_and_fp_classes_are_checked() {
        assert_eq!(
            decode(&EDGE_LITERAL[..1], 0),
            Err(DecodeError::Truncated(0))
        );
        for bits in [1, 0x7f80_0000, 0x7fc1_2345] {
            assert_eq!(
                decode(&[EDGE_LITERAL[0], bits], 0),
                Err(DecodeError::Unsupported(0))
            );
        }
        assert!(matches!(
            decode(&[EDGE_LITERAL[0], 0x8000_0000], 0),
            Ok((
                2,
                Op::MulLegacyF32 {
                    lhs: FloatSource::LiteralBits(0x8000_0000),
                    ..
                }
            ))
        ));
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
