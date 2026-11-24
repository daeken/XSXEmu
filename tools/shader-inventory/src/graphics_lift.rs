//! Strict, synthetic VS+PS contract for a small public GFX10 instruction subset.
use std::fmt::Write;

use crate::graphics_decode::{DecodeError, FloatSource, Op, Target, Vgpr, decode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Vertex,
    MultiVertex,
    Pixel,
    PackedPixel,
    PackedRgPixel,
    DualPackedPixel,
    TriplePackedPixel,
    TriplePackedRgPixel,
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
const MULTI_VS: &[u32] = &[
    0xf800_020f,
    0x0706_0504,
    0xf800_021f,
    0x0b0a_0908,
    0xf800_022f,
    0x0f0e_0d0c,
    0xf800_023f,
    0x1312_1110,
    0xf800_024f,
    0x1716_1514,
    0xf800_025f,
    0x1b1a_1918,
    0xf800_026f,
    0x1f1e_1d1c,
    0xf800_08cf,
    0x0302_0100,
    0xbf81_0000,
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

const PACKED_RG_PS: &[u32] = &[0xf800_1c03, 1, 0xbf81_0000];

const DUAL_PS: &[u32] = &[0xf800_040f, 1, 0xf800_1c1f, 0x100, 0xbf81_0000];

const TRIPLE_PS: &[u32] = &[
    0xf800_040f,
    1,
    0xf800_041f,
    0x100,
    0xf800_1c2f,
    0x101,
    0xbf81_0000,
];

const TRIPLE_RG_PS: &[u32] = &[
    0xf800_040f,
    1,
    0xf800_0413,
    0,
    0xf800_1c2f,
    0x101,
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
            Stage::MultiVertex => 32,
            Stage::Pixel => 4,
            Stage::PackedPixel => 2,
            Stage::PackedRgPixel => 2,
            Stage::DualPackedPixel | Stage::TriplePackedPixel | Stage::TriplePackedRgPixel => 2,
            Stage::DepthPixel => 3,
        }
    }

    fn exports(self) -> &'static [(Target, bool)] {
        match self {
            Stage::Vertex => &[(Target::Parameter(0), false), (Target::Position, true)],
            Stage::MultiVertex => &[
                (Target::Parameter(0), false),
                (Target::Parameter(1), false),
                (Target::Parameter(2), false),
                (Target::Parameter(3), false),
                (Target::Parameter(4), false),
                (Target::Parameter(5), false),
                (Target::Parameter(6), false),
                (Target::Position, true),
            ],
            Stage::Pixel => &[(Target::Color, true)],
            Stage::PackedPixel
            | Stage::PackedRgPixel
            | Stage::DepthPixel
            | Stage::DualPackedPixel
            | Stage::TriplePackedPixel
            | Stage::TriplePackedRgPixel => &[],
        }
    }

    fn export_count(self) -> usize {
        match self {
            Stage::PackedPixel | Stage::PackedRgPixel => 1,
            Stage::TriplePackedPixel | Stage::TriplePackedRgPixel => 3,
            Stage::DepthPixel | Stage::DualPackedPixel => 2,
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
    let mut has_vcc = false;
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
            Op::CompareNonzero { src } => {
                if matches!(stage, Stage::Vertex | Stage::MultiVertex) {
                    return Err(Reject::Unsupported(pc));
                }
                require(src)?;
                has_vcc = true;
            }
            Op::SelectBits { dst, when_true, .. } => {
                if !has_vcc {
                    return Err(Reject::Unsupported(pc));
                }
                require(when_true)?;
                live[usize::from(dst.0)] = true;
            }
            Op::MoveBits { dst, .. } => live[usize::from(dst.0)] = true,
            // All admitted profiles have no native memory, clocks, or timing-
            // observable operations. Not valid for arbitrary guest instruction streams.
            Op::NopOneCycle | Op::PrefetchThreeLines => {}
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
            Op::PackedColor {
                slot,
                src,
                done,
                vm,
            } => {
                // An explicit FP16_ABGR target. Neither profile changes EXEC;
                // the final export must communicate ordinary raster coverage.
                let valid = match stage {
                    Stage::PackedPixel => exported == 0 && slot == 0 && done && vm,
                    Stage::DepthPixel => exported == 0 && slot == 0 && !done && !vm,
                    Stage::DualPackedPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (1, 1, true, true)
                    ),
                    Stage::TriplePackedPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (1, 1, false, false) | (2, 2, true, true)
                    ),
                    Stage::TriplePackedRgPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (2, 2, true, true)
                    ),
                    _ => false,
                };
                if !valid {
                    return Err(Reject::BadExports(pc));
                }
                for r in src {
                    require(r)?;
                }
                exported += 1;
            }
            Op::PackedRg { slot, src } => {
                if !matches!(
                    (stage, exported, slot),
                    (Stage::PackedRgPixel, 0, 0) | (Stage::TriplePackedRgPixel, 1, 1)
                ) {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
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
    emit_body(out, ops, "out", false);
}

fn emit_body(out: &mut String, ops: &[Op], packed_color_lvalue: &str, multi: bool) {
    // Only the active lane's VCC bit is observable in this straight-line profile.
    if ops.iter().any(|op| matches!(op, Op::CompareNonzero { .. })) {
        out.push_str("  bool lane_vcc;\n");
    }
    for op in ops {
        match *op {
            Op::Move {
                dst: Vgpr(dst),
                src: Vgpr(src),
            } => {
                writeln!(out, "  r[{dst}] = r[{src}];").unwrap();
            }
            Op::CompareNonzero { src: Vgpr(r) } => {
                writeln!(out, "  lane_vcc = r[{r}] != 0u;").unwrap();
            }
            Op::SelectBits {
                dst: Vgpr(dst),
                when_false,
                when_true: Vgpr(src),
            } => {
                writeln!(
                    out,
                    "  r[{dst}] = lane_vcc ? r[{src}] : 0x{when_false:08x}u;"
                )
                .unwrap();
            }
            Op::MoveBits {
                dst: Vgpr(dst),
                bits,
            } => {
                writeln!(out, "  r[{dst}] = 0x{bits:08x}u;").unwrap();
            }
            Op::NopOneCycle | Op::PrefetchThreeLines => {}
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
                    Target::Parameter(0) if !multi => "out.parameter",
                    Target::Parameter(n) => {
                        writeln!(out, "  out.param{n} = as_type<float4>(uint4(r[{a}], r[{b}], r[{c}], r[{d}]));").unwrap();
                        continue;
                    }
                    Target::Color => "out",
                };
                writeln!(
                    out,
                    "  {field} = as_type<float4>(uint4(r[{a}], r[{b}], r[{c}], r[{d}]));"
                )
                .unwrap();
            }
            Op::PackedColor {
                slot,
                src: [Vgpr(rg), Vgpr(ba)],
                ..
            } => {
                let packed_color_lvalue = match slot {
                    1 => "out.color1",
                    2 => "out.color2",
                    _ => packed_color_lvalue,
                };
                writeln!(out, "  {packed_color_lvalue} = float4(float(as_type<half>(ushort(r[{rg}]))), float(as_type<half>(ushort(r[{rg}] >> 16))), float(as_type<half>(ushort(r[{ba}]))), float(as_type<half>(ushort(r[{ba}] >> 16))));").unwrap();
            }
            Op::PackedRg {
                slot,
                src: Vgpr(rg),
            } => {
                let packed_color_lvalue = if slot == 1 {
                    "out.color1"
                } else {
                    packed_color_lvalue
                };
                // B/A placeholders are never written by the owned RG-only descriptor.
                writeln!(out, "  {packed_color_lvalue} = float4(float(as_type<half>(ushort(r[{rg}]))), float(as_type<half>(ushort(r[{rg}] >> 16))), 0.0f, 0.0f);").unwrap();
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

const EDGE_SELECT: &[u32] = &[
    0x7d8a_0080,
    0x0214_02ff,
    0x7fc1_2345,
    0x7d8a_0280,
    0x0216_00ff,
    0x8000_0000,
];

const EDGE_MOV_HINTS: &[u32] = &[
    0xbfa0_0003,
    0x7e0c_0280,
    0xbf80_0000,
    0x7e0e_02f0,
    0x7e10_02f2,
    0x7e12_02ff,
    0x7fc1_2345,
];

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
    let mut pc = 0;
    while pc < EDGE_MOV_HINTS.len() {
        let (width, op) = decode(EDGE_MOV_HINTS, pc)?;
        body(&mut msl, &[op]);
        pc += width;
    }
    let select = lift(Stage::PackedPixel, &[EDGE_SELECT, PACKED_PS].concat())
        .map_err(|_| DecodeError::Unsupported(0))?;
    body(&mut msl, &select[..4]);
    msl.push_str("  out[3 * id] = uint4(r[2], r[3], r[4], r[5]);\n  out[3 * id + 1] = uint4(r[6], r[7], r[8], r[9]);\n  out[3 * id + 2] = uint4(r[10], r[11], 0u, 0u);\n}\n");
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
pub fn translate_packed_color_fixture(partial: bool) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = if partial {
        lift(Stage::PackedRgPixel, PACKED_RG_PS)?
    } else {
        lift(Stage::PackedPixel, PACKED_PS)?
    };
    let mut msl = vertex_module(&vs);
    msl.push_str(if partial {
        "fragment float4 packed_rg_ps"
    } else {
        "fragment float4 packed_ps"
    });
    msl.push_str(
        "(constant uint2 &input [[buffer(0)]]) {\n\
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
    emit_body(&mut msl, &ps, "out.color", false);
    Ok(msl)
}

#[allow(dead_code)] // Separate MRT render probe.
#[derive(Clone, Copy)]
pub(crate) enum MrtFixture {
    Dual,
    Triple,
    TripleRg,
}

impl MrtFixture {
    #[allow(dead_code)]
    pub(crate) fn entry(self) -> &'static str {
        match self {
            Self::Dual => "dual_ps",
            Self::Triple => "triple_ps",
            Self::TripleRg => "triple_rg_ps",
        }
    }
}

#[allow(dead_code)]
pub(crate) fn translate_mrt_fixture(fixture: MrtFixture) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = match fixture {
        MrtFixture::Dual => lift(Stage::DualPackedPixel, DUAL_PS)?,
        MrtFixture::Triple => lift(Stage::TriplePackedPixel, TRIPLE_PS)?,
        MrtFixture::TripleRg => lift(Stage::TriplePackedRgPixel, TRIPLE_RG_PS)?,
    };
    let mut msl = vertex_module(&vs);
    msl.push_str("struct PackedColors { float4 color0 [[color(0)]]; float4 color1 [[color(1)]];");
    if !matches!(fixture, MrtFixture::Dual) {
        msl.push_str(" float4 color2 [[color(2)]];");
    }
    let entry = fixture.entry();
    writeln!(msl, "}};\nfragment PackedColors {entry}(constant uint2 &input [[buffer(0)]]) {{\n  uint r[256]; PackedColors out; r[0] = input.x; r[1] = input.y;").unwrap();
    emit_body(&mut msl, &ps, "out.color0", false);
    Ok(msl)
}

#[allow(dead_code)] // Separate linkage probe; the fragment consumer is authored.
pub fn translate_multi_vertex_fixture() -> Result<String, Reject> {
    let vs = lift(Stage::MultiVertex, MULTI_VS)?;
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str("struct MultiOut { float4 position [[position]];\n");
    for n in 0..7 {
        writeln!(
            msl,
            "  float4 param{n} [[user(param{n}), center_no_perspective]];"
        )
        .unwrap();
    }
    msl.push_str("};\nstruct MultiIn {\n");
    // Reverse declaration order to ensure links use explicit varying names.
    for n in (0..7).rev() {
        writeln!(
            msl,
            "  float4 input{n} [[user(param{n}), center_no_perspective]];"
        )
        .unwrap();
    }
    msl.push_str("};\nvertex MultiOut multi_vs(uint vid [[vertex_id]], const device uint4 *input [[buffer(0)]]) {\n  uint r[256]; MultiOut out;\n");
    msl.push_str("  for (uint i = 0; i < 8; ++i) { uint4 p = input[8 * vid + i]; for (uint j = 0; j < 4; ++j) r[4 * i + j] = p[j]; }\n");
    emit_body(&mut msl, &vs, "out", true);
    msl.push_str("fragment float4 multi_ps(MultiIn in [[stage_in]]) {\n  float4 color = 0.0f;\n");
    for n in 0..7 {
        writeln!(msl, "  color += {}.0f * in.input{n};", n + 1).unwrap();
    }
    msl.push_str("  return color;\n}\n");
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
        let asm = "v_mov_b32_e32 v8, v4\nexp param0 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\nv_add_f32_e32 v4, 0.25, v0\nv_fma_f32 v5, v1, v2, v3\nv_mul_legacy_f32_e32 v6, v5, v4\nv_mul_legacy_f32_e32 v6, 0.5, v6\nv_mul_legacy_f32_e32 v7, 0, v3\nexp mrt0 v4, v5, v6, v7 done\ns_endpgm\nv_mul_legacy_f32_e32 v2, v0, v1\nv_mul_legacy_f32_e32 v3, 0.25, v1\nv_fmac_f32_e32 v4, v0, v1\nv_cvt_pkrtz_f16_f32_e32 v5, v0, v1\ns_inst_prefetch 3\nv_mov_b32_e32 v6, 0\ns_nop 0\nv_mov_b32_e32 v7, 0.5\nv_mov_b32_e32 v8, 1.0\nv_mov_b32_e32 v9, 0x7fc12345\nv_cmp_ne_u32_e32 vcc_lo, 0, v0\nv_cndmask_b32_e32 v10, 0x7fc12345, v1, vcc_lo\nv_cmp_ne_u32_e32 vcc_lo, 0, v1\nv_cndmask_b32_e32 v11, 0x80000000, v0, vcc_lo\nexp mrt0 v1, v1, v0, v0 done compr vm\ns_endpgm\nexp mrt0 v1, v1, off, off done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrtz v2, off, off, off done vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 compr\nexp mrt2 v1, v1, v1, v1 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, off, off compr\nexp mrt2 v1, v1, v1, v1 done compr vm\ns_endpgm\n";
        let mut asm = asm.to_owned();
        for n in 0..7 {
            let r = 4 + 4 * n;
            writeln!(asm, "exp param{n} v{r}, v{}, v{}, v{}", r + 1, r + 2, r + 3).unwrap();
        }
        asm.push_str("exp pos0 v0, v1, v2, v3 done\ns_endpgm\n");
        let expected: Vec<u8> = VS
            .iter()
            .chain(PS)
            .chain(EDGE_VGPR)
            .chain(EDGE_LITERAL)
            .chain(EDGE_FMAC)
            .chain(EDGE_RTZ)
            .chain(EDGE_MOV_HINTS)
            .chain(EDGE_SELECT)
            .chain(PACKED_PS)
            .chain(PACKED_RG_PS)
            .chain(DEPTH_PS)
            .chain(DUAL_PS)
            .chain(TRIPLE_PS)
            .chain(TRIPLE_RG_PS)
            .chain(MULTI_VS)
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
            0xf800_0403,
            0xf800_042f,
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
    fn triple_packed_rg_requires_rg_only_mrt1_before_final_full_mrt2() {
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, TRIPLE_RG_PS)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, TRIPLE_RG_PS),
            Err(Reject::BadExports(2))
        );
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, TRIPLE_PS),
            Err(Reject::BadExports(2))
        );
        let mut ps = TRIPLE_RG_PS.to_vec();
        ps[3] = 2;
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            Err(Reject::Uninitialized(2, 2))
        );
        ps[3] = 0x100;
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            Err(Reject::Unsupported(2))
        );
        ps[2..6].rotate_left(2);
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            Err(Reject::BadExports(2))
        );
    }

    #[test]
    fn triple_packed_requires_nonfinal_mrt1_and_final_mrt2() {
        assert_eq!(lift(Stage::TriplePackedPixel, TRIPLE_PS).unwrap().len(), 4);
        assert_eq!(
            lift(Stage::DualPackedPixel, TRIPLE_PS),
            Err(Reject::BadExports(2))
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, DUAL_PS),
            Err(Reject::BadExports(2))
        );
        let mut ps = TRIPLE_PS.to_vec();
        ps[4] = DUAL_PS[2];
        assert_eq!(
            lift(Stage::TriplePackedPixel, &ps),
            Err(Reject::BadExports(4))
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, &TRIPLE_PS[..6]),
            Err(Reject::BadEnd(6))
        );
        assert_eq!(
            decode(&[TRIPLE_PS[4], 0x0100_0101], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn dual_packed_requires_exact_slots_and_final_valid_mask() {
        assert_eq!(lift(Stage::DualPackedPixel, DUAL_PS).unwrap().len(), 3);
        assert_eq!(
            lift(Stage::PackedPixel, &DUAL_PS[2..]),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::DualPackedPixel, &DUAL_PS[..4]),
            Err(Reject::BadEnd(4))
        );
        let mut ps = DUAL_PS.to_vec();
        ps[2] = 0xf800_1c0f;
        assert_eq!(
            lift(Stage::DualPackedPixel, &ps),
            Err(Reject::BadExports(2))
        );
        for hdr in [0xf800_1c13, 0xf800_1c3f, 0xf800_0c1f, 0xf800_141f] {
            assert_eq!(decode(&[hdr, 0], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[DUAL_PS[2], 0x10100], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn select_requires_local_predicate_and_live_source() {
        assert_eq!(
            lift(Stage::PackedPixel, &EDGE_SELECT[1..3]),
            Err(Reject::Unsupported(0))
        );
        assert_eq!(
            lift(Stage::PackedPixel, &[EDGE_SELECT[0], 0x0214_08ff, 0]),
            Err(Reject::Uninitialized(1, 4))
        );
        assert_eq!(
            decode(&EDGE_SELECT[1..2], 0),
            Err(DecodeError::Truncated(0))
        );
        for word in [0x7d8a_0180, 0x7d8a_0181, 0x7d8a_0100, 0x0214_0300] {
            assert_eq!(decode(&[word, 0], 0), Err(DecodeError::Unsupported(0)));
        }
    }

    #[test]
    fn multi_vertex_requires_exact_owned_slots_and_defined_inputs() {
        assert_eq!(lift(Stage::MultiVertex, MULTI_VS).unwrap().len(), 9);
        assert_eq!(lift(Stage::Vertex, MULTI_VS), Err(Reject::BadExports(2)));
        let mut vs = MULTI_VS.to_vec();
        vs[2] = vs[0];
        assert_eq!(lift(Stage::MultiVertex, &vs), Err(Reject::BadExports(2)));
        vs[2] = MULTI_VS[2];
        vs[3] = 32;
        assert_eq!(
            lift(Stage::MultiVertex, &vs),
            Err(Reject::Uninitialized(2, 32))
        );
        for header in [0xf800_027f, 0xf800_0a1f, 0xf800_061f, 0xf800_0213] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
    }

    #[test]
    fn partial_packed_color_requires_rg_profile_and_only_reads_rg() {
        assert_eq!(lift(Stage::PackedRgPixel, PACKED_RG_PS).unwrap().len(), 2);
        assert_eq!(
            lift(Stage::PackedPixel, PACKED_RG_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::PackedRgPixel, PACKED_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::PackedRgPixel, &[0xf800_1c03, 7, 0xbf81_0000]),
            Err(Reject::Uninitialized(0, 7))
        );
        for header in [0xf800_1c0c, 0xf800_1c13, 0xf800_3c03] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[0xf800_1c03, 0x0101], 0),
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
    fn raw_mov_and_hints_admit_only_checked_forms() {
        assert_eq!(decode(&[0x7e12_02ff], 0), Err(DecodeError::Truncated(0)));
        for word in [
            0x7e0c_0200,
            0x7e0c_02f1,
            0xbf80_0001,
            0xbfa0_0002,
            0xbfa0_0007,
            0xbf8c_0000,
        ] {
            assert_eq!(decode(&[word], 0), Err(DecodeError::Unsupported(0)));
        }
        let mut ps = vec![0xbfa0_0003, 0xbf80_0000, 0x7e00_0280];
        ps.extend_from_slice(PACKED_PS);
        assert_eq!(lift(Stage::PackedPixel, &ps).unwrap().len(), 5);
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
